const express = require("express");
const crypto = require("node:crypto");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || "";
const BOTCONTROL_OWNER_DISCORD_ID = process.env.BOTCONTROL_OWNER_DISCORD_ID || "";
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const RENDER_API_TOKEN = process.env.RENDER_API_TOKEN || "";
const BOTCONTROL_SHARED_SECRET = process.env.BOTCONTROL_SHARED_SECRET || "";
const COOKIE_NAME = "botcontrol_session";
const OAUTH_STATE_COOKIE = "botcontrol_oauth_state";
const SESSION_TTL_SECONDS = 60 * 60 * 12;

// Avoid duplicate concurrent Discord guild-list requests and respect Discord rate limits.
const discordGuildRequests = new Map();
const discordGuildCooldowns = new Map();

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function parseCookies(header = "") {
  const result = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    try { result[key] = decodeURIComponent(part.slice(index + 1).trim()); } catch {}
  }
  return result;
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function signValue(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function encryptSessionSecret(value) {
  const key = crypto.createHash("sha256").update(SESSION_SECRET).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(part => part.toString("base64url")).join(".");
}

function decryptSessionSecret(value) {
  if (!value || !SESSION_SECRET) return null;
  try {
    const [ivPart, tagPart, encryptedPart] = String(value).split(".");
    if (!ivPart || !tagPart || !encryptedPart) return null;
    const key = crypto.createHash("sha256").update(SESSION_SECRET).digest();
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivPart, "base64url"));
    decipher.setAuthTag(Buffer.from(tagPart, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(encryptedPart, "base64url")),
      decipher.final()
    ]).toString("utf8");
  } catch {
    return null;
  }
}

function createSignedToken(data) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  return payload + "." + signValue(payload);
}

function readSignedToken(token) {
  if (!SESSION_SECRET || !token) return null;
  const [payload, signature] = token.split(".");
  if (!payload || !signature || !safeEqual(signValue(payload), signature)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (Number(data.exp) <= Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch {
    return null;
  }
}

function readSession(req) {
  return readSignedToken(parseCookies(req.headers.cookie)[COOKIE_NAME]);
}

function setCookie(res, name, value, maxAge, sameSite = "Lax") {
  const parts = [
    name + "=" + encodeURIComponent(value),
    "Path=/",
    "HttpOnly",
    "SameSite=" + sameSite,
    "Max-Age=" + maxAge
  ];
  if (isProduction) parts.push("Secure");
  res.append("Set-Cookie", parts.join("; "));
}

function setSessionCookie(res, user, oauthAccessToken) {
  const token = createSignedToken({
    discordId: String(user.id),
    username: String(user.username || "Discord user").slice(0, 100),
    globalName: String(user.global_name || "").slice(0, 100),
    avatar: user.avatar ? String(user.avatar) : null,
    discordAccessToken: encryptSessionSecret(oauthAccessToken),
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS
  });
  setCookie(res, COOKIE_NAME, token, SESSION_TTL_SECONDS, "Lax");
}

function clearCookie(res, name) {
  const parts = [name + "=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (isProduction) parts.push("Secure");
  res.append("Set-Cookie", parts.join("; "));
}

function isOwner(user) {
  return !!user && !!BOTCONTROL_OWNER_DISCORD_ID &&
    safeEqual(user.discordId, BOTCONTROL_OWNER_DISCORD_ID);
}

function requireAuth(req, res, next) {
  const user = readSession(req);
  if (!user) return res.status(401).json({ error: "Сначала войди через Discord." });
  req.user = user;
  next();
}

function requireOwner(req, res, next) {
  if (!isOwner(req.user)) return res.status(403).json({ error: "Это действие доступно только владельцу BotControl." });
  next();
}

async function supabaseRequest(tablePath, method = "GET", body) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    const error = new Error("Supabase не настроен на сервере BotControl.");
    error.status = 503;
    throw error;
  }
  const response = await fetch(SUPABASE_URL + "/rest/v1/" + tablePath, {
    method,
    headers: {
      "apikey": SUPABASE_SERVICE_ROLE_KEY,
      "Authorization": "Bearer " + SUPABASE_SERVICE_ROLE_KEY,
      "Accept": "application/json",
      ...(body ? { "Content-Type": "application/json", "Prefer": "resolution=merge-duplicates,return=representation" } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(12000)
  });
  const text = await response.text();
  if (!response.ok) {
    const error = new Error("Supabase API вернул HTTP " + response.status);
    error.status = response.status;
    throw error;
  }
  return text ? JSON.parse(text) : [];
}

async function getUserAccess(discordId, botId) {
  const query = "botcontrol_access?discord_id=eq." + encodeURIComponent(discordId) +
    "&bot_id=eq." + encodeURIComponent(botId) + "&select=*&limit=100";
  return supabaseRequest(query);
}

async function hasBotPermission(user, botId, guildId, permission) {
  if (isOwner(user)) return true;
  const rows = await getUserAccess(user.discordId, botId);
  return rows.some(row =>
    (row.guild_id === "*" || (guildId && row.guild_id === String(guildId))) &&
    row[permission] === true
  );
}

async function writeAudit(user, action, botId = null, guildId = null, details = {}) {
  try {
    await supabaseRequest("botcontrol_audit", "POST", {
      actor_discord_id: user.discordId,
      actor_username: user.username,
      action,
      bot_id: botId,
      guild_id: guildId ? String(guildId) : null,
      details
    });
  } catch (error) {
    console.error("Audit write failed:", error.message);
  }
}

function requireSameOrigin(req, res, next) {
  const origin = req.get("origin");
  if (!origin) return res.status(403).json({ error: "Origin обязателен." });
  try {
    const originUrl = new URL(origin);
    const expectedHost = req.get("x-forwarded-host") || req.get("host");
    if (originUrl.host !== expectedHost) return res.status(403).json({ error: "Недопустимый источник запроса." });
  } catch {
    return res.status(403).json({ error: "Некорректный Origin." });
  }
  next();
}

function getEnvironmentBots() {
  try {
    const parsed = JSON.parse(process.env.BOT_SERVICES || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(bot =>
      bot && typeof bot.id === "string" &&
      typeof bot.name === "string" &&
      typeof bot.renderServiceId === "string" &&
      /^[a-zA-Z0-9_-]+$/.test(bot.id) &&
      /^srv-[a-zA-Z0-9]+$/.test(bot.renderServiceId) &&
      typeof bot.controlUrl === "string" &&
      /^https:\/\/[a-zA-Z0-9.-]+(?::\d+)?$/.test(bot.controlUrl)
    );
  } catch {
    return [];
  }
}

async function getBots() {
  const bots = new Map(getEnvironmentBots().map(bot => [bot.id, bot]));
  if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
    const rows = await supabaseRequest("botcontrol_bots?select=*&enabled=eq.true&limit=200");
    for (const row of rows) {
      if (row && typeof row.id === "string" && typeof row.name === "string" &&
          typeof row.render_service_id === "string" && typeof row.control_url === "string") {
        bots.set(row.id, {
          id: row.id,
          name: row.name,
          renderServiceId: row.render_service_id,
          controlUrl: row.control_url,
          managed: true
        });
      }
    }
  }
  return [...bots.values()];
}

async function renderRequest(endpoint, method = "GET") {
  const response = await fetch("https://api.render.com/v1" + endpoint, {
    method,
    headers: {
      "Accept": "application/json",
      "Authorization": "Bearer " + RENDER_API_TOKEN
    },
    signal: AbortSignal.timeout(12000)
  });
  const body = await response.text();
  if (!response.ok) {
    const error = new Error("Render API вернул HTTP " + response.status);
    error.status = response.status;
    throw error;
  }
  return body ? JSON.parse(body) : {};
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.get("/auth/discord", (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI || !SESSION_SECRET) {
    return res.status(503).send("Discord OAuth2 не настроен. Проверь переменные Render.");
  }
  const state = crypto.randomBytes(24).toString("hex");
  const stateToken = createSignedToken({ state, exp: Math.floor(Date.now() / 1000) + 600 });
  setCookie(res, OAUTH_STATE_COOKIE, stateToken, 600, "Lax");
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds",
    state
  });
  res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
});

app.get("/auth/discord/callback", async (req, res) => {
  const stateCookie = readSignedToken(parseCookies(req.headers.cookie)[OAUTH_STATE_COOKIE]);
  clearCookie(res, OAUTH_STATE_COOKIE);
  if (!stateCookie || !req.query.state || !safeEqual(stateCookie.state, req.query.state)) {
    return res.status(400).send("OAuth state mismatch. Вернись в BotControl и попробуй войти снова.");
  }
  if (typeof req.query.code !== "string" || !DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI) {
    return res.status(400).send("Discord OAuth2 callback is incomplete.");
  }
  try {
    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: req.query.code,
        redirect_uri: DISCORD_REDIRECT_URI
      }),
      signal: AbortSignal.timeout(12000)
    });
    const tokenData = await tokenResponse.json().catch(() => ({}));
    if (!tokenResponse.ok || !tokenData.access_token) {
      return res.status(502).send("Не удалось подтвердить вход через Discord.");
    }
    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { "Authorization": "Bearer " + tokenData.access_token, "Accept": "application/json" },
      signal: AbortSignal.timeout(12000)
    });
    const user = await userResponse.json().catch(() => ({}));
    if (!userResponse.ok || !user.id) return res.status(502).send("Discord не вернул профиль пользователя.");

    try {
      await supabaseRequest("botcontrol_users?on_conflict=discord_id", "POST", {
        discord_id: String(user.id),
        username: String(user.username || "").slice(0, 100),
        global_name: String(user.global_name || "").slice(0, 100),
        avatar: user.avatar || null,
        last_login_at: new Date().toISOString()
      });
    } catch (profileError) {
      console.warn("Discord profile could not be stored:", profileError.message);
    }
    setSessionCookie(res, user, tokenData.access_token);
    res.redirect("/");
  } catch (error) {
    console.error("Discord OAuth error:", error.message);
    res.status(error.status || 502).send("Ошибка входа через Discord или проверки доступа.");
  }
});

app.post("/api/auth/logout", requireSameOrigin, (_req, res) => {
  clearCookie(res, COOKIE_NAME);
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  const user = readSession(req);
  const sessionReady = !!user && !!user.discordAccessToken;
  if (user && !sessionReady) clearCookie(res, COOKIE_NAME);
  res.json({
    authenticated: sessionReady,
    user: sessionReady ? { id: user.discordId, username: user.username, globalName: user.globalName, avatar: user.avatar, isOwner: isOwner(user) } : null
  });
});

app.post("/api/bots", requireSameOrigin, requireAuth, requireOwner, async (req, res) => {
  const id = String(req.body?.id || "").trim().toLowerCase();
  const name = String(req.body?.name || "").trim();
  const renderServiceId = String(req.body?.render_service_id || "").trim();
  const controlUrl = String(req.body?.control_url || "").trim();
  if (!/^[a-z0-9_-]{2,40}$/.test(id)) return res.status(400).json({ error: "ID бота: 2–40 символов, латиница, цифры, _ или -." });
  if (getEnvironmentBots().some(bot => bot.id === id)) return res.status(409).json({ error: "Этот ID уже занят ботом из BOT_SERVICES." });
  if (!name || name.length > 80) return res.status(400).json({ error: "Название бота должно содержать 1–80 символов." });
  if (!/^srv-[a-zA-Z0-9]+$/.test(renderServiceId)) return res.status(400).json({ error: "Укажи корректный Render Service ID (srv-...)."});
  let parsedUrl;
  try { parsedUrl = new URL(controlUrl); } catch { return res.status(400).json({ error: "Укажи корректный HTTPS URL control API бота." }); }
  if (parsedUrl.protocol !== "https:" || !parsedUrl.hostname.endsWith(".onrender.com") || parsedUrl.port || parsedUrl.pathname !== "/" || parsedUrl.search || parsedUrl.hash) {
    return res.status(400).json({ error: "Control URL должен быть корневым HTTPS-адресом сервиса *.onrender.com." });
  }
  try {
    const saved = await supabaseRequest("botcontrol_bots?on_conflict=id", "POST", {
      id, name, render_service_id: renderServiceId, control_url: parsedUrl.origin,
      enabled: true, created_by: req.user.discordId
    });
    await writeAudit(req.user, "bot_registered", id, null, { name, renderServiceId });
    res.json({ ok: true, bot: saved[0] || { id, name, renderServiceId, controlUrl: parsedUrl.origin } });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message });
  }
});

app.delete("/api/bots/:id", requireSameOrigin, requireAuth, requireOwner, async (req, res) => {
  const id = String(req.params.id || "");
  if (getEnvironmentBots().some(bot => bot.id === id)) {
    return res.status(400).json({ error: "Бот задан в BOT_SERVICES и не удаляется из панели. Удали его из переменной Render." });
  }
  try {
    await supabaseRequest("botcontrol_bots?id=eq." + encodeURIComponent(id), "DELETE");
    await supabaseRequest("botcontrol_access?bot_id=eq." + encodeURIComponent(id), "DELETE");
    await writeAudit(req.user, "bot_unregistered", id, null, {});
    res.json({ ok: true });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message });
  }
});


app.post("/api/bot-applications", requireSameOrigin, requireAuth, async (req, res) => {
  const body = req.body || {};
  const botName = String(body.bot_name || "").trim().slice(0, 80);
  const botId = String(body.bot_discord_id || "").trim();
  const description = String(body.description || "").trim().slice(0, 1000);
  const inviteUrl = String(body.invite_url || "").trim();
  const avatarUrl = String(body.avatar_url || "").trim();
  const supportUrl = String(body.support_url || "").trim();
  if (botName.length < 2 || !/^\\d{15,22}$/.test(botId) || description.length < 10) {
    return res.status(400).json({ error: "Enter a bot name, a valid Discord bot ID, and a description of at least 10 characters." });
  }
  const validHttps = value => { if (!value) return true; try { return new URL(value).protocol === "https:"; } catch { return false; } };
  if (!validHttps(inviteUrl) || !validHttps(avatarUrl) || !validHttps(supportUrl) || !inviteUrl.startsWith("https://discord.com/oauth2/authorize")) {
    return res.status(400).json({ error: "Use a valid Discord OAuth2 bot invite URL and HTTPS links." });
  }
  try {
    const saved = await supabaseRequest("botcontrol_applications", "POST", {
      applicant_discord_id: req.user.discordId, applicant_username: req.user.username,
      bot_name: botName, bot_discord_id: botId, description, invite_url: inviteUrl,
      avatar_url: avatarUrl || null, support_url: supportUrl || null, status: "pending"
    });
    res.json({ ok: true, application: saved[0] });
  } catch (error) { res.status(error.status || 502).json({ error: error.message }); }
});

app.get("/api/bot-applications/mine", requireAuth, async (req, res) => {
  try {
    const rows = await supabaseRequest("botcontrol_applications?select=*&applicant_discord_id=eq." + encodeURIComponent(req.user.discordId) + "&order=created_at.desc&limit=50");
    res.json({ ok: true, applications: rows });
  } catch (error) { res.status(error.status || 502).json({ error: error.message }); }
});

app.get("/api/bot-applications", requireAuth, requireOwner, async (_req, res) => {
  try {
    const rows = await supabaseRequest("botcontrol_applications?select=*&order=created_at.desc&limit=200");
    res.json({ ok: true, applications: rows });
  } catch (error) { res.status(error.status || 502).json({ error: error.message }); }
});

app.patch("/api/bot-applications/:id", requireSameOrigin, requireAuth, requireOwner, async (req, res) => {
  const id = String(req.params.id || "");
  const status = String(req.body?.status || "");
  if (!/^\\d+$/.test(id) || !["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid application or review status." });
  }
  try {
    const rows = await supabaseRequest("botcontrol_applications?id=eq." + encodeURIComponent(id), "PATCH", {
      status, reviewed_by: req.user.discordId, reviewed_at: new Date().toISOString()
    });
    if (!rows.length) return res.status(404).json({ error: "Application not found." });
    res.json({ ok: true, application: rows[0] });
  } catch (error) { res.status(error.status || 502).json({ error: error.message }); }
});

app.get("/api/access", requireAuth, requireOwner, async (_req, res) => {
  try {
    const rows = await supabaseRequest("botcontrol_access?select=*&order=created_at.desc&limit=500");
    res.json({ ok: true, access: rows });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message });
  }
});

app.post("/api/access", requireSameOrigin, requireAuth, requireOwner, async (req, res) => {
  const discordId = String(req.body?.discord_id || "");
  const botId = String(req.body?.bot_id || "");
  const guildId = String(req.body?.guild_id || "*");
  const permissions = req.body?.permissions || {};
  if (!/^\d{15,22}$/.test(discordId)) return res.status(400).json({ error: "Укажи корректный Discord ID пользователя." });
  if (!(await getBots()).some(bot => bot.id === botId)) return res.status(400).json({ error: "Выбранный бот не зарегистрирован в BotControl." });
  if (guildId !== "*" && !/^\d{15,22}$/.test(guildId)) return res.status(400).json({ error: "Укажи корректный ID Discord-сервера или *." });
  for (const key of ["can_view", "can_configure", "can_restart"]) {
    if (typeof permissions[key] !== "boolean") return res.status(400).json({ error: "Все права должны быть true или false." });
  }
  if (!permissions.can_view && !permissions.can_configure && !permissions.can_restart) {
    return res.status(400).json({ error: "Выбери хотя бы одно разрешение." });
  }
  const row = {
    discord_id: discordId,
    bot_id: botId,
    guild_id: guildId,
    can_view: permissions.can_view || permissions.can_configure,
    can_configure: permissions.can_configure,
    can_restart: permissions.can_restart,
    granted_by: req.user.discordId
  };
  try {
    const saved = await supabaseRequest("botcontrol_access?on_conflict=discord_id,bot_id,guild_id", "POST", row);
    await writeAudit(req.user, "access_granted_or_updated", botId, guildId === "*" ? null : guildId, { targetDiscordId: discordId, permissions: row });
    res.json({ ok: true, access: saved[0] || row });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message });
  }
});

app.delete("/api/access", requireSameOrigin, requireAuth, requireOwner, async (req, res) => {
  const discordId = String(req.body?.discord_id || "");
  const botId = String(req.body?.bot_id || "");
  const guildId = String(req.body?.guild_id || "");
  if (!/^\d{15,22}$/.test(discordId) || !botId || !guildId) {
    return res.status(400).json({ error: "Для удаления доступа нужны Discord ID, бот и сервер." });
  }
  try {
    await supabaseRequest(
      "botcontrol_access?discord_id=eq." + encodeURIComponent(discordId) +
      "&bot_id=eq." + encodeURIComponent(botId) +
      "&guild_id=eq." + encodeURIComponent(guildId),
      "DELETE"
    );
    await writeAudit(req.user, "access_revoked", botId, guildId === "*" ? null : guildId, { targetDiscordId: discordId });
    res.json({ ok: true });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message });
  }
});

app.get("/api/logs", requireAuth, requireOwner, async (_req, res) => {
  try {
    const rows = await supabaseRequest("botcontrol_audit?select=*&order=created_at.desc&limit=100");
    res.json({ ok: true, logs: rows });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message });
  }
});

app.get("/api/bots", requireAuth, async (req, res) => {
  let bots = await getBots();
  if (!isOwner(req.user)) {
    const checks = await Promise.all(bots.map(async bot => {
      try {
        const guilds = await authorizedGuildsForBot(req.user, bot);
        return guilds.length ? bot : null;
      } catch (error) {
        console.warn("Guild access check failed for", bot.id, error.message);
        return null;
      }
    }));
    bots = checks.filter(Boolean);
  }
  if (!RENDER_API_TOKEN) {
    return res.json({ connected: false, bots: bots.map(({ id, name, managed, iconUrl, icon_url }) => ({ id, name, iconUrl: iconUrl || icon_url || null, managed: !!managed, canRestart: isOwner(req.user), hostStatus: "not_configured" })) });
  }

  const results = await Promise.all(bots.map(async bot => {
    try {
      const service = await renderRequest("/services/" + encodeURIComponent(bot.renderServiceId));
      return {
        id: bot.id,
        name: bot.name,
        managed: !!bot.managed,
        canRestart: isOwner(req.user),
        hostStatus: service.suspended ? "suspended" : (service.srvStatus || service.status || "unknown"),
        serviceType: service.type || null,
        updatedAt: service.updatedAt || null
      };
    } catch (error) {
      return { id: bot.id, name: bot.name, iconUrl: bot.iconUrl || bot.icon_url || null, managed: !!bot.managed, canRestart: isOwner(req.user), hostStatus: "error", error: error.status ? "Render API HTTP " + error.status : "Render API недоступен" };
    }
  }));
  res.json({ connected: true, bots: results });
});

async function discordGuildsForUser(user) {
  const userId = String(user.discordId || "");
  const accessToken = decryptSessionSecret(user.discordAccessToken);
  if (!accessToken) {
    const error = new Error("Сессия Discord устарела. Выйди из BotControl и войди через Discord снова.");
    error.status = 401;
    throw error;
  }

  const cooldownUntil = discordGuildCooldowns.get(userId) || 0;
  if (cooldownUntil > Date.now()) {
    const waitSeconds = Math.max(1, Math.ceil((cooldownUntil - Date.now()) / 1000));
    const error = new Error("Discord временно ограничил запросы (HTTP 429). Подожди примерно " + waitSeconds + " сек. и попробуй снова. Не нажимай обновление несколько раз подряд.");
    error.status = 429;
    throw error;
  }

  const existingRequest = discordGuildRequests.get(userId);
  if (existingRequest) return existingRequest;

  const request = (async () => {
    const response = await fetch("https://discord.com/api/users/@me/guilds", {
      headers: { "Authorization": "Bearer " + accessToken, "Accept": "application/json" },
      signal: AbortSignal.timeout(12000)
    });
    const data = await response.json().catch(() => null);

    if (response.status === 429) {
      const retryAfter = Number(data?.retry_after || response.headers.get("retry-after") || 30);
      const cooldownMs = Math.max(1000, Math.ceil(retryAfter * 1000));
      discordGuildCooldowns.set(userId, Date.now() + cooldownMs);
      const waitSeconds = Math.ceil(cooldownMs / 1000);
      const error = new Error("Discord временно ограничил запросы (HTTP 429). Повтори попытку примерно через " + waitSeconds + " сек. Не обновляй страницу многократно.");
      error.status = 429;
      throw error;
    }

    if (!response.ok) {
      const discordMessage = typeof data?.message === "string" ? data.message : "";
      let message;
      if (response.status === 401) {
        message = "Discord отклонил OAuth-токен (HTTP 401). Выйди из BotControl и войди через Discord снова.";
      } else if (response.status === 403) {
        message = "Discord запретил чтение списка серверов (HTTP 403). Проверь, что OAuth-приложение запрашивает scope guilds и ты подтвердил доступ. Ответ Discord: " + (discordMessage || "Forbidden");
      } else {
        message = "Discord API не смог получить список серверов (HTTP " + response.status + "). Ответ: " + (discordMessage || "без подробностей");
      }
      const error = new Error(message);
      error.status = response.status || 502;
      throw error;
    }
    if (!Array.isArray(data)) {
      const error = new Error("Discord API вернул неожиданный ответ вместо списка серверов.");
      error.status = 502;
      throw error;
    }
    discordGuildCooldowns.delete(userId);
    return data.filter(guild => {
      if (guild.owner === true) return true;
      try { return (BigInt(String(guild.permissions || "0")) & 8n) === 8n; }
      catch { return false; }
    }).map(guild => ({ id: String(guild.id), name: String(guild.name || "Discord server"), icon: guild.icon ? "https://cdn.discordapp.com/icons/" + guild.id + "/" + guild.icon + ".png?size=128" : null }));
  })();

  discordGuildRequests.set(userId, request);
  try {
    return await request;
  } finally {
    if (discordGuildRequests.get(userId) === request) discordGuildRequests.delete(userId);
  }
}

async function authorizedGuildsForBot(user, bot) {
  const [adminGuilds, botResult] = await Promise.all([
    discordGuildsForUser(user),
    botControlRequest(bot, "GET", undefined, "/control/guilds")
  ]);
  const botGuildIds = new Set((Array.isArray(botResult.guilds) ? botResult.guilds : [])
    .map(guild => String(guild.id)));
  return adminGuilds.filter(guild => botGuildIds.has(guild.id));
}

async function requireAdminOnBotGuild(user, bot, guildId) {
  const guilds = await authorizedGuildsForBot(user, bot);
  if (!guilds.some(guild => guild.id === String(guildId))) {
    const error = new Error("Нет доступа: нужен Administrator на Discord-сервере, где установлен этот бот.");
    error.status = 403;
    throw error;
  }
}

async function botControlRequest(bot, method = "GET", body, endpoint = "/control/config") {
  if (!BOTCONTROL_SHARED_SECRET) {
    const error = new Error("BOTCONTROL_SHARED_SECRET не настроен на BotControl.");
    error.status = 503;
    throw error;
  }
  const response = await fetch(bot.controlUrl + endpoint, {
    method,
    headers: {
      "Accept": "application/json",
      "Authorization": "Bearer " + BOTCONTROL_SHARED_SECRET,
      ...(body ? { "Content-Type": "application/json" } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(12000)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    let message = data.error || "API бота вернул HTTP " + response.status;
    if (response.status === 404) {
      const route = String(endpoint).split("?")[0];
      let host = "адрес из BOT_SERVICES";
      try { host = new URL(bot.controlUrl).host; } catch {}
      message = "Бот недоступен по маршруту " + route + " (HTTP 404) на " + host + ". Это означает, что по этому адресу такой API-маршрут не найден. Для IvynX открой Render → сервис IvynX → Settings → Build & Deploy и проверь Branch: нужна botcontrol-v2-guild-settings. Затем сделай Manual Deploy → Deploy latest commit. Старый main не содержит нужных маршрутов. Секрет BOTCONTROL_SHARED_SECRET обычно не вызывает 404 — пока его не меняй.";
    } else if (response.status === 401 || response.status === 403) {
      message = "Бот отклонил запрос (HTTP " + response.status + "). Проверь, что BOTCONTROL_SHARED_SECRET одинаковый в Render у BotControl и IvynX.";
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return data;
}

app.get("/api/bots/:id/manifest", requireAuth, async (req, res) => {
  const bot = (await getBots()).find(item => item.id === req.params.id);
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  try {
    if (!(await authorizedGuildsForBot(req.user, bot)).length) {
      return res.status(403).json({ error: "На сервере с этим ботом нужен Administrator." });
    }
    const result = await botControlRequest(bot, "GET", undefined, "/control/manifest");
    if (!result.manifest || !Array.isArray(result.manifest.sections)) {
      return res.status(502).json({ error: "Бот вернул некорректную схему настроек." });
    }
    res.json({ ok: true, manifest: result.manifest });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Бот не предоставил схему настроек." });
  }
});

app.get("/api/bots/:id/guilds", requireAuth, async (req, res) => {
  const bot = (await getBots()).find(item => item.id === req.params.id);
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  try {
    const guilds = await authorizedGuildsForBot(req.user, bot);
    res.json({ ok: true, guilds });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Не удалось проверить права Discord или получить серверы бота." });
  }
});

app.get("/api/bots/:id/channels", requireAuth, async (req, res) => {
  const bot = (await getBots()).find(item => item.id === req.params.id);
  const guildId = typeof req.query.guild_id === "string" ? req.query.guild_id : "";
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  if (!/^\d{15,22}$/.test(guildId)) return res.status(400).json({ error: "Выбери Discord-сервер." });
  try {
    await requireAdminOnBotGuild(req.user, bot, guildId);
    const result = await botControlRequest(bot, "GET", undefined, "/control/channels?guild_id=" + encodeURIComponent(guildId));
    res.json({ ok: true, guildId, channels: Array.isArray(result.channels) ? result.channels : [] });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Не удалось загрузить каналы Discord." });
  }
});

app.get("/api/bots/:id/config", requireAuth, async (req, res) => {
  const bot = (await getBots()).find(item => item.id === req.params.id);
  const guildId = typeof req.query.guild_id === "string" ? req.query.guild_id : "";
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  if (!/^\d{15,22}$/.test(guildId)) return res.status(400).json({ error: "Выбери Discord-сервер." });
  try {
    await requireAdminOnBotGuild(req.user, bot, guildId);
    const result = await botControlRequest(bot, "GET", undefined, "/control/config?guild_id=" + encodeURIComponent(guildId));
    res.json({ ok: true, guildId, config: result.config });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Не удалось связаться с API бота." });
  }
});

app.put("/api/bots/:id/config", requireSameOrigin, requireAuth, async (req, res) => {
  const bot = (await getBots()).find(item => item.id === req.params.id);
  const guildId = typeof req.query.guild_id === "string" ? req.query.guild_id : "";
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  if (!/^\d{15,22}$/.test(guildId)) return res.status(400).json({ error: "Выбери Discord-сервер." });
  try {
    await requireAdminOnBotGuild(req.user, bot, guildId);
    const result = await botControlRequest(bot, "PUT", req.body, "/control/config?guild_id=" + encodeURIComponent(guildId));
    await writeAudit(req.user, "bot_config_updated", bot.id, guildId, { changedKeys: Object.keys(req.body || {}) });
    res.json({ ok: true, guildId, config: result.config, rules_published: !!result.rules_published, config_saved: true, message: result.rules_published ? "Settings saved and rules published." : "Settings saved and applied." });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Не удалось отправить настройки боту." });
  }
});

app.post("/api/bots/:id/restart", requireSameOrigin, requireAuth, requireOwner, async (req, res) => {
  if (!RENDER_API_TOKEN) return res.status(503).json({ error: "Render API ещё не настроен." });
  const bot = (await getBots()).find(item => item.id === req.params.id);
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  try {
    await renderRequest("/services/" + encodeURIComponent(bot.renderServiceId) + "/restart", "POST");
    await writeAudit(req.user, "bot_restarted", bot.id, null, {});
    res.json({ ok: true, message: "Команда перезапуска отправлена Render." });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.status ? "Render API HTTP " + error.status : "Не удалось связаться с Render API." });
  }
});

app.get("/", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use((err, _req, res, _next) => {
  console.error("Request error:", err.message);
  res.status(500).json({ error: "Внутренняя ошибка сервера." });
});

app.listen(PORT, () => {
  console.log("BotControl listening on port " + PORT);
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI || !BOTCONTROL_OWNER_DISCORD_ID || !SESSION_SECRET) {
    console.warn("Discord OAuth2 is not fully configured. Set the Discord OAuth and owner environment variables.");
  }
});