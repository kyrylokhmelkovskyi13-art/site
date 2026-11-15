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

function setSessionCookie(res, user) {
  const token = createSignedToken({
    discordId: String(user.id),
    username: String(user.username || "Discord user").slice(0, 100),
    globalName: String(user.global_name || "").slice(0, 100),
    avatar: user.avatar ? String(user.avatar) : null,
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
          controlUrl: row.control_url
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
    scope: "identify",
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

    if (!isOwner({ discordId: String(user.id) })) {
      const rows = await supabaseRequest(
        "botcontrol_access?discord_id=eq." + encodeURIComponent(String(user.id)) + "&select=discord_id&limit=1"
      );
      if (!rows.length) return res.status(403).send("У этого Discord-аккаунта пока нет доступа к BotControl. Попроси владельца выдать доступ.");
    }
    try {
      await supabaseRequest("botcontrol_users?on_conflict=discord_id", "POST", {
        discord_id: String(user.id),
        username: String(user.username || "").slice(0, 100),
        global_name: String(user.global_name || "").slice(0, 100),
        avatar: user.avatar || null,
        last_login_at: new Date().toISOString()
      });
    } catch (profileError) {
      if (!isOwner({ discordId: String(user.id) })) throw profileError;
      console.warn("Owner profile could not be stored:", profileError.message);
    }
    setSessionCookie(res, user);
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
  res.json({
    authenticated: !!user,
    user: user ? { id: user.discordId, username: user.username, globalName: user.globalName, avatar: user.avatar, isOwner: isOwner(user) } : null
  });
});

app.post("/api/bots", requireSameOrigin, requireAuth, requireOwner, async (req, res) => {
  const id = String(req.body?.id || "").trim().toLowerCase();
  const name = String(req.body?.name || "").trim();
  const renderServiceId = String(req.body?.render_service_id || "").trim();
  const controlUrl = String(req.body?.control_url || "").trim();
  if (!/^[a-z0-9_-]{2,40}$/.test(id)) return res.status(400).json({ error: "ID бота: 2–40 символов, латиница, цифры, _ или -." });
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
  if (!/^\\d{15,22}$/.test(discordId)) return res.status(400).json({ error: "Укажи корректный Discord ID пользователя." });
  if (!(await getBots()).some(bot => bot.id === botId)) return res.status(400).json({ error: "Выбранный бот не зарегистрирован в BotControl." });
  if (guildId !== "*" && !/^\\d{15,22}$/.test(guildId)) return res.status(400).json({ error: "Укажи корректный ID Discord-сервера или *." });
  for (const key of ["can_view", "can_configure", "can_restart"]) {
    if (typeof permissions[key] !== "boolean") return res.status(400).json({ error: "Все права должны быть true или false." });
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
  if (!/^\\d{15,22}$/.test(discordId) || !botId || !guildId) {
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
    const allowed = await Promise.all(bots.map(async bot => ({
      bot, access: await getUserAccess(req.user.discordId, bot.id)
    })));
    bots = allowed.filter(item => item.access.length).map(item => item.bot);
  }
  if (!RENDER_API_TOKEN) {
    return res.json({ connected: false, bots: bots.map(({ id, name }) => ({ id, name, hostStatus: "not_configured" })) });
  }

  const results = await Promise.all(bots.map(async bot => {
    try {
      const service = await renderRequest("/services/" + encodeURIComponent(bot.renderServiceId));
      return {
        id: bot.id,
        name: bot.name,
        hostStatus: service.suspended ? "suspended" : (service.srvStatus || service.status || "unknown"),
        serviceType: service.type || null,
        updatedAt: service.updatedAt || null
      };
    } catch (error) {
      return { id: bot.id, name: bot.name, hostStatus: "error", error: error.status ? "Render API HTTP " + error.status : "Render API недоступен" };
    }
  }));
  res.json({ connected: true, bots: results });
});

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
    const error = new Error(data.error || "API бота вернул HTTP " + response.status);
    error.status = response.status;
    throw error;
  }
  return data;
}

app.get("/api/bots/:id/manifest", requireAuth, async (req, res) => {
  const bot = (await getBots()).find(item => item.id === req.params.id);
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  try {
    if (!isOwner(req.user)) {
      const access = await getUserAccess(req.user.discordId, bot.id);
      if (!access.some(row => row.can_view || row.can_configure)) {
        return res.status(403).json({ error: "Нет права просматривать настройки этого бота." });
      }
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
    if (!isOwner(req.user) && !(await getUserAccess(req.user.discordId, bot.id)).length) {
      return res.status(403).json({ error: "Нет доступа к этому боту." });
    }
    const result = await botControlRequest(bot, "GET", undefined, "/control/guilds");
    let guilds = Array.isArray(result.guilds) ? result.guilds : [];
    if (!isOwner(req.user)) {
      const access = await getUserAccess(req.user.discordId, bot.id);
      const visibleAccess = access.filter(row => row.can_view || row.can_configure);
      const allGuilds = visibleAccess.some(row => row.guild_id === "*");
      const permitted = new Set(visibleAccess.map(row => String(row.guild_id)));
      if (!allGuilds) guilds = guilds.filter(guild => permitted.has(String(guild.id)));
    }
    res.json({ ok: true, guilds });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Не удалось получить Discord-серверы бота." });
  }
});

app.get("/api/bots/:id/config", requireAuth, async (req, res) => {
  const bot = (await getBots()).find(item => item.id === req.params.id);
  const guildId = typeof req.query.guild_id === "string" ? req.query.guild_id : "";
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  if (!/^\d{15,22}$/.test(guildId)) return res.status(400).json({ error: "Выбери Discord-сервер." });
  try {
    if (!(await hasBotPermission(req.user, bot.id, guildId, "can_view"))) return res.status(403).json({ error: "Нет права просматривать настройки этого сервера." });
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
    if (!(await hasBotPermission(req.user, bot.id, guildId, "can_configure"))) return res.status(403).json({ error: "Нет права изменять настройки этого сервера." });
    const result = await botControlRequest(bot, "PUT", req.body, "/control/config?guild_id=" + encodeURIComponent(guildId));
    await writeAudit(req.user, "bot_config_updated", bot.id, guildId, { changedKeys: Object.keys(req.body || {}) });
    res.json({ ok: true, guildId, config: result.config, message: "Настройки этого Discord-сервера применены." });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Не удалось отправить настройки боту." });
  }
});

app.post("/api/bots/:id/restart", requireSameOrigin, requireAuth, async (req, res) => {
  if (!RENDER_API_TOKEN) return res.status(503).json({ error: "Render API ещё не настроен." });
  const bot = (await getBots()).find(item => item.id === req.params.id);
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  if (!isOwner(req.user) && !(await hasBotPermission(req.user, bot.id, "*", "can_restart"))) {
    return res.status(403).json({ error: "Нет права перезапускать этого бота." });
  }

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