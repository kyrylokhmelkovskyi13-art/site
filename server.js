const express = require("express");
const crypto = require("node:crypto");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const RENDER_API_TOKEN = process.env.RENDER_API_TOKEN || "";
const BOTCONTROL_SHARED_SECRET = process.env.BOTCONTROL_SHARED_SECRET || "";
const COOKIE_NAME = "botcontrol_session";
const SESSION_TTL_SECONDS = 60 * 60 * 12;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 8;
const loginAttempts = new Map();

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map(part => {
    const index = part.indexOf("=");
    if (index < 0) return ["", ""];
    return [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(([key]) => key));
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function createSession() {
  const payload = Buffer.from(JSON.stringify({
    owner: true,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS
  })).toString("base64url");
  return payload + "." + sign(payload);
}

function hasSession(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!token) return false;
  const [payload, signature] = token.split(".");
  if (!payload || !signature || !safeEqual(sign(payload), signature)) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return data.owner === true && Number(data.exp) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function setSessionCookie(res, value) {
  const parts = [
    COOKIE_NAME + "=" + encodeURIComponent(value),
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    "Max-Age=" + SESSION_TTL_SECONDS
  ];
  if (isProduction) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  const parts = [COOKIE_NAME + "=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (isProduction) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function requireAuth(req, res, next) {
  if (!hasSession(req)) return res.status(401).json({ error: "Требуется вход." });
  next();
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

function getBots() {
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

app.post("/api/auth/login", requireSameOrigin, (req, res) => {
  if (!OWNER_PASSWORD || !SESSION_SECRET) {
    return res.status(503).json({ error: "Авторизация не настроена на сервере." });
  }

  const ip = req.ip || "unknown";
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, resetAt: now + LOGIN_WINDOW_MS };
  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + LOGIN_WINDOW_MS;
  }
  if (record.count >= LOGIN_MAX_ATTEMPTS) {
    return res.status(429).json({ error: "Слишком много попыток. Попробуй позже." });
  }

  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!safeEqual(password, OWNER_PASSWORD)) {
    record.count += 1;
    loginAttempts.set(ip, record);
    return res.status(401).json({ error: "Неверный пароль." });
  }

  loginAttempts.delete(ip);
  setSessionCookie(res, createSession());
  res.json({ ok: true });
});

app.post("/api/auth/logout", requireSameOrigin, (_req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => res.json({ authenticated: hasSession(req) }));

app.get("/api/bots", requireAuth, async (_req, res) => {
  const bots = getBots();
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

async function botControlRequest(bot, method = "GET", body) {
  if (!BOTCONTROL_SHARED_SECRET) {
    const error = new Error("BOTCONTROL_SHARED_SECRET не настроен на BotControl.");
    error.status = 503;
    throw error;
  }
  const response = await fetch(bot.controlUrl + "/control/config", {
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

app.get("/api/bots/:id/config", requireAuth, async (req, res) => {
  const bot = getBots().find(item => item.id === req.params.id);
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  try {
    const result = await botControlRequest(bot);
    res.json({ ok: true, config: result.config });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Не удалось связаться с API бота." });
  }
});

app.put("/api/bots/:id/config", requireSameOrigin, requireAuth, async (req, res) => {
  const bot = getBots().find(item => item.id === req.params.id);
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });
  try {
    const result = await botControlRequest(bot, "PUT", req.body);
    res.json({ ok: true, config: result.config, message: "Настройки применены ботом." });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || "Не удалось отправить настройки боту." });
  }
});

app.post("/api/bots/:id/restart", requireSameOrigin, requireAuth, async (req, res) => {
  if (!RENDER_API_TOKEN) return res.status(503).json({ error: "Render API ещё не настроен." });
  const bot = getBots().find(item => item.id === req.params.id);
  if (!bot) return res.status(404).json({ error: "Бот не найден в конфигурации сервера." });

  try {
    await renderRequest("/services/" + encodeURIComponent(bot.renderServiceId) + "/restart", "POST");
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
  if (!OWNER_PASSWORD || !SESSION_SECRET) console.warn("Set OWNER_PASSWORD and SESSION_SECRET before exposing this service.");
});