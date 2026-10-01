"use strict";

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const app = express();

const PORT = Number(process.env.PORT || 5000);

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "dev-only-change-this-secret";

const CORS_ORIGIN =
  process.env.CORS_ORIGIN ||
  "http://localhost:5173";

/* =========================================================
   SECURITY / MIDDLEWARE
========================================================= */

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  }),
);

app.use(
  cors({
    origin: CORS_ORIGIN,
    credentials: true,
  }),
);

app.use(
  express.json({
    limit: "1mb",
  }),
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb",
  }),
);

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 25,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

/* =========================================================
   DATABASE
========================================================= */

const dataDir = process.env.DB_DIR || path.join(__dirname, "data");

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, {
    recursive: true,
  });
}

const dbPath = path.join(
  dataDir,
  "cyberguard.db",
);

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    ip TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Offline',
    risk TEXT NOT NULL DEFAULT 'Low',
    last_seen TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    device_id INTEGER,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    score INTEGER NOT NULL DEFAULT 0,
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    detected_at TEXT NOT NULL,
    blocked_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER,
    status TEXT NOT NULL,
    score_before INTEGER,
    score_after INTEGER,
    threat_count INTEGER DEFAULT 0,
    result_json TEXT DEFAULT '{}',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    description TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'info',
    metadata_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'info',
    unread INTEGER NOT NULL DEFAULT 1,
    channel TEXT NOT NULL DEFAULT 'in_app',
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    threat_id INTEGER,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    summary TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE SET NULL
  );

  CREATE INDEX IF NOT EXISTS idx_users_email
  ON users(email);

  CREATE INDEX IF NOT EXISTS idx_sessions_user
  ON sessions(user_id);

  CREATE INDEX IF NOT EXISTS idx_threats_user
  ON threats(user_id);

  CREATE INDEX IF NOT EXISTS idx_logs_user
  ON logs(user_id);

  CREATE INDEX IF NOT EXISTS idx_notifications_user
  ON notifications(user_id);
`);

console.log("CyberGuard AI database ulandi");

/* =========================================================
   HELPERS
========================================================= */

function now() {
  return new Date().toISOString();
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: user.created_at,
  };
}

function signToken(user) {
  const token = jwt.sign(
    {
      sub: String(user.id),
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    },
  );

  const expiresAt = new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000,
  ).toISOString();

  db.prepare(`
    INSERT INTO sessions
    (user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `).run(
    user.id,
    hashToken(token),
    expiresAt,
    now(),
  );

  return token;
}

function revokeToken(token) {
  db.prepare(`
    UPDATE sessions
    SET revoked_at = ?
    WHERE token_hash = ?
  `).run(
    now(),
    hashToken(token),
  );
}

function getUserFromToken(token) {
  if (!token) {
    return null;
  }

  try {
    const decoded = jwt.verify(
      token,
      JWT_SECRET,
    );

    const session = db
      .prepare(`
        SELECT *
        FROM sessions
        WHERE token_hash = ?
          AND revoked_at IS NULL
          AND expires_at > ?
      `)
      .get(
        hashToken(token),
        now(),
      );

    if (!session) {
      return null;
    }

    const user = db
      .prepare(`
        SELECT *
        FROM users
        WHERE id = ?
      `)
      .get(Number(decoded.sub));

    return user || null;
  } catch {
    return null;
  }
}

function authRequired(req, res, next) {
  const authorization =
    req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required.",
    });
  }

  const token = authorization.slice(7);

  const user = getUserFromToken(token);

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Session invalid or expired.",
    });
  }

  req.token = token;
  req.user = user;

  next();
}

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email,
  );
}

function validatePassword(password) {
  const value = String(password || "");

  if (value.length < 12) {
    return "Parol kamida 12 ta belgidan iborat boвЂlishi kerak.";
  }

  if (!/[A-Z]/.test(value)) {
    return "Parolda kamida 1 ta katta harf boвЂlishi kerak.";
  }

  if (!/[a-z]/.test(value)) {
    return "Parolda kamida 1 ta kichik harf boвЂlishi kerak.";
  }

  if (!/[0-9]/.test(value)) {
    return "Parolda kamida 1 ta raqam boвЂlishi kerak.";
  }

  if (!/[^A-Za-z0-9]/.test(value)) {
    return "Parolda kamida 1 ta maxsus belgi boвЂlishi kerak.";
  }

  return "";
}

function addLog(
  userId,
  action,
  description,
  type = "info",
  metadata = {},
) {
  db.prepare(`
    INSERT INTO logs
    (
      user_id,
      action,
      description,
      type,
      metadata_json,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    userId,
    action,
    description,
    type,
    JSON.stringify(metadata),
    now(),
  );
}

function addNotification(
  userId,
  title,
  message,
  type = "info",
  channel = "in_app",
) {
  return db
    .prepare(`
      INSERT INTO notifications
      (
        user_id,
        title,
        message,
        type,
        unread,
        channel,
        created_at
      )
      VALUES (?, ?, ?, ?, 1, ?, ?)
    `)
    .run(
      userId,
      title,
      message,
      type,
      channel,
      now(),
    );
}

function calculateSecurityScore(userId) {
  const activeThreats = db
    .prepare(`
      SELECT COUNT(*) AS count
      FROM threats
      WHERE user_id = ?
        AND status = 'Active'
    `)
    .get(userId).count;

  const devices = db
    .prepare(`
      SELECT COUNT(*) AS count
      FROM devices
      WHERE user_id = ?
    `)
    .get(userId).count;

  const highThreats = db
    .prepare(`
      SELECT COUNT(*) AS count
      FROM threats
      WHERE user_id = ?
        AND status = 'Active'
        AND severity IN ('High', 'Critical')
    `)
    .get(userId).count;

  let score = 100;

  score -= activeThreats * 5;
  score -= highThreats * 8;

  if (devices === 0) {
    score -= 3;
  }

  return Math.max(
    0,
    Math.min(100, score),
  );
}

function createDefaultDevice(userId) {
  const existing = db
    .prepare(`
      SELECT *
      FROM devices
      WHERE user_id = ?
      LIMIT 1
    `)
    .get(userId);

  if (existing) {
    return existing;
  }

  const timestamp = now();

  const result = db
    .prepare(`
      INSERT INTO devices
      (
        user_id,
        name,
        type,
        ip,
        status,
        risk,
        last_seen,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      userId,
      "My Computer",
      "Desktop",
      "127.0.0.1",
      "Online",
      "Low",
      timestamp,
      timestamp,
    );

  return db
    .prepare(`
      SELECT *
      FROM devices
      WHERE id = ?
    `)
    .get(result.lastInsertRowid);
}

/* =========================================================
   NOTIFICATION SERVICES
========================================================= */

async function sendTelegram(
  message,
) {
  const botToken =
    process.env.TELEGRAM_BOT_TOKEN;

  const chatId =
    process.env.TELEGRAM_CHAT_ID;

  if (!botToken || !chatId) {
    return {
      success: false,
      skipped: true,
      message:
        "Telegram credentials are not configured.",
    };
  }

  const url =
    `https://api.telegram.org/bot${botToken}/sendMessage`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      chat_id: chatId,
      text: message,
    }),
  });

  const data = await response
    .json()
    .catch(() => ({}));

  if (!response.ok || !data.ok) {
    throw new Error(
      data.description ||
        "Telegram notification failed.",
    );
  }

  return {
    success: true,
  };
}

function createMailer() {
  const host =
    process.env.SMTP_HOST;

  const port = Number(
    process.env.SMTP_PORT || 587,
  );

  const user =
    process.env.SMTP_USER;

  const pass =
    process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    return null;
  }

  return nodemailer.createTransport({
    host,
    port,
    secure:
      String(
        process.env.SMTP_SECURE,
      ).toLowerCase() === "true",
    auth: {
      user,
      pass,
    },
  });
}

async function sendEmail(
  to,
  subject,
  text,
) {
  const transporter =
    createMailer();

  if (!transporter) {
    return {
      success: false,
      skipped: true,
      message:
        "SMTP credentials are not configured.",
    };
  }

  await transporter.sendMail({
    from:
      process.env.SMTP_FROM ||
      "CyberGuard AI <no-reply@example.com>",
    to,
    subject,
    text,
  });

  return {
    success: true,
  };
}

async function sendSMS(
  to,
  message,
) {
  const sid =
    process.env.TWILIO_ACCOUNT_SID;

  const token =
    process.env.TWILIO_AUTH_TOKEN;

  const from =
    process.env.TWILIO_FROM_NUMBER;

  if (!sid || !token || !from) {
    return {
      success: false,
      skipped: true,
      message:
        "Twilio credentials are not configured.",
    };
  }

  const body = new URLSearchParams();

  body.set("To", to);
  body.set("From", from);
  body.set("Body", message);

  const credentials = Buffer.from(
    `${sid}:${token}`,
  ).toString("base64");

  const response = await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`,
    {
      method: "POST",
      headers: {
        Authorization:
          `Basic ${credentials}`,
        "Content-Type":
          "application/x-www-form-urlencoded",
      },
      body,
    },
  );

  const data = await response
    .json()
    .catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.message ||
        "SMS sending failed.",
    );
  }

  return {
    success: true,
    sid: data.sid,
  };
}

/* =========================================================
   AI
========================================================= */

function localAIAnswer(question) {
  const q = question
    .toLowerCase()
    .trim();

  if (
    q.includes("phishing") ||
    q.includes("firib")
  ) {
    return (
      "Phishing вЂ” foydalanuvchini aldab login, " +
      "parol yoki boshqa ma'lumotlarni olishga " +
      "qaratilgan hujum. Havolani bosishdan oldin " +
      "domainni tekshiring, MFA yoqing va " +
      "shubhali fayllarni ochmang."
    );
  }

  if (
    q.includes("password") ||
    q.includes("parol")
  ) {
    return (
      "Kuchli parol kamida 12 belgidan iborat " +
      "boвЂlsin. Katta-kichik harf, raqam va " +
      "maxsus belgilarni ishlating. Har bir " +
      "xizmat uchun alohida parol va imkon boвЂlsa " +
      "password manager ishlating."
    );
  }

  if (
    q.includes("wifi") ||
    q.includes("wi-fi") ||
    q.includes("tarmoq")
  ) {
    return (
      "Wi-Fi uchun WPA2 yoki WPA3 ishlating, " +
      "router administrator parolini almashtiring, " +
      "firmware'ni yangilang va noma'lum " +
      "qurilmalarni tarmoqdan chiqaring."
    );
  }

  if (
    q.includes("virus") ||
    q.includes("malware")
  ) {
    return (
      "Virus yoki malware shubhasida qurilmani " +
      "tarmoqdan izolyatsiya qiling, muhim " +
      "ma'lumotlarni tekshirilgan backupdan " +
      "saqlang, tizimni yangilang va toвЂliq " +
      "security scan bajaring."
    );
  }

  return (
    "CyberGuard AI tavsiyasi: hodisani avval " +
    "aniqlang, dalillarni saqlang, xavfli " +
    "qurilma yoki sessionni izolyatsiya qiling, " +
    "keyin xavfsiz remediation rejasini qoвЂllang. " +
    "Savolni aniqroq yozsangiz, batafsil tahlil " +
    "beraman."
  );
}

async function askAI({
  question,
  securityScore,
  threats,
  devices,
}) {
  const apiKey =
    process.env.OPENAI_API_KEY;

  const enabled =
    String(
      process.env.AI_ENABLED || "true",
    ).toLowerCase() === "true";

  if (!enabled || !apiKey) {
    return localAIAnswer(question);
  }

  const prompt = `
You are CyberGuard AI, a defensive cybersecurity
assistant for an authorized security platform.

IMPORTANT:
- Focus only on defensive and authorized cybersecurity.
- Do not provide instructions for unauthorized intrusion,
  malware deployment, credential theft, or destructive actions.
- Explain incidents in clear human language.
- Prefer safe remediation, isolation, backup and verification.
- When a dangerous action is involved, require explicit approval.

Current security score: ${securityScore}

Threats:
${JSON.stringify(threats, null, 2)}

Devices:
${JSON.stringify(devices, null, 2)}

User question:
${question}

Answer in Uzbek unless the user asks in another language.
Structure:
1. What is happening
2. Risk level
3. Why it matters
4. Recommended safe actions
5. Verification step
`.trim();

  const response = await fetch(
    "https://api.openai.com/v1/responses",
    {
      method: "POST",
      headers: {
        Authorization:
          `Bearer ${apiKey}`,
        "Content-Type":
          "application/json",
      },
      body: JSON.stringify({
        model:
          process.env.OPENAI_MODEL ||
          "gpt-5.6-luna",
        input: prompt,
        max_output_tokens: 1200,
      }),
    },
  );

  const data = await response
    .json()
    .catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data?.error?.message ||
        "AI service failed.",
    );
  }

  if (
    typeof data.output_text ===
    "string" &&
    data.output_text.trim()
  ) {
    return data.output_text.trim();
  }

  const pieces = [];

  if (Array.isArray(data.output)) {
    for (const item of data.output) {
      if (!Array.isArray(item.content)) {
        continue;
      }

      for (const content of item.content) {
        if (
          typeof content.text ===
            "string" &&
          content.text.trim()
        ) {
          pieces.push(
            content.text.trim(),
          );
        }
      }
    }
  }

  if (pieces.length > 0) {
    return pieces.join("\n\n");
  }

  return localAIAnswer(question);
}

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      success: true,
      service: "CyberGuard AI",
      status: "online",
      time: now(),
      database: "connected",
      version: "2.0.0",
    });
  },
);

/* =========================================================
   PASSWORD POLICY
========================================================= */

app.get(
  "/api/password-policy",
  (req, res) => {
    res.json({
      success: true,
      policy: {
        minLength: 12,
        requireUppercase: true,
        requireLowercase: true,
        requireNumber: true,
        requireSpecial: true,
      },
    });
  },
);

/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/api/register",
  authLimiter,
  async (req, res) => {
    try {
      const name =
        String(req.body?.name || "")
          .trim();

      const email =
        normalizeEmail(
          req.body?.email,
        );

      const password =
        String(
          req.body?.password || "",
        );

      if (name.length < 2) {
        return res.status(400).json({
          success: false,
          message:
            "Ism kamida 2 ta belgidan iborat boвЂlishi kerak.",
        });
      }

      if (!validEmail(email)) {
        return res.status(400).json({
          success: false,
          message:
            "Email notoвЂgвЂri.",
        });
      }

      const passwordError =
        validatePassword(password);

      if (passwordError) {
        return res.status(400).json({
          success: false,
          message: passwordError,
        });
      }

      const existing =
        db.prepare(`
          SELECT id
          FROM users
          WHERE email = ?
        `).get(email);

      if (existing) {
        return res.status(409).json({
          success: false,
          message:
            "Bu email allaqachon roвЂyxatdan oвЂtgan.",
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12,
        );

      const timestamp = now();

      const result =
        db.prepare(`
          INSERT INTO users
          (
            name,
            email,
            password_hash,
            role,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, 'user', ?, ?)
        `).run(
          name,
          email,
          passwordHash,
          timestamp,
          timestamp,
        );

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE id = ?
        `).get(
          result.lastInsertRowid,
        );

      createDefaultDevice(
        user.id,
      );

      addLog(
        user.id,
        "Account created",
        "New CyberGuard account created.",
        "success",
      );

      addNotification(
        user.id,
        "Welcome to CyberGuard AI",
        "Hisob muvaffaqiyatli yaratildi.",
        "success",
      );

      const token =
        signToken(user);

      return res.status(201).json({
        success: true,
        message:
          "RoвЂyxatdan oвЂtish muvaffaqiyatli.",
        token,
        user: safeUser(user),
      });
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error,
      );

      return res.status(500).json({
        success: false,
        message:
          "Server xatosi.",
      });
    }
  },
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  authLimiter,
  async (req, res) => {
    try {
      const email =
        normalizeEmail(
          req.body?.email,
        );

      const password =
        String(
          req.body?.password || "",
        );

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Email va parolni kiriting.",
        });
      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(email);

      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            "Email yoki parol notoвЂgвЂri.",
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash,
        );

      if (!valid) {
        addLog(
          user.id,
          "Login failed",
          "Invalid password attempt.",
          "danger",
        );

        return res.status(401).json({
          success: false,
          message:
            "Email yoki parol notoвЂgвЂri.",
        });
      }

      const token =
        signToken(user);

      addLog(
        user.id,
        "Login",
        "User successfully logged in.",
        "success",
      );

      return res.json({
        success: true,
        message:
          "Tizimga muvaffaqiyatli kirdingiz.",
        token,
        user: safeUser(user),
      });
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error,
      );

      return res.status(500).json({
        success: false,
        message:
          "Server xatosi.",
      });
    }
  },
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  authRequired,
  (req, res) => {
    revokeToken(
      req.token,
    );

    addLog(
      req.user.id,
      "Logout",
      "User logged out.",
      "info",
    );

    return res.json({
      success: true,
      message:
        "Logout successful.",
    });
  },
);

/* =========================================================
   ME
========================================================= */

app.get(
  "/api/auth/me",
  authRequired,
  (req, res) => {
    return res.json({
      success: true,
      user: safeUser(
        req.user,
      ),
    });
  },
);

/* =========================================================
   DASHBOARD
========================================================= */

app.get(
  "/api/dashboard",
  authRequired,
  (req, res) => {
    createDefaultDevice(
      req.user.id,
    );

    const devices =
      db.prepare(`
        SELECT *
        FROM devices
        WHERE user_id = ?
        ORDER BY id DESC
      `).all(req.user.id);

    const threats =
      db.prepare(`
        SELECT
          t.*,
          d.name AS device_name
        FROM threats t
        LEFT JOIN devices d
          ON d.id = t.device_id
        WHERE t.user_id = ?
        ORDER BY t.id DESC
      `).all(req.user.id);

    const activeThreats =
      threats.filter(
        (item) =>
          item.status === "Active",
      ).length;

    const score =
      calculateSecurityScore(
        req.user.id,
      );

    return res.json({
      success: true,
      securityScore: score,
      activeThreats,
      devices,
      threats,
    });
  },
);

/* =========================================================
   DEVICES
========================================================= */

app.get(
  "/api/devices",
  authRequired,
  (req, res) => {
    createDefaultDevice(
      req.user.id,
    );

    const devices =
      db.prepare(`
        SELECT *
        FROM devices
        WHERE user_id = ?
        ORDER BY id DESC
      `).all(req.user.id);

    res.json({
      success: true,
      devices,
    });
  },
);

app.post(
  "/api/devices",
  authRequired,
  (req, res) => {
    const name =
      String(
        req.body?.name ||
          "New Device",
      ).trim();

    const type =
      String(
        req.body?.type ||
          "Desktop",
      ).trim();

    const ip =
      String(
        req.body?.ip || "",
      ).trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        message:
          "Device name required.",
      });
    }

    const result =
      db.prepare(`
        INSERT INTO devices
        (
          user_id,
          name,
          type,
          ip,
          status,
          risk,
          last_seen,
          created_at
        )
        VALUES (?, ?, ?, ?, 'Online', 'Low', ?, ?)
      `).run(
        req.user.id,
        name,
        type,
        ip,
        now(),
        now(),
      );

    const device =
      db.prepare(`
        SELECT *
        FROM devices
        WHERE id = ?
      `).get(
        result.lastInsertRowid,
      );

    addLog(
      req.user.id,
      "Device added",
      `Device ${name} was added.`,
      "success",
    );

    res.status(201).json({
      success: true,
      device,
    });
  },
);

app.patch(
  "/api/devices/:id/status",
  authRequired,
  (req, res) => {
    const deviceId =
      Number(req.params.id);

    const device =
      db.prepare(`
        SELECT *
        FROM devices
        WHERE id = ?
          AND user_id = ?
      `).get(
        deviceId,
        req.user.id,
      );

    if (!device) {
      return res.status(404).json({
        success: false,
        message:
          "Device not found.",
      });
    }

    const status =
      device.status ===
      "Online"
        ? "Offline"
        : "Online";

    db.prepare(`
      UPDATE devices
      SET
        status = ?,
        last_seen = ?
      WHERE id = ?
        AND user_id = ?
    `).run(
      status,
      now(),
      deviceId,
      req.user.id,
    );

    const updated =
      db.prepare(`
        SELECT *
        FROM devices
        WHERE id = ?
      `).get(
        deviceId,
      );

    addLog(
      req.user.id,
      "Device status changed",
      `${device.name} -> ${status}`,
      "info",
    );

    res.json({
      success: true,
      device: updated,
    });
  },
);

/* =========================================================
   SECURITY SCAN
========================================================= */

app.post(
  "/api/security/scan",
  authRequired,
  async (req, res) => {
    try {
      const device =
        req.body?.deviceId
          ? db.prepare(`
              SELECT *
              FROM devices
              WHERE id = ?
                AND user_id = ?
            `).get(
              Number(
                req.body.deviceId,
              ),
              req.user.id,
            )
          : createDefaultDevice(
              req.user.id,
            );

      if (!device) {
        return res.status(404).json({
          success: false,
          message:
            "Device not found.",
        });
      }

      const scoreBefore =
        calculateSecurityScore(
          req.user.id,
        );

      const startedAt = now();

      const scanResult =
        db.prepare(`
          INSERT INTO scans
          (
            user_id,
            device_id,
            status,
            score_before,
            started_at
          )
          VALUES (?, ?, 'running', ?, ?)
        `).run(
          req.user.id,
          device.id,
          scoreBefore,
          startedAt,
        );

      /*
       * Defensive MVP scanner:
       * We inspect known security signals stored
       * by CyberGuard. Later an endpoint agent can
       * provide OS-level telemetry.
       */

      const existingActive =
        db.prepare(`
          SELECT *
          FROM threats
          WHERE user_id = ?
            AND status = 'Active'
          ORDER BY severity DESC
        `).all(req.user.id);

      const createdThreats = [];

      if (
        existingActive.length === 0
      ) {
        const result =
          db.prepare(`
            INSERT INTO threats
            (
              user_id,
              name,
              type,
              device_id,
              severity,
              status,
              score,
              description,
              evidence,
              detected_at
            )
            VALUES (?, ?, ?, ?, ?, 'Active', ?, ?, ?, ?)
          `).run(
            req.user.id,
            "Security Configuration Review",
            "Configuration",
            device.id,
            "Low",
            25,
            "Security configuration requires review.",
            JSON.stringify({
              source:
                "CyberGuard security engine",
              checks: [
                "Authentication",
                "Network",
                "Password policy",
                "Device state",
              ],
            }),
            now(),
          );

        const threat =
          db.prepare(`
            SELECT
              t.*,
              d.name AS device_name
            FROM threats t
            LEFT JOIN devices d
              ON d.id = t.device_id
            WHERE t.id = ?
          `).get(
            result.lastInsertRowid,
          );

        createdThreats.push(
          threat,
        );
      }

      const scoreAfter =
        calculateSecurityScore(
          req.user.id,
        );

      const allThreats =
        db.prepare(`
          SELECT
            t.id,
            t.name,
            t.type,
            t.device_id,
            t.severity,
            t.status,
            t.score,
            t.description,
            t.evidence,
            t.detected_at,
            t.blocked_at,
            d.name AS device_name
          FROM threats t
          LEFT JOIN devices d
            ON d.id = t.device_id
          WHERE t.user_id = ?
          ORDER BY t.id DESC
        `).all(req.user.id);

      const activeCount =
        allThreats.filter(
          (item) =>
            item.status === "Active",
        ).length;

      db.prepare(`
        UPDATE scans
        SET
          status = 'completed',
          score_after = ?,
          threat_count = ?,
          result_json = ?,
          completed_at = ?
        WHERE id = ?
      `).run(
        scoreAfter,
        activeCount,
        JSON.stringify({
          createdThreats:
            createdThreats.map(
              (item) => item.id,
            ),
          scoreBefore,
          scoreAfter,
        }),
        now(),
        scanResult.lastInsertRowid,
      );

      addLog(
        req.user.id,
        "System scan",
        "Security scan completed.",
        activeCount > 0
          ? "warning"
          : "success",
        {
          scoreBefore,
          scoreAfter,
          activeCount,
        },
      );

      addNotification(
        req.user.id,
        "System scan",
        activeCount > 0
          ? `${activeCount} ta faol security signal mavjud.`
          : "Skanerlash yakunlandi. Faol tahdid topilmadi.",
        activeCount > 0
          ? "warning"
          : "success",
      );

      res.json({
        success: true,
        message:
          "Security scan completed.",
        score: scoreAfter,
        threats:
          allThreats.map(
            (item) => ({
              id: item.id,
              name: item.name,
              type: item.type,
              device:
                item.device_name ||
                "Unknown",
              severity:
                item.severity,
              status:
                item.status,
              time:
                item.detected_at,
            }),
          ),
        scanId:
          scanResult.lastInsertRowid,
      });
    } catch (error) {
      console.error(
        "SCAN ERROR:",
        error,
      );

      return res.status(500).json({
        success: false,
        message:
          "Security scan failed.",
      });
    }
  },
);

/* =========================================================
   THREATS
========================================================= */

app.get(
  "/api/threats",
  authRequired,
  (req, res) => {
    const threats =
      db.prepare(`
        SELECT
          t.*,
          d.name AS device_name
        FROM threats t
        LEFT JOIN devices d
          ON d.id = t.device_id
        WHERE t.user_id = ?
        ORDER BY t.id DESC
      `).all(req.user.id);

    res.json({
      success: true,
      threats,
    });
  },
);

app.post(
  "/api/threats/:id/block",
  authRequired,
  (req, res) => {
    const threatId =
      Number(req.params.id);

    const threat =
      db.prepare(`
        SELECT
          t.*,
          d.name AS device_name
        FROM threats t
        LEFT JOIN devices d
          ON d.id = t.device_id
        WHERE t.id = ?
          AND t.user_id = ?
      `).get(
        threatId,
        req.user.id,
      );

    if (!threat) {
      return res.status(404).json({
        success: false,
        message:
          "Threat not found.",
      });
    }

    if (
      threat.status ===
      "Blocked"
    ) {
      return res.json({
        success: true,
        message:
          "Threat already blocked.",
        threat,
      });
    }

    db.prepare(`
      UPDATE threats
      SET
        status = 'Blocked',
        blocked_at = ?
      WHERE id = ?
        AND user_id = ?
    `).run(
      now(),
      threatId,
      req.user.id,
    );

    const updated =
      db.prepare(`
        SELECT
          t.*,
          d.name AS device_name
        FROM threats t
        LEFT JOIN devices d
          ON d.id = t.device_id
        WHERE t.id = ?
      `).get(
        threatId,
      );

    const incident =
      db.prepare(`
        SELECT id
        FROM incidents
        WHERE threat_id = ?
          AND user_id = ?
        LIMIT 1
      `).get(
        threatId,
        req.user.id,
      );

    if (!incident) {
      db.prepare(`
        INSERT INTO incidents
        (
          user_id,
          threat_id,
          title,
          severity,
          status,
          summary,
          remediation,
          created_at,
          resolved_at
        )
        VALUES (?, ?, ?, ?, 'Resolved', ?, ?, ?, ?)
      `).run(
        req.user.id,
        threatId,
        `Threat blocked: ${threat.name}`,
        threat.severity,
        `Threat was detected on ${threat.device_name || "device"}.`,
        "Threat was blocked by an authorized user action.",
        now(),
        now(),
      );
    }

    addLog(
      req.user.id,
      "Threat blocked",
      `${threat.name} was blocked.`,
      "success",
      {
        threatId,
      },
    );

    addNotification(
      req.user.id,
      "Threat blocked",
      `${threat.name} successfully blocked.`,
      "success",
    );

    res.json({
      success: true,
      message:
        "Threat blocked.",
      threat: updated,
      securityScore:
        calculateSecurityScore(
          req.user.id,
        ),
    });
  },
);

/* =========================================================
   AI ANALYZE
========================================================= */

app.post(
  "/api/ai/analyze",
  authRequired,
  async (req, res) => {
    try {
      const question =
        String(
          req.body?.question || "",
        ).trim();

      if (!question) {
        return res.status(400).json({
          success: false,
          message:
            "Savol kiriting.",
        });
      }

      const threats =
        db.prepare(`
          SELECT
            t.id,
            t.name,
            t.type,
            t.severity,
            t.status,
            t.score,
            t.description,
            d.name AS device
          FROM threats t
          LEFT JOIN devices d
            ON d.id = t.device_id
          WHERE t.user_id = ?
          ORDER BY t.id DESC
          LIMIT 20
        `).all(req.user.id);

      const devices =
        db.prepare(`
          SELECT
            id,
            name,
            type,
            ip,
            status,
            risk,
            last_seen
          FROM devices
          WHERE user_id = ?
          ORDER BY id DESC
        `).all(req.user.id);

      const score =
        calculateSecurityScore(
          req.user.id,
        );

      const answer =
        await askAI({
          question,
          securityScore: score,
          threats,
          devices,
        });

      addLog(
        req.user.id,
        "AI analysis",
        `AI analyzed: ${question}`,
        "info",
      );

      return res.json({
        success: true,
        answer,
        securityScore: score,
      });
    } catch (error) {
      console.error(
        "AI ERROR:",
        error,
      );

      return res.status(500).json({
        success: false,
        message:
          "AI server bilan bogвЂlanishda xatolik.",
      });
    }
  },
);

/* =========================================================
   NOTIFICATIONS
========================================================= */

app.get(
  "/api/notifications",
  authRequired,
  (req, res) => {
    const items =
      db.prepare(`
        SELECT *
        FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 100
      `).all(req.user.id);

    res.json({
      success: true,
      notifications:
        items.map(
          (item) => ({
            id: item.id,
            title: item.title,
            message: item.message,
            type: item.type,
            unread:
              Boolean(item.unread),
            channel:
              item.channel,
            time:
              item.created_at,
          }),
        ),
    });
  },
);

app.post(
  "/api/notifications/read-all",
  authRequired,
  (req, res) => {
    db.prepare(`
      UPDATE notifications
      SET unread = 0
      WHERE user_id = ?
    `).run(
      req.user.id,
    );

    res.json({
      success: true,
    });
  },
);

/* =========================================================
   LOGS
========================================================= */

app.get(
  "/api/logs",
  authRequired,
  (req, res) => {
    const logs =
      db.prepare(`
        SELECT *
        FROM logs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 200
      `).all(req.user.id);

    res.json({
      success: true,
      logs,
    });
  },
);

/* =========================================================
   INCIDENTS
========================================================= */

app.get(
  "/api/incidents",
  authRequired,
  (req, res) => {
    const incidents =
      db.prepare(`
        SELECT *
        FROM incidents
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 100
      `).all(req.user.id);

    res.json({
      success: true,
      incidents,
    });
  },
);

/* =========================================================
   SECURITY REPORT DATA
========================================================= */

app.get(
  "/api/reports/security",
  authRequired,
  (req, res) => {
    const score =
      calculateSecurityScore(
        req.user.id,
      );

    const totalThreats =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM threats
        WHERE user_id = ?
      `).get(
        req.user.id,
      ).count;

    const activeThreats =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM threats
        WHERE user_id = ?
          AND status = 'Active'
      `).get(
        req.user.id,
      ).count;

    const blockedThreats =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM threats
        WHERE user_id = ?
          AND status = 'Blocked'
      `).get(
        req.user.id,
      ).count;

    const deviceCount =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
        WHERE user_id = ?
      `).get(
        req.user.id,
      ).count;

    const incidentCount =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE user_id = ?
      `).get(
        req.user.id,
      ).count;

    res.json({
      success: true,
      report: {
        generatedAt: now(),
        securityScore: score,
        totalThreats,
        activeThreats,
        blockedThreats,
        deviceCount,
        incidentCount,
        recommendations: [
          "Use unique strong passwords.",
          "Enable MFA where available.",
          "Keep operating systems and applications updated.",
          "Review connected devices regularly.",
          "Investigate critical incidents immediately.",
        ],
      },
    });
  },
);

/* =========================================================
   ALERT TEST
========================================================= */

app.post(
  "/api/notifications/test",
  authRequired,
  async (req, res) => {
    const channel =
      String(
        req.body?.channel ||
          "telegram",
      ).toLowerCase();

    const message =
      "рџљЁ CyberGuard AI test alert\n" +
      "Bu xabar notification tizimi ishlayotganini tekshirish uchun yuborildi.";

    try {
      let result;

      if (channel === "telegram") {
        result =
          await sendTelegram(
            message,
          );
      } else if (channel === "email") {
        result =
          await sendEmail(
            req.user.email,
            "CyberGuard AI Test Alert",
            message,
          );
      } else if (channel === "sms") {
        const phone =
          String(
            req.body?.phone || "",
          ).trim();

        if (!phone) {
          return res.status(400).json({
            success: false,
            message:
              "SMS uchun phone kerak.",
          });
        }

        result =
          await sendSMS(
            phone,
            message,
          );
      } else {
        return res.status(400).json({
          success: false,
          message:
            "Unknown notification channel.",
        });
      }

      addLog(
        req.user.id,
        "Notification test",
        `Test sent through ${channel}.`,
        "info",
      );

      res.json({
        success: true,
        channel,
        result,
      });
    } catch (error) {
      console.error(
        "NOTIFICATION ERROR:",
        error,
      );

      res.status(500).json({
        success: false,
        message:
          error.message ||
          "Notification failed.",
      });
    }
  },
);

/* =========================================================
   404
========================================================= */

/* =========================================================
   FRONTEND
========================================================= */

const distPath = path.join(__dirname, "..", "dist");

app.use(express.static(distPath));

app.get(/^\/(?!api(?:\/|$)).*/, (req, res) => {
  const indexPath = path.join(distPath, "index.html");

  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }

  return res.status(503).send(
    "Frontend build topilmadi. Avval npm run build ni bajaring."
  );
});
app.use((req, res) => {
    res.status(404).json({
      success: false,
      message:
        `Route not found: ${req.method} ${req.path}`,
    });
  },
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next,
  ) => {
    console.error(
      "UNHANDLED ERROR:",
      error,
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      message:
        "Internal server error.",
    });
  },
);

/* =========================================================
   START
========================================================= */

const HOST = process.env.HOST || "0.0.0.0";
const server = app.listen(PORT, HOST, () => {
      console.log("");
      console.log(
        "======================================",
      );
      console.log(
        "     CYBERGUARD AI SECURITY SERVER",
      );
      console.log(
        "======================================",
      );
      console.log(
        `Server: http://${HOST}:${PORT}`,
      );
      console.log(
        `Health: http://localhost:${PORT}/api/health`,
      );
      console.log(
        "Database: SQLite",
      );
      console.log(
        "Authentication: JWT + bcrypt",
      );
      console.log(
        "AI: Responses API + local fallback",
      );
      console.log(
        "======================================",
      );
      console.log("");
    },
  );

function shutdown(
  signal,
) {
  console.log(
    `\n${signal} received. Shutting down...`,
  );

  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on(
  "SIGINT",
  () => shutdown("SIGINT"),
);

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM"),
);
