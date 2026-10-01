const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("./database.cjs");

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "CyberGuard-AI-2026-Super-Secret-Key-9f7K2mQ8xL4vN6pR";

const SESSION_DAYS = 30;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validatePassword(password) {
  const value = String(password || "");

  if (value.length < 8) {
    return "Parol kamida 8 ta belgidan iborat bo‘lishi kerak";
  }

  if (!/[A-Z]/.test(value)) {
    return "Parolda kamida 1 ta katta harf bo‘lishi kerak";
  }

  if (!/[a-z]/.test(value)) {
    return "Parolda kamida 1 ta kichik harf bo‘lishi kerak";
  }

  if (!/[0-9]/.test(value)) {
    return "Parolda kamida 1 ta raqam bo‘lishi kerak";
  }

  if (!/[^A-Za-z0-9]/.test(value)) {
    return "Parolda kamida 1 ta maxsus belgi bo‘lishi kerak";
  }

  return null;
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    JWT_SECRET,
    {
      expiresIn: `${SESSION_DAYS}d`,
    },
  );
}

function saveSession(userId, token) {
  const expiresAt =
    Math.floor(Date.now() / 1000) + SESSION_SECONDS;

  db.prepare(`
    INSERT INTO sessions (
      user_id,
      token,
      expires_at
    )
    VALUES (?, ?, ?)
  `).run(userId, token, expiresAt);

  return expiresAt;
}

function cleanupExpiredSessions() {
  db.prepare(`
    DELETE FROM sessions
    WHERE expires_at < ?
  `).run(Math.floor(Date.now() / 1000));
}

// REGISTER
async function register(name, email, password) {
  try {
    const cleanName = String(name || "").trim();
    const cleanEmail = normalizeEmail(email);

    if (!cleanName) {
      return {
        success: false,
        message: "Ismni kiriting",
      };
    }

    if (!cleanEmail) {
      return {
        success: false,
        message: "Emailni kiriting",
      };
    }

    const passwordError = validatePassword(password);

    if (passwordError) {
      return {
        success: false,
        message: passwordError,
      };
    }

    const existingUser = db
      .prepare(`
        SELECT id
        FROM users
        WHERE email = ?
      `)
      .get(cleanEmail);

    if (existingUser) {
      return {
        success: false,
        message: "Bu email allaqachon ro‘yxatdan o‘tgan",
      };
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = db
      .prepare(`
        INSERT INTO users (
          name,
          email,
          password
        )
        VALUES (?, ?, ?)
      `)
      .run(
        cleanName,
        cleanEmail,
        hashedPassword,
      );

    const user = {
      id: String(result.lastInsertRowid),
      name: cleanName,
      email: cleanEmail,
    };

    const token = createToken(user);

    saveSession(user.id, token);

    cleanupExpiredSessions();

    return {
      success: true,
      message: "Hisob muvaffaqiyatli yaratildi",
      token,
      expiresIn: SESSION_SECONDS,
      user,
    };
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return {
      success: false,
      message: "Ro‘yxatdan o‘tishda xatolik yuz berdi",
    };
  }
}

// LOGIN
async function login(email, password) {
  try {
    const cleanEmail = normalizeEmail(email);

    const user = db
      .prepare(`
        SELECT
          id,
          name,
          email,
          password
        FROM users
        WHERE email = ?
      `)
      .get(cleanEmail);

    if (!user) {
      return {
        success: false,
        message: "Email yoki parol noto‘g‘ri",
      };
    }

    const passwordCorrect = await bcrypt.compare(
      String(password || ""),
      user.password,
    );

    if (!passwordCorrect) {
      return {
        success: false,
        message: "Email yoki parol noto‘g‘ri",
      };
    }

    const loggedUser = {
      id: String(user.id),
      name: user.name,
      email: user.email,
    };

    const token = createToken(loggedUser);

    saveSession(user.id, token);

    cleanupExpiredSessions();

    return {
      success: true,
      message: "Tizimga muvaffaqiyatli kirdingiz",
      token,
      expiresIn: SESSION_SECONDS,
      user: loggedUser,
    };
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return {
      success: false,
      message: "Login vaqtida xatolik yuz berdi",
    };
  }
}

// TOKEN TEKSHIRISH
function verifySession(token) {
  try {
    if (!token) {
      return null;
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET,
    );

    const session = db
      .prepare(`
        SELECT
          id,
          user_id,
          expires_at
        FROM sessions
        WHERE token = ?
      `)
      .get(token);

    if (!session) {
      return null;
    }

    const now = Math.floor(Date.now() / 1000);

    if (session.expires_at < now) {
      db.prepare(`
        DELETE FROM sessions
        WHERE token = ?
      `).run(token);

      return null;
    }

    const user = db
      .prepare(`
        SELECT
          id,
          name,
          email
        FROM users
        WHERE id = ?
      `)
      .get(decoded.id);

    if (!user) {
      return null;
    }

    return {
      id: String(user.id),
      name: user.name,
      email: user.email,
    };
  } catch {
    return null;
  }
}

// LOGOUT
function logout(token) {
  if (!token) {
    return;
  }

  db.prepare(`
    DELETE FROM sessions
    WHERE token = ?
  `).run(token);
}

// BARCHA SESSIONLARNI O‘CHIRISH
function logoutAll(userId) {
  db.prepare(`
    DELETE FROM sessions
    WHERE user_id = ?
  `).run(userId);
}

module.exports = {
  register,
  login,
  verifySession,
  logout,
  logoutAll,
  validatePassword,
};