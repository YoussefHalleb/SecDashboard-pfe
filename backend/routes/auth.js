const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const pool = require("../db");

let googleClient;

function getGoogleClient() {
  if (!googleClient) {
    googleClient = new OAuth2Client(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI,
    );
  }
  return googleClient;
}

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
}

function setAuthCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 3600 * 1000,
  });
}

async function authMiddleware(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { rows } = await pool.query(
      `SELECT id, email, role FROM users WHERE id = $1`,
      [decoded.sub],
    );

    if (!rows[0]) return res.status(401).json({ error: "User not found" });

    req.user = { ...decoded, role: rows[0].role };
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// REGISTER
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Missing fields" });

    if (password.length < 8)
      return res.status(400).json({ error: "Password too short (min 8)" });

    const password_hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email`,
      [email, password_hash],
    );

    const user = result.rows[0];
    const token = signToken(user);
    setAuthCookie(res, token);
    res.json(user);
  } catch (err) {
    console.error("REGISTER ERROR:", err.message);
    return res.status(400).json({ error: err.message });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Missing fields" });

    const result = await pool.query(
      `SELECT id, email, password_hash FROM users WHERE email = $1`,
      [email],
    );

    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    if (!user.password_hash) {
      return res.status(401).json({
        error: "Ce compte utilise Google Login. Connectez-vous avec Google.",
      });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = signToken(user);
    setAuthCookie(res, token);
    res.json({ id: user.id, email: user.email });
  } catch (err) {
    return res.status(500).json({ error: "Login failed" });
  }
});

// GOOGLE LOGIN - START
router.get("/google", (req, res) => {
  const url = getGoogleClient().generateAuthUrl({
    access_type: "offline",
    scope: ["openid", "email", "profile"],
    prompt: "select_account",
  });
  res.redirect(url);
});

// GOOGLE LOGIN - CALLBACK
router.get("/google/callback", async (req, res) => {
  try {
    const { code } = req.query;

    if (!code) {
      return res.redirect(
        `${process.env.CLIENT_ORIGIN}/?error=google_login_failed`,
      );
    }

    const { tokens } = await getGoogleClient().getToken(code);

    const ticket = await getGoogleClient().verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email;
    const name = payload.name;
    const picture = payload.picture;

    if (!email || !payload.email_verified) {
      return res.redirect(
        `${process.env.CLIENT_ORIGIN}/?error=email_not_verified`,
      );
    }

    let result = await pool.query(
      `SELECT id, email, role FROM users WHERE email = $1`,
      [email],
    );

    let user = result.rows[0];

    if (!user) {
      result = await pool.query(
        `INSERT INTO users (email, password_hash, google_id, name, avatar_url)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, email, role`,
        [email, null, googleId, name || null, picture || null],
      );
      user = result.rows[0];
    } else {
      await pool.query(
        `UPDATE users
         SET google_id = COALESCE(google_id, $1),
             name = COALESCE(name, $2),
             avatar_url = COALESCE(avatar_url, $3)
         WHERE id = $4`,
        [googleId, name || null, picture || null, user.id],
      );
    }

    const token = signToken(user);
    setAuthCookie(res, token);
    return res.redirect(process.env.CLIENT_ORIGIN);
  } catch (err) {
    console.error("GOOGLE LOGIN ERROR:", err.message);
    return res.redirect(
      `${process.env.CLIENT_ORIGIN}/?error=google_login_failed`,
    );
  }
});

// ME
router.get("/me", authMiddleware, async (req, res) => {
  res.json({ id: req.user.sub, email: req.user.email, role: req.user.role });
});

// LOGOUT
router.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });
  res.json({ ok: true });
});

module.exports = { router, authMiddleware, signToken, setAuthCookie };
