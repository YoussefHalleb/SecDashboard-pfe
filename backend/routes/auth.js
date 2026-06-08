const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const pool = require("../db");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

let googleClient;

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

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

// FORGOT PASSWORD
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email requis" });
    }

    const result = await pool.query(
      `SELECT id, email, password_hash FROM users WHERE email = $1`,
      [email],
    );

    const user = result.rows[0];

    if (!user) {
      return res.json({
        message:
          "Si un compte existe, un email de réinitialisation a été envoyé.",
      });
    }

    if (!user.password_hash) {
      return res.status(400).json({
        error: "Ce compte utilise Google Login. Connectez-vous avec Google.",
      });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    const resetTokenHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    const expires = new Date(Date.now() + 1000 * 60 * 30);

    await pool.query(
      `UPDATE users
       SET reset_token_hash = $1,
           reset_token_expires = $2
       WHERE id = $3`,
      [resetTokenHash, expires, user.id],
    );

    const resetUrl = `${process.env.CLIENT_ORIGIN}/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: user.email,
      subject: "Réinitialisation de votre mot de passe CodeCure",
      html: `
        <p>Bonjour,</p>
        <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
        <p>Cliquez sur ce lien pour choisir un nouveau mot de passe :</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>
        <p>Ce lien expire dans 30 minutes.</p>
      `,
    });

    return res.json({
      message: "Email de réinitialisation envoyé.",
    });
  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// RESET PASSWORD
router.post("/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ error: "Token et mot de passe requis" });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 8 caractères",
      });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const result = await pool.query(
      `SELECT id, email
       FROM users
       WHERE reset_token_hash = $1
         AND reset_token_expires > NOW()`,
      [tokenHash],
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({
        error: "Lien invalide ou expiré",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await pool.query(
      `UPDATE users
       SET password_hash = $1,
           reset_token_hash = NULL,
           reset_token_expires = NULL
       WHERE id = $2`,
      [passwordHash, user.id],
    );

    return res.json({
      message: "Mot de passe modifié avec succès",
    });
  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

module.exports = { router, authMiddleware, signToken, setAuthCookie };
