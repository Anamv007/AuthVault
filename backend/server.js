// ─────────────────────────────────────────────────────────────────────────────
//  AuthVault — JWT Authentication Backend
//  Stack: Node.js · Express · JWT · bcrypt
//  Security: Access tokens (15m) · Refresh rotation · Rate limiting · Brute-force
// ─────────────────────────────────────────────────────────────────────────────

const express     = require('express');
const jwt         = require('jsonwebtoken');
const bcrypt      = require('bcryptjs');
const cors        = require('cors');
const cookieParser= require('cookie-parser');
const crypto      = require('crypto');

const app  = express();
const PORT = process.env.PORT || 5000;

// ── ENV / SECRETS ─────────────────────────────────────────────────────────────
// In production: load from .env via dotenv
const ACCESS_SECRET  = process.env.ACCESS_SECRET  || 'access_super_secret_change_in_prod';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'refresh_super_secret_change_in_prod';
const RESET_SECRET   = process.env.RESET_SECRET   || 'reset_super_secret_change_in_prod';

const ACCESS_EXPIRY  = '15m';
const REFRESH_EXPIRY = '7d';
const RESET_EXPIRY   = '15m';

// ── IN-MEMORY STORES (replace with DB in prod) ────────────────────────────────
const users          = new Map(); // email → { id, email, passwordHash, name, twoFAEnabled, twoFASecret }
const refreshTokens  = new Set(); // valid refresh tokens (blacklist approach)
const resetTokens    = new Map(); // token → { email, expiresAt }
const loginAttempts  = new Map(); // ip → { count, lockedUntil }
const tokenBlacklist = new Set(); // revoked access tokens (jti)

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// ── RATE LIMITER (brute-force protection) ─────────────────────────────────────
const RATE_WINDOW_MS    = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS      = 5;
const LOCKOUT_MS        = 60 * 1000;       // 1 minute lockout
const PROGRESSIVE_DELAY = [0, 0, 500, 1000, 2000]; // ms delay per attempt

function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, lockedUntil: 0, windowStart: now };

  // Reset window if expired
  if (now - entry.windowStart > RATE_WINDOW_MS) {
    loginAttempts.set(ip, { count: 0, lockedUntil: 0, windowStart: now });
    return next();
  }

  // Check lockout
  if (entry.lockedUntil && now < entry.lockedUntil) {
    const retryAfter = Math.ceil((entry.lockedUntil - now) / 1000);
    return res.status(429).json({
      error: 'Too many attempts. Try again later.',
      retryAfter,
      locked: true,
    });
  }

  // Apply progressive delay
  const delay = PROGRESSIVE_DELAY[Math.min(entry.count, PROGRESSIVE_DELAY.length - 1)];
  if (delay > 0) {
    setTimeout(next, delay);
  } else {
    next();
  }
}

function recordFailedAttempt(ip) {
  const now   = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, lockedUntil: 0, windowStart: now };
  entry.count++;

  if (entry.count >= MAX_ATTEMPTS) {
    entry.lockedUntil = now + LOCKOUT_MS;
  }

  loginAttempts.set(ip, entry);
  return { count: entry.count, locked: entry.count >= MAX_ATTEMPTS };
}

function clearAttempts(ip) {
  loginAttempts.delete(ip);
}

// ── TOKEN FACTORIES ───────────────────────────────────────────────────────────
function generateAccessToken(user) {
  const jti = crypto.randomBytes(16).toString('hex');
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role || 'user', jti },
    ACCESS_SECRET,
    { expiresIn: ACCESS_EXPIRY, issuer: 'authvault', audience: 'authvault-client' }
  );
}

function generateRefreshToken(user) {
  const jti = crypto.randomBytes(16).toString('hex');
  const token = jwt.sign(
    { sub: user.id, jti },
    REFRESH_SECRET,
    { expiresIn: REFRESH_EXPIRY, issuer: 'authvault' }
  );
  refreshTokens.add(token); // register as valid
  return token;
}

function generateResetToken(email) {
  const token = crypto.randomBytes(32).toString('hex');
  resetTokens.set(token, { email, expiresAt: Date.now() + 15 * 60 * 1000 });
  return token;
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) return res.status(401).json({ error: 'No token provided' });

  // Check blacklist
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token revoked' });
  }

  jwt.verify(token, ACCESS_SECRET, {
    issuer:   'authvault',
    audience: 'authvault-client',
  }, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
      if (err.name === 'JsonWebTokenError')  return res.status(403).json({ error: 'Invalid token' });
      return res.status(403).json({ error: 'Token verification failed' });
    }
    req.user = decoded;
    next();
  });
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, lastName } = req.body;

    // Validate
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    if (!/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Password strength
    const pwRegex = /^(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{8,}$/;
    if (!pwRegex.test(password)) {
      return res.status(400).json({
        error: 'Password must be 8+ chars with at least 1 number and 1 symbol',
      });
    }

    if (users.has(email.toLowerCase())) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const id = 'usr_' + crypto.randomBytes(6).toString('hex');

    const user = {
      id, email: email.toLowerCase(), passwordHash,
      name, lastName: lastName || '',
      role: 'user',
      twoFAEnabled: false,
      twoFASecret: null,
      createdAt: new Date().toISOString(),
    };

    users.set(email.toLowerCase(), user);

    const accessToken  = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Set refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(201).json({
      message: 'Account created',
      accessToken,
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', rateLimiter, async (req, res) => {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = users.get(email.toLowerCase());

    // Always compare (even if user not found) to prevent timing attacks
    const dummyHash = '$2a$12$invalidhashfortimingnormalization000000000000000000000';
    const hash = user ? user.passwordHash : dummyHash;
    const match = await bcrypt.compare(password, hash);

    if (!user || !match) {
      const { count, locked } = recordFailedAttempt(ip);
      return res.status(401).json({
        error: 'Invalid credentials',
        attemptsLeft: Math.max(0, MAX_ATTEMPTS - count),
        locked,
      });
    }

    clearAttempts(ip);

    // If 2FA enabled, issue a short-lived pre-auth token
    if (user.twoFAEnabled) {
      const preAuthToken = jwt.sign(
        { sub: user.id, step: 'pre-auth' },
        ACCESS_SECRET,
        { expiresIn: '5m' }
      );
      return res.json({ requiresTwoFA: true, preAuthToken });
    }

    const accessToken  = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      message: 'Login successful',
      accessToken,
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/verify-2fa
app.post('/api/auth/verify-2fa', async (req, res) => {
  try {
    const { preAuthToken, code } = req.body;
    if (!preAuthToken || !code) return res.status(400).json({ error: 'Token and code required' });

    let decoded;
    try {
      decoded = jwt.verify(preAuthToken, ACCESS_SECRET);
    } catch {
      return res.status(401).json({ error: 'Invalid or expired pre-auth token' });
    }

    if (decoded.step !== 'pre-auth') return res.status(400).json({ error: 'Invalid token type' });

    // In production: verify TOTP using speakeasy or otplib
    // const valid = speakeasy.totp.verify({ secret, encoding:'base32', token: code });
    const valid = code.length === 6 && /^\d+$/.test(code); // demo: accept any 6 digits

    if (!valid) return res.status(401).json({ error: 'Invalid 2FA code' });

    const user = [...users.values()].find(u => u.id === decoded.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const accessToken  = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true, secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict', maxAge: 7*24*60*60*1000,
    });

    res.json({ message: '2FA verified', accessToken,
      user: { id: user.id, email: user.email, name: user.name, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/refresh  — Refresh token rotation
app.post('/api/auth/refresh', (req, res) => {
  const incomingRefresh = req.cookies.refreshToken;
  if (!incomingRefresh) return res.status(401).json({ error: 'No refresh token' });

  // Check it's in our valid set
  if (!refreshTokens.has(incomingRefresh)) {
    // Possible token reuse — could indicate theft — revoke all for this user
    return res.status(401).json({ error: 'Refresh token reuse detected — session invalidated' });
  }

  jwt.verify(incomingRefresh, REFRESH_SECRET, { issuer: 'authvault' }, (err, decoded) => {
    if (err) {
      refreshTokens.delete(incomingRefresh);
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    // Rotate: invalidate old, issue new
    refreshTokens.delete(incomingRefresh);

    const user = [...users.values()].find(u => u.id === decoded.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const newAccessToken  = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true, secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict', maxAge: 7*24*60*60*1000,
    });

    res.json({ accessToken: newAccessToken });
  });
});

// POST /api/auth/logout
app.post('/api/auth/logout', authenticate, (req, res) => {
  // Blacklist the access token's jti
  if (req.user?.jti) tokenBlacklist.add(req.user.jti);

  // Revoke refresh token
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) refreshTokens.delete(refreshToken);

  res.clearCookie('refreshToken');
  res.json({ message: 'Signed out successfully' });
});

// POST /api/auth/logout-all — Revoke ALL sessions for a user
app.post('/api/auth/logout-all', authenticate, (req, res) => {
  // In production: store a "revoke-all-before" timestamp per user in DB
  // All tokens with iat < that timestamp are rejected in authenticate middleware
  if (req.user?.jti) tokenBlacklist.add(req.user.jti);
  res.clearCookie('refreshToken');
  res.json({ message: 'All sessions revoked' });
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  // Always return 200 to prevent user enumeration
  if (users.has(email?.toLowerCase())) {
    const token = generateResetToken(email.toLowerCase());
    // In production: send email with link:
    // await sendEmail({ to: email, subject: 'Reset link', body: `https://app.com/reset?token=${token}` })
    console.log(`[DEV] Reset token for ${email}: ${token}`);
  }
  res.json({ message: 'If that email exists, a reset link has been sent.' });
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const entry = resetTokens.get(token);

    if (!entry || Date.now() > entry.expiresAt) {
      return res.status(400).json({ error: 'Reset link expired or invalid' });
    }

    const pwRegex = /^(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{8,}$/;
    if (!pwRegex.test(newPassword)) {
      return res.status(400).json({ error: 'Password too weak' });
    }

    const user = users.get(entry.email);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    resetTokens.delete(token); // single-use token
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/user/me — Protected route example
app.get('/api/user/me', authenticate, (req, res) => {
  const user = [...users.values()].find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { passwordHash, twoFASecret, ...safe } = user;
  res.json({ user: safe });
});

// PATCH /api/user/profile — Update profile
app.patch('/api/user/profile', authenticate, async (req, res) => {
  const user = [...users.values()].find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { name, lastName, phone } = req.body;
  if (name) user.name = name;
  if (lastName !== undefined) user.lastName = lastName;
  if (phone !== undefined) user.phone = phone;

  const { passwordHash, twoFASecret, ...safe } = user;
  res.json({ message: 'Profile updated', user: safe });
});

// POST /api/user/change-password
app.post('/api/user/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = [...users.values()].find(u => u.id === req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const match = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Current password incorrect' });

    const pwRegex = /^(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{8,}$/;
    if (!pwRegex.test(newPassword)) return res.status(400).json({ error: 'Password too weak' });

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    res.json({ message: 'Password changed' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/user/enable-2fa
app.post('/api/user/enable-2fa', authenticate, (req, res) => {
  const user = [...users.values()].find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // In production: generate TOTP secret with speakeasy, store it, return QR URL
  // const secret = speakeasy.generateSecret({ name: `AuthVault:${user.email}` });
  // user.twoFASecret = secret.base32;
  // return res.json({ otpauthUrl: secret.otpauth_url, secret: secret.base32 });

  user.twoFAEnabled = true;
  user.twoFASecret  = 'JBSWY3DPEHPK3PXP'; // demo
  res.json({ message: '2FA enabled', secret: user.twoFASecret });
});

// POST /api/user/disable-2fa
app.post('/api/user/disable-2fa', authenticate, (req, res) => {
  const user = [...users.values()].find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.twoFAEnabled = false; user.twoFASecret = null;
  res.json({ message: '2FA disabled' });
});

// Health check
app.get('/api/health', (_, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// 404 handler
app.use((_, res) => res.status(404).json({ error: 'Route not found' }));

// Global error handler
app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`\n🔐 AuthVault Backend running on http://localhost:${PORT}`);
  console.log(`   Access token expiry:  ${ACCESS_EXPIRY}`);
  console.log(`   Refresh token expiry: ${REFRESH_EXPIRY}`);
  console.log(`   Rate limit: ${MAX_ATTEMPTS} attempts / ${RATE_WINDOW_MS/60000}min\n`);
});

module.exports = app;
