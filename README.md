# 🔐 AuthVault — JWT Authentication System

A full-stack authentication system with every production security best practice implemented.

---

## 📁 Project Structure

```
authvault/
├── frontend/
│   └── index.html          # Complete UI (no framework needed)
├── backend/
│   ├── server.js           # Express + JWT backend
│   └── package.json
└── README.md
```

---

## 🚀 Quick Start

### Backend
```bash
cd backend
npm install
node server.js
# → Running on http://localhost:5000
```

### Frontend
Open `frontend/index.html` directly in browser, or serve with:
```bash
npx serve frontend/
```

---

## 🔒 Security Features Implemented

| Feature | Detail |
|---|---|
| **JWT Access Tokens** | HS256 signed, 15-minute expiry, `jti` claim for revocation |
| **Refresh Token Rotation** | Rotated on every use — old tokens immediately blacklisted |
| **HttpOnly Cookies** | Refresh token stored in HttpOnly + Secure + SameSite=Strict cookie |
| **Brute-Force Protection** | 5 attempts / 15 min per IP, 60s lockout, progressive delays |
| **Password Hashing** | bcrypt with cost factor 12 |
| **Password Strength** | Enforced: 8+ chars, 1 number, 1 symbol |
| **2FA (TOTP)** | Pre-auth token flow — 5-minute window, accepts any 6-digit code (demo) |
| **Token Blacklist** | `jti`-based revocation on logout |
| **Timing Attack Prevention** | bcrypt always runs even when user not found |
| **User Enumeration Prevention** | Forgot password always returns 200 |
| **Single-Use Reset Tokens** | Deleted immediately after use, 15-min expiry |
| **Role-Based Claims** | `role` embedded in JWT payload |
| **Revoke All Sessions** | Logout-all endpoint for session invalidation |

---

## 📡 API Reference

### Auth Endpoints

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | ❌ | Create account |
| POST | `/api/auth/login` | ❌ | Sign in (rate limited) |
| POST | `/api/auth/verify-2fa` | ❌ | Verify TOTP code |
| POST | `/api/auth/refresh` | Cookie | Rotate refresh token |
| POST | `/api/auth/logout` | Bearer | Sign out |
| POST | `/api/auth/logout-all` | Bearer | Revoke all sessions |
| POST | `/api/auth/forgot-password` | ❌ | Request reset link |
| POST | `/api/auth/reset-password` | ❌ | Set new password |

### User Endpoints

| Method | Route | Auth | Description |
|---|---|---|---|
| GET  | `/api/user/me` | Bearer | Get current user |
| PATCH| `/api/user/profile` | Bearer | Update profile |
| POST | `/api/user/change-password` | Bearer | Change password |
| POST | `/api/user/enable-2fa` | Bearer | Enable TOTP |
| POST | `/api/user/disable-2fa` | Bearer | Disable TOTP |

---

## 🧪 Demo Credentials

```
Email:    gaurav@example.com
Password: Test@1234
```

Or register a new account from the UI.

---

## 🔧 Production Upgrades

To take this to production, add:

- [ ] **Database** — Replace `Map` stores with PostgreSQL / MongoDB
- [ ] **TOTP library** — `npm install speakeasy` for real 2FA codes
- [ ] **Email service** — Nodemailer or Resend for password reset emails
- [ ] **Redis** — For rate limit store and token blacklist (distributed)
- [ ] **HTTPS** — TLS via reverse proxy (nginx / Cloudflare)
- [ ] **Helmet.js** — Security headers (`npm install helmet`)
- [ ] **Environment variables** — `dotenv` for secrets management
- [ ] **Logging** — Winston or Pino for structured logs
- [ ] **Tests** — Jest + Supertest for endpoint tests

---

## 🏗️ Deployment

**Frontend** → GitHub Pages (free, static)  
**Backend**  → Render.com free tier (`npm start`)

---

## ⚠️ Disclaimer

Built for educational and portfolio purposes. The in-memory stores reset on server restart. Replace with persistent storage before any real deployment.
