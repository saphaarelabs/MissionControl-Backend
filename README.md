# OpenClaw Central Backend

Stateless multi-tenant proxy. Authenticates every request with Clerk, resolves the user's dedicated OpenClaw Gateway URL and token from Supabase, then transparently proxies the request to their isolated container.

## Architecture

```
Frontend (Vercel)
    ↓ Clerk JWT in Authorization header
Central Backend (Cloudflare / Node)  ← this service
    ↓ verifies JWT → looks up user_profiles(instance_url, gateway_token)
User's OpenClaw Gateway (Docker container on VPS)
```

## Environment Variables

```env
# Port (default: 4000)
PORT=4000

# Supabase (service role — server-side only)
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJ...

# Clerk (for JWT verification)
CLERK_JWT_KEY=...          # preferred: RS256 public key (no network call)
CLERK_SECRET_KEY=sk_...    # fallback if JWT_KEY not set

# Control plane (internal)
OPENCLAW_CONTROL_PLANE_URL=http://localhost:4445
OPENCLAW_INTERNAL_SECRET=...
```

> **Not needed**: `OPENCLAW_GATEWAY_URL`, `OPENCLAW_GATEWAY_TOKEN`, `LOCAL_API_SECRET`
> These are per-user values stored in the `user_profiles` Supabase table.

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Check user's gateway status |
| `GET` | `/api/user/profile` | Get user profile from Supabase |
| `POST` | `/api/user/profile/sync` | Upsert profile + trigger provisioning |
| `*` | `/api/*` | Catch-all: proxy to user's gateway container |

## Running

```bash
# Production
npm run backend

# Development (auto-restart)
npm run backend:dev
```

## Health Check Script

```bash
# Get a Clerk JWT from the browser console: await window.Clerk.session.getToken()
node server/backend/api-health-check.js https://openclaw-api.magicteams.ai <CLERK_JWT>
```
