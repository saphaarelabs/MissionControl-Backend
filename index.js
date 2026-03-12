import 'dotenv/config';
import express from 'express';
import { createClient } from '@supabase/supabase-js';
import { verifyToken } from '@clerk/backend';
import { createProxyMiddleware, fixRequestBody } from 'http-proxy-middleware';
import WebSocket from 'ws';
import crypto from 'crypto';

const app = express();
const PORT = parseInt(process.env.PORT || '4000', 10);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const CLERK_SECRET_KEY = process.env.CLERK_SECRET_KEY;
const CLERK_JWT_KEY = process.env.CLERK_JWT_KEY;

const supabaseAdmin = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
    })
    : null;

function requireSupabaseAdmin(_req, res) {
    if (supabaseAdmin) return supabaseAdmin;
    if (!SUPABASE_URL) res.status(500).json({ error: 'SUPABASE_URL not set' });
    else if (!SUPABASE_SERVICE_ROLE_KEY) res.status(500).json({ error: 'SUPABASE_SERVICE_ROLE_KEY not set' });
    else res.status(500).json({ error: 'Supabase admin client not configured' });
    return null;
}

function getBearerToken(req) {
    const header = req.headers?.authorization || req.headers?.Authorization;
    if (!header || typeof header !== 'string') return null;
    const match = header.match(/^Bearer\s+(.+)$/i);
    return match?.[1]?.trim() || null;
}

async function requireClerkUserId(req, res) {
    const token = getBearerToken(req);
    if (!token) {
        console.warn(`[backend] AUTH 401 ${req.method} ${req.path} — no Bearer token`);
        res.status(401).json({ error: 'Missing Authorization: Bearer <token>' });
        return null;
    }

    if (!CLERK_JWT_KEY && !CLERK_SECRET_KEY) {
        console.error('[backend] AUTH 500 — neither CLERK_JWT_KEY nor CLERK_SECRET_KEY is set');
        res.status(500).json({ error: 'Set CLERK_JWT_KEY (recommended) or CLERK_SECRET_KEY to verify tokens' });
        return null;
    }

    try {
        const verified = await verifyToken(token, {
            ...(CLERK_JWT_KEY ? { jwtKey: CLERK_JWT_KEY } : {}),
            ...(CLERK_SECRET_KEY ? { secretKey: CLERK_SECRET_KEY } : {})
        });
        const userId = verified?.sub;
        if (!userId) {
            console.warn(`[backend] AUTH 401 ${req.method} ${req.path} — token missing sub`);
            res.status(401).json({ error: 'Invalid token (missing sub claim)' });
            return null;
        }
        return userId;
    } catch (err) {
        console.warn(`[backend] AUTH 401 ${req.method} ${req.path} — ${err.message}`);
        res.status(401).json({ error: 'Invalid token' });
        return null;
    }
}

function normalizeGatewayBaseUrl(value) {
    if (!value || typeof value !== 'string') return null;
    try {
        return new URL(value).origin;
    } catch {
        return null;
    }
}

async function resolveUserGatewayContext(req, res, { requireProvisioned = true } = {}) {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return null;

    const sb = requireSupabaseAdmin(req, res);
    if (!sb) return null;

    const { data, error } = await sb
        .from('user_profiles')
        .select('operation_status, instance_url, gateway_token, local_websocket')
        .eq('userid', userId)
        .maybeSingle();

    if (error) {
        res.status(500).json({ error: error.message });
        return null;
    }

    if (!data) {
        res.status(404).json({ error: 'User profile not found' });
        return null;
    }

    const baseUrl = normalizeGatewayBaseUrl(data.instance_url);
    if (data.instance_url && !baseUrl) {
        res.status(500).json({ error: 'Invalid instance_url on user profile' });
        return null;
    }

    if (requireProvisioned && !baseUrl) {
        res.status(409).json({
            error: 'User instance is not provisioned yet',
            operationStatus: data.operation_status || null
        });
        return null;
    }

    return {
        userId,
        profile: data,
        baseUrl,
        gatewayToken: data.gateway_token || null,
        wsUrl: data.local_websocket || null
    };
}

const allowedOrigins = [
    // Production deployments
    'https://openclaw-frontend.vercel.app',
    'https://mission-control-frontend-kappa.vercel.app',
    'https://mission-control-control-plane.vercel.app',
    'https://automation-1.magicteams.ai',
    'https://openclaw-api.magicteams.ai',
    'https://openclaw.ai',
    'https://app.openclaw.ai',
    
    // Development
    'http://127.0.0.1:4444',
    'http://localhost:4444',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    
    // Environment variable support
    ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []),
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) : [])
];

console.log('[CORS] Allowed origins:', allowedOrigins);

// Manual CORS middleware for maximum control and reliability
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    console.log(`[CORS] ${req.method} ${req.path} from origin: ${origin || 'none'}`);
    
    // Check if origin is allowed
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');
        console.log(`[CORS] ✓ Set CORS headers for: ${origin}`);
    } else if (!origin) {
        // Allow requests with no origin (curl, Postman, etc.)
        res.setHeader('Access-Control-Allow-Origin', '*');
        console.log('[CORS] ✓ Allowing request with no origin');
    } else {
        console.log(`[CORS] ✗ Origin not allowed: ${origin}`);
    }
    
    // Handle preflight OPTIONS requests
    if (req.method === 'OPTIONS') {
        console.log(`[CORS] Handling OPTIONS preflight for ${req.path}`);
        res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, PUT, PATCH, POST, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control, X-HTTP-Method-Override');
        res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
        return res.status(204).end();
    }
    
    next();
});

app.use(express.json({ limit: '2mb' }));

// ── Request logger ────────────────────────────────────────────────────────────
app.use((req, res, next) => {
    const start = Date.now();
    const hasAuth = Boolean(req.headers.authorization);
    res.on('finish', () => {
        const ms = Date.now() - start;
        const status = res.statusCode;
        const flag = status >= 500 ? '✗' : status >= 400 ? '!' : '✓';
        console.log(`[backend] ${flag} ${req.method} ${req.path} → ${status} (${ms}ms)${hasAuth ? '' : ' [no-auth]'}`);
    });
    next();
});

// ── Root endpoint ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
    res.json({
        message: 'MissionControl Backend API',
        version: '2.0.0-subagent-fix',
        buildTime: '2026-03-12T10:30:00Z',
        timestamp: new Date().toISOString(),
        features: {
            subagentSpawnFixed: true,
            detailedLogging: true
        },
        cors: {
            origin: req.headers.origin,
            allowedOrigins: allowedOrigins
        }
    });
});

// ── CORS Test endpoint ────────────────────────────────────────────────────────
app.get('/api/cors-test', (req, res) => {
    console.log(`[CORS-TEST] Headers:`, {
        origin: req.headers.origin,
        'access-control-request-method': req.headers['access-control-request-method'],
        'access-control-request-headers': req.headers['access-control-request-headers']
    });
    
    res.json({
        message: 'CORS test successful',
        timestamp: new Date().toISOString(),
        origin: req.headers.origin,
        method: req.method,
        corsHeadersSet: {
            'access-control-allow-origin': res.getHeader('access-control-allow-origin'),
            'access-control-allow-credentials': res.getHeader('access-control-allow-credentials')
        }
    });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
    const gateway = await resolveUserGatewayContext(req, res, { requireProvisioned: false });
    if (!gateway) return;

    try {
        const { baseUrl, gatewayToken, profile } = gateway;
        if (!baseUrl) {
            return res.status(200).json({
                status: 'provisioning',
                operationStatus: profile.operation_status || null,
                message: 'User instance is not ready yet'
            });
        }

        // Fast path: root HTML responds quickly if gateway is up.
        try {
            const rootRes = await fetch(`${baseUrl}/`, {
                method: 'GET',
                signal: AbortSignal.timeout(2000)
            });
            if (rootRes.ok) {
                return res.json({ status: 'online', ts: new Date().toISOString() });
            }
        } catch {
            // Fall through to deeper check
        }

        if (!gatewayToken) {
            return res.status(200).json({ status: 'offline', message: 'Missing user gateway token' });
        }

        const response = await fetch(`${baseUrl}/v1/chat/completions`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${gatewayToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'health-check',
                messages: [{ role: 'user', content: 'ping' }],
                max_tokens: 1
            }),
            signal: AbortSignal.timeout(10000)
        });

        if (!response.ok) {
            const text = await response.text();
            return res.status(200).json({
                status: 'offline',
                message: `Gateway error ${response.status}`,
                details: text.slice(0, 200)
            });
        }

        return res.json({ status: 'online', ts: new Date().toISOString() });
    } catch (error) {
        return res.status(200).json({ status: 'offline', message: error.message });
    }
});

// ── CORS test endpoint ──────────────────────────────────────────────────────────
app.get('/api/cors-test', (req, res) => {
    res.json({
        message: 'CORS is working!',
        origin: req.headers.origin,
        allowedOrigins,
        timestamp: new Date().toISOString()
    });
});

// ── User profile sync (upsert + trigger control plane provisioning) ────────────
app.post('/api/user/profile/sync', async (req, res) => {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return;

    const { 
        username, 
        fullName, 
        phoneNumber, 
        onboardingData,
        triggerProvision 
    } = req.body || {};
    
    const normalizedUsername = typeof username === 'string' ? username.trim() : '';
    if (!normalizedUsername) {
        return res.status(400).json({ error: 'username is required' });
    }

    const sb = requireSupabaseAdmin(req, res);
    if (!sb) return;

    try {
        // Build upsert object with new fields
        const upsertData = {
            userid: userId,
            username: normalizedUsername,
        };
        
        // Add optional onboarding fields if provided
        if (fullName) upsertData.full_name = fullName;
        if (phoneNumber) upsertData.phone_number = phoneNumber;
        if (onboardingData) upsertData.onboarding_data = onboardingData;

        const { data, error } = await sb
            .from('user_profiles')
            .upsert(upsertData, { onConflict: 'userid' })
            .select('*')
            .single();

        if (error) return res.status(500).json({ error: error.message });

        console.log(`[profile/sync] userId=${userId} operation_status=${data.operation_status} onboarding_data=${!!data.onboarding_data}`);

        // auto-provision if onboarded AND not already provisioning
        // OR if explicitly triggered via triggerProvision flag
        const shouldProvision = (data.operation_status === 'onboarded' || triggerProvision) 
                                && !data.provisioning_lock_id;
        
        if (shouldProvision) {
            // Try to acquire provisioning lock to prevent duplicate requests
            const { data: lockResult } = await sb.rpc('acquire_provisioning_lock', { user_id: userId });
            
            if (lockResult) {
                console.log(`[profile/sync] ✓ acquired lock for ${userId}, triggering provision...`);
                const controlPlaneUrl = process.env.OPENCLAW_CONTROL_PLANE_URL || 'http://localhost:4445';
                
                // Pass onboarding data to control plane for LLM configuration
                fetch(`${controlPlaneUrl}/api/provision/user`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Internal-Secret': process.env.OPENCLAW_INTERNAL_SECRET || ''
                    },
                    body: JSON.stringify({ 
                        userId, 
                        username: normalizedUsername,
                        onboardingData: data.onboarding_data  // Pass along for LLM config
                    }),
                }).then(async (r) => {
                    const body = await r.text().catch(() => '');
                    console.log(`[profile/sync] control-plane responded ${r.status}: ${body.slice(0, 200)}`);
                }).catch((err) => console.error('[profile/sync] control-plane fetch failed:', err.message));
            } else {
                console.log(`[profile/sync] ⏭ provisioning already in progress for ${userId}, skipping duplicate`);
            }
        }

        return res.json({ profile: data });
    } catch (error) {
        return res.status(500).json({ error: error?.message || 'Failed to sync profile' });
    }
});

// ── User profile get ──────────────────────────────────────────────────────────
app.get('/api/user/profile', async (req, res) => {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return;

    const sb = requireSupabaseAdmin(req, res);
    if (!sb) return;

    try {
        const { data, error } = await sb
            .from('user_profiles')
            .select('*')
            .eq('userid', userId)
            .maybeSingle();

        if (error) return res.status(500).json({ error: error.message });
        return res.json({ profile: data || null });
    } catch (error) {
        return res.status(500).json({ error: error?.message || 'Failed to fetch profile' });
    }
});

// ── VPS-Agent helpers ─────────────────────────────────────────────────────────
const INTERNAL_SECRET = process.env.OPENCLAW_INTERNAL_SECRET || '';
const LOCAL_API_PORT = process.env.LOCAL_API_PORT || '4444';

async function resolveVpsAgentContext(req, res) {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return null;

    const sb = requireSupabaseAdmin(req, res);
    if (!sb) return null;

    const { data: profile, error: profileErr } = await sb
        .from('user_profiles')
        .select('operation_status, instance_url, gateway_token, vps_node_id')
        .eq('userid', userId)
        .maybeSingle();

    if (profileErr || !profile) {
        res.status(profileErr ? 500 : 404).json({ error: profileErr?.message || 'Profile not found' });
        return null;
    }

    if (!profile.vps_node_id) {
        res.status(409).json({ error: 'User instance not provisioned' });
        return null;
    }

    const { data: node, error: nodeErr } = await sb
        .from('vps_nodes')
        .select('ip_address')
        .eq('id', profile.vps_node_id)
        .maybeSingle();

    if (nodeErr || !node) {
        res.status(500).json({ error: nodeErr?.message || 'VPS node not found' });
        return null;
    }

    return { userId, agentBaseUrl: `http://${node.ip_address}:${LOCAL_API_PORT}` };
}

async function callVpsAgent(agentBaseUrl, path, body) {
    const res = await fetch(`${agentBaseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30_000)
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}

// ── Gateway WebSocket helper (challenge-response auth + send command) ──────────
function gatewayWsSend(wsUrl, token, message, timeoutMs = 15_000) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        const timer = setTimeout(() => { ws.close(); reject(new Error('WebSocket timeout')); }, timeoutMs);
        let authenticated = false;
        const connectId = crypto.randomUUID ? crypto.randomUUID() : `conn-${Date.now()}`;

        ws.on('message', (raw) => {
            let msg;
            try { msg = JSON.parse(raw.toString()); } catch { return; }

            // Step 1: respond to auth challenge with "connect" req
            if (msg.event === 'connect.challenge') {
                ws.send(JSON.stringify({
                    type: 'req',
                    method: 'connect',
                    id: connectId,
                    params: {
                        minProtocol: 3,
                        maxProtocol: 3,
                        client: { id: 'gateway-client', version: 'dev', platform: 'linux', mode: 'backend' },
                        caps: [],
                        auth: { token },
                        role: 'operator',
                        scopes: ['operator.admin']
                    }
                }));
                return;
            }

            // Step 2: connect response = auth success, now send actual command
            if (msg.id === connectId && !authenticated) {
                authenticated = true;
                ws.send(JSON.stringify(message));
                return;
            }

            // Step 3: collect the response to our command
            if (authenticated && msg.id === message.id) {
                clearTimeout(timer);
                ws.close();
                resolve(msg);
            }
        });

        ws.on('error', (err) => { clearTimeout(timer); reject(err); });
        ws.on('close', () => clearTimeout(timer));
    });
}

// ── GET /api/models/config — read directly from config file via vps-agent ──────
app.get('/api/models/config', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    try {
        const r = await fetch(`${ctx.agentBaseUrl}/api/internal/model-config?instanceId=${encodeURIComponent(ctx.userId)}`, {
            headers: { 'X-Internal-Secret': INTERNAL_SECRET },
            signal: AbortSignal.timeout(5_000)
        });
        const data = await r.json();
        if (!r.ok) return res.status(500).json(data);
        console.log(`[backend] GET /models/config: primary=${data.primary}, models=${data.allowedModels}`);
        res.json(data);
    } catch (err) {
        res.status(502).json({ error: err.message });
    }
});

// ── GET /api/models/catalog — list available models for a provider ───────────
app.get('/api/models/catalog', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;

    const { provider } = req.query;
    if (!provider) return res.status(400).json({ error: 'provider query parameter required' });
    
    try {
        // Call VPS agent to get models list from the OpenClaw gateway
        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/models-list', {
            instanceId: ctx.userId
        });
        
        if (!ok) {
            console.error(`[backend] models-list failed: ${status}`, data);
            return res.status(500).json({ error: data.error || 'Failed to fetch models', detail: data });
        }
        
        // Filter models by provider if specified
        const allModels = data.models || [];
        const filteredModels = provider 
            ? allModels.filter(m => {
                const modelId = m.id || m;
                return typeof modelId === 'string' && modelId.startsWith(`${provider}/`);
            })
            : allModels;
        
        // Transform to simple format if needed
        const models = filteredModels.map(m => {
            if (typeof m === 'string') {
                const parts = m.split('/');
                return { id: parts[1] || m, name: parts[1] || m };
            }
            // If model has provider prefix, strip it for display
            const modelId = m.id || '';
            const parts = modelId.split('/');
            return {
                id: parts[1] || modelId,
                name: m.name || parts[1] || modelId
            };
        });
        
        res.json({ models });
    } catch (err) {
        console.error(`[backend] models/catalog error:`, err.message);
        res.status(502).json({ error: err.message });
    }
});

// ── GET /api/models/catalog-all — list all models from all providers ─────────
app.get('/api/models/catalog-all', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    
    try {
        // Call VPS agent to get complete models list from the OpenClaw gateway
        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/models-list', {
            instanceId: ctx.userId
        });
        
        if (!ok) {
            console.error(`[backend] models-list failed: ${status}`, data);
            return res.status(500).json({ error: data.error || 'Failed to fetch models', detail: data });
        }
        
        const allModels = data.models || [];
        
        // Transform to include provider in response
        const models = allModels.map(m => {
            if (typeof m === 'string') {
                const parts = m.split('/');
                return {
                    id: m,
                    name: parts[1] || m,
                    provider: parts[0] || 'unknown'
                };
            }
            return {
                id: m.id || '',
                name: m.name || m.id || '',
                provider: m.provider || (m.id || '').split('/')[0] || 'unknown'
            };
        });
        
        res.json({ models });
    } catch (err) {
        console.error(`[backend] models/catalog-all error:`, err.message);
        res.status(502).json({ error: err.message });
    }
});

// ── GET /api/openclaw-config — read from config file via vps-agent ─────────────
app.get('/api/openclaw-config', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    try {
        const r = await fetch(`${ctx.agentBaseUrl}/api/internal/openclaw-config?instanceId=${encodeURIComponent(ctx.userId)}`, {
            headers: { 'X-Internal-Secret': INTERNAL_SECRET },
            signal: AbortSignal.timeout(5_000)
        });
        const data = await r.json();
        if (!r.ok) return res.status(500).json(data);
        res.json(data);
    } catch (err) {
        res.status(502).json({ error: err.message });
    }
});

// ── Provider configuration (bypasses read-only gateway REST API) ──────────────
app.post('/api/providers/connect', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;

    const { provider, token, authMethod, expiresIn } = req.body || {};
    if (!provider || !token) return res.status(400).json({ error: 'provider and token are required' });

    const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/configure-provider', {
        instanceId: ctx.userId, 
        provider, 
        token, 
        authMethod: authMethod || 'api_key',
        ...(expiresIn ? { expiresIn } : {})
    });
    console.log(`[backend] vps-agent configure-provider → ${status}`, data);
    if (!ok) return res.status(500).json({ error: data.error || 'Failed to configure provider', detail: data });
    res.json({ success: true });
});

// ── Custom provider config ────────────────────────────────────────────────────
app.post('/api/providers/custom', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    const { key, label, baseUrl, api, authHeader, headers, models } = req.body || {};
    if (!key || !baseUrl) return res.status(400).json({ error: 'key and baseUrl are required' });
    const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/configure-custom-provider', {
        instanceId: ctx.userId, key, label, baseUrl, api, authHeader, headers, models
    });
    console.log(`[backend] vps-agent configure-custom-provider → ${status}`, data);
    if (!ok) return res.status(500).json({ error: data.error || 'Failed to save custom provider', detail: data });
    res.json({ success: true });
});

// ── OAuth provider authentication ─────────────────────────────────────────────
const oauthStates = new Map(); // Store OAuth state temporarily (in production, use Redis)

// OAuth provider configurations 
const OAUTH_PROVIDERS = {
    'openai-codex': {
        type: 'oauth',
        authUrl: 'https://auth.openai.com/oauth/authorize',
        tokenUrl: 'https://auth.openai.com/oauth/token', 
        clientId: process.env.OPENAI_CODEX_CLIENT_ID || 'Iv1.1234567890abcdef', // OpenAI's hardcoded CLI client ID
        scope: 'openai.codex',
        redirectUri: 'https://mission-control-frontend-kappa.vercel.app/auth/callback' // Fixed by OpenAI - cannot be changed
    },
    'minimax-portal': {
        type: 'plugin',
        pluginId: 'minimax-portal-auth',
        authUrl: 'https://api.minimax.io/oauth/authorize',
        tokenUrl: 'https://api.minimax.io/oauth/token',
        clientId: '78257093-7e40-4613-99e0-527b14b39113',
        scope: 'group_id profile model.completion',
        regions: {
            global: { baseUrl: 'https://api.minimax.io', clientId: '78257093-7e40-4613-99e0-527b14b39113' },
            china: { baseUrl: 'https://api.minimaxi.com', clientId: '78257093-7e40-4613-99e0-527b14b39113' }
        }
    },
    'qwen-portal': {
        type: 'plugin',
        pluginId: 'qwen-portal-auth', 
        authUrl: 'https://chat.qwen.ai/oauth/authorize',
        tokenUrl: 'https://chat.qwen.ai/api/v1/oauth2/token',
        clientId: 'f0304373b74a44d2b584a3fb70ca9e56',
        scope: 'chat.read chat.write'
    }
};

app.post('/api/providers/oauth/start', async (req, res) => {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return;

    const { provider, region = 'global' } = req.body || {};
    if (!provider) return res.status(400).json({ error: 'provider is required' });

    const providerConfig = OAUTH_PROVIDERS[provider];
    if (!providerConfig) {
        return res.status(400).json({ 
            error: `OAuth configuration missing for provider: ${provider}`,
            supportedProviders: Object.keys(OAUTH_PROVIDERS)
        });
    }

    // Handle plugin-based OAuth differently
    if (providerConfig.type === 'plugin') {
        return res.status(400).json({
            error: `${provider} uses plugin-based OAuth. Enable the plugin first: openclaw plugins enable ${providerConfig.pluginId}`,
            authType: 'plugin',
            pluginId: providerConfig.pluginId,
            instructions: [
                `1. Enable plugin: openclaw plugins enable ${providerConfig.pluginId}`,
                `2. Restart OpenClaw gateway`,
                `3. Login: openclaw models auth login --provider ${provider} --set-default`
            ]
        });
    }

    // Traditional OAuth flow (only openai-codex)
    if (!providerConfig.clientId) {
        return res.status(500).json({ 
            error: `OAuth client ID not configured for ${provider}. Note: OpenAI Codex uses a hardcoded client ID.` 
        });
    }

    // Generate state and PKCE parameters
    const state = crypto.randomBytes(32).toString('hex');
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

    // Store state temporarily (expires in 10 minutes) with user token
    const userToken = getBearerToken(req);
    oauthStates.set(state, {
        userId,
        provider,
        codeVerifier,
        userToken,
        createdAt: Date.now()
    });

    // Clean up expired states
    setTimeout(() => oauthStates.delete(state), 10 * 60 * 1000);

    // Use OpenAI's fixed redirect URI - this will "fail" but contain the auth code
    const redirectUri = providerConfig.redirectUri; // http://127.0.0.1:1455/auth/callback
    const authUrl = new URL(providerConfig.authUrl);
    
    authUrl.searchParams.set('client_id', providerConfig.clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', providerConfig.scope);
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    res.json({ 
        authUrl: authUrl.toString(), 
        state,
        redirectUri,
        instructions: [
            '1. Click the auth URL to login with ChatGPT',
            '2. You will see a "Site cannot be reached" error - this is expected!',
            '3. Copy the full URL from the error page (contains ?code=...)',
            '4. Paste it in the frontend to complete authentication'
        ]
    });
});

// OAuth callback handler - handles "broken redirect" manual URL processing
app.post('/api/providers/oauth/callback-manual', async (req, res) => {
    try {
        const { callbackUrl } = req.body;
        
        if (!callbackUrl) {
            return res.status(400).json({ error: 'Callback URL is required' });
        }
        
        // Parse the callback URL (from the error page)
        const url = new URL(callbackUrl);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        
        if (!code || !state) {
            return res.status(400).json({ error: 'Missing code or state in callback URL' });
        }
        
        // Verify state and get stored data
        const storedData = oauthStates.get(state);
        if (!storedData) {
            return res.status(400).json({ error: 'Invalid or expired state' });
        }
        
        // Clean up state
        oauthStates.delete(state);
        
        const { provider, codeVerifier, userToken, userId } = storedData;
        const providerConfig = OAUTH_PROVIDERS[provider];
        
        // Exchange code for token
        const tokenResponse = await fetch(providerConfig.tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code,
                client_id: providerConfig.clientId,
                redirect_uri: providerConfig.redirectUri,
                code_verifier: codeVerifier
            })
        });
        
        const tokenData = await tokenResponse.json();
        
        if (!tokenResponse.ok) {
            console.error('Token exchange failed:', tokenData);
            return res.status(400).json({ error: 'Failed to exchange code for token', details: tokenData });
        }
        
        // Store token via VPS agent using the stored user token
        const ctx = await resolveVpsAgentContext({ headers: { authorization: `Bearer ${userToken}` } }, null, userId);
        if (!ctx) {
            return res.status(500).json({ error: 'Failed to resolve user context' });
        }

        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/configure-provider', {
            instanceId: ctx.userId,
            provider,
            token: tokenData.access_token,
            authMethod: 'oauth',
            ...(tokenData.expires_in ? { expiresIn: tokenData.expires_in } : {})
        });

        if (!ok) {
            console.error('Failed to configure OAuth provider:', data);
            return res.status(500).json({ error: 'Failed to configure provider on VPS' });
        }
        
        res.json({ 
            success: true, 
            message: `${provider} configured successfully with OAuth`,
            provider 
        });
        
    } catch (error) {
        console.error('OAuth manual callback error:', error);
        res.status(500).json({ error: 'OAuth callback failed', details: error.message });
    }
});

app.get('/api/providers/oauth/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;

    if (error) {
        console.error(`[backend] OAuth error: ${error} - ${error_description}`);
        return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_error=${encodeURIComponent(error_description || error)}`);
    }

    if (!code || !state) {
        return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_error=${encodeURIComponent('Missing code or state parameter')}`);
    }

    const stateData = oauthStates.get(state);
    if (!stateData) {
        return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_error=${encodeURIComponent('Invalid or expired state')}`);
    }

    // Clean up state
    oauthStates.delete(state);

    const { userId, provider, codeVerifier, userToken } = stateData;
    const providerConfig = OAUTH_PROVIDERS[provider];

    try {
        // Exchange code for access token
        const tokenResponse = await fetch(providerConfig.tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: providerConfig.clientId,
                code: code,
                redirect_uri: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/oauth/callback`,
                code_verifier: codeVerifier
            })
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.text();
            console.error(`[backend] Token exchange failed:`, errorData);
            return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_error=${encodeURIComponent('Token exchange failed')}`);
        }

        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;

        if (!accessToken) {
            return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_error=${encodeURIComponent('No access token received')}`);
        }

        // Store token via VPS agent using the stored user token
        const ctx = await resolveVpsAgentContext({ headers: { authorization: `Bearer ${userToken}` } }, null, userId);
        if (!ctx) {
            return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_error=${encodeURIComponent('Failed to resolve user context')}`);
        }

        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/configure-provider', {
            instanceId: ctx.userId,
            provider,
            token: accessToken,
            authMethod: 'oauth',
            ...(tokenData.expires_in ? { expiresIn: tokenData.expires_in } : {})
        });

        if (!ok) {
            console.error(`[backend] Failed to configure OAuth provider:`, data);
            return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_error=${encodeURIComponent('Failed to save OAuth token')}`);
        }

        // Redirect back to settings with success
        res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_success=${encodeURIComponent(provider)}`);

    } catch (error) {
        console.error(`[backend] OAuth callback error:`, error);
        res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/app/settings?oauth_error=${encodeURIComponent('OAuth flow failed')}`);
    }
});

// ── Plugin OAuth endpoints for device code flow ─────────────────────────────

// Start plugin OAuth device code flow
app.post('/api/providers/plugin-oauth/start', async (req, res) => {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return;

    const { provider, region = 'global' } = req.body || {};
    if (!provider) return res.status(400).json({ error: 'provider is required' });

    const providerConfig = OAUTH_PROVIDERS[provider];
    if (!providerConfig || providerConfig.type !== 'plugin') {
        return res.status(400).json({ error: `Plugin OAuth not supported for ${provider}` });
    }

    try {
        let baseUrl, clientId;
        
        if (provider === 'minimax-portal') {
            const regionConfig = providerConfig.regions[region] || providerConfig.regions.global;
            baseUrl = regionConfig.baseUrl;
            clientId = regionConfig.clientId;
        } else {
            baseUrl = providerConfig.authUrl.split('/oauth')[0];
            clientId = providerConfig.clientId;
        }

        // Generate device authorization request
        const deviceAuthUrl = `${baseUrl}/oauth/device`;
        const deviceResponse = await fetch(deviceAuthUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: clientId,
                scope: providerConfig.scope || '',
                ...(provider === 'minimax-portal' ? { grant_type: 'urn:ietf:params:oauth:grant-type:user_code' } : {})
            })
        });

        if (!deviceResponse.ok) {
            throw new Error(`Device authorization failed: ${await deviceResponse.text()}`);
        }

        const deviceData = await deviceResponse.json();

        // Store device info for polling
        const deviceCode = deviceData.device_code;
        oauthStates.set(deviceCode, {
            userId,
            provider,
            region,
            userCode: deviceData.user_code,
            verificationUri: deviceData.verification_uri,
            expiresIn: deviceData.expires_in || 600,
            interval: deviceData.interval || 5,
            createdAt: Date.now()
        });

        // Clean up after expiry
        setTimeout(() => oauthStates.delete(deviceCode), (deviceData.expires_in || 600) * 1000);

        res.json({
            userCode: deviceData.user_code,
            verificationUri: deviceData.verification_uri,
            deviceCode,
            expiresIn: deviceData.expires_in || 600,
            interval: deviceData.interval || 5
        });

    } catch (error) {
        console.error(`[backend] Plugin OAuth start error:`, error);
        res.status(500).json({ error: error.message });
    }
});

// Poll for plugin OAuth completion
app.post('/api/providers/plugin-oauth/poll', async (req, res) => {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return;

    const { deviceCode } = req.body || {};
    if (!deviceCode) return res.status(400).json({ error: 'deviceCode is required' });

    const deviceInfo = oauthStates.get(deviceCode);
    if (!deviceInfo || deviceInfo.userId !== userId) {
        return res.status(400).json({ error: 'Invalid device code' });
    }

    const { provider, region } = deviceInfo;
    const providerConfig = OAUTH_PROVIDERS[provider];

    try {
        let tokenUrl, clientId;
        
        if (provider === 'minimax-portal') {
            const regionConfig = providerConfig.regions[region];
            tokenUrl = `${regionConfig.baseUrl}/oauth/token`;
            clientId = regionConfig.clientId;
        } else {
            tokenUrl = providerConfig.tokenUrl;
            clientId = providerConfig.clientId;
        }

        const tokenResponse = await fetch(tokenUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: provider === 'minimax-portal' ? 'urn:ietf:params:oauth:grant-type:user_code' : 'urn:ietf:params:oauth:grant-type:device_code',
                device_code: deviceCode,
                client_id: clientId
            })
        });

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok) {
            if (tokenData.error === 'authorization_pending') {
                return res.json({ status: 'pending' });
            }
            if (tokenData.error === 'slow_down') {
                return res.json({ status: 'slow_down' });
            }
            if (tokenData.error === 'expired_token') {
                oauthStates.delete(deviceCode);
                return res.status(400).json({ error: 'Device code expired' });
            }
            throw new Error(tokenData.error_description || tokenData.error);
        }

        // Success - clean up device code
        oauthStates.delete(deviceCode);

        // Store token via VPS agent
        const ctx = await resolveVpsAgentContext(req, res, userId);
        if (!ctx) {
            return res.status(500).json({ error: 'Failed to resolve user context' });
        }

        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/configure-provider', {
            instanceId: ctx.userId,
            provider,
            token: tokenData.access_token,
            authMethod: 'plugin-oauth',
            ...(tokenData.expires_in ? { expiresIn: tokenData.expires_in } : {}),
            ...(tokenData.refresh_token ? { refreshToken: tokenData.refresh_token } : {})
        });

        if (!ok) {
            console.error(`[backend] Failed to configure plugin OAuth provider:`, data);
            return res.status(500).json({ error: 'Failed to save OAuth token' });
        }

        res.json({ status: 'success', provider });

    } catch (error) {
        console.error(`[backend] Plugin OAuth poll error:`, error);
        res.status(500).json({ error: error.message });
    }
});

// ── Get provider catalog with OAuth support info ─────────────────────────────
app.get('/api/providers/catalog', async (req, res) => {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return;

    const providers = [
        { 
            key: 'openai', 
            label: 'OpenAI',
            authMethods: ['api_key'],
            description: 'Uses OPENAI_API_KEY'
        },
        { 
            key: 'openai-codex', 
            label: 'OpenAI Codex',
            authMethods: ['oauth'],
            authLabels: {
                oauth: 'Login with ChatGPT'
            },
            description: 'OAuth via ChatGPT - only provider with true OAuth support'
        },
        { 
            key: 'anthropic', 
            label: 'Anthropic',
            authMethods: ['api_key', 'setup_token'],
            authLabels: {
                api_key: 'API Key',
                setup_token: 'Setup Token (claude setup-token)'
            },
            description: 'ANTHROPIC_API_KEY or claude setup-token (not OAuth)'
        },
        { key: 'gemini', label: 'Gemini', authMethods: ['api_key'], description: 'Uses GEMINI_API_KEY' },
        { key: 'azurev1', label: 'Azure OpenAI', authMethods: ['api_key'], description: 'Uses AZURE_OPENAI_API_KEY' },
        { key: 'openrouter', label: 'OpenRouter', authMethods: ['api_key'], description: 'Uses OPENROUTER_API_KEY' },
        { key: 'venice', label: 'Venice AI', authMethods: ['api_key'], description: 'Uses VENICE_API_KEY' },
        { key: 'bedrock', label: 'Amazon Bedrock', authMethods: ['api_key'], description: 'Uses AWS credentials' },
        { key: 'nvidia', label: 'NVIDIA', authMethods: ['api_key'], description: 'Uses NVIDIA_API_KEY' },
        { key: 'huggingface', label: 'Hugging Face', authMethods: ['api_key'], description: 'Uses HUGGINGFACE_HUB_TOKEN' },
        { key: 'together', label: 'Together AI', authMethods: ['api_key'], description: 'Uses TOGETHER_API_KEY' },
        { key: 'custom', label: '+ Custom Provider', authMethods: ['api_key'], description: 'Custom provider configuration' }
    ];

    res.json({ providers });
});

// ── Model config save (primary model via CLI, allowedModels stored in profile) ─
app.put('/api/models/config', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;

    const { primary, fallbacks = [], allowedModels = [] } = req.body || {};
    if (!primary) return res.status(400).json({ error: 'primary model is required' });

    // Ensure primary is in allowedModels
    const allAllowed = [...new Set([primary, ...fallbacks, ...allowedModels])];

    // Read current config first to preserve other settings
    const configPath = path.join(INSTANCES_DIR, ctx.userId, 'openclaw.json');
    let config;
    try {
        const { ok: readOk, data: readData } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/openclaw-config', {
            instanceId: ctx.userId
        }, 'GET');
        if (!readOk) throw new Error('Failed to read config');
        config = JSON.parse(readData.content || '{}');
    } catch (err) {
        console.error('[backend] Failed to read openclaw.json:', err.message);
        config = {};
    }

    // Update model configuration
    config.agents = config.agents || {};
    config.agents.defaults = config.agents.defaults || {};
    config.agents.defaults.model = {
        primary,
        fallbacks
    };

    // Update allowed models - convert array to object format
    config.agents.defaults.models = {};
    for (const modelKey of allAllowed) {
        config.agents.defaults.models[modelKey] = { enabled: true };
    }

    // Write back via VPS agent
    const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/openclaw-config', {
        instanceId: ctx.userId,
        content: JSON.stringify(config, null, 2)
    }, 'PUT');

    console.log(`[backend] vps-agent openclaw-config update → ${status}`, data);
    if (!ok) return res.status(500).json({ error: data.error || 'Failed to update config', detail: data });

    // Also call config.apply via WebSocket to reload in running agent
    try {
        await callVpsAgent(ctx.agentBaseUrl, '/api/internal/agent-config-update', {
            instanceId: ctx.userId,
            agentId: 'main',
            updates: {
                model: { primary, fallbacks }
            }
        });
    } catch (err) {
        console.log('[backend] config.apply notification failed (non-fatal):', err.message);
    }

    res.json({ success: true, primary, fallbacks, allowedModels: allAllowed });
});

// ── File-based endpoints via vps-agent ────────────────────────────────────────
async function vpsAgentGet(req, res, agentPath) {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    try {
        const url = `${ctx.agentBaseUrl}${agentPath}?instanceId=${encodeURIComponent(ctx.userId)}`;
        const r = await fetch(url, { headers: { 'X-Internal-Secret': INTERNAL_SECRET }, signal: AbortSignal.timeout(5_000) });
        const data = await r.json();
        if (!r.ok) return res.status(500).json(data);
        res.json(data);
    } catch (err) { res.status(502).json({ error: err.message }); }
}

async function vpsAgentPut(req, res, agentPath, extraQuery = '') {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    try {
        const url = `${ctx.agentBaseUrl}${agentPath}?instanceId=${encodeURIComponent(ctx.userId)}${extraQuery}`;
        const r = await fetch(url, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
            body: JSON.stringify(req.body),
            signal: AbortSignal.timeout(5_000)
        });
        const data = await r.json();
        if (!r.ok) return res.status(500).json(data);
        res.json(data);
    } catch (err) { res.status(502).json({ error: err.message }); }
}

app.get('/api/soul', (req, res) => vpsAgentGet(req, res, '/api/internal/soul'));
app.put('/api/soul', (req, res) => vpsAgentPut(req, res, '/api/internal/soul'));

app.get('/api/workspace-list', (req, res) => vpsAgentGet(req, res, '/api/internal/workspace-list'));
app.get('/api/workspace-file', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    try {
        const name = req.query.name || '';
        const url = `${ctx.agentBaseUrl}/api/internal/workspace-file?instanceId=${encodeURIComponent(ctx.userId)}&name=${encodeURIComponent(name)}`;
        const r = await fetch(url, { headers: { 'X-Internal-Secret': INTERNAL_SECRET }, signal: AbortSignal.timeout(5_000) });
        const data = await r.json();
        if (!r.ok) return res.status(500).json(data);
        res.json(data);
    } catch (err) { res.status(502).json({ error: err.message }); }
});
app.put('/api/workspace-file', async (req, res) => {
    const name = req.query.name || '';
    vpsAgentPut(req, res, '/api/internal/workspace-file', `&name=${encodeURIComponent(name)}`);
});

app.put('/api/openclaw-config', (req, res) => vpsAgentPut(req, res, '/api/internal/openclaw-config'));

// ── Sub-agents (agents.list + sessions.list merged for full info) ─────────────
app.get('/api/subagents', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;

    try {
        // Fetch agents and sessions in parallel
        const [agentsRes, sessionsRes] = await Promise.all([
            callVpsAgent(ctx.agentBaseUrl, '/api/internal/agents-list', { instanceId: ctx.userId }),
            callVpsAgent(ctx.agentBaseUrl, '/api/internal/sessions-list', { instanceId: ctx.userId, limit: 200 })
        ]);

        console.log(`[backend] /api/subagents - agentsRes.ok=${agentsRes.ok}, agents count=${agentsRes.data?.agents?.length || 0}`);
        console.log(`[backend] /api/subagents - agents:`, JSON.stringify(agentsRes.data?.agents || []).slice(0, 500));

        const agents = agentsRes.ok && Array.isArray(agentsRes.data?.agents) ? agentsRes.data.agents : [];
        const jobs = sessionsRes.ok && Array.isArray(sessionsRes.data?.jobs) ? sessionsRes.data.jobs : [];

        console.log(`[backend] /api/subagents - total agents: ${agents.length}, filtering out 'main'`);

        // Build session lookup by agentId
        const sessionMap = {};
        for (const job of jobs) {
            if (job.agentId) sessionMap[job.agentId] = job;
        }

        const subagents = agents
            .filter(a => a.id !== 'main')
            .map(a => {
                const session = sessionMap[a.id] || {};
                return {
                    sessionKey: `agent:${a.id}:${a.id}`,
                    id: a.id,
                    label: a.name || a.id,
                    model: session.model || '',
                    updatedAt: session.metadata?.updatedAt || null,
                    status: session.status || 'active'
                };
            });

        console.log(`[backend] /api/subagents - returning ${subagents.length} subagents`);
        return res.json({ subagents });
    } catch (err) {
        console.error(`[backend] /api/subagents error:`, err);
    }
    res.json({ subagents: [] });
});

// Debug endpoint to verify deployment version
app.get('/api/subagents/version', (req, res) => {
    res.json({
        version: '2.0.0-subagent-spawn-fix',
        timestamp: new Date().toISOString(),
        commit: 'ec65745+',
        features: {
            wsAgentsCreate: true,
            detailedLogging: true,
            structuredResponse: true
        }
    });
});

app.post('/api/subagents/spawn', async (req, res) => {
    const gateway = await resolveUserGatewayContext(req, res, { requireProvisioned: true });
    if (!gateway) return;
    if (!gateway.gatewayToken) return res.status(403).json({ error: 'Missing gateway token' });

    const { task, label, model, agentId } = req.body || {};
    if (!task) return res.status(400).json({ error: 'task is required' });

    // Generate agent ID from label or timestamp
    const aid = agentId || (label || 'sub-' + Date.now()).toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 30);

    console.log(`[backend] spawn subagent: wsUrl=${gateway.wsUrl ? 'YES' : 'NO'}, aid=${aid}, label=${label}`);

    // Try direct WebSocket first, fall back to vps-agent (docker exec)
    if (gateway.wsUrl) {
        try {
            console.log(`[backend] spawn: trying WS ${gateway.wsUrl}, creating agent ${aid}`);
            
            // Step 1: Create the agent
            const createMessage = {
                type: 'req', 
                id: `create-${Date.now()}`,
                method: 'agents.create',
                params: {
                    name: aid,
                    workspace: `/home/node/.openclaw/agents/${aid}`
                }
            };
            
            console.log(`[backend] sending agents.create for ${aid}...`);
            const createResult = await gatewayWsSend(gateway.wsUrl, gateway.gatewayToken, createMessage);
            console.log(`[backend] agents.create result:`, JSON.stringify(createResult).slice(0, 300));
            
            if (!createResult.ok && createResult.error) {
                console.error(`[backend] agents.create failed:`, createResult.error);
                return res.status(400).json({ error: createResult.error?.message || 'Failed to create agent' });
            }

            // Step 2: Send the initial task message
            const chatMessage = {
                type: 'req', 
                id: `spawn-${Date.now()}`,
                method: 'chat.send',
                params: {
                    sessionKey: `agent:${aid}:${aid}`,
                    message: task,
                    idempotencyKey: `spawn-${Date.now()}-${Math.random().toString(36).slice(2)}`
                }
            };
            
            console.log(`[backend] sending chat.send to agent:${aid}:${aid}...`);
            const chatResult = await gatewayWsSend(gateway.wsUrl, gateway.gatewayToken, chatMessage);
            console.log(`[backend] chat.send result:`, JSON.stringify(chatResult).slice(0, 300));
            
            return res.json({
                ok: true,
                version: '2.0-subagent-fix',
                agent: { id: aid, name: label || aid },
                chat: chatResult?.payload || chatResult
            });
        } catch (err) {
            console.error(`[backend] spawn WS error:`, err);
            console.warn(`[backend] spawn WS failed (${err.message}), falling back to vps-agent`);
        }
    } else {
        console.log(`[backend] No wsUrl, using vps-agent fallback directly`);
    }

    // Fallback: vps-agent docker exec approach
    try {
        const ctx = await resolveVpsAgentContext(req, res);
        if (!ctx) return;
        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/subagents-spawn', {
            instanceId: ctx.userId, task, label, model, agentId
        });
        if (!ok) return res.status(status).json(data);
        console.log(`[backend] sub-agent spawned via vps-agent:`, data);
        res.json(data);
    } catch (err) {
        console.error('[backend] subagents/spawn fallback error:', err.message);
        res.status(502).json({ error: err.message });
    }
});

// ── Agents management (via vps-agent WebSocket) ──────────────────────────────
app.get('/api/agents', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;

    // ?action=models → return available models for the dropdown
    if (req.query.action === 'models') {
        try {
            const { ok, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/models-list', {
                instanceId: ctx.userId
            });
            if (ok) {
                // Transform to [{ key, name }] format the frontend expects
                // Key must include provider prefix (e.g. "azurev1/Kimi-K2.5") to match config
                const models = Array.isArray(data?.models) ? data.models
                    : Array.isArray(data) ? data : [];
                const mapped = models.map(m => {
                    const id = m.key || m.id || m.model || m.name;
                    const provider = m.provider || '';
                    const key = provider && !id.includes('/') ? `${provider}/${id}` : id;
                    return { key, name: m.name || id, provider };
                });
                return res.json(mapped);
            }
        } catch { /* fall through */ }
        return res.json([]);
    }

    // ?id=<agentId> → return single agent config from openclaw.json
    if (req.query.id) {
        try {
            const { ok, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/agent-config', {
                instanceId: ctx.userId, agentId: req.query.id
            });
            if (ok) return res.json(data);
        } catch { /* fall through */ }
        return res.json({ agentId: req.query.id });
    }

    // No params → list all agents
    try {
        const { ok, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/agents-list', {
            instanceId: ctx.userId
        });
        if (ok) return res.json(data);
    } catch { /* fall through */ }
    res.json({ agents: [] });
});

app.patch('/api/agents', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    const agentId = req.query.id || 'main';
    const updates = req.body || {};

    try {
        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/agent-config-update', {
            instanceId: ctx.userId, agentId, updates
        });
        if (!ok) return res.status(status).json(data);
        res.json(data);
    } catch (err) {
        console.error('[backend] agents update error:', err.message);
        res.status(502).json({ error: err.message });
    }
});

app.delete('/api/agents', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    const agentId = req.query.id;
    if (!agentId) return res.status(400).json({ error: 'id query param required' });

    try {
        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/agents-delete', {
            instanceId: ctx.userId, agentId
        });
        if (!ok) return res.status(status).json(data);
        res.json(data);
    } catch (err) {
        res.status(502).json({ error: err.message });
    }
});

// ── Channel management ────────────────────────────────────────────────────────

app.post('/api/channels/add', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    const { channel, token, slackBotToken, slackAppToken } = req.body || {};
    if (!channel) return res.status(400).json({ error: 'channel is required' });
    const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/channels-add', {
        instanceId: ctx.userId, channel, token, slackBotToken, slackAppToken
    });
    console.log(`[backend] vps-agent channels-add → ${status}`, data);
    if (!ok) return res.status(500).json({ error: data.error || 'Failed to add channel', detail: data });
    res.json(data);
});

app.get('/api/channels/status', (req, res) => vpsAgentGet(req, res, '/api/internal/channels-status'));
app.get('/api/channels/list', (req, res) => vpsAgentGet(req, res, '/api/internal/channels-list'));

app.post('/api/channels/login', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;
    const { channel, verbose } = req.body || {};
    if (!channel) return res.status(400).json({ error: 'channel is required' });
    const controller = new AbortController();
    req.on('close', () => controller.abort());
    try {
        const agentRes = await fetch(`${ctx.agentBaseUrl}/api/internal/channels-login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
            body: JSON.stringify({ instanceId: ctx.userId, channel, verbose }),
            signal: controller.signal,
        });
        if (!agentRes.ok) {
            const errData = await agentRes.json().catch(() => ({}));
            return res.status(agentRes.status).json({ error: errData.error || 'Login failed' });
        }
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Transfer-Encoding', 'chunked');
        for await (const chunk of agentRes.body) {
            res.write(chunk);
        }
        res.end();
    } catch (err) {
        if (!res.headersSent) res.status(502).json({ error: err.message });
        else res.end();
    }
});

// ── Chat endpoint (calls AI provider directly; gateway uses WebSocket, not REST) ──
app.all('/api/chat', async (req, res) => {
    if (req.method === 'GET') {
        const { action } = req.query;
        const userId = await requireClerkUserId(req, res);
        if (!userId) return;
        if (action === 'sessions') return res.json({ sessions: [] });
        if (action === 'history') return res.json({ messages: [] });
        return res.json({});
    }

    if (req.method === 'POST') {
        const ctx = await resolveVpsAgentContext(req, res);
        if (!ctx) return;

        const { message, stream } = req.body || {};
        if (!message) return res.status(400).json({ error: 'message is required' });

        try {
            // Read openclaw.json to get provider config
            const cfgRes = await fetch(
                `${ctx.agentBaseUrl}/api/internal/openclaw-config?instanceId=${encodeURIComponent(ctx.userId)}`,
                { headers: { 'X-Internal-Secret': INTERNAL_SECRET }, signal: AbortSignal.timeout(5_000) }
            );
            const cfgData = await cfgRes.json();
            if (!cfgRes.ok || !cfgData.content) {
                return res.status(502).json({ error: 'Failed to read instance config' });
            }

            const config = JSON.parse(cfgData.content);
            const primaryModel = config.agents?.defaults?.model?.primary || '';
            const slashIdx = primaryModel.indexOf('/');
            const providerKey = slashIdx > 0 ? primaryModel.slice(0, slashIdx) : null;
            const modelName = slashIdx > 0 ? primaryModel.slice(slashIdx + 1) : null;
            if (!providerKey || !modelName) {
                return res.status(400).json({ error: 'No model/provider configured. Go to Settings → Models to configure one.' });
            }

            const provider = config.models?.providers?.[providerKey];
            if (!provider?.baseUrl) {
                return res.status(400).json({ error: `Provider "${providerKey}" has no baseUrl configured.` });
            }

            const apiKey = provider.apiKey || null;
            const headers = {
                'Content-Type': 'application/json',
                ...(provider.headers || {}),
            };
            if (apiKey) {
                headers['Authorization'] = `Bearer ${apiKey}`;
                if (!headers['api-key']) headers['api-key'] = apiKey;
            }

            const completionsUrl = `${provider.baseUrl.replace(/\/$/, '')}/chat/completions`;
            console.log(`[backend] POST /api/chat → ${completionsUrl} (model: ${providerKey}/${modelName})`);

            const upstream = await fetch(completionsUrl, {
                method: 'POST',
                headers,
                body: JSON.stringify({
                    model: modelName,
                    messages: [{ role: 'user', content: message }],
                    stream: false
                }),
                signal: AbortSignal.timeout(120_000)
            });

            if (!upstream.ok) {
                const errText = await upstream.text().catch(() => '');
                console.error(`[backend] POST /api/chat → provider ${upstream.status}: ${errText.slice(0, 300)}`);
                return res.status(upstream.status).json({ error: errText || `Provider error ${upstream.status}` });
            }

            const data = await upstream.json();
            res.json(data);
        } catch (err) {
            console.error('[backend] POST /api/chat error:', err.message);
            if (!res.headersSent) res.status(502).json({ error: err.message });
            else res.end();
        }
        return;
    }

    res.status(405).json({ error: 'Method Not Allowed' });
});

// ── Task listing (GET /api/tasks → sessions.list via vps-agent) ──────────────
app.get('/api/tasks', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;

    try {
        const { ok, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/sessions-list', {
            instanceId: ctx.userId,
            ids: req.query.ids || undefined,
            limit: parseInt(req.query.limit) || 100,
            includeNarrative: req.query.includeNarrative === 'true',
            includeLog: req.query.includeLog === 'true'
        });
        if (ok) return res.json(data);
    } catch { /* fall through */ }
    res.json({ jobs: [] });
});

// ── Task creation (POST /api/tasks → chat.send with unique session) ──────────
app.post('/api/tasks', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;

    const { message, agentId, priority, name } = req.body || {};
    if (!message) return res.status(400).json({ error: 'message is required' });

    const aid = agentId || 'main';
    // Each task gets its own session so it doesn't go to Telegram/existing channels
    const taskId = `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const sessionKey = `agent:${aid}:${taskId}`;

    try {
        const { ok, status, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/chat-send', {
            instanceId: ctx.userId,
            sessionKey,
            message,
            idempotencyKey: taskId
        });
        if (!ok) return res.status(status).json(data);
        res.json(data);
    } catch (err) {
        console.error('[backend] task creation error:', err.message);
        res.status(502).json({ error: err.message });
    }
});

// ── Broadcast (POST /api/broadcast → chat.send to multiple agents) ───────────
app.post('/api/broadcast', async (req, res) => {
    const ctx = await resolveVpsAgentContext(req, res);
    if (!ctx) return;

    const { message, agentIds } = req.body || {};
    if (!message) return res.status(400).json({ error: 'message is required' });
    const agents = Array.isArray(agentIds) && agentIds.length ? agentIds : ['main'];

    const tasks = [];
    for (const aid of agents) {
        try {
            const taskId = `bcast-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
            const { ok, data } = await callVpsAgent(ctx.agentBaseUrl, '/api/internal/chat-send', {
                instanceId: ctx.userId,
                sessionKey: `agent:${aid}:${taskId}`,
                message,
                idempotencyKey: taskId
            });
            tasks.push({ agentId: aid, ok, ...(data || {}) });
        } catch (err) {
            tasks.push({ agentId: aid, ok: false, error: err.message });
        }
    }

    res.json({ tasks });
});

// ── Heartbeat stub ────────────────────────────────────────────────────────────
app.post('/api/heartbeat', async (req, res) => {
    const userId = await requireClerkUserId(req, res);
    if (!userId) return;
    res.json({ ok: true });
});

// ── Multi-Tenant Catch-All Proxy ──────────────────────────────────────────────
const gatewayProxy = createProxyMiddleware({
    router: (req) => req._gatewayTarget,
    changeOrigin: true,
    secure: false,
    on: {
        proxyReq: (proxyReq, req) => {
            // Express app.use('/api', ...) strips the /api prefix from req.url,
            // but the gateway expects paths under /api/. Re-add the prefix.
            proxyReq.path = '/api' + proxyReq.path;
            proxyReq.setHeader('Authorization', `Bearer ${req._gatewayToken}`);
            proxyReq.setHeader('x-gateway-token', req._gatewayToken);
            fixRequestBody(proxyReq, req);
        },
        error: (err, _req, res) => {
            if (!res.headersSent) res.status(502).json({ error: 'Proxy error: ' + err.message });
        }
    }
});

app.use('/api', async (req, res, next) => {
    // Routes handled directly by this backend
    if (req.path === '/health' || req.path.startsWith('/user/profile')
        || req.path === '/chat' || req.path === '/heartbeat'
        || req.path.startsWith('/subagents') || req.path.startsWith('/agents')
        || req.path.startsWith('/channels') || req.path.startsWith('/providers')
        || req.path.startsWith('/models') || req.path.startsWith('/soul')
        || req.path.startsWith('/workspace') || req.path.startsWith('/openclaw-config')
        || req.path.startsWith('/tasks') || req.path === '/broadcast'
        || req.path === '/cors-test') {
        console.log(`[API] Direct route: ${req.method} ${req.path}`);
        return next();
    }

    // Continue to proxy middleware for other routes
    const gateway = await resolveUserGatewayContext(req, res, { requireProvisioned: true });
    if (!gateway) return;

    if (!gateway.gatewayToken) {
        return res.status(403).json({ error: 'User is provisioned but missing gateway token' });
    }

    console.log(`[backend → proxy] ${req.method} /api${req.path} → ${gateway.baseUrl} (user: ${gateway.userId})`);
    req._gatewayTarget = gateway.baseUrl;
    req._gatewayToken = gateway.gatewayToken;
    return gatewayProxy(req, res, next);
});

// ── OAuth state cleanup ─────────────────────────────────────────────────────
// Clean up expired OAuth states periodically
setInterval(() => {
    const now = Date.now();
    for (const [key, state] of oauthStates.entries()) {
        const expiredAt = state.createdAt + (state.expiresIn * 1000);
        if (now > expiredAt) {
            oauthStates.delete(key);
        }
    }
}, 60000); // Clean up every minute

app.listen(PORT, () => {
    console.log(`[backend] Listening on port ${PORT}`);
});
