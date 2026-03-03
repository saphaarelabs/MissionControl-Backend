/**
 * OpenClaw Backend — Health Check Script
 * Tests the multi-tenant backend proxy endpoints.
 * Usage: node api-health-check.js [BASE_URL] [CLERK_JWT_TOKEN]
 *
 * Example:
 *   node api-health-check.js https://openclaw-api.magicteams.ai eyJhbGci...
 *
 * Get a Clerk JWT by opening the browser console on the app and running:
 *   await window.Clerk.session.getToken()
 */

const BASE_URL = process.argv[2] || 'https://openclaw-api.magicteams.ai';
const TOKEN = process.argv[3] || process.env.CLERK_JWT || '';

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

function icon(status) {
    if (status >= 200 && status < 300) return `${GREEN}✓${RESET}`;
    if (status === 401 || status === 403) return `${YELLOW}⚿${RESET}`;
    if (status === 404) return `${YELLOW}?${RESET}`;
    return `${RED}✗${RESET}`;
}

async function check(method, path, opts = {}) {
    const url = `${BASE_URL}${path}`;
    const headers = {
        'Content-Type': 'application/json',
        ...(TOKEN ? { 'Authorization': `Bearer ${TOKEN}` } : {}),
        ...(opts.headers || {})
    };
    const init = { method, headers };
    if (opts.body) init.body = JSON.stringify(opts.body);

    try {
        const res = await fetch(url, init);
        const text = await res.text().catch(() => '');
        let note = '';
        try {
            const json = JSON.parse(text);
            if (json.error) note = ` → ${json.error}`;
            else if (json.status) note = ` → status:${json.status}`;
        } catch { /* not JSON */ }
        const label = method.padEnd(6) + path;
        console.log(`  ${icon(res.status)} ${String(res.status).padEnd(4)} ${label}${note}`);
        return res.status;
    } catch (err) {
        const label = method.padEnd(6) + path;
        console.log(`  ${RED}✗${RESET} ERR  ${label} → ${err.message}`);
        return 0;
    }
}

async function main() {
    console.log(`\n${BOLD}OpenClaw Backend — Health Check${RESET}`);
    console.log(`Base URL : ${BASE_URL}`);
    console.log(`Auth     : ${TOKEN ? 'Clerk JWT set' : 'none (add as 2nd arg — all /api routes will return 401)'}`);
    console.log('─'.repeat(65));

    const results = [];
    const run = async (m, p, opts) => results.push(await check(m, p, opts));

    // ── User Profile (direct backend routes) ──────────────────────────────────
    console.log(`\n${BOLD}User Profile (backend-handled)${RESET}`);
    await run('GET', '/api/health');
    await run('GET', '/api/user/profile');
    await run('POST', '/api/user/profile/sync', { body: { username: 'test' } });

    // ── Proxied Routes (forwarded to user's gateway container) ────────────────
    console.log(`\n${BOLD}Proxied → user's OpenClaw Gateway container${RESET}`);
    await run('GET', '/api/agents');
    await run('GET', '/api/subagents');
    await run('GET', '/api/models');
    await run('GET', '/api/chat');
    await run('GET', '/api/tasks');
    await run('GET', '/api/providers');
    await run('GET', '/api/channels/list');
    await run('GET', '/api/plugins');
    await run('GET', '/api/soul');
    await run('GET', '/api/workspace-list');

    // ── Summary ───────────────────────────────────────────────────────────────
    console.log('\n' + '─'.repeat(65));
    const ok = results.filter(s => s >= 200 && s < 300).length;
    const warn = results.filter(s => s === 400 || s === 401 || s === 403 || s === 404).length;
    const fail = results.filter(s => s === 0 || s >= 500).length;
    console.log(`${BOLD}Results:${RESET}  ${GREEN}${ok} OK${RESET}  ${YELLOW}${warn} warnings${RESET}  ${RED}${fail} errors${RESET}  (${results.length} total)`);
    console.log('\nLegend:');
    console.log(`  ${GREEN}✓${RESET} = 2xx OK             ${YELLOW}⚿${RESET} = 401/403 auth gate (expected without JWT)`);
    console.log(`  ${YELLOW}?${RESET} = 404 not found      ${RED}✗${RESET} = 5xx error or network failure\n`);

    process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
