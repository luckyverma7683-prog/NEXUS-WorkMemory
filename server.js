const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { promisify } = require('node:util');

const projectDirectory = __dirname;
const allowedPages = new Set(['dashboard.html', 'home.html', 'connect.html', 'intro.html', 'settings.html', 'README.md', 'nexus-theme.js']);
const maxRequestBytes = 2 * 1024 * 1024;
const sessionLifetime = 30 * 24 * 60 * 60 * 1000;
const database = new DatabaseSync(path.join(projectDirectory, '.nexus.sqlite'));
const rateLimits = new Map();
const authRateLimits = new Map();
const scrypt = promisify(crypto.scrypt);

database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        google_sub TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        name TEXT NOT NULL,
        password_salt TEXT,
        password_hash TEXT,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_states (
        state_hash TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        flow TEXT NOT NULL,
        user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS integrations (
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        credentials TEXT NOT NULL,
        metadata TEXT NOT NULL,
        connected_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, provider)
    );
    CREATE TABLE IF NOT EXISTS documents (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        payload TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        sources TEXT,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS memories (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'decision',
        pinned INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS user_settings (
        user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        settings_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_messages_convo ON messages(conversation_id, created_at ASC);
    CREATE INDEX IF NOT EXISTS idx_memories_user ON memories(user_id, pinned DESC, created_at DESC);
`);

const userColumns = new Set(database.prepare('PRAGMA table_info(users)').all().map(column => column.name));
if (!userColumns.has('password_salt')) database.exec('ALTER TABLE users ADD COLUMN password_salt TEXT');
if (!userColumns.has('password_hash')) database.exec('ALTER TABLE users ADD COLUMN password_hash TEXT');

const DEFAULT_SETTINGS = {
    ai: {
        model: 'gemini-3.8-flash',
        temperature: 0.7,
        customInstructions: '',
        maxHistoryTurns: 10,
        includeMemories: true
    },
    workspace: {
        defaultContext: 'all',
        autoExtractMemories: true,
        streamSpeed: 'smooth'
    },
    appearance: {
        theme: 'cyber-nexus',
        codeTheme: 'github-dark',
        codeLineNumbers: true,
        fontSize: 'standard'
    },
    notifications: {
        soundEffects: false,
        autoScroll: true
    }
};

function getUserSettings(userId) {
    const row = database.prepare('SELECT settings_json FROM user_settings WHERE user_id = ?').get(userId);
    if (!row) return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
    try {
        const stored = JSON.parse(row.settings_json);
        return {
            ai: { ...DEFAULT_SETTINGS.ai, ...(stored.ai || {}) },
            workspace: { ...DEFAULT_SETTINGS.workspace, ...(stored.workspace || {}) },
            appearance: { ...DEFAULT_SETTINGS.appearance, ...(stored.appearance || {}) },
            notifications: { ...DEFAULT_SETTINGS.notifications, ...(stored.notifications || {}) }
        };
    } catch {
        return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
    }
}

function saveUserSettings(userId, newSettings) {
    const current = getUserSettings(userId);
    const merged = {
        ai: { ...current.ai, ...(newSettings.ai || {}) },
        workspace: { ...current.workspace, ...(newSettings.workspace || {}) },
        appearance: { ...current.appearance, ...(newSettings.appearance || {}) },
        notifications: { ...current.notifications, ...(newSettings.notifications || {}) }
    };
    const now = Date.now();
    database.prepare(`
        INSERT INTO user_settings (user_id, settings_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            settings_json = excluded.settings_json,
            updated_at = excluded.updated_at
    `).run(userId, JSON.stringify(merged), now);
    return merged;
}

function loadEnvironmentFile() {
    const envPath = path.join(projectDirectory, '.env');
    if (!fs.existsSync(envPath)) return;

    for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
        const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
        if (!match || Object.hasOwn(process.env, match[1])) continue;
        process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2').replace(/\\n/g, '\n');
    }
}

loadEnvironmentFile();

const port = Number(process.env.PORT) || 3000;
const host = process.env.HOST || '127.0.0.1';

function encryptionKey() {
    const configured = process.env.NEXUS_ENCRYPTION_KEY;
    if (configured) return crypto.createHash('sha256').update(configured).digest();

    const keyPath = path.join(projectDirectory, '.nexus.key');
    if (!fs.existsSync(keyPath)) {
        fs.writeFileSync(keyPath, crypto.randomBytes(32).toString('hex'), { flag: 'wx', mode: 0o600 });
    }
    return crypto.createHash('sha256').update(fs.readFileSync(keyPath, 'utf8').trim()).digest();
}

function encrypt(value) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64');
}

function decrypt(value) {
    const data = Buffer.from(value, 'base64');
    if (data.length < 29) throw new Error('Encrypted integration data is invalid.');
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), data.subarray(0, 12));
    decipher.setAuthTag(data.subarray(12, 28));
    return JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8'));
}

function parseCookies(request) {
    const cookies = {};
    for (const item of (request.headers.cookie || '').split(';')) {
        const separator = item.indexOf('=');
        if (separator > 0) {
            cookies[item.slice(0, separator).trim()] = decodeURIComponent(item.slice(separator + 1).trim());
        }
    }
    return cookies;
}

function setSessionCookie(response, token, secure) {
    response.setHeader('Set-Cookie', `nexus_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionLifetime / 1000}${secure ? '; Secure' : ''}`);
}

function clearSessionCookie(response, secure) {
    response.setHeader('Set-Cookie', `nexus_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure ? '; Secure' : ''}`);
}

function getUser(request) {
    const token = parseCookies(request).nexus_session;
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const session = database.prepare(`
        SELECT users.id, users.email, users.name
        FROM sessions JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `).get(tokenHash, Date.now());
    return session || null;
}

function sendJson(response, statusCode, body) {
    response.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    });
    response.end(JSON.stringify(body));
}

function sendText(response, statusCode, body) {
    response.writeHead(statusCode, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    });
    response.end(body);
}

function htmlError(message, backLink = 'home.html') {
    return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>NEXUS connection</title><body style="font:16px system-ui;max-width:620px;margin:12vh auto;padding:24px;background:#101827;color:#edf6ff"><h1>Connection needs attention</h1><p>${escapeHtml(message)}</p><a style="color:#67e8f9" href="${backLink}">Return to NEXUS</a></body></html>`;
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[character]);
}

async function readJson(request, limit = maxRequestBytes) {
    let body = '';
    for await (const chunk of request) {
        body += chunk;
        if (Buffer.byteLength(body) > limit) throw Object.assign(new Error('The request is too large.'), { statusCode: 413 });
    }
    try {
        return JSON.parse(body);
    } catch {
        throw Object.assign(new Error('Send valid JSON.'), { statusCode: 400 });
    }
}

function verifyOrigin(request) {
    const origin = request.headers.origin;
    if (!origin) return true;

    try {
        const originUrl = new URL(origin);
        const hostHeader = request.headers.host;

        // 1. Direct match with current request's Host header
        if (hostHeader) {
            if (origin === `http://${hostHeader}` || origin === `https://${hostHeader}`) {
                return true;
            }
            if (originUrl.host.toLowerCase() === hostHeader.toLowerCase()) {
                return true;
            }

            // Loopback allowance between localhost, 127.0.0.1, ::1
            const loopbacks = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
            const reqHostname = hostHeader.split(':')[0].toLowerCase().replace(/^\[|\]$/g, '');
            if (loopbacks.has(originUrl.hostname.toLowerCase()) && loopbacks.has(reqHostname)) {
                return true;
            }
        }

        // 2. Direct match with configured NEXUS_PUBLIC_URL
        if (process.env.NEXUS_PUBLIC_URL) {
            const configured = new URL(process.env.NEXUS_PUBLIC_URL);
            if (originUrl.origin.toLowerCase() === configured.origin.toLowerCase()) {
                return true;
            }

            // Loopback allowance if configured URL is localhost/127.0.0.1
            const loopbacks = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
            if (loopbacks.has(originUrl.hostname.toLowerCase()) && loopbacks.has(configured.hostname.toLowerCase())) {
                return true;
            }
        }

        // 3. Fallback: Any loopback origin in local development
        const loopbacks = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
        if (loopbacks.has(originUrl.hostname.toLowerCase())) {
            return true;
        }

        return false;
    } catch {
        return false;
    }
}

function publicBaseUrl(request) {
    if (process.env.NEXUS_PUBLIC_URL) {
        const configured = new URL(process.env.NEXUS_PUBLIC_URL);
        if (configured.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(configured.hostname)) {
            throw new Error('NEXUS_PUBLIC_URL must use HTTPS for public deployment.');
        }
        return configured.origin;
    }

    const requestHost = (request.headers.host || '').split(':')[0];
    if (!['localhost', '127.0.0.1', '::1'].includes(requestHost)) {
        throw new Error('Set NEXUS_PUBLIC_URL to your public HTTPS address before enabling OAuth.');
    }
    return `http://${request.headers.host}`;
}

function isSecure(request) {
    return process.env.NEXUS_PUBLIC_URL
        ? new URL(process.env.NEXUS_PUBLIC_URL).protocol === 'https:'
        : false;
}

function envValue(name) {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`Set ${name} in the server environment before connecting this provider.`);
    return value;
}

function githubAppSetupStatus() {
    const appId = process.env.GITHUB_APP_ID?.trim();
    const slug = process.env.GITHUB_APP_SLUG?.trim();
    const privateKey = process.env.GITHUB_PRIVATE_KEY?.trim();
    const missing = [
        !appId && 'GITHUB_APP_ID',
        !slug && 'GITHUB_APP_SLUG',
        !privateKey && 'GITHUB_PRIVATE_KEY'
    ].filter(Boolean);
    if (missing.length) {
        return { configured: false, message: `Add ${missing.join(', ')} to the server .env file.` };
    }
    if (!/^\d+$/.test(appId)) {
        return { configured: false, message: 'GITHUB_APP_ID must be the numeric App ID from GitHub.' };
    }
    if (!/^[A-Za-z0-9-]+$/.test(slug)) {
        return { configured: false, message: 'GITHUB_APP_SLUG must be the App URL slug from GitHub.' };
    }
    try {
        crypto.createPrivateKey(privateKey.replace(/\\n/g, '\n'));
    } catch {
        return { configured: false, message: 'GITHUB_PRIVATE_KEY is not a valid private key. Replace it with the key downloaded from your GitHub App.' };
    }
    return { configured: true, message: '' };
}

function requireGithubAppSetup() {
    const status = githubAppSetupStatus();
    if (!status.configured) throw new Error(status.message);
}

function oauthState(request, response, provider, flow, userId = null) {
    const state = crypto.randomBytes(32).toString('hex');
    database.prepare(`
        INSERT INTO oauth_states (state_hash, provider, flow, user_id, expires_at)
        VALUES (?, ?, ?, ?, ?)
    `).run(crypto.createHash('sha256').update(state).digest('hex'), provider, flow, userId, Date.now() + 10 * 60 * 1000);
    if (flow === 'login') {
        response.setHeader('Set-Cookie', `nexus_oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600${isSecure(request) ? '; Secure' : ''}`);
    }
    return state;
}

function consumeOAuthState(request, state, provider, flow) {
    if (typeof state !== 'string' || !/^[a-f0-9]{64}$/.test(state)) return null;
    const hash = crypto.createHash('sha256').update(state).digest('hex');
    const row = database.prepare('SELECT * FROM oauth_states WHERE state_hash = ? AND expires_at > ?').get(hash, Date.now());
    database.prepare('DELETE FROM oauth_states WHERE state_hash = ?').run(hash);
    if (!row || row.provider !== provider || row.flow !== flow) return null;

    if (flow === 'login' && parseCookies(request).nexus_oauth_state !== state) return null;
    if (flow === 'connect') {
        const user = getUser(request);
        if (!user || row.user_id !== user.id) return null;
    }
    return row;
}

async function providerJson(url, options = {}) {
    const response = await fetch(url, { ...options, signal: AbortSignal.timeout(20000) });
    let result;
    try {
        result = await response.json();
    } catch {
        throw new Error('The identity provider returned an unreadable response.');
    }
    if (!response.ok) {
        const detail = result.error_description || result.error?.message || result.error || `HTTP ${response.status}`;
        throw new Error(`Provider request failed: ${String(detail).slice(0, 300)}`);
    }
    return result;
}

function googleCredentials() {
    return { clientId: envValue('GOOGLE_CLIENT_ID'), clientSecret: envValue('GOOGLE_CLIENT_SECRET') };
}

function redirectUri(request) {
    return `${publicBaseUrl(request)}/auth/callback/google`;
}

async function exchangeGoogleCode(request, code) {
    const credentials = googleCredentials();
    const form = new URLSearchParams({
        code,
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        redirect_uri: redirectUri(request),
        grant_type: 'authorization_code'
    });
    return providerJson('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
    });
}

async function googleIdentity(idToken) {
    const result = await providerJson(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
    if (result.aud !== envValue('GOOGLE_CLIENT_ID')
        || !result.sub
        || result.email_verified !== 'true'
        || Number(result.exp) <= Math.floor(Date.now() / 1000)) {
        throw new Error('Google did not return a verified identity for this application.');
    }
    return { googleSub: result.sub, email: result.email, name: result.name || result.email };
}

function saveIntegration(userId, provider, credentials, metadata) {
    database.prepare(`
        INSERT INTO integrations (user_id, provider, credentials, metadata, connected_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id, provider) DO UPDATE SET
            credentials = excluded.credentials,
            metadata = excluded.metadata,
            connected_at = excluded.connected_at
    `).run(userId, provider, encrypt(credentials), encrypt(metadata), Date.now());
}

function getIntegration(userId, provider) {
    const row = database.prepare('SELECT credentials, metadata, connected_at FROM integrations WHERE user_id = ? AND provider = ?').get(userId, provider);
    if (!row) return null;
    return { credentials: decrypt(row.credentials), metadata: decrypt(row.metadata), connectedAt: row.connected_at };
}

function createSession(response, request, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    database.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
    database.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(
        crypto.createHash('sha256').update(token).digest('hex'),
        userId,
        Date.now() + sessionLifetime
    );
    setSessionCookie(response, token, isSecure(request));
    return token;
}

function githubAppJwt() {
    requireGithubAppSetup();
    const appId = envValue('GITHUB_APP_ID');
    const privateKey = envValue('GITHUB_PRIVATE_KEY').replace(/\\n/g, '\n');
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(JSON.stringify({ iat: now - 60, exp: now + 8 * 60, iss: appId })).toString('base64url');
    const unsigned = `${header}.${payload}`;
    const signature = crypto.sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url');
    return `${unsigned}.${signature}`;
}

async function createGithubInstallationToken(installationId) {
    const jwt = githubAppJwt();
    const result = await providerJson(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}/access_tokens`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${jwt}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'NEXUS'
        },
        body: JSON.stringify({
            permissions: {
                contents: 'read',
                issues: 'read',
                pull_requests: 'read'
            }
        })
    });
    if (!result.token) throw new Error('GitHub did not return an installation access token.');
    const permissions = result.permissions || {};
    for (const permission of ['contents', 'issues', 'pull_requests']) {
        if (permissions[permission] !== 'read') {
            throw new Error(`GitHub did not grant the required read-only ${permission} permission. Check the GitHub App settings and installation.`);
        }
    }
    return result.token;
}

async function listGithubAppInstallations() {
    if (!githubAppSetupStatus().configured) return [];
    try {
        const jwt = githubAppJwt();
        const installations = await providerJson('https://api.github.com/app/installations', {
            headers: {
                Authorization: `Bearer ${jwt}`,
                Accept: 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'NEXUS'
            }
        });
        return Array.isArray(installations) ? installations : [];
    } catch (err) {
        console.warn(`Could not list GitHub app installations: ${err.message}`);
        return [];
    }
}

async function verifyAndConnectGithubInstallation(userId, installationId) {
    if (!installationId || !/^\d+$/.test(String(installationId))) {
        throw new Error('Choose a valid numeric GitHub App installation ID to continue.');
    }
    const token = await createGithubInstallationToken(installationId);
    const installation = await providerJson('https://api.github.com/installation/repositories?per_page=1', {
        headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'NEXUS'
        }
    });

    let accountName = installation.repositories?.[0]?.owner?.login;
    if (!accountName) {
        try {
            const jwt = githubAppJwt();
            const instDetail = await providerJson(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}`, {
                headers: {
                    Authorization: `Bearer ${jwt}`,
                    Accept: 'application/vnd.github+json',
                    'X-GitHub-Api-Version': '2022-11-28',
                    'User-Agent': 'NEXUS'
                }
            });
            accountName = instDetail.account?.login;
        } catch { }
    }
    accountName = accountName || 'GitHub installation';

    saveIntegration(userId, 'github', { installationId: String(installationId) }, {
        account: accountName,
        permissions: ['Read repository contents', 'Read issues and pull requests'],
        repositoryCount: installation.total_count || 0
    });

    return {
        account: accountName,
        repositoryCount: installation.total_count || 0
    };
}

async function beginOAuth(request, response, provider, flow) {
    const user = flow === 'connect' ? getUser(request) : null;
    if (flow === 'connect' && !user) {
        response.writeHead(302, { Location: '/home.html' });
        response.end();
        return;
    }

    if (provider === 'github') requireGithubAppSetup();
    const callback = provider === 'google' ? redirectUri(request) : `${publicBaseUrl(request)}/auth/callback/${provider}`;
    const state = oauthState(request, response, provider, flow, user?.id || null);
    const url = new URL('https://example.com');

    if (provider === 'google') {
        const credentials = googleCredentials();
        url.href = 'https://accounts.google.com/o/oauth2/v2/auth';
        url.search = new URLSearchParams({
            client_id: credentials.clientId,
            redirect_uri: callback,
            response_type: 'code',
            scope: flow === 'login'
                ? 'openid email profile'
                : 'openid email profile https://www.googleapis.com/auth/drive.readonly',
            state,
            access_type: 'offline',
            prompt: flow === 'login' ? 'select_account' : 'consent'
        }).toString();
    } else if (provider === 'github') {
        const reqUrl = new URL(request.url, 'http://localhost');
        const queryInstallId = reqUrl.searchParams.get('installation_id');
        const forceNew = reqUrl.searchParams.get('new') === 'true';

        // 1. If explicit installation_id was requested
        if (queryInstallId && /^\d+$/.test(queryInstallId)) {
            await verifyAndConnectGithubInstallation(user.id, queryInstallId);
            response.writeHead(302, { Location: '/dashboard.html?connection=success&provider=github', 'Cache-Control': 'no-store' });
            response.end();
            return;
        }

        // 2. Check if GitHub App is already installed on GitHub
        if (!forceNew) {
            const installations = await listGithubAppInstallations();
            if (installations.length === 1) {
                await verifyAndConnectGithubInstallation(user.id, installations[0].id);
                response.writeHead(302, { Location: '/dashboard.html?connection=success&provider=github', 'Cache-Control': 'no-store' });
                response.end();
                return;
            }
        }

        url.href = `https://github.com/apps/${encodeURIComponent(envValue('GITHUB_APP_SLUG'))}/installations/new`;
        url.search = new URLSearchParams({ state }).toString();
    } else if (provider === 'notion') {
        url.href = 'https://api.notion.com/v1/oauth/authorize';
        url.search = new URLSearchParams({
            client_id: envValue('NOTION_CLIENT_ID'),
            redirect_uri: callback,
            response_type: 'code',
            owner: 'user',
            state
        }).toString();
    } else if (provider === 'slack') {
        url.href = 'https://slack.com/oauth/v2/authorize';
        url.search = new URLSearchParams({
            client_id: envValue('SLACK_CLIENT_ID'),
            redirect_uri: callback,
            scope: 'channels:read,channels:history,groups:read,groups:history,users:read',
            state
        }).toString();
    } else {
        throw new Error('This provider is not supported.');
    }

    response.writeHead(302, { Location: url.toString(), 'Cache-Control': 'no-store' });
    response.end();
}

async function completeOAuth(request, response, provider, query) {
    if (query.searchParams.has('error')) {
        sendText(response, 400, htmlError(`Authorization was not completed: ${query.searchParams.get('error')}.`, 'connect.html'));
        return;
    }

    try {
        let userId = null;

        // GitHub App callbacks (can arrive via setup URL redirect which does not include state parameter)
        if (provider === 'github') {
            const state = query.searchParams.get('state');
            const stateRow = state ? consumeOAuthState(request, state, 'github', 'connect') : null;
            if (stateRow) {
                userId = stateRow.user_id;
            } else {
                const user = getUser(request);
                if (user) userId = user.id;
            }

            if (!userId) {
                sendText(response, 401, htmlError('Please sign in to NEXUS to complete connecting GitHub.', 'home.html'));
                return;
            }

            let installationId = query.searchParams.get('installation_id');
            if (!installationId) {
                const installations = await listGithubAppInstallations();
                if (installations.length > 0) {
                    installationId = installations[0].id;
                }
            }

            if (!installationId || !/^\d+$/.test(String(installationId))) {
                throw new Error('Choose a GitHub App installation to continue.');
            }

            await verifyAndConnectGithubInstallation(userId, installationId);

            response.writeHead(302, { Location: '/dashboard.html?connection=success&provider=github', 'Cache-Control': 'no-store' });
            response.end();
            return;
        }

        const state = query.searchParams.get('state');
        const flow = provider === 'google' ? null : 'connect';
        const stateRow = provider === 'google'
            ? consumeGoogleState(request, state)
            : consumeOAuthState(request, state, provider, flow);
        if (!stateRow) {
            sendText(response, 400, htmlError('The authorization request expired or could not be verified. Please start again.', 'connect.html'));
            return;
        }

        if (provider === 'google' && stateRow.flow === 'login') {
            const code = query.searchParams.get('code');
            if (!code) throw new Error('Google did not return an authorization code.');
            const tokens = await exchangeGoogleCode(request, code);
            if (!tokens.id_token) throw new Error('Google did not return an identity token.');
            const identity = await googleIdentity(tokens.id_token);
            const user = database.prepare(`
                INSERT INTO users (id, google_sub, email, name, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(google_sub) DO UPDATE SET email = excluded.email, name = excluded.name
                RETURNING id, email, name
            `).get(crypto.randomUUID(), identity.googleSub, identity.email, identity.name, Date.now());
            const sessionToken = createSession(response, request, user.id);
            response.setHeader('Set-Cookie', [
                `nexus_session=${sessionToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionLifetime / 1000}${isSecure(request) ? '; Secure' : ''}`,
                `nexus_oauth_state=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${isSecure(request) ? '; Secure' : ''}`
            ]);
            response.writeHead(302, { Location: '/dashboard.html', 'Cache-Control': 'no-store' });
            response.end();
            return;
        }

        userId = stateRow.user_id;
        const integrationProvider = provider === 'google' ? 'google-drive' : provider;
        if (provider === 'google') {
            const code = query.searchParams.get('code');
            if (!code) throw new Error('Google did not return an authorization code.');
            const tokens = await exchangeGoogleCode(request, code);
            const previous = getIntegration(userId, integrationProvider);
            const googleIdentityData = tokens.id_token ? await googleIdentity(tokens.id_token) : null;
            saveIntegration(userId, integrationProvider, {
                ...(previous?.credentials || {}),
                accessToken: tokens.access_token,
                refreshToken: tokens.refresh_token || previous?.credentials?.refreshToken || null,
                expiresAt: Date.now() + Number(tokens.expires_in || 3600) * 1000
            }, {
                email: googleIdentityData?.email || previous?.metadata?.email || '',
                permissions: ['Read files in Google Drive']
            });
        } else if (provider === 'notion') {
            const result = await providerJson('https://api.notion.com/v1/oauth/token', {
                method: 'POST',
                headers: {
                    Authorization: `Basic ${Buffer.from(`${envValue('NOTION_CLIENT_ID')}:${envValue('NOTION_CLIENT_SECRET')}`).toString('base64')}`,
                    'Content-Type': 'application/json',
                    'Notion-Version': '2022-06-28'
                },
                body: JSON.stringify({ grant_type: 'authorization_code', code: query.searchParams.get('code'), redirect_uri: `${publicBaseUrl(request)}/auth/callback/notion` })
            });
            saveIntegration(userId, provider, { accessToken: result.access_token }, {
                workspace: result.workspace_name || 'Notion workspace',
                permissions: ['Read pages shared with the NEXUS integration']
            });
        } else if (provider === 'slack') {
            const result = await providerJson('https://slack.com/api/oauth.v2.access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    client_id: envValue('SLACK_CLIENT_ID'),
                    client_secret: envValue('SLACK_CLIENT_SECRET'),
                    code: query.searchParams.get('code') || '',
                    redirect_uri: `${publicBaseUrl(request)}/auth/callback/slack`
                })
            });
            if (!result.ok || !result.access_token) throw new Error(result.error || 'Slack authorization failed.');
            saveIntegration(userId, provider, { accessToken: result.access_token }, {
                workspace: result.team?.name || 'Slack workspace',
                permissions: ['Read public and invited channels', 'Read messages from accessible channels']
            });
        }

        response.writeHead(302, { Location: `/dashboard.html?connection=success&provider=${provider}`, 'Cache-Control': 'no-store' });
        response.end();
    } catch (error) {
        console.error(`${provider} OAuth failed: ${error.message}`);
        const sourceName = provider === 'github' ? 'GitHub' : (provider === 'google' ? 'Google Drive' : (provider === 'notion' ? 'Notion' : 'Slack'));
        const safeError = encodeURIComponent(error.message || 'Connection failed. Please retry.');
        response.writeHead(302, { Location: `/connect.html?source=${encodeURIComponent(sourceName)}&error=${safeError}`, 'Cache-Control': 'no-store' });
        response.end();
    }
}

function consumeGoogleState(request, state) {
    if (typeof state !== 'string' || !/^[a-f0-9]{64}$/.test(state)) return null;
    const hash = crypto.createHash('sha256').update(state).digest('hex');
    const row = database.prepare('SELECT * FROM oauth_states WHERE state_hash = ? AND expires_at > ?').get(hash, Date.now());
    database.prepare('DELETE FROM oauth_states WHERE state_hash = ?').run(hash);
    if (!row || row.provider !== 'google') return null;
    if (row.flow === 'login' && parseCookies(request).nexus_oauth_state !== state) return null;
    if (row.flow === 'connect') {
        const user = getUser(request);
        if (!user || row.user_id !== user.id) return null;
    }
    return row;
}

function getProviderStatus(userId) {
    const rows = database.prepare('SELECT provider, metadata, connected_at FROM integrations WHERE user_id = ?').all(userId);
    const statuses = {};
    for (const row of rows) {
        const metadata = decrypt(row.metadata);
        statuses[row.provider] = {
            connected: true,
            account: metadata.workspace || metadata.account || metadata.email || '',
            permissions: metadata.permissions || [],
            connectedAt: row.connected_at,
            repositoryCount: metadata.repositoryCount
        };
    }
    const documentCount = database.prepare('SELECT COUNT(*) AS count FROM documents WHERE user_id = ?').get(userId).count;
    statuses.documents = {
        connected: documentCount > 0,
        account: documentCount ? `${documentCount} uploaded file${documentCount === 1 ? '' : 's'}` : '',
        permissions: documentCount ? ['Read files you explicitly upload'] : [],
        documentCount
    };
    for (const p of ['github', 'google-drive', 'notion', 'slack']) {
        if (!statuses[p]) {
            statuses[p] = { connected: false, account: '', permissions: [] };
        }
    }
    return statuses;
}

async function loadGoogleAccessToken(userId) {
    const integration = getIntegration(userId, 'google-drive');
    if (!integration) throw new Error('Google Drive is not connected.');
    const credentials = integration.credentials;
    if (credentials.accessToken && credentials.expiresAt > Date.now() + 60_000) return credentials.accessToken;
    if (!credentials.refreshToken) throw new Error('Google Drive authorization expired. Reconnect Google Drive.');

    const form = new URLSearchParams({
        client_id: envValue('GOOGLE_CLIENT_ID'),
        client_secret: envValue('GOOGLE_CLIENT_SECRET'),
        refresh_token: credentials.refreshToken,
        grant_type: 'refresh_token'
    });
    const refreshed = await providerJson('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
    });
    credentials.accessToken = refreshed.access_token;
    credentials.expiresAt = Date.now() + Number(refreshed.expires_in || 3600) * 1000;
    saveIntegration(userId, 'google-drive', credentials, integration.metadata);
    return credentials.accessToken;
}

async function handleSourceItems(request, response, user, provider) {
    const integration = getIntegration(user.id, provider);
    if (!integration) {
        sendJson(response, 404, { error: 'Connect this provider before browsing its data.' });
        return;
    }

    try {
        let items = [];
        if (provider === 'google-drive') {
            const token = await loadGoogleAccessToken(user.id);
            const result = await providerJson('https://www.googleapis.com/drive/v3/files?pageSize=30&orderBy=modifiedTime%20desc&fields=files(id,name,mimeType,modifiedTime,webViewLink)', {
                headers: { Authorization: `Bearer ${token}` }
            });
            items = (result.files || []).map(file => ({
                id: file.id,
                name: file.name,
                detail: file.mimeType,
                url: file.webViewLink
            }));
        } else if (provider === 'github') {
            const token = await createGithubInstallationToken(integration.credentials.installationId);
            const result = await providerJson('https://api.github.com/installation/repositories?per_page=100', {
                headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'NEXUS' }
            });
            items = (result.repositories || []).map(repo => ({
                id: repo.full_name,
                name: repo.full_name,
                detail: repo.description || (repo.private ? 'Private repository' : 'Public repository'),
                url: repo.html_url
            }));
        } else if (provider === 'notion') {
            const result = await providerJson('https://api.notion.com/v1/search', {
                method: 'POST',
                headers: { Authorization: `Bearer ${integration.credentials.accessToken}`, 'Notion-Version': '2022-06-28', 'Content-Type': 'application/json' },
                body: JSON.stringify({ page_size: 50, sort: { direction: 'descending', timestamp: 'last_edited_time' } })
            });
            items = (result.results || []).map(page => ({
                id: page.id,
                name: page.properties?.title?.title?.map(part => part.plain_text).join('') || page.title?.map(part => part.plain_text).join('') || 'Untitled page',
                detail: 'Notion page',
                url: page.url
            }));
        } else if (provider === 'slack') {
            const result = await providerJson('https://slack.com/api/conversations.list?limit=200&exclude_archived=true', {
                headers: { Authorization: `Bearer ${integration.credentials.accessToken}` }
            });
            if (!result.ok) throw new Error(result.error || 'Could not list Slack channels.');
            items = (result.channels || []).map(channel => ({
                id: channel.id,
                name: `#${channel.name}`,
                detail: channel.is_member ? 'NEXUS can read messages' : 'Invite the NEXUS app to read messages',
                url: ''
            }));
        }
        sendJson(response, 200, { items });
    } catch (error) {
        console.error(`${provider} data request failed: ${error.message}`);
        sendJson(response, 502, { error: `${provider} could not load data: ${error.message}` });
    }
}

async function collectDriveContext(userId) {
    const token = await loadGoogleAccessToken(userId);
    const listing = await providerJson('https://www.googleapis.com/drive/v3/files?pageSize=6&orderBy=modifiedTime%20desc&fields=files(id,name,mimeType,modifiedTime)', {
        headers: { Authorization: `Bearer ${token}` }
    });
    const chunks = [];
    for (const file of listing.files || []) {
        if (file.mimeType === 'application/vnd.google-apps.folder') continue;
        if (file.mimeType.startsWith('application/vnd.google-apps.')) {
            const exportUrl = new URL(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(file.id)}/export`);
            exportUrl.searchParams.set('mimeType', 'text/plain');
            const exportResponse = await fetch(exportUrl, {
                headers: { Authorization: `Bearer ${token}` },
                signal: AbortSignal.timeout(12000)
            });
            if (!exportResponse.ok) continue;
            chunks.push(`Google Drive: ${file.name}\n${(await exportResponse.text()).slice(0, 3000)}`);
        } else if (file.mimeType.startsWith('text/') || ['application/json', 'application/xml'].includes(file.mimeType)) {
            const downloadUrl = new URL(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(file.id)}`);
            downloadUrl.searchParams.set('alt', 'media');
            const downloadResponse = await fetch(downloadUrl, {
                headers: { Authorization: `Bearer ${token}` },
                signal: AbortSignal.timeout(12000)
            });
            if (downloadResponse.ok) {
                chunks.push(`Google Drive: ${file.name}\n${(await downloadResponse.text()).slice(0, 3000)}`);
            }
        }
        if (chunks.join('\n').length > 8000) break;
    }
    return chunks.join('\n\n').slice(0, 8000);
}

function notionBlockText(block) {
    const value = block[block.type];
    const richText = value?.rich_text || value?.title || [];
    return richText.map(part => part.plain_text || '').join('');
}

async function collectNotionContext(userId) {
    const integration = getIntegration(userId, 'notion');
    if (!integration) return '';
    const result = await providerJson('https://api.notion.com/v1/search', {
        method: 'POST',
        headers: { Authorization: `Bearer ${integration.credentials.accessToken}`, 'Notion-Version': '2022-06-28', 'Content-Type': 'application/json' },
        body: JSON.stringify({ page_size: 6, sort: { direction: 'descending', timestamp: 'last_edited_time' } })
    });
    const chunks = [];
    for (const page of result.results || []) {
        const title = page.properties?.title?.title?.map(part => part.plain_text).join('')
            || page.title?.map(part => part.plain_text).join('')
            || 'Untitled page';
        const blocks = await providerJson(`https://api.notion.com/v1/blocks/${encodeURIComponent(page.id)}/children?page_size=30`, {
            headers: { Authorization: `Bearer ${integration.credentials.accessToken}`, 'Notion-Version': '2022-06-28' }
        });
        const text = (blocks.results || []).map(notionBlockText).filter(Boolean).join('\n');
        if (text) chunks.push(`Notion: ${title}\n${text.slice(0, 2500)}`);
    }
    return chunks.join('\n\n').slice(0, 8000);
}

async function collectSlackContext(userId) {
    const integration = getIntegration(userId, 'slack');
    if (!integration) return '';
    const channels = await providerJson('https://slack.com/api/conversations.list?limit=200&exclude_archived=true', {
        headers: { Authorization: `Bearer ${integration.credentials.accessToken}` }
    });
    if (!channels.ok) throw new Error(channels.error || 'Could not list Slack channels.');
    const chunks = [];
    for (const channel of (channels.channels || []).filter(item => item.is_member).slice(0, 4)) {
        const history = await providerJson(`https://slack.com/api/conversations.history?channel=${encodeURIComponent(channel.id)}&limit=12`, {
            headers: { Authorization: `Bearer ${integration.credentials.accessToken}` }
        });
        if (!history.ok) continue;
        const messages = (history.messages || []).map(message => message.text || '').filter(Boolean).join('\n');
        if (messages) chunks.push(`Slack #${channel.name}\n${messages.slice(0, 2000)}`);
    }
    return chunks.join('\n\n').slice(0, 7000);
}

async function collectGitHubContext(userId) {
    const integration = getIntegration(userId, 'github');
    if (!integration) return '';
    const token = await createGithubInstallationToken(integration.credentials.installationId);
    const listing = await providerJson('https://api.github.com/installation/repositories?per_page=10', {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'NEXUS' }
    });
    const chunks = [];
    for (const repository of listing.repositories || []) {
        const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'NEXUS' };
        const readme = await fetch(`https://api.github.com/repos/${encodeURIComponent(repository.owner.login)}/${encodeURIComponent(repository.name)}/readme`, {
            headers,
            signal: AbortSignal.timeout(12000)
        });
        if (readme.ok) {
            const data = await readme.json();
            if (data.encoding === 'base64' && data.content) {
                chunks.push(`GitHub ${repository.full_name} README\n${Buffer.from(data.content, 'base64').toString('utf8').slice(0, 2500)}`);
            }
        }
        const issues = await fetch(`https://api.github.com/repos/${encodeURIComponent(repository.owner.login)}/${encodeURIComponent(repository.name)}/issues?state=all&per_page=5&sort=updated&direction=desc`, {
            headers,
            signal: AbortSignal.timeout(12000)
        });
        if (issues.ok) {
            const items = await issues.json();
            const summaries = items.map(item => `${item.pull_request ? 'Pull request' : 'Issue'} #${item.number}: ${item.title}\n${(item.body || '').slice(0, 500)}`);
            if (summaries.length) chunks.push(`GitHub ${repository.full_name} recent issues and pull requests\n${summaries.join('\n')}`);
        }
        if (chunks.join('\n').length > 8000) break;
    }
    return chunks.join('\n\n').slice(0, 8000);
}

function parseSourceMentions(question) {
    const targets = new Set();
    const clean = question.replace(/@(github|drive|google-drive|slack|notion|docs|documents|all)\b/gi, (match, p1) => {
        let tag = p1.toLowerCase();
        if (tag === 'google-drive') tag = 'drive';
        if (tag === 'documents') tag = 'docs';
        targets.add(tag);
        return '';
    }).trim();
    return {
        targets: targets.has('all') || targets.size === 0 ? null : targets,
        cleanedQuestion: clean || question
    };
}

async function collectConnectedContext(userId, targets = null) {
    const tasks = [
        ['GitHub', 'github', () => collectGitHubContext(userId)],
        ['Google Drive', 'drive', () => collectDriveContext(userId)],
        ['Notion', 'notion', () => collectNotionContext(userId)],
        ['Slack', 'slack', () => collectSlackContext(userId)]
    ];
    const chunks = [];
    const warnings = [];
    const sources = [];
    for (const [providerName, key, collect] of tasks) {
        if (targets && !targets.has(key)) continue;
        const providerId = key === 'drive' ? 'google-drive' : key;
        if (!getIntegration(userId, providerId)) continue;
        try {
            const context = await collect();
            if (context) {
                chunks.push(context);
                sources.push(providerName);
            }
        } catch (error) {
            console.error(`${providerName} context request failed: ${error.message}`);
            warnings.push(`${providerName} data could not be loaded; its content was not included.`);
        }
    }
    return { context: chunks.join('\n\n').slice(0, 26000), warnings, sources };
}

async function collectWorkspaceContext(userId, targets = null) {
    let documentContext = '';
    const sourcesUsed = [];
    if (!targets || targets.has('docs')) {
        const documents = database.prepare('SELECT payload FROM documents WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(userId);
        if (documents.length) {
            documentContext = documents.map(row => {
                const doc = decrypt(row.payload);
                sourcesUsed.push(`Doc: ${doc.name}`);
                return `File: ${doc.name}\n${doc.content.slice(0, 4000)}`;
            }).join('\n\n').slice(0, 18000);
        }
    }

    const { context: connectedContext, warnings, sources: connectedSources } = await collectConnectedContext(userId, targets);
    sourcesUsed.push(...connectedSources);

    const context = [documentContext, connectedContext].filter(Boolean).join('\n\n').slice(0, 30000);
    return { context, warnings, sourcesUsed };
}

async function streamGeminiWithFallback(apiKey, contents, systemInstruction, options = {}) {
    const candidateModels = [
        options.preferredModel,
        'gemini-3.8-flash',
        'gemini-3.6-flash',
        'gemini-3.5-flash',
        'gemini-2.5-flash-lite'
    ].filter(Boolean);
    const uniqueModels = [...new Set(candidateModels)];

    for (const model of uniqueModels) {
        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`;
        const bodyPayload = { contents };
        if (systemInstruction) {
            bodyPayload.systemInstruction = { parts: [{ text: systemInstruction }] };
        }
        if (typeof options.temperature === 'number') {
            bodyPayload.generationConfig = { temperature: options.temperature };
        }

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyPayload),
                signal: AbortSignal.timeout(20000)
            });

            if (res.status === 200 && res.body) {
                return { stream: res.body, model };
            }
            console.warn(`Model ${model} stream returned status ${res.status}`);
        } catch (err) {
            console.warn(`Model ${model} stream error: ${err.message}`);
        }
    }
    throw new Error('All AI models are currently busy or unavailable. Please try again in a few moments.');
}

async function generateGeminiWithFallback(apiKey, contents, systemInstruction, options = {}) {
    const candidateModels = [
        options.preferredModel,
        'gemini-3.8-flash',
        'gemini-3.6-flash',
        'gemini-3.5-flash',
        'gemini-2.5-flash-lite'
    ].filter(Boolean);
    const uniqueModels = [...new Set(candidateModels)];

    for (const model of uniqueModels) {
        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
        const bodyPayload = { contents };
        if (systemInstruction) {
            bodyPayload.systemInstruction = { parts: [{ text: systemInstruction }] };
        }
        if (typeof options.temperature === 'number') {
            bodyPayload.generationConfig = { temperature: options.temperature };
        }

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyPayload),
                signal: AbortSignal.timeout(20000)
            });

            if (res.status === 200) {
                const data = await res.json();
                const text = data.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('').trim();
                if (text) return { text, model };
            }
        } catch (err) {
            console.warn(`Model ${model} generate error: ${err.message}`);
        }
    }
    throw new Error('All AI models are currently busy or unavailable. Please try again in a moment.');
}

async function handleChatStream(request, response, user) {
    let body;
    try {
        body = await readJson(request, 10 * 1024);
    } catch (error) {
        sendJson(response, error.statusCode || 400, { error: error.message });
        return;
    }

    const rawQuestion = typeof body.question === 'string' ? body.question.trim() : '';
    if (!rawQuestion || rawQuestion.length > 3000) {
        sendJson(response, 400, { error: 'Enter a question of 1 to 3,000 characters.' });
        return;
    }

    const apiKey = process.env.GEMINI_API_KEY?.trim();
    if (!apiKey) {
        sendJson(response, 503, { error: 'Add your Gemini API key to the GEMINI_API_KEY entry in the project .env file.' });
        return;
    }

    let conversationId = typeof body.conversationId === 'string' && /^[a-f0-9-]+$/.test(body.conversationId)
        ? body.conversationId
        : null;

    let conversationTitle = '';
    const now = Date.now();

    if (conversationId) {
        const existing = database.prepare('SELECT id, title FROM conversations WHERE id = ? AND user_id = ?').get(conversationId, user.id);
        if (!existing) conversationId = null;
        else conversationTitle = existing.title;
    }

    if (!conversationId) {
        conversationId = crypto.randomUUID();
        conversationTitle = rawQuestion.length > 36 ? rawQuestion.slice(0, 33).trim() + '...' : rawQuestion;
        database.prepare('INSERT INTO conversations (id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').run(
            conversationId, user.id, conversationTitle, now, now
        );
    }

    const userMsgId = crypto.randomUUID();
    database.prepare('INSERT INTO messages (id, conversation_id, user_id, role, content, sources, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        userMsgId, conversationId, user.id, 'user', rawQuestion, null, now
    );

    const { targets, cleanedQuestion } = parseSourceMentions(rawQuestion);
    const { context: workspaceContext, warnings, sourcesUsed } = await collectWorkspaceContext(user.id, targets);

    const userSettings = getUserSettings(user.id);
    const maxTurns = userSettings.ai?.maxHistoryTurns || 10;
    const pastMessages = database.prepare('SELECT role, content FROM messages WHERE conversation_id = ? AND id != ? ORDER BY created_at ASC LIMIT ?').all(conversationId, userMsgId, maxTurns);
    const contents = pastMessages.map(msg => ({
        role: msg.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: msg.content }]
    }));
    contents.push({
        role: 'user',
        parts: [{ text: cleanedQuestion }]
    });

    let memoryLines = '';
    if (userSettings.ai?.includeMemories !== false) {
        const memories = database.prepare('SELECT title, content, category FROM memories WHERE user_id = ? ORDER BY pinned DESC, created_at DESC LIMIT 15').all(user.id);
        memoryLines = memories.map(m => `• [${m.category.toUpperCase()}] ${m.title}: ${m.content}`).join('\n');
    }

    const customPersona = (userSettings.ai?.customInstructions || '').trim();

    const systemInstruction = [
        `You are NEXUS, an advanced AI Work Memory workspace assistant.`,
        `Synthesize knowledge across connected workspace tools (files, repositories, Drive, Notion, Slack) and permanent team memories to deliver clear, structured, and insightful answers.`,
        `Always format code snippets using markdown code blocks with correct language identifiers.`,
        `Cite sources in your answers when referencing connected data (e.g. [Source: README.md] or [Source: Slack #general]).`,
        customPersona ? `USER CUSTOM PREFERENCES & PERSONA:\n${customPersona}` : '',
        memoryLines ? `PERMANENT WORK MEMORIES & TEAM DECISIONS (Strictly adhere to these rules):\n${memoryLines}` : '',
        workspaceContext ? `CONNECTED WORKSPACE REFERENCE MATERIAL:\n${workspaceContext}` : ''
    ].filter(Boolean).join('\n\n');

    response.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });

    response.write(`data: ${JSON.stringify({
        type: 'meta',
        conversationId,
        title: conversationTitle,
        sources: sourcesUsed,
        warnings
    })}\n\n`);

    let fullAnswer = '';

    try {
        const { stream } = await streamGeminiWithFallback(apiKey, contents, systemInstruction, {
            preferredModel: userSettings.ai?.model,
            temperature: userSettings.ai?.temperature
        });
        const reader = stream.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed.startsWith('data:')) continue;
                const jsonStr = trimmed.slice(5).trim();
                if (!jsonStr || jsonStr === '[DONE]') continue;
                try {
                    const parsed = JSON.parse(jsonStr);
                    const partText = parsed.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
                    if (partText) {
                        fullAnswer += partText;
                        response.write(`data: ${JSON.stringify({ type: 'token', text: partText })}\n\n`);
                    }
                } catch {
                    // Skip incomplete chunk
                }
            }
        }

        if (fullAnswer) {
            const assistantMsgId = crypto.randomUUID();
            database.prepare('INSERT INTO messages (id, conversation_id, user_id, role, content, sources, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
                assistantMsgId, conversationId, user.id, 'assistant', fullAnswer, JSON.stringify(sourcesUsed), Date.now()
            );
            database.prepare('UPDATE conversations SET updated_at = ? WHERE id = ?').run(Date.now(), conversationId);
        }

        response.write(`data: ${JSON.stringify({ type: 'done', conversationId, fullAnswer })}\n\n`);
    } catch (error) {
        console.error(`Streaming chat error: ${error.message}`);
        response.write(`data: ${JSON.stringify({ type: 'error', error: error.message || 'Streaming was interrupted.' })}\n\n`);
    } finally {
        response.end();
    }
}

async function handleChat(request, response, user) {
    let body;
    try {
        body = await readJson(request, 10 * 1024);
    } catch (error) {
        sendJson(response, error.statusCode || 400, { error: error.message });
        return;
    }
    const rawQuestion = body.question;
    if (typeof rawQuestion !== 'string' || !rawQuestion.trim() || rawQuestion.length > 3000) {
        sendJson(response, 400, { error: 'Enter a question of 1 to 3,000 characters.' });
        return;
    }
    const apiKey = process.env.GEMINI_API_KEY?.trim();
    if (!apiKey) {
        sendJson(response, 503, { error: 'Add your Gemini API key to the GEMINI_API_KEY entry in the project .env file.' });
        return;
    }

    const { targets, cleanedQuestion } = parseSourceMentions(rawQuestion);
    const { context: workspaceContext, warnings, sourcesUsed } = await collectWorkspaceContext(user.id, targets);

    const memories = database.prepare('SELECT title, content, category FROM memories WHERE user_id = ? ORDER BY pinned DESC, created_at DESC LIMIT 15').all(user.id);
    const memoryLines = memories.map(m => `• [${m.category.toUpperCase()}] ${m.title}: ${m.content}`).join('\n');

    const systemInstruction = [
        `You are NEXUS, an advanced AI Work Memory workspace assistant.`,
        `Synthesize knowledge across connected sources and permanent team memories to give clear, structured, and insightful answers.`,
        memoryLines ? `PERMANENT WORK MEMORIES & TEAM DECISIONS:\n${memoryLines}` : '',
        workspaceContext ? `CONNECTED WORKSPACE REFERENCE MATERIAL:\n${workspaceContext}` : ''
    ].filter(Boolean).join('\n\n');

    const contents = [{ role: 'user', parts: [{ text: cleanedQuestion }] }];

    try {
        const { text: answer } = await generateGeminiWithFallback(apiKey, contents, systemInstruction);
        sendJson(response, 200, { answer, sources: sourcesUsed, warnings });
    } catch (error) {
        console.error(`Gemini API request failed: ${error.message}`);
        sendJson(response, 502, { error: 'Could not get an answer from Gemini. Check the API key and try again.' });
    }
}

function checkRateLimit(userId) {
    const now = Date.now();
    const requests = (rateLimits.get(userId) || []).filter(timestamp => now - timestamp < 60_000);
    if (requests.length >= 30) return false;
    requests.push(now);
    rateLimits.set(userId, requests);
    return true;
}

function checkAuthRateLimit(request) {
    const ip = request.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const attempts = (authRateLimits.get(ip) || []).filter(timestamp => now - timestamp < 15 * 60_000);
    if (attempts.length >= 10) return false;
    attempts.push(now);
    authRateLimits.set(ip, attempts);
    return true;
}

async function handlePasswordAuth(request, response, action) {
    if (!checkAuthRateLimit(request)) {
        sendJson(response, 429, { error: 'Too many sign-in attempts. Please wait 15 minutes and try again.' });
        return;
    }

    let body;
    try {
        body = await readJson(request, 10 * 1024);
    } catch (error) {
        sendJson(response, error.statusCode || 400, { error: error.message });
        return;
    }

    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const name = typeof body.name === 'string' ? body.name.trim().slice(0, 80) : '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
        sendJson(response, 400, { error: 'Enter a valid email address.' });
        return;
    }
    if (password.length < 10 || password.length > 128) {
        sendJson(response, 400, { error: 'Use a password between 10 and 128 characters.' });
        return;
    }

    if (action === 'register') {
        if (name.length < 2) {
            sendJson(response, 400, { error: 'Enter your name (at least 2 characters).' });
            return;
        }
        const salt = crypto.randomBytes(16).toString('hex');
        const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
        const userId = crypto.randomUUID();
        try {
            database.prepare(`
                INSERT INTO users (id, google_sub, email, name, password_salt, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(userId, `local:${email}`, email, name, salt, passwordHash, Date.now());
        } catch (error) {
            if (error.code === 'ERR_SQLITE_CONSTRAINT_UNIQUE' || /UNIQUE constraint failed/.test(error.message)) {
                sendJson(response, 409, { error: 'An account with this email already exists. Sign in instead.' });
                return;
            }
            throw error;
        }
        createSession(response, request, userId);
        sendJson(response, 201, { authenticated: true, user: { email, name } });
        return;
    }

    const user = database.prepare(`
        SELECT id, email, name, password_salt, password_hash
        FROM users
        WHERE email = ? AND password_salt IS NOT NULL AND password_hash IS NOT NULL
    `).get(email);
    const salt = user?.password_salt || 'nexus-invalid-user-salt';
    const actualHash = await scrypt(password, salt, 64);
    const expectedHash = Buffer.from(user?.password_hash || '0'.repeat(128), 'hex');
    const valid = expectedHash.length === actualHash.length && crypto.timingSafeEqual(actualHash, expectedHash);
    if (!user || !valid) {
        sendJson(response, 401, { error: 'Email or password is incorrect.' });
        return;
    }

    createSession(response, request, user.id);
    sendJson(response, 200, { authenticated: true, user: { email: user.email, name: user.name } });
}

async function handleApi(request, response, url) {
    if (request.method === 'GET' && url.pathname === '/api/health') {
        sendJson(response, 200, {
            ok: true,
            localSignInAvailable: true,
            signInConfigured: Boolean(process.env.GOOGLE_CLIENT_ID?.trim() && process.env.GOOGLE_CLIENT_SECRET?.trim()),
            chatConfigured: Boolean(process.env.GEMINI_API_KEY?.trim()),
            authenticated: Boolean(getUser(request))
        });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/auth/register') {
        await handlePasswordAuth(request, response, 'register');
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/auth/login') {
        await handlePasswordAuth(request, response, 'login');
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/auth/me') {
        const user = getUser(request);
        if (!user) {
            sendJson(response, 401, { authenticated: false });
            return;
        }
        sendJson(response, 200, { authenticated: true, user: { email: user.email, name: user.name } });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
        const token = parseCookies(request).nexus_session;
        if (token) database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(crypto.createHash('sha256').update(token).digest('hex'));
        clearSessionCookie(response, isSecure(request));
        sendJson(response, 200, { ok: true });
        return;
    }

    const user = getUser(request);
    if (!user) {
        sendJson(response, 401, { error: 'Sign in to NEXUS to continue.' });
        return;
    }

    if (!checkRateLimit(user.id)) {
        sendJson(response, 429, { error: 'Too many requests. Please wait a minute and try again.' });
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/sources') {
        const ghStatus = githubAppSetupStatus();
        let ghInstallations = [];
        if (ghStatus.configured) {
            ghInstallations = (await listGithubAppInstallations()).map(i => ({
                id: i.id,
                account: i.account?.login || 'GitHub Account',
                targetType: i.target_type,
                repositorySelection: i.repository_selection
            }));
        }
        sendJson(response, 200, {
            sources: getProviderStatus(user.id),
            providers: {
                github: {
                    ...ghStatus,
                    installations: ghInstallations,
                    installUrl: ghStatus.configured ? `https://github.com/apps/${encodeURIComponent(envValue('GITHUB_APP_SLUG'))}/installations/new` : null
                }
            }
        });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/sources/github/connect') {
        let body = {};
        try { body = await readJson(request); } catch { }
        let installationId = body.installationId;
        if (!installationId) {
            const installations = await listGithubAppInstallations();
            if (installations.length > 0) {
                installationId = installations[0].id;
            }
        }
        if (!installationId) {
            sendJson(response, 400, { error: 'No GitHub App installation found. Install the NEXUS GitHub App on your account first.' });
            return;
        }
        try {
            const details = await verifyAndConnectGithubInstallation(user.id, installationId);
            sendJson(response, 200, { ok: true, connected: true, ...details });
        } catch (err) {
            sendJson(response, 400, { error: `GitHub verification failed: ${err.message}` });
        }
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/documents') {
        const documents = database.prepare('SELECT id, payload, created_at FROM documents WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
        sendJson(response, 200, {
            documents: documents.map(row => {
                const document = decrypt(row.payload);
                return { id: row.id, name: document.name, createdAt: row.created_at };
            })
        });
        return;
    }

    const allowedDocExtensions = new Set([
        '.txt', '.md', '.markdown', '.csv', '.json',
        '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
        '.py', '.html', '.htm', '.css', '.scss',
        '.yaml', '.yml', '.toml', '.xml', '.sql',
        '.sh', '.bash', '.env', '.log', '.rst'
    ]);

    if (request.method === 'POST' && url.pathname === '/api/documents') {
        let body;
        try {
            body = await readJson(request);
        } catch (error) {
            sendJson(response, error.statusCode || 400, { error: error.message });
            return;
        }
        const name = typeof body.name === 'string' ? path.basename(body.name).slice(0, 160) : '';
        const content = body.content;
        const extension = path.extname(name).toLowerCase();
        if (!name || !allowedDocExtensions.has(extension) || typeof content !== 'string' || !content.trim()) {
            sendJson(response, 400, { error: 'Upload a supported text or code file (.txt, .md, .csv, .json, .js, .ts, .py, .html, .css, .yaml, .sql, etc.).' });
            return;
        }
        if (Buffer.byteLength(content, 'utf8') > 2 * 1024 * 1024) {
            sendJson(response, 413, { error: 'Each uploaded file must be 2 MB or smaller.' });
            return;
        }
        const id = crypto.randomUUID();
        database.prepare('INSERT INTO documents (id, user_id, payload, created_at) VALUES (?, ?, ?, ?)').run(
            id, user.id, encrypt({ name, content }), Date.now()
        );
        sendJson(response, 201, { id, name });
        return;
    }

    const documentMatch = url.pathname.match(/^\/api\/documents\/([a-f0-9-]+)$/);
    if (request.method === 'DELETE' && documentMatch) {
        const result = database.prepare('DELETE FROM documents WHERE id = ? AND user_id = ?').run(documentMatch[1], user.id);
        if (!result.changes) {
            sendJson(response, 404, { error: 'File not found.' });
            return;
        }
        sendJson(response, 200, { ok: true });
        return;
    }

    // ===== CONVERSATIONS API =====
    if (url.pathname === '/api/conversations') {
        if (request.method === 'GET') {
            const list = database.prepare('SELECT id, title, created_at, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC').all(user.id);
            sendJson(response, 200, { conversations: list });
            return;
        }
        if (request.method === 'POST') {
            let body = {};
            try { body = await readJson(request); } catch { }
            const title = typeof body.title === 'string' && body.title.trim() ? body.title.trim().slice(0, 80) : 'New Chat';
            const id = crypto.randomUUID();
            const now = Date.now();
            database.prepare('INSERT INTO conversations (id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').run(
                id, user.id, title, now, now
            );
            sendJson(response, 201, { id, title, createdAt: now, updatedAt: now });
            return;
        }
    }

    const convoMatch = url.pathname.match(/^\/api\/conversations\/([a-f0-9-]+)$/);
    if (convoMatch) {
        const convoId = convoMatch[1];
        if (request.method === 'GET') {
            const convo = database.prepare('SELECT id, title, created_at, updated_at FROM conversations WHERE id = ? AND user_id = ?').get(convoId, user.id);
            if (!convo) {
                sendJson(response, 404, { error: 'Conversation not found.' });
                return;
            }
            const rawMessages = database.prepare('SELECT id, role, content, sources, created_at FROM messages WHERE conversation_id = ? ORDER BY created_at ASC').all(convoId);
            const messages = rawMessages.map(m => {
                let parsedSources = [];
                try { if (m.sources) parsedSources = JSON.parse(m.sources); } catch { }
                return {
                    id: m.id,
                    role: m.role,
                    content: m.content,
                    sources: parsedSources,
                    createdAt: m.created_at
                };
            });
            sendJson(response, 200, { conversation: convo, messages });
            return;
        }
        if (request.method === 'PATCH') {
            let body;
            try { body = await readJson(request); } catch (e) { sendJson(response, 400, { error: e.message }); return; }
            const title = typeof body.title === 'string' ? body.title.trim().slice(0, 80) : '';
            if (!title) { sendJson(response, 400, { error: 'Title cannot be empty.' }); return; }
            database.prepare('UPDATE conversations SET title = ?, updated_at = ? WHERE id = ? AND user_id = ?').run(title, Date.now(), convoId, user.id);
            sendJson(response, 200, { ok: true, id: convoId, title });
            return;
        }
        if (request.method === 'DELETE') {
            database.prepare('DELETE FROM conversations WHERE id = ? AND user_id = ?').run(convoId, user.id);
            sendJson(response, 200, { ok: true });
            return;
        }
    }

    // ===== MEMORIES (WORK MEMORY VAULT) API =====
    if (url.pathname === '/api/memories') {
        if (request.method === 'GET') {
            const list = database.prepare('SELECT id, title, content, category, pinned, created_at FROM memories WHERE user_id = ? ORDER BY pinned DESC, created_at DESC').all(user.id);
            sendJson(response, 200, { memories: list });
            return;
        }
        if (request.method === 'POST') {
            let body;
            try { body = await readJson(request); } catch (e) { sendJson(response, 400, { error: e.message }); return; }
            const title = typeof body.title === 'string' ? body.title.trim().slice(0, 160) : '';
            const content = typeof body.content === 'string' ? body.content.trim().slice(0, 4000) : '';
            const validCategories = new Set(['decision', 'rule', 'architecture', 'meeting', 'note', 'general']);
            const category = typeof body.category === 'string' && validCategories.has(body.category) ? body.category : 'decision';
            const pinned = body.pinned ? 1 : 0;
            if (!title || !content) {
                sendJson(response, 400, { error: 'Both title and content are required for a memory item.' });
                return;
            }
            const id = crypto.randomUUID();
            const now = Date.now();
            database.prepare('INSERT INTO memories (id, user_id, title, content, category, pinned, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
                id, user.id, title, content, category, pinned, now
            );
            sendJson(response, 201, { id, title, content, category, pinned, createdAt: now });
            return;
        }
    }

    const memoryMatch = url.pathname.match(/^\/api\/memories\/([a-f0-9-]+)$/);
    if (memoryMatch && request.method === 'DELETE') {
        database.prepare('DELETE FROM memories WHERE id = ? AND user_id = ?').run(memoryMatch[1], user.id);
        sendJson(response, 200, { ok: true });
        return;
    }

    const memoryPinMatch = url.pathname.match(/^\/api\/memories\/([a-f0-9-]+)\/pin$/);
    if (memoryPinMatch && request.method === 'PATCH') {
        const existing = database.prepare('SELECT pinned FROM memories WHERE id = ? AND user_id = ?').get(memoryPinMatch[1], user.id);
        if (!existing) {
            sendJson(response, 404, { error: 'Memory not found.' });
            return;
        }
        const newPinned = existing.pinned ? 0 : 1;
        database.prepare('UPDATE memories SET pinned = ? WHERE id = ? AND user_id = ?').run(newPinned, memoryPinMatch[1], user.id);
        sendJson(response, 200, { ok: true, pinned: newPinned });
        return;
    }

    const disconnectMatch = url.pathname.match(/^\/api\/sources\/(google-drive|github|notion|slack)$/);
    if (request.method === 'DELETE' && disconnectMatch) {
        database.prepare('DELETE FROM integrations WHERE user_id = ? AND provider = ?').run(user.id, disconnectMatch[1]);
        sendJson(response, 200, { ok: true });
        return;
    }

    const itemsMatch = url.pathname.match(/^\/api\/sources\/(google-drive|github|notion|slack)\/items$/);
    if (request.method === 'GET' && itemsMatch) {
        await handleSourceItems(request, response, user, itemsMatch[1]);
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/chat/stream') {
        await handleChatStream(request, response, user);
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/chat') {
        await handleChat(request, response, user);
        return;
    }

    // ===== USER SETTINGS & PREFERENCES API =====
    if (request.method === 'GET' && url.pathname === '/api/settings') {
        const settings = getUserSettings(user.id);
        const convCount = database.prepare('SELECT COUNT(*) as count FROM conversations WHERE user_id = ?').get(user.id)?.count || 0;
        const msgCount = database.prepare('SELECT COUNT(*) as count FROM messages WHERE user_id = ?').get(user.id)?.count || 0;
        const memCount = database.prepare('SELECT COUNT(*) as count FROM memories WHERE user_id = ?').get(user.id)?.count || 0;
        const docCount = database.prepare('SELECT COUNT(*) as count FROM documents WHERE user_id = ?').get(user.id)?.count || 0;
        const integrations = database.prepare('SELECT provider FROM integrations WHERE user_id = ?').all(user.id);

        sendJson(response, 200, {
            settings,
            meta: {
                user: { id: user.id, email: user.email, name: user.name },
                stats: {
                    conversations: convCount,
                    messages: msgCount,
                    memories: memCount,
                    documents: docCount,
                    integrations: integrations.map(i => i.provider)
                },
                encryption: {
                    algorithm: 'AES-256-GCM',
                    status: 'Hardware Accelerated (Active)'
                },
                geminiConfigured: Boolean(process.env.GEMINI_API_KEY?.trim())
            }
        });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/settings') {
        let body;
        try { body = await readJson(request); } catch (e) { sendJson(response, 400, { error: e.message }); return; }
        const incoming = typeof body.settings === 'object' && body.settings !== null ? body.settings : body;
        const updated = saveUserSettings(user.id, incoming);
        sendJson(response, 200, { ok: true, settings: updated });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/settings/profile') {
        let body;
        try { body = await readJson(request); } catch (e) { sendJson(response, 400, { error: e.message }); return; }
        const newName = typeof body.name === 'string' ? body.name.trim() : '';
        const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
        const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';

        if (newName && newName.length >= 2) {
            database.prepare('UPDATE users SET name = ? WHERE id = ?').run(newName, user.id);
            user.name = newName;
        }

        if (newPassword) {
            if (newPassword.length < 10 || newPassword.length > 128) {
                sendJson(response, 400, { error: 'New password must be between 10 and 128 characters.' });
                return;
            }

            const dbUser = database.prepare('SELECT password_salt, password_hash FROM users WHERE id = ?').get(user.id);
            if (!dbUser || !dbUser.password_salt || !dbUser.password_hash) {
                sendJson(response, 400, { error: 'Password cannot be changed for OAuth accounts without local credentials.' });
                return;
            }

            const actualHash = await scrypt(currentPassword, dbUser.password_salt, 64);
            const expectedHash = Buffer.from(dbUser.password_hash, 'hex');
            const valid = expectedHash.length === actualHash.length && crypto.timingSafeEqual(actualHash, expectedHash);
            if (!valid) {
                sendJson(response, 400, { error: 'Current password is incorrect.' });
                return;
            }

            const salt = crypto.randomBytes(16).toString('hex');
            const newHash = (await scrypt(newPassword, salt, 64)).toString('hex');
            database.prepare('UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?').run(salt, newHash, user.id);
        }

        sendJson(response, 200, { ok: true, name: user.name, message: 'Profile updated successfully.' });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/settings/export') {
        const rawConversations = database.prepare('SELECT id, title, created_at, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC').all(user.id);
        const conversations = rawConversations.map(c => {
            const rawMessages = database.prepare('SELECT id, role, content, sources, created_at FROM messages WHERE conversation_id = ? ORDER BY created_at ASC').all(c.id);
            return {
                ...c,
                messages: rawMessages.map(m => {
                    let sources = [];
                    try { if (m.sources) sources = JSON.parse(m.sources); } catch { }
                    return { ...m, sources };
                })
            };
        });

        const memories = database.prepare('SELECT id, title, content, category, pinned, created_at FROM memories WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
        const rawDocs = database.prepare('SELECT id, payload, created_at FROM documents WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
        const documents = rawDocs.map(d => {
            try {
                const dec = decrypt(d.payload);
                return { id: d.id, name: dec.name, sizeBytes: dec.content?.length || 0, createdAt: d.created_at };
            } catch {
                return { id: d.id, name: 'Encrypted Document', createdAt: d.created_at };
            }
        });

        const exportData = {
            exportVersion: '1.0',
            exportedAt: new Date().toISOString(),
            user: { id: user.id, email: user.email, name: user.name },
            settings: getUserSettings(user.id),
            stats: {
                conversationsCount: conversations.length,
                memoriesCount: memories.length,
                documentsCount: documents.length
            },
            conversations,
            memories,
            documents
        };

        sendJson(response, 200, exportData);
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/settings/clear') {
        let body;
        try { body = await readJson(request); } catch (e) { sendJson(response, 400, { error: e.message }); return; }
        const target = body.target;
        if (target === 'chats') {
            database.prepare('DELETE FROM conversations WHERE user_id = ?').run(user.id);
        } else if (target === 'memories') {
            database.prepare('DELETE FROM memories WHERE user_id = ?').run(user.id);
        } else if (target === 'documents') {
            database.prepare('DELETE FROM documents WHERE user_id = ?').run(user.id);
        } else if (target === 'all') {
            database.prepare('DELETE FROM conversations WHERE user_id = ?').run(user.id);
            database.prepare('DELETE FROM memories WHERE user_id = ?').run(user.id);
            database.prepare('DELETE FROM documents WHERE user_id = ?').run(user.id);
        } else {
            sendJson(response, 400, { error: 'Invalid clear target. Choose chats, memories, documents, or all.' });
            return;
        }
        sendJson(response, 200, { ok: true, cleared: target });
        return;
    }

    sendJson(response, 404, { error: 'API endpoint not found.' });
}

async function handleRequest(request, response) {
    const url = new URL(request.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
        if (request.headers.origin && verifyOrigin(request)) {
            response.setHeader('Access-Control-Allow-Origin', request.headers.origin);
            response.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        if (request.method === 'OPTIONS') {
            if (verifyOrigin(request)) {
                response.writeHead(204, {
                    'Access-Control-Allow-Origin': request.headers.origin || '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                    'Access-Control-Allow-Credentials': 'true',
                    'Access-Control-Max-Age': '86400'
                });
                response.end();
                return;
            }
            sendJson(response, 403, { error: 'Request origin could not be verified.' });
            return;
        }
        if (['POST', 'DELETE', 'PUT', 'PATCH'].includes(request.method) && !verifyOrigin(request)) {
            sendJson(response, 403, { error: 'Request origin could not be verified.' });
            return;
        }
        await handleApi(request, response, url);
        return;
    }

    if (request.method === 'GET' && url.pathname === '/auth/login/google') {
        try {
            await beginOAuth(request, response, 'google', 'login');
        } catch (error) {
            sendText(response, 503, htmlError(error.message));
        }
        return;
    }

    const connectMatch = url.pathname.match(/^\/auth\/connect\/(google|github|notion|slack)$/);
    if (request.method === 'GET' && connectMatch) {
        const provider = connectMatch[1] === 'google' ? 'google' : connectMatch[1];
        try {
            await beginOAuth(request, response, provider, 'connect');
        } catch (error) {
            sendText(response, 503, htmlError(error.message, 'connect.html'));
        }
        return;
    }

    const callbackMatch = url.pathname.match(/^\/auth\/callback\/(google|github|notion|slack)$/);
    if (request.method === 'GET' && callbackMatch) {
        await completeOAuth(request, response, callbackMatch[1], url);
        return;
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
        response.writeHead(405, { Allow: 'GET, HEAD' });
        response.end('Method not allowed');
        return;
    }

    let page;
    try {
        const routes = {
            '/': 'intro.html',
            '/start': 'intro.html',
            '/login': 'home.html',
            '/app': 'dashboard.html',
            '/settings': 'settings.html'
        };
        page = routes[url.pathname] || decodeURIComponent(url.pathname.slice(1));
    } catch {
        page = '';
    }
    if (!allowedPages.has(page)) {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        response.end('Not found');
        return;
    }

    fs.readFile(path.join(projectDirectory, page), (error, content) => {
        if (error) {
            response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            response.end('Page not found');
            return;
        }
        let contentType = 'text/html; charset=utf-8';
        if (page.endsWith('.md')) contentType = 'text/markdown; charset=utf-8';
        else if (page.endsWith('.js')) contentType = 'application/javascript; charset=utf-8';
        else if (page.endsWith('.css')) contentType = 'text/css; charset=utf-8';
        else if (page.endsWith('.svg')) contentType = 'image/svg+xml';
        response.writeHead(200, {
            'Content-Type': contentType,
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': 'no-cache'
        });
        response.end(request.method === 'HEAD' ? undefined : content);
    });
}

const server = http.createServer((request, response) => {
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    handleRequest(request, response).catch(error => {
        console.error(`Request failed: ${error.message}`);
        if (!response.headersSent) sendJson(response, 500, { error: 'The request could not be completed.' });
        else response.end();
    });
});

server.listen(port, host, () => {
    console.log(`NEXUS is running at http://127.0.0.1:${port}`);
});

server.on('error', error => {
    if (error.code === 'EADDRINUSE') {
        console.error(`Port ${port} is already in use. NEXUS may already be running at http://127.0.0.1:${port}.`);
        console.error(`Open that address instead of starting a second server, or stop the existing server before running npm start again.`);
        process.exitCode = 1;
        return;
    }
    console.error(`NEXUS could not start: ${error.message}`);
    process.exitCode = 1;
});
