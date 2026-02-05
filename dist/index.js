import * as jose from 'jose';
// ─── Cookie Domain Helper ─────────────────────────────────────────────────
/**
 * Derive cookie domain from hostname if not explicitly configured.
 * - Production: *.tony.codes → .tony.codes (shared SSO)
 * - Local: myapp.test → .myapp.test (isolated per app)
 * - Subdomains: api.myapp.test → .myapp.test
 */
function deriveCookieDomain(hostname) {
    // Production: use shared .tony.codes domain
    if (hostname.endsWith('.tony.codes') || hostname === 'tony.codes') {
        return '.tony.codes';
    }
    // Local .test domains: derive app-specific domain
    if (hostname.endsWith('.test')) {
        const parts = hostname.split('.');
        // myapp.test → .myapp.test
        // api.myapp.test → .myapp.test
        if (parts.length >= 2) {
            // Get the last two parts before .test (or just the app name)
            const appPart = parts.length === 2 ? parts[0] : parts[parts.length - 2];
            return `.${appPart}.test`;
        }
    }
    // Unknown domain structure — don't set domain (browser default)
    return undefined;
}
// ─── JWKS Cache ──────────────────────────────────────────────────────────
let jwksCache = null;
let jwksCacheExpiry = 0;
const JWKS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
async function getJWKS(authUrl) {
    const now = Date.now();
    if (jwksCache && now < jwksCacheExpiry) {
        return jwksCache;
    }
    const res = await fetch(`${authUrl}/.well-known/jwks.json`);
    if (!res.ok) {
        throw new Error(`Failed to fetch JWKS: ${res.status}`);
    }
    jwksCache = (await res.json());
    jwksCacheExpiry = now + JWKS_CACHE_TTL;
    return jwksCache;
}
async function verifyToken(token, authUrl) {
    const jwks = await getJWKS(authUrl);
    const JWKS = jose.createLocalJWKSet(jwks);
    const { payload } = await jose.jwtVerify(token, JWKS, {
        issuer: 'auth.tony.codes',
        audience: 'tony.codes',
    });
    return payload;
}
// ─── Middleware Factory ──────────────────────────────────────────────────
export function createAuthMiddleware(config) {
    const { authUrl, clientId, clientSecret, cookieDomain: configuredDomain, appUrl } = config;
    /**
     * Get the effective cookie domain for a request.
     * Uses configured domain if provided, otherwise derives from hostname.
     */
    function getCookieDomain(req) {
        if (configuredDomain)
            return configuredDomain;
        const hostname = req.get('host')?.split(':')[0]; // Remove port if present
        return hostname ? deriveCookieDomain(hostname) : undefined;
    }
    /**
     * Base middleware — verifies JWT if present, attaches req.auth
     * Does NOT reject unauthenticated requests
     */
    function middleware() {
        return async (req, _res, next) => {
            const authHeader = req.headers.authorization;
            if (!authHeader?.startsWith('Bearer ')) {
                return next();
            }
            const token = authHeader.substring(7);
            try {
                const payload = await verifyToken(token, authUrl);
                const org = payload.org;
                req.auth = {
                    userId: payload.sub,
                    email: payload.email,
                    name: payload.name || null,
                    avatarUrl: payload.avatarUrl || null,
                    orgId: org?.id || null,
                    orgName: org?.name || null,
                    orgSlug: org?.slug || null,
                    orgRole: org?.role || null,
                    isSuperAdmin: payload.isSuperAdmin || false,
                };
            }
            catch {
                // Invalid token — continue without auth
            }
            next();
        };
    }
    /**
     * Require authenticated user with active organization
     * Super admins can use X-Org-Id header to access any org
     */
    function requireOrg() {
        return async (req, res, next) => {
            if (!req.auth) {
                res.status(401).json({ error: 'Unauthorized' });
                return;
            }
            // Super admins can override org via header
            const headerOrgId = req.headers['x-org-id'];
            if (req.auth.isSuperAdmin && headerOrgId) {
                req.auth.orgId = headerOrgId;
                req.auth.orgRole = 'admin';
                return next();
            }
            if (!req.auth.orgId) {
                res.status(403).json({ error: 'No organization selected' });
                return;
            }
            next();
        };
    }
    /**
     * Require super admin access
     */
    function requireSuperAdmin() {
        return (req, res, next) => {
            if (!req.auth) {
                res.status(401).json({ error: 'Unauthorized' });
                return;
            }
            if (!req.auth.isSuperAdmin) {
                res.status(403).json({ error: 'Super admin access required' });
                return;
            }
            // Super admins can set org via header
            const headerOrgId = req.headers['x-org-id'];
            if (headerOrgId) {
                req.auth.orgId = headerOrgId;
                req.auth.orgRole = 'admin';
            }
            next();
        };
    }
    /**
     * Require specific organization role
     */
    function requireOrgRole(...roles) {
        return (req, res, next) => {
            if (req.auth?.isSuperAdmin)
                return next();
            if (req.apiKey)
                return next(); // API key auth uses scopes, not roles
            if (!req.auth?.orgRole || !roles.includes(req.auth.orgRole)) {
                res.status(403).json({ error: `Requires role: ${roles.join(' or ')}` });
                return;
            }
            next();
        };
    }
    /**
     * Require specific API key scopes (session auth passes automatically)
     */
    function requireScope(...scopes) {
        return (req, res, next) => {
            if (!req.apiKey)
                return next(); // Session auth has all scopes
            const hasScope = scopes.some((s) => req.apiKey.scopes.includes(s));
            if (!hasScope) {
                res.status(403).json({ error: `Requires scope: ${scopes.join(' or ')}` });
                return;
            }
            next();
        };
    }
    /**
     * Handle auth callback — exchanges authorization code for tokens
     * Mount at GET /auth/callback
     */
    function callbackHandler() {
        return async (req, res) => {
            const { code, state } = req.query;
            if (!code || typeof code !== 'string') {
                res.status(400).json({ error: 'Missing authorization code' });
                return;
            }
            try {
                const redirectUri = appUrl
                    ? `${appUrl}/auth/callback`
                    : `${req.protocol}://${req.get('host')}/auth/callback`;
                const tokenRes = await fetch(`${authUrl}/api/token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        code,
                        client_id: clientId,
                        client_secret: clientSecret,
                        redirect_uri: redirectUri,
                    }),
                });
                if (!tokenRes.ok) {
                    const err = (await tokenRes.json());
                    res.status(401).json({ error: err.error || 'Token exchange failed' });
                    return;
                }
                const tokens = (await tokenRes.json());
                // Set refresh token as httpOnly cookie on the derived/configured domain
                if (tokens.refresh_token) {
                    res.cookie('refresh_token', tokens.refresh_token, {
                        httpOnly: true,
                        secure: true,
                        sameSite: 'lax',
                        domain: getCookieDomain(req),
                        maxAge: 30 * 24 * 60 * 60 * 1000,
                        path: '/',
                    });
                }
                res.json({
                    access_token: tokens.access_token,
                    expires_in: tokens.expires_in,
                });
            }
            catch (err) {
                res.status(500).json({ error: 'Token exchange failed' });
            }
        };
    }
    /**
     * Proxy refresh token requests to the auth service
     * Mount at POST /auth/refresh
     */
    function refreshProxy() {
        return async (req, res) => {
            try {
                const tokenRes = await fetch(`${authUrl}/api/token`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        Cookie: req.headers.cookie || '',
                    },
                    body: JSON.stringify({ grant_type: 'refresh_token' }),
                });
                if (!tokenRes.ok) {
                    res.status(tokenRes.status).json(await tokenRes.json());
                    return;
                }
                const tokens = (await tokenRes.json());
                // Set rotated refresh token cookie
                if (tokens.refresh_token) {
                    res.cookie('refresh_token', tokens.refresh_token, {
                        httpOnly: true,
                        secure: true,
                        sameSite: 'lax',
                        domain: getCookieDomain(req),
                        maxAge: 30 * 24 * 60 * 60 * 1000,
                        path: '/',
                    });
                }
                res.json({
                    access_token: tokens.access_token,
                    expires_in: tokens.expires_in,
                });
            }
            catch {
                res.status(500).json({ error: 'Refresh failed' });
            }
        };
    }
    /**
     * Proxy org switch requests to the auth service
     * Mount at POST /auth/switch-org
     */
    function switchOrgProxy() {
        return async (req, res) => {
            const { org_id } = req.body;
            try {
                const tokenRes = await fetch(`${authUrl}/api/token`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        Cookie: req.headers.cookie || '',
                    },
                    body: JSON.stringify({ grant_type: 'switch_organization', org_id }),
                });
                if (!tokenRes.ok) {
                    res.status(tokenRes.status).json(await tokenRes.json());
                    return;
                }
                const tokens = (await tokenRes.json());
                // Set rotated refresh token cookie
                if (tokens.refresh_token) {
                    res.cookie('refresh_token', tokens.refresh_token, {
                        httpOnly: true,
                        secure: true,
                        sameSite: 'lax',
                        domain: getCookieDomain(req),
                        maxAge: 30 * 24 * 60 * 60 * 1000,
                        path: '/',
                    });
                }
                res.json({
                    access_token: tokens.access_token,
                    expires_in: tokens.expires_in,
                });
            }
            catch {
                res.status(500).json({ error: 'Organization switch failed' });
            }
        };
    }
    /**
     * Proxy logout requests to the auth service
     * Mount at POST /auth/logout
     */
    function logoutProxy() {
        return async (req, res) => {
            try {
                await fetch(`${authUrl}/api/logout`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        Cookie: req.headers.cookie || '',
                    },
                });
                // Clear refresh token cookie
                res.clearCookie('refresh_token', {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'lax',
                    domain: getCookieDomain(req),
                    path: '/',
                });
                res.json({ ok: true });
            }
            catch {
                res.status(500).json({ error: 'Logout failed' });
            }
        };
    }
    return {
        middleware,
        requireOrg,
        requireSuperAdmin,
        requireOrgRole,
        requireScope,
        callbackHandler,
        refreshProxy,
        switchOrgProxy,
        logoutProxy,
        config: { authUrl, clientId },
    };
}
//# sourceMappingURL=index.js.map