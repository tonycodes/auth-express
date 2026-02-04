import type { Request, Response, NextFunction, RequestHandler } from 'express';
import * as jose from 'jose';

// ─── Types ───────────────────────────────────────────────────────────────

export interface AuthConfig {
  /** Auth service URL (e.g., https://auth.tony.codes) */
  authUrl: string;
  /** Client ID for this app (e.g., "rag-platform") */
  clientId: string;
  /** Client secret for token exchange */
  clientSecret: string;
  /** Cookie domain for refresh tokens (e.g., ".tony.codes") */
  cookieDomain?: string;
  /** Frontend app URL — required when API and frontend are on different hosts (e.g., api.autopilot.test vs autopilot.test) */
  appUrl?: string;
}

export interface AuthUser {
  userId: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
  orgId: string | null;
  orgName: string | null;
  orgSlug: string | null;
  orgRole: string | null;
  isSuperAdmin: boolean;
}

// Extend Express Request
declare global {
  namespace Express {
    interface Request {
      auth?: AuthUser;
      apiKey?: {
        id: string;
        name: string;
        scopes: string[];
      };
    }
  }
}

// ─── JWKS Cache ──────────────────────────────────────────────────────────

let jwksCache: jose.JSONWebKeySet | null = null;
let jwksCacheExpiry = 0;
const JWKS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

async function getJWKS(authUrl: string): Promise<jose.JSONWebKeySet> {
  const now = Date.now();
  if (jwksCache && now < jwksCacheExpiry) {
    return jwksCache;
  }

  const res = await fetch(`${authUrl}/.well-known/jwks.json`);
  if (!res.ok) {
    throw new Error(`Failed to fetch JWKS: ${res.status}`);
  }

  jwksCache = (await res.json()) as jose.JSONWebKeySet;
  jwksCacheExpiry = now + JWKS_CACHE_TTL;
  return jwksCache;
}

async function verifyToken(token: string, authUrl: string): Promise<jose.JWTPayload> {
  const jwks = await getJWKS(authUrl);
  const JWKS = jose.createLocalJWKSet(jwks);
  const { payload } = await jose.jwtVerify(token, JWKS, {
    issuer: 'auth.tony.codes',
    audience: 'tony.codes',
  });
  return payload;
}

// ─── Middleware Factory ──────────────────────────────────────────────────

export function createAuthMiddleware(config: AuthConfig) {
  const { authUrl, clientId, clientSecret, cookieDomain, appUrl } = config;

  /**
   * Base middleware — verifies JWT if present, attaches req.auth
   * Does NOT reject unauthenticated requests
   */
  function middleware(): RequestHandler {
    return async (req: Request, _res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return next();
      }

      const token = authHeader.substring(7);
      try {
        const payload = await verifyToken(token, authUrl);
        const org = payload.org as { id: string; name: string; slug: string; role: string } | null;

        req.auth = {
          userId: payload.sub!,
          email: payload.email as string,
          name: (payload.name as string) || null,
          avatarUrl: (payload.avatarUrl as string) || null,
          orgId: org?.id || null,
          orgName: org?.name || null,
          orgSlug: org?.slug || null,
          orgRole: org?.role || null,
          isSuperAdmin: (payload.isSuperAdmin as boolean) || false,
        };
      } catch {
        // Invalid token — continue without auth
      }
      next();
    };
  }

  /**
   * Require authenticated user with active organization
   * Super admins can use X-Org-Id header to access any org
   */
  function requireOrg(): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
      if (!req.auth) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      // Super admins can override org via header
      const headerOrgId = req.headers['x-org-id'] as string | undefined;
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
  function requireSuperAdmin(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!req.auth) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      if (!req.auth.isSuperAdmin) {
        res.status(403).json({ error: 'Super admin access required' });
        return;
      }

      // Super admins can set org via header
      const headerOrgId = req.headers['x-org-id'] as string | undefined;
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
  function requireOrgRole(...roles: string[]): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
      if (req.auth?.isSuperAdmin) return next();
      if (req.apiKey) return next(); // API key auth uses scopes, not roles

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
  function requireScope(...scopes: string[]): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!req.apiKey) return next(); // Session auth has all scopes

      const hasScope = scopes.some((s) => req.apiKey!.scopes.includes(s));
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
  function callbackHandler(): RequestHandler {
    return async (req: Request, res: Response) => {
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
          const err = (await tokenRes.json()) as { error: string };
          res.status(401).json({ error: err.error || 'Token exchange failed' });
          return;
        }

        const tokens = (await tokenRes.json()) as {
          access_token: string;
          token_type: string;
          expires_in: number;
        };

        res.json({
          access_token: tokens.access_token,
          expires_in: tokens.expires_in,
        });
      } catch (err) {
        res.status(500).json({ error: 'Token exchange failed' });
      }
    };
  }

  /**
   * Proxy refresh token requests to the auth service
   * Mount at POST /auth/refresh
   */
  function refreshProxy(): RequestHandler {
    return async (req: Request, res: Response) => {
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

        // Forward Set-Cookie headers from auth service
        const setCookies = tokenRes.headers.getSetCookie?.() || [];
        for (const cookie of setCookies) {
          res.append('Set-Cookie', cookie);
        }

        const tokens = (await tokenRes.json()) as {
          access_token: string;
          expires_in: number;
        };

        res.json({
          access_token: tokens.access_token,
          expires_in: tokens.expires_in,
        });
      } catch {
        res.status(500).json({ error: 'Refresh failed' });
      }
    };
  }

  /**
   * Proxy org switch requests to the auth service
   * Mount at POST /auth/switch-org
   */
  function switchOrgProxy(): RequestHandler {
    return async (req: Request, res: Response) => {
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

        // Forward Set-Cookie headers
        const setCookies = tokenRes.headers.getSetCookie?.() || [];
        for (const cookie of setCookies) {
          res.append('Set-Cookie', cookie);
        }

        res.json(await tokenRes.json());
      } catch {
        res.status(500).json({ error: 'Organization switch failed' });
      }
    };
  }

  /**
   * Proxy logout requests to the auth service
   * Mount at POST /auth/logout
   */
  function logoutProxy(): RequestHandler {
    return async (req: Request, res: Response) => {
      try {
        const logoutRes = await fetch(`${authUrl}/api/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: req.headers.cookie || '',
          },
        });

        // Forward Set-Cookie headers (clears cookie)
        const setCookies = logoutRes.headers.getSetCookie?.() || [];
        for (const cookie of setCookies) {
          res.append('Set-Cookie', cookie);
        }

        res.json({ ok: true });
      } catch {
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
