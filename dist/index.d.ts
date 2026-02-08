import { Router } from 'express';
import type { RequestHandler } from 'express';
export interface AuthConfig {
    /** Client ID for this app (e.g., "rag-platform") */
    clientId: string;
    /** Client secret for token exchange (plaintext, NOT the hash) */
    clientSecret: string;
    /** Auth service URL. Defaults to https://auth.tony.codes */
    authUrl?: string;
    /**
     * Cookie domain for refresh tokens.
     * If not specified, auto-derived from request hostname:
     * - *.tony.codes → .tony.codes (shared SSO)
     * - myapp.test → .myapp.test
     * - api.myapp.test → .myapp.test
     */
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
export declare function createAuthMiddleware(config: AuthConfig): {
    middleware: () => RequestHandler;
    requireOrg: () => RequestHandler;
    requireSuperAdmin: () => RequestHandler;
    requireOrgRole: (...roles: string[]) => RequestHandler;
    requireScope: (...scopes: string[]) => RequestHandler;
    callbackHandler: () => RequestHandler;
    refreshProxy: () => RequestHandler;
    switchOrgProxy: () => RequestHandler;
    logoutProxy: () => RequestHandler;
    routes: () => Router;
    config: {
        authUrl: string;
        clientId: string;
    };
};
interface CallbackPageConfig {
    /** Client ID for token exchange */
    clientId: string;
    /** Client secret for token exchange */
    clientSecret: string;
    /** Auth service URL. Defaults to https://auth.tony.codes */
    authUrl?: string;
}
/**
 * Standalone callback handler for hosted login page mode.
 * Exchanges the authorization code for tokens, sets cookies, and redirects.
 *
 * Use this when you don't need the full SDK — just redirect to /authorize
 * and mount this single route:
 *
 *   app.get('/auth/callback', createCallbackPage({
 *     clientId: 'my-app',
 *     clientSecret: process.env.AUTH_SECRET!,
 *   }));
 */
export declare function createCallbackPage(config: CallbackPageConfig): RequestHandler;
export {};
//# sourceMappingURL=index.d.ts.map