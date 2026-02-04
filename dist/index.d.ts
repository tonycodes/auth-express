import type { RequestHandler } from 'express';
export interface AuthConfig {
    /** Auth service URL (e.g., https://auth.tony.codes) */
    authUrl: string;
    /** Client ID for this app (e.g., "rag-platform") */
    clientId: string;
    /** Client secret for token exchange */
    clientSecret: string;
    /** Cookie domain for refresh tokens (e.g., ".tony.codes") */
    cookieDomain?: string;
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
    config: {
        authUrl: string;
        clientId: string;
    };
};
//# sourceMappingURL=index.d.ts.map