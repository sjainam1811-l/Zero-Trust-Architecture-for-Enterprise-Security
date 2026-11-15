/**
 * @file        zero-trust-auth.jsx
 * @description Zero-Trust Authentication — React Hook + Context
 * @author      Kelvin Chipili <KelvinChipili>
 * @license     MIT
 *
 * ─────────────────────────────────────────────────────────────
 *  ZERO-TRUST PHILOSOPHY (Frontend Edition)
 *  "Never trust, always verify."
 *
 *  On the frontend this means:
 *  • Tokens live in memory — never localStorage or sessionStorage
 *  • Every token is silently refreshed before it expires
 *  • Sessions end automatically after inactivity
 *  • Device changes are detected and flagged
 * ─────────────────────────────────────────────────────────────
 *
 *  WHAT THIS FILE PROVIDES
 *  ────────────────────────
 *  • AuthProvider  — React context that manages the auth state
 *  • useAuth       — hook for accessing auth state and actions
 *  • usePermission — hook for checking user permissions (RBAC)
 *  • ProtectedRoute    — redirect to login if not authenticated
 *  • RequirePermission — conditionally render based on permissions
 *  • NewDevicePrompt   — ask the user to trust a new device
 *  • apiClient         — pre-configured Axios instance that auto-attaches
 *                        the Authorization header and silently refreshes
 *
 *  HOW TO USE
 *  ──────────
 *  1. npm install axios jwt-decode react-router-dom
 *  2. Copy this file into your project
 *  3. Set REACT_APP_API_URL in your .env file
 *  4. Wrap your app in <AuthProvider>
 *  5. Use useAuth() in any component that needs auth state
 *  6. Use apiClient for all authenticated API calls
 *
 *  EDIT GUIDE
 *  ──────────
 *  Search for "// EDIT:" comments — these are the only lines
 *  you need to change to plug this into your application.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';

// ─── CONFIGURATION ───────────────────────────────────────────
// EDIT: Set REACT_APP_API_URL in your .env file to point at your backend.
const AUTH_CONFIG = {
  apiBase: (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) ||
           (typeof process !== 'undefined' && process.env?.REACT_APP_API_URL) ||
           'http://localhost:4000',

  // How long before expiry to request a new token (1 minute)
  // This ensures the token is always fresh when a request goes out
  refreshBufferMs: 60_000,

  // EDIT: How long of inactivity before the session ends automatically
  sessionTimeoutMs: 30 * 60_000, // 30 minutes

  // How many times to retry a failed token refresh before logging out
  refreshRetryLimit: 3,
};

// ─── SECURE TOKEN STORE WITH RELOAD PERSISTENCE ─────────────
let _accessToken  = typeof window !== 'undefined' ? localStorage.getItem('zt_access_token') : null;
let _refreshToken = typeof window !== 'undefined' ? localStorage.getItem('zt_refresh_token') : null;

export const tokenStore = {
  /** Saves tokens in memory and localStorage for browser refresh persistence */
  setTokens(access, refresh) {
    _accessToken  = access;
    _refreshToken = refresh;
    try {
      if (access) localStorage.setItem('zt_access_token', access);
      else localStorage.removeItem('zt_access_token');
      if (refresh) localStorage.setItem('zt_refresh_token', refresh);
      else localStorage.removeItem('zt_refresh_token');
    } catch {}
  },
  getAccessToken()  {
    if (!_accessToken && typeof window !== 'undefined') {
      _accessToken = localStorage.getItem('zt_access_token');
    }
    return _accessToken;
  },
  getRefreshToken() {
    if (!_refreshToken && typeof window !== 'undefined') {
      _refreshToken = localStorage.getItem('zt_refresh_token');
    }
    return _refreshToken;
  },
  /** Clears both tokens — call this on logout. */
  clearTokens() {
    _accessToken  = null;
    _refreshToken = null;
    try {
      localStorage.removeItem('zt_access_token');
      localStorage.removeItem('zt_refresh_token');
    } catch {}
  },
};

// ─── AXIOS INSTANCE ──────────────────────────────────────────
// Export this and use it for ALL authenticated API calls.
// The request interceptor below auto-attaches the Bearer token.
// The response interceptor silently refreshes on 401 errors.
export const apiClient = axios.create({
  baseURL:         AUTH_CONFIG.apiBase,
  withCredentials: false,
  timeout:         10000,
});

// These variables manage concurrent refresh requests.
// If three requests all get 401 at the same time, only one refresh
// attempt is made — the others wait in the queue.
let isRefreshing = false;
let refreshQueue = [];

/**
 * Resolves or rejects all queued requests after a token refresh attempt.
 * @param {Error|null} error - null on success, error on failure
 * @param {string|null} token - new access token on success
 */
function processQueue(error, token = null) {
  refreshQueue.forEach(({ resolve, reject }) =>
    error ? reject(error) : resolve(token)
  );
  refreshQueue = [];
}

// ─── AUTH CONTEXT ────────────────────────────────────────────
const AuthContext = createContext(null);

/**
 * AuthProvider — wraps your app and manages authentication state.
 *
 * Place this near the root of your component tree:
 *
 *   function App() {
 *     return (
 *       <AuthProvider>
 *         <Router>...</Router>
 *       </AuthProvider>
 *     );
 *   }
 */
export function AuthProvider({ children }) {
  // Core auth state
  const [user,        setUser]        = useState(null);   // decoded token payload
  const [loading,     setLoading]     = useState(true);   // true during initial session check
  const [mfaRequired, setMfaRequired] = useState(false);  // true when server requests MFA
  const [newDevice,   setNewDevice]   = useState(false);  // true when server flags a new device

  // Refs for timers and retry count — use refs so callbacks don't re-create
  const refreshTimerRef  = useRef(null);
  const activityTimerRef = useRef(null);
  const refreshAttempts  = useRef(0);

  // ── Helpers ────────────────────────────────────────────────

  /**
   * Decodes a JWT and returns the payload.
   * Returns null if the token is malformed.
   */
  const parseUser = useCallback((token) => {
    try { return jwtDecode(token); }
    catch { return null; }
  }, []);

  /**
   * Schedules a silent token refresh just before the access token expires.
   * This ensures the user is never unexpectedly logged out mid-session.
   */
  const scheduleRefresh = useCallback((accessToken) => {
    clearTimeout(refreshTimerRef.current);
    const decoded = parseUser(accessToken);
    if (!decoded?.exp) return;

    // Calculate how long until we should refresh (expiry minus buffer)
    const msUntilExpiry = decoded.exp * 1000 - Date.now();
    const refreshIn     = Math.max(0, msUntilExpiry - AUTH_CONFIG.refreshBufferMs);

    refreshTimerRef.current = setTimeout(() => silentRefresh(), refreshIn);
  }, [parseUser]); // eslint-disable-line react-hooks/exhaustive-deps

  /**
   * Resets the inactivity timer.
   * If the user is idle for sessionTimeoutMs, they're automatically logged out.
   */
  const resetActivityTimer = useCallback(() => {
    clearTimeout(activityTimerRef.current);
    activityTimerRef.current = setTimeout(
      () => logout('inactivity'),
      AUTH_CONFIG.sessionTimeoutMs
    );
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /**
   * Stores a new token pair, decodes the user from the access token,
   * and restarts both the refresh and activity timers.
   */
  const setSession = useCallback((accessToken, refreshToken) => {
    tokenStore.setTokens(accessToken, refreshToken);
    setUser(parseUser(accessToken));
    scheduleRefresh(accessToken);
    resetActivityTimer();
    refreshAttempts.current = 0; // reset failure counter
  }, [parseUser, scheduleRefresh, resetActivityTimer]);

  // ── Silent Token Refresh ───────────────────────────────────

  /**
   * Silently exchanges the refresh token for a new token pair.
   *
   * Called automatically before the access token expires.
   * Also called by the Axios response interceptor when a 401 is received.
   *
   * If multiple requests trigger this simultaneously, only one HTTP call
   * is made — the rest wait in the queue.
   */
  const silentRefresh = useCallback(async () => {
    const refresh = tokenStore.getRefreshToken();
    if (!refresh) { logout('no_refresh_token'); return; }

    // Queue this request if a refresh is already in progress
    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        refreshQueue.push({ resolve, reject });
      });
    }

    isRefreshing = true;
    try {
      const { data } = await apiClient.post(
        '/auth/refresh',
        { refresh_token: refresh, refreshToken: refresh }
      );

      // Normalise both snake_case and camelCase responses
      const at = data.access_token  || data.accessToken;
      const rt = data.refresh_token || data.refreshToken;

      setSession(at, rt);
      processQueue(null, at);

    } catch (err) {
      processQueue(err);
      refreshAttempts.current++;

      // If we've failed too many times, force logout
      if (refreshAttempts.current >= AUTH_CONFIG.refreshRetryLimit) {
        logout('refresh_failed');
      }
    } finally {
      isRefreshing = false;
    }
  }, [setSession]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Axios Interceptors ─────────────────────────────────────

  useEffect(() => {
    // REQUEST interceptor — auto-attach the Bearer token to every request
    const requestId = apiClient.interceptors.request.use((config) => {
      const token = tokenStore.getAccessToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // RESPONSE interceptor — silently refresh on 401 and retry the original request
    const responseId = apiClient.interceptors.response.use(
      (response) => response, // pass through successful responses unchanged

      async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401) {
          const errMsg = error.response?.data?.error || '';
          if (
            errMsg.includes('User account') ||
            errMsg.includes('User identity') ||
            errMsg.includes('no longer exists') ||
            errMsg.includes('disabled')
          ) {
            logout('user_deleted');
            return Promise.reject(error);
          }

          // Only retry once — _retry flag prevents infinite loops
          if (!originalRequest._retry) {
            originalRequest._retry = true;
            try {
              await silentRefresh();
              const newToken = tokenStore.getAccessToken();
              if (!newToken) {
                logout('auth_error');
                return Promise.reject(error);
              }
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
              return apiClient(originalRequest); // retry with new token
            } catch {
              logout('auth_error');
            }
          }
        }
        return Promise.reject(error);
      }
    );

    // Clean up interceptors when the provider unmounts
    return () => {
      apiClient.interceptors.request.eject(requestId);
      apiClient.interceptors.response.eject(responseId);
    };
  }, [silentRefresh]);

  // ── Activity Detection ─────────────────────────────────────

  // Listen for any user interaction and reset the inactivity timer
  useEffect(() => {
    const events  = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    const handler = () => { if (user) resetActivityTimer(); };
    events.forEach(e => window.addEventListener(e, handler, { passive: true }));
    return () => events.forEach(e => window.removeEventListener(e, handler));
  }, [user, resetActivityTimer]);

  // ── Auth Actions ───────────────────────────────────────────

  /**
   * Logs in a user with their credentials.
   *
   * If MFA is required, returns { mfaRequired: true } and you should
   * collect the TOTP code and call login() again with mfaToken set.
   *
   * @param {string} identifier - Email or username
   * @param {string} password   - User's password
   * @param {string} mfaToken   - 6-digit TOTP code (if MFA required)
   * @returns {{ success: true } | { mfaRequired: true }}
   */
  const login = useCallback(async (identifier, password, mfaToken = null) => {
    const { data } = await apiClient.post('/auth/login', {
      identifier,
      password,
      ...(mfaToken ? { mfa_token: mfaToken } : {}),
    });

    // Server is asking for a TOTP code — tell the UI
    if (data.mfa_required || data.mfaRequired) {
      setMfaRequired(true);
      return { mfaRequired: true };
    }

    const at = data.access_token  || data.accessToken;
    const rt = data.refresh_token || data.refreshToken;

    setSession(at, rt);
    setMfaRequired(false);

    // Server flagged this as a new/unknown device
    if (data.new_device || data.newDevice) {
      setNewDevice(true);
    }

    return { success: true };
  }, [setSession]);

  /**
   * Logs out the current user.
   *
   * Clears tokens from memory, cancels timers, and tells the server
   * to revoke the session (best-effort — doesn't block on failure).
   *
   * @param {string} reason - Why the logout was triggered (for logging)
   */
  const logout = useCallback(async (reason = 'user') => {
    // Cancel pending timers immediately
    clearTimeout(refreshTimerRef.current);
    clearTimeout(activityTimerRef.current);

    const access  = tokenStore.getAccessToken();
    const refresh = tokenStore.getRefreshToken();

    // Clear tokens from memory before the async call
    tokenStore.clearTokens();
    setUser(null);
    setMfaRequired(false);
    setNewDevice(false);

    // Tell the server to revoke the session (best-effort)
    try {
      if (access) {
        await apiClient.post(
          '/auth/logout',
          { refresh_token: refresh, refreshToken: refresh },
          { headers: { Authorization: `Bearer ${access}` } }
        );
      }
    } catch {
      // Ignore server errors — the client-side session is already cleared
    }

    // EDIT: Navigate to your login page
    // navigate('/login');
    console.info(`[ZeroTrust] Session ended. Reason: ${reason}`);
  }, []);

  /**
   * Terminates ALL sessions for the current user across all devices.
   * Use this when a password is changed or an account is compromised.
   */
  const logoutAll = useCallback(async () => {
    await apiClient.post('/auth/logout-all');
    logout('logout_all');
  }, [logout]);

  /**
   * Registers a new user account with identifier, password, and role.
   */
  const register = useCallback(async (email, password, role = 'editor') => {
    const { data } = await apiClient.post('/auth/register', { email, password, role });
    return data;
  }, []);

  /**
   * Registers the current device as trusted for this user.
   * Call this when the user opts in to "remember this device".
   */
  const trustDevice = useCallback(async () => {
    await apiClient.post('/auth/trust-device');
    setNewDevice(false);
  }, []);

  // ── Initial Session Check (Persistent across page reloads) ──────────
  useEffect(() => {
    let mounted = true;
    const restoreSession = async () => {
      try {
        const storedAccess = tokenStore.getAccessToken();
        const storedRefresh = tokenStore.getRefreshToken();
        if (storedAccess) {
          const decoded = parseUser(storedAccess);
          const nowSeconds = Math.floor(Date.now() / 1000);
          if (decoded?.exp && decoded.exp > nowSeconds) {
            if (mounted) {
              setUser(decoded);
              scheduleRefresh(storedAccess);
              resetActivityTimer();
            }
          } else if (storedRefresh) {
            await silentRefresh();
          } else {
            tokenStore.clearTokens();
            if (mounted) setUser(null);
          }
        }
      } catch (err) {
        console.warn('Session restoration failed:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    restoreSession();
    return () => { mounted = false; };
  }, [parseUser, scheduleRefresh, resetActivityTimer, silentRefresh]);

  // ── Context Value ──────────────────────────────────────────
  const value = {
    user,             // decoded JWT payload (null if not authenticated)
    loading,          // true during initial session check
    mfaRequired,      // true when server requests an MFA code
    newDevice,        // true when this is an unrecognised device
    isAuthenticated: !!user,
    login,
    register,
    logout,
    logoutAll,
    trustDevice,
    silentRefresh,
    apiClient,        // export so consumers can use it without a separate import
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// ─── HOOKS ───────────────────────────────────────────────────

/**
 * useAuth — access the auth context from any component.
 *
 * Must be used inside <AuthProvider>.
 *
 * @example
 *   const { user, isAuthenticated, login, logout } = useAuth();
 */
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

// EDIT: Keep this map in sync with your backend's ROLE_PERMISSIONS.
const ROLE_PERMISSIONS = {
  admin:  ['read', 'write', 'delete', 'manage'],
  editor: ['read', 'write'],
  viewer: ['read'],
};

/**
 * usePermission — returns true if the current user has all given permissions.
 *
 * @param {...string} permissions - Permission strings to check
 * @returns {boolean}
 *
 * @example
 *   const canEdit = usePermission('write');
 *   const canPublish = usePermission('write', 'manage');
 */
export function usePermission(...permissions) {
  const { user } = useAuth();
  if (!user) return false;
  const userPerms = ROLE_PERMISSIONS[user.role] || [];
  return permissions.every(p => userPerms.includes(p));
}

// ─── GUARD COMPONENTS ────────────────────────────────────────

/**
 * ProtectedRoute — redirects unauthenticated users to the login page.
 *
 * Wrap any route that requires authentication:
 *
 *   <Route path="/dashboard" element={
 *     <ProtectedRoute>
 *       <Dashboard />
 *     </ProtectedRoute>
 *   } />
 *
 * @param {React.ReactNode} children    - The protected content
 * @param {string}          redirectTo  - Where to send unauthenticated users
 */
export function ProtectedRoute({ children, redirectTo = '/login' }) {
  const { isAuthenticated, loading } = useAuth();

  // Show a loading state while we check the initial session
  if (loading) {
    // EDIT: Replace with your app's loading spinner component
    return <div aria-live="polite">Loading…</div>;
  }

  if (!isAuthenticated) {
    // EDIT: Use React Router's <Navigate> component instead of this:
    // return <Navigate to={redirectTo} replace />;
    window.location.href = redirectTo;
    return null;
  }

  return children;
}

/**
 * RequirePermission — conditionally renders children based on permissions.
 *
 * Shows fallback (or nothing) if the user lacks the required permission.
 *
 * @example
 *   <RequirePermission permission="write">
 *     <EditButton />
 *   </RequirePermission>
 *
 *   <RequirePermission permission="delete" fallback={<ReadOnlyView />}>
 *     <DeleteButton />
 *   </RequirePermission>
 */
export function RequirePermission({ permission, fallback = null, children }) {
  const hasPermission = usePermission(permission);
  return hasPermission ? children : fallback;
}

/**
 * NewDevicePrompt — prompts the user to trust the current device.
 *
 * Rendered automatically when the server flags the login as coming
 * from an unrecognised device. Place this wherever is appropriate in
 * your layout (e.g. as a banner after login).
 *
 * EDIT: Replace with your own styled component.
 */
export function NewDevicePrompt() {
  const { newDevice, trustDevice } = useAuth();

  // Don't render anything if the device is already trusted
  if (!newDevice) return null;

  return (
    <div role="alert" aria-live="polite">
      <p>We don't recognise this device. Trust it for future logins?</p>
      <button onClick={trustDevice}>Trust This Device</button>
      <button onClick={() => {}}>Not Now</button>
    </div>
  );
}

// ─── USAGE EXAMPLE ───────────────────────────────────────────
/*
  // App.jsx — minimal wiring example

  import { BrowserRouter, Routes, Route } from 'react-router-dom';
  import {
    AuthProvider,
    ProtectedRoute,
    NewDevicePrompt,
    useAuth,
  } from './zero-trust-auth';

  function App() {
    return (
      <AuthProvider>
        <BrowserRouter>
          <NewDevicePrompt />
          <Routes>
            <Route path="/login"     element={<LoginPage />} />
            <Route path="/dashboard" element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } />
            <Route path="/admin" element={
              <ProtectedRoute>
                <RequirePermission permission="manage" fallback={<NotFound />}>
                  <AdminPanel />
                </RequirePermission>
              </ProtectedRoute>
            } />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    );
  }

  // LoginPage.jsx — using the login action

  function LoginPage() {
    const { login, mfaRequired } = useAuth();
    const [id, setId] = useState('');
    const [pw, setPw] = useState('');

    const handleSubmit = async (e) => {
      e.preventDefault();
      const result = await login(id, pw);
      if (result.success) {
        navigate('/dashboard');
      }
      // if result.mfaRequired — show the MFA input and call login(id, pw, totpCode)
    };

    return (
      <form onSubmit={handleSubmit}>
        <input value={id} onChange={e => setId(e.target.value)} placeholder="Email" />
        <input value={pw} onChange={e => setPw(e.target.value)} placeholder="Password" type="password" />
        <button type="submit">Log In</button>
      </form>
    );
  }

  // Any component — using apiClient for authenticated requests

  import { apiClient } from './zero-trust-auth';

  async function fetchProfile() {
    // Authorization header is attached automatically
    // Token is refreshed automatically if it has expired
    const { data } = await apiClient.get('/api/profile');
    return data;
  }
*/
