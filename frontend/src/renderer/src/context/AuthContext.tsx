import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import api, { AUTH_EXPIRED_EVENT, AuthUser, Tier } from '../services/api';

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (emailOrUsername: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  loginWithGoogle: (idToken: string) => Promise<void>;
  logout: () => Promise<void>;
  upgradeTier: (
    tier: Tier,
    card: { cardNumber: string; expMonth: number; expYear: number; cvc: string }
  ) => Promise<void>;
  downgradeTier: () => Promise<void>;
  hasFeature: (feature: 'custom_rules' | 'export_data' | 'api_access') => boolean;
}

const TIER_FEATURES: Record<Tier, Record<string, boolean>> = {
  free: { custom_rules: false, export_data: false, api_access: false },
  pro: { custom_rules: false, export_data: true, api_access: true },
  enterprise: { custom_rules: true, export_data: true, api_access: true },
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(api.getStoredUser());
  const [isLoading, setIsLoading] = useState(true);

  // Re-validate the stored session against the backend on launch, in case
  // the token expired while the app was closed.
  useEffect(() => {
    let cancelled = false;

    async function bootstrap() {
      if (api.getToken()) {
        try {
          const res = await api.me();
          if (!cancelled) setUser(res.user);
        } catch {
          if (!cancelled) {
            api.clearSession();
            setUser(null);
          }
        }
      }
      if (!cancelled) setIsLoading(false);
    }

    bootstrap();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onExpired = () => setUser(null);
    window.addEventListener(AUTH_EXPIRED_EVENT, onExpired);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, onExpired);
  }, []);

  const login = useCallback(async (emailOrUsername: string, password: string) => {
    const res = await api.login(emailOrUsername, password);
    setUser(res.user);
  }, []);

  const register = useCallback(async (username: string, email: string, password: string) => {
    const res = await api.register(username, email, password);
    setUser(res.user);
  }, []);

  const loginWithGoogle = useCallback(async (idToken: string) => {
    const res = await api.loginWithGoogle(idToken);
    setUser(res.user);
  }, []);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
  }, []);

  const upgradeTier = useCallback(
    async (tier: Tier, card: { cardNumber: string; expMonth: number; expYear: number; cvc: string }) => {
      const res = await api.upgradeTier(tier, card);
      setUser(res.user);
    },
    []
  );

  const downgradeTier = useCallback(async () => {
    const res = await api.downgradeTier();
    setUser(res.user);
  }, []);

  const hasFeature = useCallback(
    (feature: 'custom_rules' | 'export_data' | 'api_access') => {
      if (!user) return false;
      return !!TIER_FEATURES[user.tier]?.[feature];
    },
    [user]
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        loginWithGoogle,
        logout,
        upgradeTier,
        downgradeTier,
        hasFeature,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
