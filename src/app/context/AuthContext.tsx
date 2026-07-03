import { createContext, useContext, useEffect, useState } from 'react';

export type Role = 'admin' | 'analyst' | 'auditor';

export interface AuthUser {
  id:    string;
  email: string;
  role:  Role;
}

export interface Trial {
  count:     number;
  remaining: number;
}

interface AuthContextValue {
  user:        AuthUser | null;
  trial:       Trial;
  loading:     boolean;
  login:       (email: string, password: string) => Promise<void>;
  logout:      () => Promise<void>;
  updateTrial: (t: Trial) => void;
}

const AuthContext = createContext<AuthContextValue>(null!);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user,    setUser]    = useState<AuthUser | null>(null);
  const [trial,   setTrial]   = useState<Trial>({ count: 0, remaining: 3 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/auth/me', { credentials: 'include' })
      .then(r => r.json())
      .then(data => {
        setUser(data.user ?? null);
        if (data.trial) setTrial(data.trial);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method:      'POST',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/json' },
      body:        JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');
    setUser(data.user);
    setTrial({ count: 0, remaining: 3 });
  };

  const logout = async () => {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    setUser(null);
    setTrial({ count: 0, remaining: 3 });
  };

  const updateTrial = (t: Trial) => setTrial(t);

  return (
    <AuthContext.Provider value={{ user, trial, loading, login, logout, updateTrial }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
