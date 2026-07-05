import { useState } from 'react';
import { Shield, LogIn, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { Button }  from './ui/button';
import { Card }    from './ui/card';
import { useAuth } from '../context/AuthContext';

interface LoginPageProps {
  onSuccess: () => void;
  onContinueAsGuest?: () => void;
}

export function LoginPage({ onSuccess, onContinueAsGuest }: LoginPageProps) {
  const { login } = useAuth();
  const [email,     setEmail]     = useState('');
  const [password,  setPassword]  = useState('');
  const [showPass,  setShowPass]  = useState(false);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(email.trim(), password);
      onSuccess();
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">

        {/* Branding */}
        <div className="text-center space-y-3">
          <div className="flex items-center justify-center gap-3">
            <div className="relative">
              <Shield className="w-10 h-10 text-blue-500" />
              <div className="absolute inset-0 bg-blue-500/20 blur-xl" />
            </div>
            <h1 className="text-2xl font-bold text-white">PhishForensics</h1>
          </div>
          <p className="text-slate-400 text-sm">Phishing Email Forensic Analysis System</p>
        </div>

        {/* Login card */}
        <Card className="bg-slate-900 border-slate-800 p-8">
          <h2 className="text-lg font-semibold text-white mb-6">Sign in to your account</h2>

          {error && (
            <div className="mb-4 flex items-center gap-2 p-3 rounded-lg bg-red-950/40 border border-red-700/50 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs text-slate-400 font-medium mb-1.5 uppercase tracking-wide">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@phishscan.com"
                required
                className="w-full px-3 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 font-medium mb-1.5 uppercase tracking-wide">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPass ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  className="w-full px-3 py-2.5 pr-10 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <Button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Signing in...
                </span>
              ) : (
                <span className="flex items-center justify-center gap-2">
                  <LogIn className="w-4 h-4" />
                  Sign in
                </span>
              )}
            </Button>
          </form>

          {/* Guest option */}
          {onContinueAsGuest && (
            <div className="mt-5 pt-5 border-t border-slate-800 text-center">
              <button
                onClick={onContinueAsGuest}
                className="text-sm text-slate-400 hover:text-white transition-colors"
              >
                Continue as guest <span className="text-slate-600">(3 free analyses)</span>
              </button>
            </div>
          )}
        </Card>

        <p className="text-center text-xs text-slate-600">
          FYP 2026 · No self-registration — contact admin for access
        </p>
      </div>
    </div>
  );
}
