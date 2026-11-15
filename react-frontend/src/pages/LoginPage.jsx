import React, { useState, useRef } from 'react';
import { Loader2, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../../zero-trust-auth.jsx';

export function LoginPage({ onLogin, loading, error, mfaRequired }) {
  const { register } = useAuth();
  // First show registration page per user instruction: "first only show registation page then show login page"
  const [mode, setMode] = useState('register'); // 'register' | 'login'
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [digits, setDigits] = useState(['', '', '', '', '', '']);
  const [regLoading, setRegLoading] = useState(false);
  const [regSuccess, setRegSuccess] = useState(null);
  const [regError, setRegError] = useState(null);
  const digitRefs = useRef([]);

  const handleDigitChange = (index, value) => {
    if (!/^\d*$/.test(value)) return;
    const newDigits = [...digits];
    newDigits[index] = value.slice(-1);
    setDigits(newDigits);

    // Auto-advance
    if (value && index < 5) {
      digitRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      digitRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const paste = e.clipboardData.getData('text').trim();
    if (/^\d{6}$/.test(paste)) {
      setDigits(paste.split(''));
      digitRefs.current[5]?.focus();
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (mfaRequired) {
      const code = digits.join('');
      onLogin(identifier, password, code);
    } else {
      onLogin(identifier, password, null);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setRegError(null);
    setRegSuccess(null);

    if (!identifier || !password) {
      setRegError('Please provide both email and password.');
      return;
    }

    if (password !== confirmPassword) {
      setRegError('Passwords do not match. Please re-enter.');
      return;
    }

    if (password.length < 6) {
      setRegError('Password must contain at least 6 characters.');
      return;
    }

    setRegLoading(true);
    try {
      const res = await register(identifier, password, 'editor');
      setRegSuccess(res.message || 'Account created successfully! Please sign in with your credentials.');
      // After registration, show login page with pre-filled email
      setPassword('');
      setConfirmPassword('');
      setMode('login');
    } catch (err) {
      setRegError(err.response?.data?.error || 'Registration failed. Try a different email address.');
    } finally {
      setRegLoading(false);
    }
  };

  return (
    <div className="min-h-[100dvh] w-full flex items-center justify-center p-4 bg-base font-sans">
      <div className="w-[min(420px,100%-32px)] bg-surface border border-border rounded-card p-7 shadow-sm">
        {/* Header - Logo REMOVED per user instruction */}
        <div className="text-center mb-6">
          <h1 className="text-2xl font-bold text-text-primary tracking-tight">
            {mode === 'register' ? 'Create Account' : 'Sign In'}
          </h1>
          <p className="text-xs font-semibold text-text-secondary mt-1">
            {mode === 'register'
              ? 'Register a new identity to access the Zero-Trust Architecture Console'
              : (mfaRequired ? 'Enter your 6-digit rolling authenticator code' : 'Welcome back! Enter your credentials to sign in')}
          </p>
        </div>

        {/* Alerts */}
        {regSuccess && (
          <div className="mb-4 p-3 rounded-control pill-pass w-full text-xs !justify-start">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-status-pass" />
            <span className="font-bold">{regSuccess}</span>
          </div>
        )}
        {(error || regError) && (
          <div className="mb-4 p-3 rounded-control pill-fail w-full text-xs !justify-start">
            <span className="font-bold">{error || regError}</span>
          </div>
        )}

        {mode === 'register' ? (
          /* REGISTRATION FORM (Role removed, email, password, confirm password) */
          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-text-primary mb-1.5">
                Email address
              </label>
              <input
                type="email"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                required
                placeholder="name@example.com"
                className="w-full h-10 px-3 bg-surface border border-border rounded-control text-sm font-semibold text-text-primary placeholder-text-muted focus:border-blue focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-text-primary mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="Enter password"
                className="w-full h-10 px-3 bg-surface border border-border rounded-control text-sm font-semibold text-text-primary placeholder-text-muted focus:border-blue focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-text-primary mb-1.5">
                Confirm password
              </label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                placeholder="Re-enter password"
                className="w-full h-10 px-3 bg-surface border border-border rounded-control text-sm font-semibold text-text-primary placeholder-text-muted focus:border-blue focus:outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={regLoading}
              className="btn-primary w-full mt-3 !h-10 text-sm font-bold"
            >
              {regLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                  <span>Registering Account...</span>
                </>
              ) : (
                <span>Create Account</span>
              )}
            </button>

            <div className="text-center pt-2">
              <button
                type="button"
                onClick={() => { setMode('login'); setRegError(null); }}
                className="text-xs font-bold text-blue hover:underline"
              >
                Already have an account? Sign in &rarr;
              </button>
            </div>
          </form>
        ) : (
          /* SIGN IN FORM (Credentials demo removed) */
          <form onSubmit={handleSubmit} className="space-y-4">
            {!mfaRequired ? (
              <>
                <div>
                  <label className="block text-xs font-bold text-text-primary mb-1.5">
                    Email address
                  </label>
                  <input
                    type="email"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    required
                    placeholder="name@example.com"
                    className="w-full h-10 px-3 bg-surface border border-border rounded-control text-sm font-semibold text-text-primary placeholder-text-muted focus:border-blue focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-text-primary mb-1.5">
                    Password
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••"
                    className="w-full h-10 px-3 bg-surface border border-border rounded-control text-sm font-semibold text-text-primary placeholder-text-muted focus:border-blue focus:outline-none"
                  />
                </div>
              </>
            ) : (
              <div>
                <label className="block text-xs font-bold text-text-primary mb-2 text-center">
                  6-digit authenticator code
                </label>
                <div className="flex justify-between gap-1.5" onPaste={handlePaste}>
                  {digits.map((digit, i) => (
                    <input
                      key={i}
                      ref={(el) => (digitRefs.current[i] = el)}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      value={digit}
                      onChange={(e) => handleDigitChange(i, e.target.value)}
                      onKeyDown={(e) => handleKeyDown(i, e)}
                      className="w-11 h-12 text-center text-lg font-mono font-bold bg-surface border border-border rounded-control text-text-primary focus:border-blue focus:outline-none"
                    />
                  ))}
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full mt-3 !h-10 text-sm font-bold"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                  <span>Verifying credentials...</span>
                </>
              ) : mfaRequired ? (
                <span>Confirm code</span>
              ) : (
                <span>Sign in</span>
              )}
            </button>

            <div className="text-center pt-2">
              <button
                type="button"
                onClick={() => { setMode('register'); setRegError(null); }}
                className="text-xs font-bold text-blue hover:underline"
              >
                Don&apos;t have an account? Register &rarr;
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
