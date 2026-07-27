import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import GoogleSignInButton from './GoogleSignInButton';
import './Auth.css';

const Login: React.FC = () => {
  const { login, loginWithGoogle } = useAuth();
  const navigate = useNavigate();
  const location = useLocation() as { state?: { from?: string } };

  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const redirectTo = location.state?.from || '/';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      await login(identifier, password);
      navigate(redirectTo, { replace: true });
    } catch (err: any) {
      setError(err?.message || 'Login failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleGoogle = async (idToken: string) => {
    setError('');
    try {
      await loginWithGoogle(idToken);
      navigate(redirectTo, { replace: true });
    } catch (err: any) {
      setError(err?.message || 'Google sign-in failed');
    }
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-brand">
          <span className="auth-brand-icon">🛡️</span>
          <span className="auth-brand-name">Network Intrusion Detection System</span>
        </div>
        <div className="auth-title">Welcome back</div>
        <div className="auth-subtitle">Sign in to view live alerts and manage your detection rules.</div>

        {error && <div className="auth-error">{error}</div>}

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="auth-field">
            <label htmlFor="identifier">Email or username</label>
            <input
              id="identifier"
              type="text"
              autoComplete="username"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              required
            />
          </div>
          <div className="auth-field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <button className="auth-submit" type="submit" disabled={submitting}>
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div className="auth-divider">or</div>
        <GoogleSignInButton onCredential={handleGoogle} onError={setError} />

        <div className="auth-footer">
          Don&apos;t have an account? <Link to="/register">Create one</Link>
        </div>
      </div>
    </div>
  );
};

export default Login;
