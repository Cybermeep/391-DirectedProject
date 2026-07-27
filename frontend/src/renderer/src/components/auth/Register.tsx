import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import GoogleSignInButton from './GoogleSignInButton';
import './Auth.css';

const Register: React.FC = () => {
  const { register, loginWithGoogle } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setSubmitting(true);
    try {
      await register(username, email, password);
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err?.message || 'Registration failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleGoogle = async (idToken: string) => {
    setError('');
    try {
      await loginWithGoogle(idToken);
      navigate('/', { replace: true });
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
        <div className="auth-title">Create your account</div>
        <div className="auth-subtitle">Free tier includes core detection, real-time alerts, and a 7-day history.</div>

        {error && <div className="auth-error">{error}</div>}

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="auth-field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
            <div className="auth-hint">3–32 characters: letters, numbers, _ or -</div>
          </div>
          <div className="auth-field">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="auth-field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <div className="auth-hint">At least 8 characters, with letters and numbers</div>
          </div>
          <div className="auth-field">
            <label htmlFor="confirmPassword">Confirm password</label>
            <input
              id="confirmPassword"
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>
          <button className="auth-submit" type="submit" disabled={submitting}>
            {submitting ? 'Creating account…' : 'Create account'}
          </button>
        </form>

        <div className="auth-divider">or</div>
        <GoogleSignInButton onCredential={handleGoogle} onError={setError} />

        <div className="auth-footer">
          Already have an account? <Link to="/login">Sign in</Link>
        </div>
      </div>
    </div>
  );
};

export default Register;
