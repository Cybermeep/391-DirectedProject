import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import './Account.css';

const AccountSettings: React.FC = () => {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();

  if (!user) return null;

  return (
    <div className="account-page">
      <h2>Account</h2>

      <div className="account-card">
        <div className="account-row">
          <span className="account-label">Username</span>
          <span>{user.username}</span>
        </div>
        <div className="account-row">
          <span className="account-label">Email</span>
          <span>{user.email}</span>
        </div>
        <div className="account-row">
          <span className="account-label">Sign-in method</span>
          <span>
            {user.auth_provider === 'google' ? 'Google' : 'Email & password'}
            {user.google_linked && user.auth_provider !== 'google' ? ' (Google linked)' : ''}
          </span>
        </div>
        <div className="account-row">
          <span className="account-label">Plan</span>
          <span className="tier-badge">{user.tier}</span>
        </div>
        {user.tier_expires_at && (
          <div className="account-row">
            <span className="account-label">Renews</span>
            <span>{new Date(user.tier_expires_at).toLocaleDateString()}</span>
          </div>
        )}
        <div className="account-row">
          <span className="account-label">Member since</span>
          <span>{user.created_at ? new Date(user.created_at).toLocaleDateString() : '—'}</span>
        </div>
      </div>

      <div className="account-card">
        <div className="account-row">
          <span className="account-label">Appearance</span>
          <button className="theme-toggle-btn" onClick={toggleTheme}>
            {theme === 'dark' ? '🌙 Dark mode' : '☀️ Light mode'} — switch
          </button>
        </div>
      </div>

      <div className="account-actions">
        {user.tier === 'free' && (
          <Link className="auth-submit" to="/billing/upgrade" style={{ textDecoration: 'none', textAlign: 'center' }}>
            Upgrade plan
          </Link>
        )}
        <button className="logout-btn-full" onClick={() => logout()}>
          Log out
        </button>
      </div>
    </div>
  );
};

export default AccountSettings;
