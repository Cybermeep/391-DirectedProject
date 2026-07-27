// frontend/src/renderer/src/App.tsx
import React, { useEffect, useState, useRef } from 'react';
import { HashRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Login from './components/auth/Login';
import Register from './components/auth/Register';
import ProtectedRoute from './components/auth/ProtectedRoute';
import UpgradeTier from './components/billing/UpgradeTier';
import RuleBuilder from './components/rules/RuleBuilder';
import AttackTimeline from './components/timeline/AttackTimeline';
import AccountSettings from './components/account/AccountSettings';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import api from './services/api';
import './App.css';

// HashRouter (not BrowserRouter) is used deliberately: this app ships both
// as an Electron renderer (loaded from a file:// path) and as a plain
// static website. Hash-based routing works in both without needing any
// server-side rewrite rules for a deployed static host.

const ApiStatusPill: React.FC = () => {
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        await api.healthCheck();
        if (!cancelled) setOnline(true);
      } catch {
        if (!cancelled) setOnline(false);
      }
    };
    check();
    const interval = setInterval(check, 15_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="status-bar">
      <span className={`status-dot ${online ? 'active' : 'offline'}`}></span>
      <span>{online === null ? 'Checking…' : online ? 'API Online' : 'API Offline'}</span>
    </div>
  );
};

const AvatarMenu: React.FC = () => {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);

  if (!user) return null;

  return (
    <div className="avatar-menu" ref={ref}>
      <button className="avatar-btn" onClick={() => setOpen((o) => !o)}>
        {user.username.slice(0, 2).toUpperCase()}
      </button>
      {open && (
        <div className="avatar-dropdown">
          <div className="avatar-dropdown-user">
            <div>{user.username}</div>
            <span className="tier-badge">{user.tier}</span>
          </div>
          <NavLink to="/account" onClick={() => setOpen(false)}>Account settings</NavLink>
          <button onClick={toggleTheme}>{theme === 'dark' ? '☀️ Light mode' : '🌙 Dark mode'}</button>
          <button onClick={() => logout()}>Log out</button>
        </div>
      )}
    </div>
  );
};

const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();

  return (
    <div className="app">
      <header className="app-header">
        <h1>🛡️ NIDS</h1>

        {isAuthenticated && (
          <nav className="app-nav">
            <NavLink to="/" end className={({ isActive }) => (isActive ? 'active' : '')}>
              Dashboard
            </NavLink>
            <NavLink to="/rules" className={({ isActive }) => (isActive ? 'active' : '')}>
              Rules
            </NavLink>
            <NavLink to="/timeline" className={({ isActive }) => (isActive ? 'active' : '')}>
              Timeline
            </NavLink>
            <NavLink to="/billing/upgrade" className={({ isActive }) => (isActive ? 'active' : '')}>
              Upgrade
            </NavLink>
          </nav>
        )}

        <ApiStatusPill />

        {isAuthenticated && <AvatarMenu />}
      </header>

      <div className="app-body">{children}</div>
    </div>
  );
};

function App(): React.JSX.Element {
  return (
    <ThemeProvider>
      <AuthProvider>
        <HashRouter>
          <AppShell>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/rules"
                element={
                  <ProtectedRoute>
                    <RuleBuilder />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/timeline"
                element={
                  <ProtectedRoute>
                    <AttackTimeline />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/billing/upgrade"
                element={
                  <ProtectedRoute>
                    <UpgradeTier />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/account"
                element={
                  <ProtectedRoute>
                    <AccountSettings />
                  </ProtectedRoute>
                }
              />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </AppShell>
        </HashRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
