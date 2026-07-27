import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import api, { Rule } from '../../services/api';
import './DashboardWidgets.css';

const SignatureDetectionTable: React.FC = () => {
  const { hasFeature } = useAuth();
  const canAddCustom = hasFeature('custom_rules');

  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [quickName, setQuickName] = useState('');
  const [quickRule, setQuickRule] = useState('');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');

  const refresh = useCallback(() => {
    api
      .getRules()
      .then((res) => setRules(res.rules))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const builtins = rules.filter((r) => r.is_builtin);
  const activeCount = builtins.filter((r) => r.enabled).length;

  const handleToggle = async (rule: Rule) => {
    setRules((prev) => prev.map((r) => (r.id === rule.id ? { ...r, enabled: !r.enabled } : r)));
    try {
      await api.updateRule(rule.id, { enabled: !rule.enabled });
    } catch {
      refresh(); // revert on failure
    }
  };

  const [justAdded, setJustAdded] = useState('');

  const handleQuickAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setJustAdded('');
    if (!quickName.trim() || !quickRule.trim()) return;

    setAdding(true);
    try {
      await api.createRule({ name: quickName, rule_text: quickRule, severity: 'medium', enabled: true });
      setJustAdded(quickName);
      setQuickName('');
      setQuickRule('');
      refresh();
    } catch (err: any) {
      setError(err?.message || 'Failed to add signature - check the rule syntax on the full Rule Builder page.');
    } finally {
      setAdding(false);
    }
  };

  return (
    <div className="widget-card">
      <div className="widget-header">
        <h3>Signature Detection</h3>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {activeCount} / {builtins.length} active
        </span>
      </div>

      {loading ? (
        <div className="widget-empty">Loading…</div>
      ) : (
        <div className="signature-table-wrap">
          <table className="signature-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Threshold</th>
                <th>Window</th>
                <th>Description</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {builtins.map((r) => (
                <tr key={r.id} className={r.enabled ? '' : 'disabled'}>
                  <td><span className="sig-code">{r.code}</span></td>
                  <td>{r.name}</td>
                  <td style={{ color: 'var(--text-muted)' }}>{r.attack_type}</td>
                  <td><span className={`sig-severity ${r.severity}`}>{r.severity}</span></td>
                  <td>{r.threshold ?? '—'}</td>
                  <td>{r.window_seconds ? `${r.window_seconds}s` : '—'}</td>
                  <td style={{ color: 'var(--text-muted)', maxWidth: 260, whiteSpace: 'normal' }}>{r.description}</td>
                  <td>
                    <button
                      className={`toggle-switch ${r.enabled ? 'on' : ''}`}
                      onClick={() => handleToggle(r)}
                      aria-label={r.enabled ? 'Disable' : 'Enable'}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="custom-sig-section">
        <h4>Custom Signatures</h4>
        {canAddCustom ? (
          <form className="custom-sig-form" onSubmit={handleQuickAdd}>
            <input
              placeholder="Name (e.g. Suspicious upload)"
              value={quickName}
              onChange={(e) => setQuickName(e.target.value)}
              style={{ flex: '0 0 220px' }}
            />
            <input
              placeholder="SYN_Flag_Cnt > 5 AND Flow_Byts/s > 1000"
              value={quickRule}
              onChange={(e) => setQuickRule(e.target.value)}
            />
            <button type="submit" disabled={adding}>
              {adding ? 'Adding…' : 'Add Custom Signature'}
            </button>
          </form>
        ) : (
          <div className="custom-sig-locked">
            Writing your own AST-validated signatures is an Enterprise feature.{' '}
            <Link to="/billing/upgrade">Upgrade</Link>, or open the{' '}
            <Link to="/rules">full Rule Builder</Link> for field help and examples.
          </div>
        )}
        {error && <div className="auth-error" style={{ marginTop: 8 }}>{error}</div>}
        {justAdded && !error && (
          <div className="billing-success" style={{ marginTop: 8 }}>
            "{justAdded}" added and enabled. See it (and edit/delete it) on the{' '}
            <Link to="/rules">full Rule Builder page</Link>.
          </div>
        )}
        {(() => {
          const customCount = rules.filter((r) => !r.is_builtin).length;
          return customCount > 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
              You have {customCount} custom signature{customCount === 1 ? '' : 's'} saved.
            </div>
          ) : null;
        })()}
      </div>
    </div>
  );
};

export default SignatureDetectionTable;
