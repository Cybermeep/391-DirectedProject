import React, { useEffect, useState } from 'react';
import api from '../../services/api';
import './DashboardWidgets.css';

interface RulePerf {
  rule_id: string;
  name: string;
  attack_type: string | null;
  severity: string | null;
  fire_count: number;
  total_occurrences: number;
  last_fired: string | null;
  avg_confidence: number | null;
  enabled: boolean | null;
}

function timeAgo(iso: string | null): string {
  if (!iso) return 'never';
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

const RulePerformanceTable: React.FC = () => {
  const [rules, setRules] = useState<RulePerf[]>([]);
  const [loading, setLoading] = useState(true);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.getRulePerformance();
        if (!cancelled && res.success) setRules(res.rules);
      } catch {
        /* leave empty */
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const withActivity = rules.filter((r) => r.fire_count > 0);

  return (
    <div className="widget-card">
      <div className="widget-header widget-header-collapsible" onClick={() => setCollapsed((c) => !c)}>
        <h3>
          <span className={`widget-chevron ${collapsed ? 'collapsed' : ''}`}>▾</span>
          Rule Performance
        </h3>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {withActivity.length === 0 ? 'No rules have fired' : `${withActivity.length} rule${withActivity.length === 1 ? '' : 's'} have fired`}
        </span>
      </div>

      {!collapsed && (
        loading ? (
          <div className="widget-empty">Loading…</div>
        ) : rules.length === 0 ? (
          <div className="widget-empty">No rule data yet.</div>
        ) : withActivity.length === 0 ? (
          <div className="widget-empty">No rules have fired yet.</div>
        ) : (
          <div className="signature-table-wrap">
            <table className="signature-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th>Severity</th>
                  <th>Fires</th>
                  <th>Occurrences</th>
                  <th>Last Fired</th>
                </tr>
              </thead>
              <tbody>
                {withActivity.map((r) => (
                  <tr key={r.rule_id} className={r.enabled === false ? 'disabled' : ''}>
                    <td><span className="sig-code">{r.rule_id}</span></td>
                    <td>{r.name}</td>
                    <td>{r.severity ? <span className={`sig-severity ${r.severity}`}>{r.severity}</span> : '—'}</td>
                    <td>{r.fire_count}</td>
                    <td>{r.total_occurrences}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{timeAgo(r.last_fired)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  );
};

export default RulePerformanceTable;
