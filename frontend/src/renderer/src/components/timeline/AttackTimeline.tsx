import React, { useEffect, useState } from 'react';
import api, { Alert } from '../../services/api';
import './Timeline.css';

interface TimelineGroup {
  source_ip: string;
  alert_count: number;
  first_seen: string;
  last_seen: string;
  severities: string[];
  attack_types: string[];
  alerts: Alert[];
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function worstSeverity(severities: string[]): string {
  return severities.reduce((worst, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[worst] ? s : worst), 'low');
}

const AttackTimeline: React.FC = () => {
  const [groups, setGroups] = useState<TimelineGroup[]>([]);
  const [hours, setHours] = useState(24);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .getAlertTimeline(hours)
      .then((res) => {
        if (!cancelled && res.success) setGroups(res.groups);
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [hours]);

  return (
    <div className="timeline-page">
      <div className="timeline-header">
        <div>
          <h2>Attack Timeline</h2>
          <p>Alerts grouped by source IP - a sequence of related activity from one attacker, not scattered rows.</p>
        </div>
        <div className="timeframe-toggle">
          {[1, 24, 24 * 7].map((h) => (
            <button key={h} className={hours === h ? 'active' : ''} onClick={() => setHours(h)}>
              {h === 1 ? '1H' : h === 24 ? '24H' : '7D'}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="widget-empty">Loading…</div>
      ) : groups.length === 0 ? (
        <div className="widget-empty">
          No correlated activity in this window - either things are quiet, or each alert so far has come
          from a different, unrelated source.
        </div>
      ) : (
        <div className="timeline-groups">
          {groups.map((g) => {
            const isOpen = expanded === g.source_ip;
            const worst = worstSeverity(g.severities);
            return (
              <div className="timeline-group" key={g.source_ip}>
                <div className="timeline-group-header" onClick={() => setExpanded(isOpen ? null : g.source_ip)}>
                  <div>
                    <span className="timeline-source-ip">{g.source_ip}</span>
                    <span className={`alert-card-badge ${worst}`} style={{ marginLeft: 10 }}>
                      {worst}
                    </span>
                  </div>
                  <div className="timeline-group-meta">
                    <span>{g.alert_count} alerts</span>
                    <span>{new Date(g.first_seen).toLocaleTimeString()} → {new Date(g.last_seen).toLocaleTimeString()}</span>
                    <span className="timeline-expand-icon">{isOpen ? '▲' : '▼'}</span>
                  </div>
                </div>

                {isOpen && (
                  <div className="timeline-chain">
                    {g.alerts.map((alert, i) => (
                      <div className="timeline-chain-item" key={alert.alert_id}>
                        <div className="timeline-chain-dot" />
                        {i < g.alerts.length - 1 && <div className="timeline-chain-line" />}
                        <div className="timeline-chain-content">
                          <div className="timeline-chain-top">
                            <strong>{alert.attack_type}</strong>
                            <span className={`alert-card-badge ${alert.severity}`}>{alert.severity}</span>
                          </div>
                          <div className="timeline-chain-meta">
                            {new Date(alert.timestamp).toLocaleString()}
                            {alert.dest_port ? ` · port ${alert.dest_port}` : ''}
                            {alert.protocol ? ` · ${alert.protocol}` : ''}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default AttackTimeline;
