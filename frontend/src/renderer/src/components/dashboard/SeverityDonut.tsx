import React, { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import api from '../../services/api';
import './DashboardWidgets.css';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;
const SEVERITY_COLORS: Record<string, string> = {
  low: '#4C6FFF',
  medium: '#F5A524',
  high: '#E5484D',
  critical: '#DC2626',
};

const SeverityDonut: React.FC = () => {
  const [distribution, setDistribution] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.getSeverityDistribution();
        if (!cancelled && res.success) setDistribution(res.distribution || {});
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

  const data = SEVERITY_ORDER
    .map((sev) => ({ severity: sev, count: distribution[sev] || 0 }))
    .filter((d) => d.count > 0);
  const total = data.reduce((sum, d) => sum + d.count, 0);

  return (
    <div className="widget-card">
      <div className="widget-header">
        <h3>Severity Breakdown</h3>
      </div>

      {loading ? (
        <div className="widget-empty">Loading…</div>
      ) : total === 0 ? (
        <div className="widget-empty">No alerts yet.</div>
      ) : (
        <>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={data} dataKey="count" nameKey="severity" innerRadius={65} outerRadius={95} paddingAngle={2}>
                {data.map((d) => (
                  <Cell key={d.severity} fill={SEVERITY_COLORS[d.severity]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-center-label">
            <div className="big-number">{total}</div>
            <div className="caption">alerts</div>
          </div>
          <div className="donut-legend">
            {data.map((d) => (
              <div className="donut-legend-item" key={d.severity}>
                <span className="donut-legend-dot" style={{ background: SEVERITY_COLORS[d.severity] }} />
                {d.severity} ({d.count})
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

export default SeverityDonut;
