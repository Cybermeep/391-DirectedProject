import React, { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import api from '../../services/api';
import './DashboardWidgets.css';

const COLORS = ['#4C6FFF', '#2F4FE0', '#7C93FF', '#1B2FA8', '#A6B6FF'];

const ThreatClassificationDonut: React.FC = () => {
  const [data, setData] = useState<Array<{ attack_type: string; count: number }>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.getAttackTypes();
        if (!cancelled && res.success) setData(res.attack_types);
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

  const total = data.reduce((sum, d) => sum + d.count, 0);

  return (
    <div className="widget-card">
      <div className="widget-header">
        <h3>Threat Classification</h3>
      </div>

      {loading ? (
        <div className="widget-empty">Loading…</div>
      ) : total === 0 ? (
        <div className="widget-empty">No attacks classified yet.</div>
      ) : (
        <>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={data} dataKey="count" nameKey="attack_type" innerRadius={65} outerRadius={95} paddingAngle={2}>
                {data.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-center-label">
            <div className="big-number">{total}</div>
            <div className="caption">attacks</div>
          </div>
          <div className="donut-legend">
            {data.map((d, i) => (
              <div className="donut-legend-item" key={d.attack_type}>
                <span className="donut-legend-dot" style={{ background: COLORS[i % COLORS.length] }} />
                {d.attack_type}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

export default ThreatClassificationDonut;
