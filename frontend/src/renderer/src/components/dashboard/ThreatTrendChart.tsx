import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import api from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import './DashboardWidgets.css';

type Timeframe = '1H' | '6H' | '24H' | '7D' | '365D';
type TrendPoint = { time: string; threats_detected: number; total_packets: number };

const TIMEFRAME_HOURS: Record<Timeframe, number> = { '1H': 1, '6H': 6, '24H': 24, '7D': 24 * 7, '365D': 24 * 365 };

const ThreatTrendChart: React.FC = () => {
  const { user } = useAuth();
  const isEnterprise = user?.tier === 'enterprise';

  const [timeframe, setTimeframe] = useState<Timeframe>('1H');
  const [data, setData] = useState<TrendPoint[]>([]);
  const [maxHoursForTier, setMaxHoursForTier] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.getDashboardStats(TIMEFRAME_HOURS[timeframe]);
        if (!cancelled && res.success) {
          setData(res.timeline);
          setMaxHoursForTier(res.max_hours_for_tier);
        }
      } catch {
        /* leave chart empty rather than crash the dashboard */
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
  }, [timeframe]);

  const formatTime = (t: string) => t.split(' ')[1]?.slice(0, 5) || t;
  const requestedHours = TIMEFRAME_HOURS[timeframe];
  const capped = maxHoursForTier != null && requestedHours > maxHoursForTier;

  const hasData = data.length > 0 && !data.every((d) => d.total_packets === 0 && d.threats_detected === 0);

  return (
    <div id="tutorial-trend" className="widget-card">
      <div className="widget-header">
        <h3>Threat Detection Trend</h3>
        <div className="timeframe-toggle">
          {(['1H', '6H', '24H', '7D'] as const).map((tf) => (
            <button key={tf} className={tf === timeframe ? 'active' : ''} onClick={() => setTimeframe(tf)}>
              {tf}
            </button>
          ))}
          <button
            className={timeframe === '365D' ? 'active' : ''}
            disabled={!isEnterprise}
            title={isEnterprise ? undefined : 'Enterprise unlocks up to 365 days of history'}
            onClick={() => isEnterprise && setTimeframe('365D')}
          >
            {isEnterprise ? '365D' : '🔒 365D'}
          </button>
        </div>
      </div>

      {!isEnterprise && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
          <Link to="/billing/upgrade">Upgrade to Enterprise</Link> to view up to 365 days of history.
        </div>
      )}

      {capped && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
          Your plan retains {maxHoursForTier! / 24} day{maxHoursForTier === 24 ? '' : 's'} of history - showing
          the maximum available. <Link to="/billing/upgrade">Upgrade</Link> for a longer window.
        </div>
      )}

      {loading ? (
        <div className="widget-empty">Loading…</div>
      ) : !hasData ? (
        <div className="widget-empty">No traffic data yet. Start a capture to see live numbers.</div>
      ) : (
        <div className="threat-trend-split">
          <div className="threat-trend-pane">
            <div className="threat-trend-pane-label">Total Packets</div>
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={data}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="time" tickFormatter={formatTime} stroke="var(--text-muted)" fontSize={12} />
                <YAxis stroke="var(--text-muted)" fontSize={12} tickFormatter={(v) => v.toLocaleString()} />
                <Tooltip
                  labelFormatter={formatTime}
                  formatter={(value: number) => value.toLocaleString()}
                  contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}
                />
                <Line type="monotone" dataKey="total_packets" name="Total Packets" stroke="var(--accent)" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="threat-trend-pane">
            <div className="threat-trend-pane-label">Threats Detected</div>
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={data}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="time" tickFormatter={formatTime} stroke="var(--text-muted)" fontSize={12} />
                <YAxis stroke="var(--text-muted)" fontSize={12} allowDecimals={false} />
                <Tooltip
                  labelFormatter={formatTime}
                  contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}
                />
                <Line type="monotone" dataKey="threats_detected" name="Threats Detected" stroke="var(--danger)" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatTrendChart;
