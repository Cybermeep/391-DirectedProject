import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import api, { ModelStatus } from '../../services/api';
import './DashboardWidgets.css';

const AIDetectionPanel: React.FC = () => {
  const { user } = useAuth();
  const isGated = !user || user.tier === 'free';
  const [status, setStatus] = useState<ModelStatus | null>(null);

  useEffect(() => {
    if (isGated) return;
    let cancelled = false;
    const load = async () => {
      const res = await api.getModelStatus();
      if (!cancelled) setStatus(res);
    };
    load();
    const interval = setInterval(load, 15_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [isGated]);

  const stats = status?.stats;
  const total = stats?.total_predictions ?? 0;
  const attacks = stats?.attack_predictions ?? 0;
  const detectionRate = total > 0 ? `${((attacks / total) * 100).toFixed(1)}%` : '--';
  const accuracy = stats?.accuracy != null ? `${(stats.accuracy * 100).toFixed(1)}%` : '0.0%';

  return (
    <div className="widget-card">
      <div className="widget-header">
        <h3>AI Detection</h3>
      </div>

      <div className="ai-stats-grid">
        <div className="ai-stat">
          <div className="value">{isGated ? '0' : total}</div>
          <div className="label">Analyzed</div>
        </div>
        <div className="ai-stat">
          <div className="value">{isGated ? '0' : attacks}</div>
          <div className="label">Attacks</div>
        </div>
        <div className="ai-stat">
          <div className="value">{isGated ? '--' : detectionRate}</div>
          <div className="label">Detection Rate</div>
        </div>
        <div className="ai-stat">
          <div className="value">{isGated ? '0.0%' : accuracy}</div>
          <div className="label">Accuracy</div>
          <div className="sublabel">validation set</div>
        </div>
      </div>

      {isGated ? (
        <div className="ai-gated">
          Non-accessible on the Free plan.{' '}
          <Link to="/billing/upgrade">Upgrade to Pro</Link> to see live AI detection stats.
        </div>
      ) : status && !status.loaded ? (
        <div className="ai-gated">Model not installed yet - see INSTALL.md to add one.</div>
      ) : null}
    </div>
  );
};

export default AIDetectionPanel;
