import React, { useEffect, useState, useCallback } from 'react';
import api, { Alert } from '../../services/api';
import { wsClient } from '../../services/websocket';
import './DashboardWidgets.css';

function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

type ViewMode = 'active' | 'archived';

const AlertLogPanel: React.FC<{ onSelect?: (alert: Alert) => void }> = ({ onSelect }) => {
  const [activeAlerts, setActiveAlerts] = useState<Alert[]>([]);
  const [archivedAlerts, setArchivedAlerts] = useState<Alert[]>([]);
  const [view, setView] = useState<ViewMode>('active');
  const [loading, setLoading] = useState(true);

  const loadActive = useCallback(() => {
    return api.getAlerts(100, 0, 'active').then((res) => res.success && setActiveAlerts(res.alerts));
  }, []);

  const loadArchived = useCallback(() => {
    return api.getAlerts(100, 0, 'resolved').then((res) => res.success && setArchivedAlerts(res.alerts));
  }, []);

  useEffect(() => {
    Promise.all([loadActive(), loadArchived()]).finally(() => setLoading(false));

    wsClient.connect();
    wsClient.onAlert((alert: Alert) => {
      setActiveAlerts((prev) => [alert, ...prev.filter((a) => a.alert_id !== alert.alert_id)]);
    });
    wsClient.subscribeAlerts();
  }, [loadActive, loadArchived]);

  const handleArchive = async (alert: Alert, e: React.MouseEvent) => {
    e.stopPropagation();
    setActiveAlerts((prev) => prev.filter((a) => a.alert_id !== alert.alert_id));
    setArchivedAlerts((prev) => [{ ...alert, status: 'resolved' }, ...prev]);
    try {
      await api.updateAlertStatus(alert.alert_id, 'resolved');
    } catch {
      loadActive();
      loadArchived();
    }
  };

  const handleRestore = async (alert: Alert, e: React.MouseEvent) => {
    e.stopPropagation();
    setArchivedAlerts((prev) => prev.filter((a) => a.alert_id !== alert.alert_id));
    setActiveAlerts((prev) => [{ ...alert, status: 'active' }, ...prev]);
    try {
      await api.updateAlertStatus(alert.alert_id, 'active');
    } catch {
      loadActive();
      loadArchived();
    }
  };

  const displayed = view === 'active' ? activeAlerts : archivedAlerts;

  return (
    <div className="alert-log-panel">
      <div className="alert-log-header">
        <h3>Alert Log</h3>
        <span className="alert-log-count">{activeAlerts.length}</span>
      </div>

      <div className="timeframe-toggle" style={{ marginBottom: 14 }}>
        <button className={view === 'active' ? 'active' : ''} onClick={() => setView('active')}>
          Active
        </button>
        <button className={view === 'archived' ? 'active' : ''} onClick={() => setView('archived')}>
          Archived ({archivedAlerts.length})
        </button>
      </div>

      {loading ? (
        <div className="alert-log-empty">Loading…</div>
      ) : displayed.length === 0 ? (
        <div className="alert-log-empty">
          {view === 'active' ? 'No active alerts. Start capture to begin monitoring.' : 'No archived alerts yet.'}
        </div>
      ) : (
        <div className="alert-log-list">
          {displayed.map((alert) => (
            <div className="alert-card" key={alert.alert_id} onClick={() => onSelect?.(alert)}>
              <div className="alert-card-top">
                <span className="alert-card-title">{alert.attack_type}</span>
                <span className={`alert-card-badge ${alert.severity}`}>{alert.severity}</span>
              </div>
              <div className="alert-card-route">
                <span>{alert.source_ip}{alert.source_port ? `:${alert.source_port}` : ''}</span>
                <span>→</span>
                <span>{alert.dest_ip}{alert.dest_port ? `:${alert.dest_port}` : ''}</span>
                {alert.protocol && <span className="alert-card-proto">{alert.protocol}</span>}
              </div>
              <div className="alert-card-meta">
                <span>{timeAgo(alert.timestamp)}</span>
                <span>{Math.round((alert.ml_confidence || 0) * 100)}% confidence</span>
              </div>
              <div className="alert-card-actions">
                <button onClick={(e) => { e.stopPropagation(); onSelect?.(alert); }}>View Alert</button>
                {view === 'active' ? (
                  <button onClick={(e) => handleArchive(alert, e)}>Archive</button>
                ) : (
                  <button onClick={(e) => handleRestore(alert, e)}>Restore</button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AlertLogPanel;
