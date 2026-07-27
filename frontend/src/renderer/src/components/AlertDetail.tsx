// frontend/renderer/src/components/AlertDetail.tsx
import React from 'react';
import { Alert } from '../services/api';
import './AlertDetail.css';

interface AlertDetailProps {
  alert: Alert | null;
  explanation: string | null;
  onClose: () => void;
}

const AlertDetail: React.FC<AlertDetailProps> = ({ alert, explanation, onClose }) => {
  if (!alert) {
    return (
      <div className="alert-detail empty">
        <span className="empty-icon"></span>
        <p>Select an alert to view details</p>
      </div>
    );
  }

  const getSeverityColor = (severity: string): string => {
    const colors: Record<string, string> = {
      low: 'var(--success)',
      medium: 'var(--warning)',
      high: 'var(--danger)',
      critical: 'var(--critical)'
    };
    return colors[severity] || 'var(--text-muted)';
  };

  return (
    <div className="alert-detail-backdrop" onClick={onClose}>
      <div className="alert-detail" onClick={(e) => e.stopPropagation()}>
      <div className="detail-header">
        <div className="detail-title">
          <span className="detail-icon"></span>
          <span>Alert Details</span>
        </div>
        <button className="detail-close" onClick={onClose}>✕</button>
      </div>

      <div className="detail-body">
        <div className="detail-row">
          <span className="detail-label">Attack Type</span>
          <span className="detail-value">{alert.attack_type}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Severity</span>
          <span
            className="detail-value"
            style={{ color: getSeverityColor(alert.severity) }}
          >
            {alert.severity.toUpperCase()}
          </span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Source</span>
          <span className="detail-value">{alert.source_ip}:{alert.source_port || 'any'}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Destination</span>
          <span className="detail-value">{alert.dest_ip}:{alert.dest_port || 'any'}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Protocol</span>
          <span className="detail-value">{alert.protocol}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Confidence</span>
          <span className="detail-value">{(alert.ml_confidence * 100).toFixed(1)}%</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Status</span>
          <span className="detail-value">{alert.status}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Occurrences</span>
          <span className="detail-value">{alert.count_occurrences || 1}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">Message</span>
          <span className="detail-value">{alert.message}</span>
        </div>

        {explanation && (
          <div className="detail-explanation">
            <div className="detail-label"> Explanation</div>
            <div className="explanation-text">{explanation}</div>
          </div>
        )}

        <div className="detail-row">
          <span className="detail-label">Alert ID</span>
          <span className="detail-value detail-id">{alert.alert_id}</span>
        </div>

        <div className="detail-row">
          <span className="detail-label">First Seen</span>
          <span className="detail-value">
            {new Date(alert.timestamp).toLocaleString()}
          </span>
        </div>
      </div>
      </div>
    </div>
  );
};

export default AlertDetail;
