// frontend/renderer/src/components/Dashboard.tsx
import React, { useState } from 'react';
import ThreatTrendChart from './dashboard/ThreatTrendChart';
import CaptureControl from './dashboard/CaptureControl';
import ThreatClassificationDonut from './dashboard/ThreatClassificationDonut';
import SeverityDonut from './dashboard/SeverityDonut';
import AIDetectionPanel from './dashboard/AIDetectionPanel';
import SignatureDetectionTable from './dashboard/SignatureDetectionTable';
import RulePerformanceTable from './dashboard/RulePerformanceTable';
import AlertLogPanel from './dashboard/AlertLogPanel';
import AlertDetail from './AlertDetail';
import api, { Alert } from '../services/api';
import { useAuth } from '../context/AuthContext';
import './dashboard/DashboardWidgets.css';

const Dashboard: React.FC = () => {
  const { hasFeature } = useAuth();
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [explanation, setExplanation] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState('');

  const handleExport = async () => {
    setExporting(true);
    setExportError('');
    try {
      await api.exportAlertsCsv(30);
    } catch (err: any) {
      setExportError(err?.message || 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  const handleSelectAlert = async (alert: Alert) => {
    setSelectedAlert(alert);
    setExplanation(alert.explanation || null);
    if (!alert.explanation) {
      try {
        const res = await api.explainAlert(alert.alert_id);
        if (res.success) setExplanation(res.explanation);
      } catch {
        setExplanation('Failed to load explanation');
      }
    }
  };

  return (
    <div className="dashboard-grid">
      <div className="dashboard-main">
        <div className="dashboard-header">
          <h2>Dashboard</h2>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {hasFeature('export_data') && (
              <button className="add-widget-btn" onClick={handleExport} disabled={exporting}>
                {exporting ? 'Exporting…' : '⬇ Export CSV'}
              </button>
            )}
            <button className="add-widget-btn" title="More widget types coming soon">
              Add Widget
            </button>
          </div>
        </div>
        {exportError && <div className="auth-error">{exportError}</div>}

        <CaptureControl />
        <ThreatTrendChart />

        <div className="widget-row widget-row-3">
          <ThreatClassificationDonut />
          <SeverityDonut />
          <AIDetectionPanel />
        </div>

        <SignatureDetectionTable />

        <RulePerformanceTable />
      </div>

      <AlertLogPanel onSelect={handleSelectAlert} />

      {selectedAlert && (
        <AlertDetail alert={selectedAlert} explanation={explanation} onClose={() => setSelectedAlert(null)} />
      )}
    </div>
  );
};

export default Dashboard;
