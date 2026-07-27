import React, { useState, useEffect } from 'react';
import api from '../../services/api';
import './DashboardWidgets.css';

const CaptureControl: React.FC = () => {
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [flowsProcessed, setFlowsProcessed] = useState<number | null>(null);

  useEffect(() => {
    const init = async () => {
      try {
        const [ifaceRes, statusRes] = await Promise.all([api.getInterfaces(), api.getCaptureStatus()]);
        if (ifaceRes.success && ifaceRes.interfaces.length > 0) {
          setInterfaces(ifaceRes.interfaces);
          setSelectedInterface(ifaceRes.interfaces[0]);
        }
        if (statusRes.success) {
          setIsCapturing(statusRes.is_capturing);
          if (statusRes.stats?.flows_processed != null) setFlowsProcessed(statusRes.stats.flows_processed);
        }
      } catch {
        setError('Could not reach the backend to list interfaces.');
      } finally {
        setLoading(false);
      }
    };
    init();
  }, []);

  // Poll status while capturing, so flow/alert counters stay live.
  useEffect(() => {
    if (!isCapturing) return;
    const interval = setInterval(async () => {
      try {
        const res = await api.getCaptureStatus();
        if (res.success && res.stats?.flows_processed != null) setFlowsProcessed(res.stats.flows_processed);
      } catch {
        /* ignore transient poll failures */
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [isCapturing]);

  const handleStart = async () => {
    if (!selectedInterface) return;
    setBusy(true);
    setError('');
    try {
      const res = await api.startCapture(selectedInterface);
      if (res.success) {
        setIsCapturing(true);
      } else {
        setError((res as any).error || 'Failed to start capture');
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to start capture');
    } finally {
      setBusy(false);
    }
  };

  const handleStop = async () => {
    setBusy(true);
    setError('');
    try {
      await api.stopCapture();
      setIsCapturing(false);
    } catch (err: any) {
      setError(err?.message || 'Failed to stop capture');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="widget-card capture-control">
      <div className="widget-header">
        <h3>Packet Capture</h3>
        <span className={`capture-status-text ${isCapturing ? 'live' : ''}`}>
          {isCapturing ? '● Monitoring' : '○ Idle'}
        </span>
      </div>

      {loading ? (
        <div className="widget-empty">Loading interfaces…</div>
      ) : (
        <div className="capture-control-row">
          <select
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={isCapturing || busy || interfaces.length === 0}
            className="capture-interface-select"
          >
            {interfaces.length === 0 && <option value="">No interfaces found</option>}
            {interfaces.map((iface) => (
              <option key={iface} value={iface}>
                {iface}
              </option>
            ))}
          </select>

          {isCapturing ? (
            <button className="capture-btn stop" onClick={handleStop} disabled={busy}>
              ■ Stop Capture
            </button>
          ) : (
            <button className="capture-btn start" onClick={handleStart} disabled={busy || !selectedInterface}>
              ▶ Start Capture
            </button>
          )}

          {flowsProcessed != null && (
            <span className="capture-flow-count">{flowsProcessed} flows analyzed</span>
          )}
        </div>
      )}

      {error && <div className="auth-error" style={{ marginTop: 10 }}>{error}</div>}
    </div>
  );
};

export default CaptureControl;
