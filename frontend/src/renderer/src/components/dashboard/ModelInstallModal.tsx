import React, { useState } from 'react';
import api from '../../services/api';
import './ModelInstallModal.css';

type Phase = 'prompt' | 'installing' | 'done' | 'error';

const ModelInstallModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [phase, setPhase] = useState<Phase>('prompt');
  const [error, setError] = useState('');

  const handleInstall = async () => {
    setPhase('installing');
    setError('');
    const res = await api.installModel();
    if (res.loaded) {
      setPhase('done');
    } else {
      setPhase('error');
      setError(res.error || 'Could not install the model.');
    }
  };

  return (
    <div className="alert-detail-backdrop">
      <div className="model-install-card">
        {phase === 'prompt' && (
          <>
            <div className="model-install-icon">🧠</div>
            <h3>Set up AI Detection</h3>
            <p>
              Your plan now includes AI-powered threat detection. Install the trained model to
              start seeing live predictions and confidence scores on the dashboard.
            </p>
            <button className="auth-submit" onClick={handleInstall}>
              Install AI Model
            </button>
            <button className="model-install-skip" onClick={onClose}>
              Skip for now
            </button>
          </>
        )}

        {phase === 'installing' && (
          <>
            <div className="model-install-icon spinning">⚙️</div>
            <h3>Installing…</h3>
            <p>Setting up the trained detection model. This only takes a moment.</p>
          </>
        )}

        {phase === 'done' && (
          <>
            <div className="model-install-icon">✅</div>
            <h3>AI Detection is ready</h3>
            <p>The model is installed. Live predictions and confidence scores are now active on your dashboard.</p>
            <button className="auth-submit" onClick={onClose}>
              Done
            </button>
          </>
        )}

        {phase === 'error' && (
          <>
            <div className="model-install-icon">⚠️</div>
            <h3>Couldn't install the model yet</h3>
            <p>{error}</p>
            <p className="model-install-hint">
              This usually means the trained model files haven't been placed on this machine yet.
              See INSTALL.md for how to add them, then try again.
            </p>
            <button className="auth-submit" onClick={handleInstall}>
              Try again
            </button>
            <button className="model-install-skip" onClick={onClose}>
              Close
            </button>
          </>
        )}
      </div>
    </div>
  );
};

export default ModelInstallModal;
