// UUser tutorial component, shows on the first load of the app, allows preference selection and a walkthrough of the application

import React, { useEffect, useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import './TutorialModal.css';

const TutorialModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const { theme, setTheme } = useTheme();
  const [step, setStep] = useState<1 | 2>(1);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="tutorial-modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="tutorial-modal">
        {step === 1 && (
          <div className="tutorial-modal-step" key="step-1">
            <h3 className="tutorial-modal-title-centered">Welcome!</h3>
            <p className="tutorial-modal-subtext-centered">
              Since you're new here, we recommend taking a quick tour of the app to get started!
            </p>
            <button className="auth-submit tutorial-modal-confirm" onClick={() => setStep(2)}>
              Next
            </button>
            <button className="tutorial-modal-skip" onClick={onClose}>
              No thanks, I'll explore on my own
            </button>
          </div>
        )}

        {step === 2 && (
          <div className="tutorial-modal-step" key="step-2">
            <h3 className="tutorial-modal-title-centered">Lighting Preference</h3>
            <p className="tutorial-modal-subtext-centered">Choose your preferred lighting mode</p>

            <div className="theme-picker-row">
              <div className="theme-picker-option">
                <div
                  className="theme-preview theme-preview-light"
                  onClick={() => setTheme('light')}
                  role="button"
                  aria-label="Preview light mode"
                >
                  <span className="theme-preview-widget" />
                  <span className="theme-preview-widget" />
                  <span className="theme-preview-widget theme-preview-widget-wide" />
                </div>
                <button
                  type="button"
                  className={`theme-picker-radio ${theme === 'light' ? 'selected' : ''}`}
                  aria-label="Select light mode"
                  onClick={() => setTheme('light')}
                />
                <span className="theme-picker-label"></span>
              </div>

              <div className="theme-picker-option">
                <div
                  className="theme-preview theme-preview-dark"
                  onClick={() => setTheme('dark')}
                  role="button"
                  aria-label="Preview dark mode"
                >
                  <span className="theme-preview-widget" />
                  <span className="theme-preview-widget" />
                  <span className="theme-preview-widget theme-preview-widget-wide" />
                </div>
                <button
                  type="button"
                  className={`theme-picker-radio ${theme === 'dark' ? 'selected' : ''}`}
                  aria-label="Select dark mode"
                  onClick={() => setTheme('dark')}
                />
                <span className="theme-picker-label"></span>
              </div>
            </div>

            <button className="auth-submit tutorial-modal-confirm" onClick={onClose}>
              Confirm
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default TutorialModal;
