import React, { useEffect, useRef, useState } from 'react';

// The Google Identity Services script is loaded lazily (only when a login
// screen actually mounts) rather than unconditionally in index.html, so the
// app still works fully offline / without GOOGLE_CLIENT_ID configured -
// the button simply won't render if it fails to load or isn't configured.
const GSI_SCRIPT_SRC = 'https://accounts.google.com/gsi/client';

// Set this via a build-time env var (Vite): VITE_GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_ID = (import.meta as any).env?.VITE_GOOGLE_CLIENT_ID || '';

declare global {
  interface Window {
    google?: any;
  }
}

function loadGsiScript(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (window.google?.accounts?.id) {
      resolve();
      return;
    }
    const existing = document.querySelector(`script[src="${GSI_SCRIPT_SRC}"]`);
    if (existing) {
      existing.addEventListener('load', () => resolve());
      existing.addEventListener('error', () => reject(new Error('Failed to load Google script')));
      return;
    }
    const script = document.createElement('script');
    script.src = GSI_SCRIPT_SRC;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('Failed to load Google script'));
    document.head.appendChild(script);
  });
}

interface GoogleSignInButtonProps {
  onCredential: (idToken: string) => void;
  onError?: (message: string) => void;
}

const GoogleSignInButton: React.FC<GoogleSignInButtonProps> = ({ onCredential, onError }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [available, setAvailable] = useState(false);

  useEffect(() => {
    if (!GOOGLE_CLIENT_ID) {
      // Not configured - silently omit the button rather than showing a
      // broken/dead control. See INSTALL.md for how to set this up.
      return;
    }

    let cancelled = false;

    loadGsiScript()
      .then(() => {
        if (cancelled || !containerRef.current || !window.google) return;

        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: (response: { credential: string }) => {
            onCredential(response.credential);
          },
        });

        window.google.accounts.id.renderButton(containerRef.current, {
          theme: 'filled_black',
          size: 'large',
          width: 320,
          shape: 'rectangular',
          text: 'continue_with',
        });

        setAvailable(true);
      })
      .catch((err) => {
        onError?.(err.message);
      });

    return () => {
      cancelled = true;
    };
  }, [onCredential, onError]);

  if (!GOOGLE_CLIENT_ID) return null;

  return <div className="google-signin-container" ref={containerRef} aria-hidden={!available} />;
};

export default GoogleSignInButton;
