import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Tier } from '../../services/api';
import api from '../../services/api';
import ModelInstallModal from '../dashboard/ModelInstallModal';
import './Billing.css';

const TIERS: Array<{ id: Tier; label: string; price: string; features: string[] }> = [
  {
    id: 'free',
    label: 'Free',
    price: '$0',
    features: ['Core detection', 'Real-time alerts', '7-day alert history', '1 user'],
  },
  {
    id: 'pro',
    label: 'Pro',
    price: '$9.99',
    features: ['Everything in Free', '30-day alert history', 'Full explainability', 'Data export', 'API access', '5 users'],
  },
  {
    id: 'enterprise',
    label: 'Enterprise',
    price: '$29.99',
    features: ['Everything in Pro', '365-day alert history', 'Custom rule builder', 'Priority support', 'Advanced analytics', '100 users'],
  },
];

/** Luhn check, purely for instant client-side feedback before hitting the API. */
function luhnValid(digits: string): boolean {
  const clean = digits.replace(/\D/g, '');
  if (clean.length < 12) return false;
  let sum = 0;
  const parity = clean.length % 2;
  for (let i = 0; i < clean.length; i++) {
    let d = parseInt(clean[i], 10);
    if (i % 2 === parity) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

function formatCardNumber(value: string): string {
  const digits = value.replace(/\D/g, '').slice(0, 16);
  return digits.replace(/(.{4})/g, '$1 ').trim();
}

const UpgradeTier: React.FC = () => {
  const { user, upgradeTier, downgradeTier } = useAuth();
  const [showModelModal, setShowModelModal] = useState(false);
  const [selectedTier, setSelectedTier] = useState<Tier>('pro');
  const [cardNumber, setCardNumber] = useState('');
  const [expMonth, setExpMonth] = useState('');
  const [expYear, setExpYear] = useState('');
  const [cvc, setCvc] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const currentTier = user?.tier || 'free';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess(false);

    if (selectedTier === 'free') {
      setError('Select Pro or Enterprise to upgrade');
      return;
    }
    if (!luhnValid(cardNumber)) {
      setError(
        'This card number does not pass format validation. Try a test number like 4111 1111 1111 1111.'
      );
      return;
    }

    setSubmitting(true);
    try {
      await upgradeTier(selectedTier, {
        cardNumber,
        expMonth: parseInt(expMonth, 10),
        expYear: parseInt(expYear, 10),
        cvc,
      });
      setSuccess(true);

      const modelStatus = await api.getModelStatus();
      if (!modelStatus.loaded) {
        setShowModelModal(true);
      }
    } catch (err: any) {
      setError(err?.message || 'Upgrade failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="billing-page">
      <div className="billing-header">
        <h2>Plans & billing</h2>
        <p>
          This is a demo billing flow for a school project - no real payment processor is involved.
          Card numbers are validated for format only (Luhn check) and never stored in full; only the
          brand and last 4 digits are kept.
        </p>
      </div>

      <div className="tier-grid">
        {TIERS.map((tier) => {
          const isCurrent = tier.id === currentTier;
          return (
            <div
              key={tier.id}
              className={`tier-card ${selectedTier === tier.id ? 'selected' : ''} ${isCurrent ? 'current' : ''}`}
              onClick={() => !isCurrent && tier.id !== 'free' && setSelectedTier(tier.id)}
            >
              <div className="tier-name">
                {tier.label}
                {isCurrent && <span className="current-badge">Current plan</span>}
              </div>
              <div className="tier-price">
                {tier.price}
                {tier.id !== 'free' && <span> / month</span>}
              </div>
              <ul className="tier-features">
                {tier.features.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>

      {success && (
        <div className="billing-success">
          You&apos;ve been upgraded to {selectedTier}. Refresh to see newly unlocked features.
        </div>
      )}

      <form className="card-form" onSubmit={handleSubmit}>
        <h3>Payment details</h3>
        <div className="demo-note">
          Demo mode - try 4111 1111 1111 1111 (Visa) or 5555 5555 5555 4444 (Mastercard), any future
          expiration, any 3-digit CVC.
        </div>

        {error && <div className="auth-error">{error}</div>}

        <div className="auth-form">
          <div className="auth-field">
            <label htmlFor="cardNumber">Card number</label>
            <input
              id="cardNumber"
              type="text"
              inputMode="numeric"
              placeholder="4111 1111 1111 1111"
              value={cardNumber}
              onChange={(e) => setCardNumber(formatCardNumber(e.target.value))}
              required
            />
          </div>
          <div className="card-row">
            <div className="auth-field">
              <label htmlFor="expMonth">Exp. month</label>
              <input
                id="expMonth"
                type="text"
                inputMode="numeric"
                placeholder="MM"
                maxLength={2}
                value={expMonth}
                onChange={(e) => setExpMonth(e.target.value.replace(/\D/g, ''))}
                required
              />
            </div>
            <div className="auth-field">
              <label htmlFor="expYear">Exp. year</label>
              <input
                id="expYear"
                type="text"
                inputMode="numeric"
                placeholder="YYYY"
                maxLength={4}
                value={expYear}
                onChange={(e) => setExpYear(e.target.value.replace(/\D/g, ''))}
                required
              />
            </div>
            <div className="auth-field">
              <label htmlFor="cvc">CVC</label>
              <input
                id="cvc"
                type="text"
                inputMode="numeric"
                placeholder="123"
                maxLength={4}
                value={cvc}
                onChange={(e) => setCvc(e.target.value.replace(/\D/g, ''))}
                required
              />
            </div>
          </div>
          <button className="auth-submit" type="submit" disabled={submitting}>
            {submitting ? 'Processing…' : `Upgrade to ${selectedTier}`}
          </button>
        </div>
      </form>

      {currentTier !== 'free' && (
        <button
          className="logout-btn-full"
          style={{ marginTop: 16, maxWidth: 420 }}
          onClick={async () => {
            if (confirm('Downgrade to Free? You will lose access to paid features immediately.')) {
              try {
                await downgradeTier();
              } catch (err: any) {
                setError(err?.message || 'Downgrade failed');
              }
            }
          }}
        >
          Downgrade to Free
        </button>
      )}

      {showModelModal && <ModelInstallModal onClose={() => setShowModelModal(false)} />}
    </div>
  );
};

export default UpgradeTier;
