import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '../../context/AuthContext';
import api, { Rule } from '../../services/api';
import { Link } from 'react-router-dom';
import './Rules.css';

const EXAMPLE_RULE = 'SYN_Flag_Cnt > 5 AND RST_Flag_Cnt > 3 AND Flow_Byts/s > 1000';

const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

const RuleBuilder: React.FC = () => {
  const { hasFeature, user } = useAuth();
  const canUseRules = hasFeature('custom_rules');

  const [fields, setFields] = useState<string[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [name, setName] = useState('');
  const [ruleText, setRuleText] = useState('');
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>('medium');
  const [validation, setValidation] = useState<{ valid: boolean; error?: string; normalized?: string } | null>(
    null
  );
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!canUseRules) return;
    api.getRuleFields().then((res) => setFields(res.fields)).catch(() => {});
    refreshRules();
  }, [canUseRules]);

  const refreshRules = useCallback(() => {
    api
      .getRules()
      .then((res) => setRules(res.rules.filter((r) => !r.is_builtin)))
      .catch(() => {});
  }, []);

  // Live-validate as the user types, debounced lightly.
  useEffect(() => {
    if (!ruleText.trim()) {
      setValidation(null);
      return;
    }
    const timeout = setTimeout(() => {
      api
        .validateRule(ruleText)
        .then((res) => setValidation({ valid: res.valid, error: res.error, normalized: res.normalized }))
        .catch(() => setValidation({ valid: false, error: 'Could not reach validation service' }));
    }, 350);
    return () => clearTimeout(timeout);
  }, [ruleText]);

  const insertField = (field: string) => {
    setRuleText((prev) => (prev ? `${prev} ${field}` : field));
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');

    if (!name.trim()) {
      setFormError('Give your rule a name');
      return;
    }
    if (!validation?.valid) {
      setFormError('Fix the rule syntax before saving');
      return;
    }

    setSaving(true);
    try {
      await api.createRule({ name, rule_text: ruleText, severity, enabled: true });
      setName('');
      setRuleText('');
      setValidation(null);
      refreshRules();
    } catch (err: any) {
      setFormError(err?.message || 'Failed to save rule');
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (rule: Rule) => {
    await api.updateRule(rule.id, { enabled: !rule.enabled });
    refreshRules();
  };

  const handleDelete = async (rule: Rule) => {
    await api.deleteRule(rule.id);
    refreshRules();
  };

  if (!canUseRules) {
    return (
      <div className="rules-page">
        <div className="rules-header">
          <h2>Custom rule signatures</h2>
        </div>
        <div className="rules-locked">
          Custom rule/signature generation is an Enterprise-tier feature.
          <br />
          Your current plan is <strong>{user?.tier || 'free'}</strong>.
          <br />
          <Link to="/billing/upgrade">Upgrade to Enterprise</Link> to unlock this.
        </div>
      </div>
    );
  }

  return (
    <div className="rules-page">
      <div className="rules-header">
        <h2>Custom rule signatures</h2>
        <p>Write your own detection rules as simple field comparisons, combined with AND / OR / NOT.</p>
      </div>

      <div className="rules-layout">
        <div>
          <form className="rule-form" onSubmit={handleCreate}>
            <div className="auth-field">
              <label htmlFor="ruleName">Rule name</label>
              <input
                id="ruleName"
                type="text"
                placeholder="e.g. Possible SYN flood"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>

            <div className="auth-field" style={{ marginTop: 12 }}>
              <label htmlFor="ruleText">Rule expression</label>
              <textarea
                id="ruleText"
                className={`rule-textarea ${
                  validation ? (validation.valid ? 'valid' : 'invalid') : ''
                }`}
                placeholder={EXAMPLE_RULE}
                value={ruleText}
                onChange={(e) => setRuleText(e.target.value)}
              />
              <div className={`rule-validation ${validation ? (validation.valid ? 'ok' : 'err') : ''}`}>
                {validation &&
                  (validation.valid
                    ? `✓ Valid — normalized: ${validation.normalized}`
                    : `✗ ${validation.error}`)}
              </div>
            </div>

            <div className="rule-fields">
              {fields.slice(0, 14).map((f) => (
                <span key={f} className="rule-field-chip" onClick={() => insertField(f)}>
                  {f}
                </span>
              ))}
            </div>

            <div className="auth-field" style={{ marginTop: 12 }}>
              <label htmlFor="severity">Severity</label>
              <select
                id="severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as any)}
                style={{
                  background: 'var(--bg)',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  padding: '8px 10px',
                  color: 'var(--text)',
                }}
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>

            {formError && <div className="auth-error" style={{ marginTop: 12 }}>{formError}</div>}

            <button className="auth-submit" style={{ marginTop: 14 }} type="submit" disabled={saving}>
              {saving ? 'Saving…' : 'Save rule'}
            </button>
          </form>

          <div className="rule-list">
            {rules.map((r) => (
              <div className="rule-item" key={r.id}>
                <div className="rule-item-top">
                  <span className="rule-item-name">{r.name}</span>
                  <div className="rule-item-actions">
                    <span className={`rule-severity ${r.severity}`}>{r.severity}</span>
                    <button className="rule-icon-btn" onClick={() => handleToggle(r)}>
                      {r.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button className="rule-icon-btn" onClick={() => handleDelete(r)}>
                      Delete
                    </button>
                  </div>
                </div>
                <div className="rule-item-text">{r.rule_text}</div>
              </div>
            ))}
            {rules.length === 0 && (
              <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                No rules yet — write one on the left to get started.
              </div>
            )}
          </div>
        </div>

        <div className="rule-help">
          <h4>How rule syntax works</h4>
          <p>
            A rule is a boolean expression over the same network-flow features the ML model uses.
            Combine comparisons with <code>AND</code>, <code>OR</code>, and <code>NOT</code>, and use
            parentheses to group them.
          </p>
          <p>
            Supported operators: <code>&gt;</code> <code>&lt;</code> <code>&gt;=</code>{' '}
            <code>&lt;=</code> <code>==</code> <code>!=</code>
          </p>
          <p>Example — flag a likely SYN flood:</p>
          <div className="rule-example">{EXAMPLE_RULE}</div>
          <p>
            Every field name is checked against the model&apos;s known feature list before the rule can
            be saved, so a typo like <code>Syn_Flag_Cnt</code> (wrong case) or a made-up field will be
            rejected immediately with an explanation, rather than silently failing at detection time.
          </p>
          <p>Click a field name below to insert it into your rule:</p>
          <div className="rule-fields">
            {fields.map((f) => (
              <span key={f} className="rule-field-chip" onClick={() => insertField(f)}>
                {f}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default RuleBuilder;
