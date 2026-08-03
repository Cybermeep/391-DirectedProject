/**
 * API Client for the HomiNIDS Backend
 *
 * Base URL is configurable at build time via VITE_API_BASE_URL so this
 * same bundle can run as an Electron renderer talking to a local backend
 * AND be built as a static website pointed at a deployed backend
 * (e.g. https://api.yournids.com/api). Falls back to localhost for local
 * development if the env var isn't set.
 */

const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:5000/api';

export interface Alert {
  id: number;
  alert_id: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  attack_type: string;
  source_ip: string;
  dest_ip: string;
  source_port: number | null;
  dest_port: number | null;
  protocol: string;
  message: string;
  explanation: string;
  ml_confidence: number;
  count_occurrences: number;
  status: 'active' | 'resolved' | 'false_positive';
}

export interface AlertStats {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
}

export interface DashboardStats {
  stats: AlertStats;
  timeline: Array<{ time: string; threats_detected: number; total_packets: number }>;
  recent_alerts_count: number;
  timestamp: string;
}

export interface PredictionResult {
  prediction: 'Benign' | 'Attack';
  confidence: number;
  probability_attack: number;
  probability_benign: number;
}

export type Tier = 'free' | 'pro' | 'enterprise';

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  auth_provider: 'local' | 'google';
  tier: Tier;
  tier_expires_at: string | null;
  is_active: boolean;
  created_at: string | null;
  last_login: string | null;
  has_password: boolean;
  google_linked: boolean;
}

export interface AuthResponse {
  success: boolean;
  token: string;
  refresh_token: string;
  user: AuthUser;
}

export interface Rule {
  id: number;
  code: string | null;
  user_id: number | null;
  name: string;
  description: string | null;
  attack_type: string | null;
  rule_text: string;
  ast: Record<string, unknown>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  threshold: number | null;
  window_seconds: number | null;
  is_builtin: boolean;
  enabled: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface ModelStatus {
  loaded: boolean;
  stats?: {
    total_predictions: number;
    attack_predictions: number;
    benign_predictions: number;
    accuracy?: number;
  };
  error?: string;
}

const TOKEN_KEY = 'nids_access_token';
const REFRESH_KEY = 'nids_refresh_token';
const USER_KEY = 'nids_user';

/** Fired whenever the API layer detects an expired/invalid session (401). */
export const AUTH_EXPIRED_EVENT = 'nids:auth-expired';

class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE) {
    this.baseUrl = baseUrl;
  }

  // --- Token/session storage -------------------------------------------
  getToken(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  }

  getRefreshToken(): string | null {
    return localStorage.getItem(REFRESH_KEY);
  }

  getStoredUser(): AuthUser | null {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as AuthUser) : null;
  }

  setSession(auth: AuthResponse) {
    localStorage.setItem(TOKEN_KEY, auth.token);
    localStorage.setItem(REFRESH_KEY, auth.refresh_token);
    localStorage.setItem(USER_KEY, JSON.stringify(auth.user));
  }

  updateToken(token: string, user?: AuthUser) {
    localStorage.setItem(TOKEN_KEY, token);
    if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
  }

  private authHeaders(): Record<string, string> {
    const token = this.getToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  private async handle<T>(response: Response): Promise<T> {
    if (response.status === 401) {
      this.clearSession();
      window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
    }
    if (!response.ok) {
      let message = response.statusText;
      try {
        const body = await response.json();
        message = body.error || message;
      } catch {
        /* response wasn't JSON - fall back to statusText */
      }
      throw new ApiError(message, response.status);
    }
    return response.json();
  }

  async get<T>(endpoint: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      headers: { ...this.authHeaders() },
    });
    return this.handle<T>(response);
  }

  async post<T>(endpoint: string, data?: any): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this.authHeaders() },
      body: data ? JSON.stringify(data) : undefined,
    });
    return this.handle<T>(response);
  }

  async put<T>(endpoint: string, data?: any): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...this.authHeaders() },
      body: data ? JSON.stringify(data) : undefined,
    });
    return this.handle<T>(response);
  }

  async delete<T>(endpoint: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'DELETE',
      headers: { ...this.authHeaders() },
    });
    return this.handle<T>(response);
  }

  // Alert endpoints
  async getAlerts(limit: number = 100, offset: number = 0, status?: string): Promise<{ success: boolean; alerts: Alert[]; count: number }> {
    const statusParam = status ? `&status=${status}` : '';
    return this.get(`/alerts/?limit=${limit}&offset=${offset}${statusParam}`);
  }

  async getAlertById(alertId: string): Promise<{ success: boolean; alert: Alert }> {
    return this.get(`/alerts/${alertId}`);
  }

  async createAlert(alertData: Partial<Alert>): Promise<{ success: boolean; alert: Alert; is_duplicate: boolean }> {
    return this.post('/alerts/', alertData);
  }

  async updateAlertStatus(alertId: string, status: string): Promise<{ success: boolean; message: string }> {
    return this.put(`/alerts/${alertId}/status`, { status });
  }

  async getAlertStats(): Promise<{ success: boolean; stats: AlertStats }> {
    return this.get('/alerts/stats');
  }

  async explainAlert(alertId: string, detailed: boolean = false): Promise<{ success: boolean; explanation: string }> {
    return this.get(`/alerts/${alertId}/explain?detailed=${detailed}`);
  }

  // Stats endpoints
  async getDashboardStats(hours: number = 24): Promise<DashboardStats & { success: boolean; hours_included: number; max_hours_for_tier: number }> {
    return this.get(`/stats/dashboard?hours=${hours}`);
  }

  async getAttackTypes(): Promise<{ success: boolean; attack_types: Array<{ attack_type: string; count: number }> }> {
    return this.get('/stats/attack_types');
  }

  async getSeverityDistribution(): Promise<{ success: boolean; distribution: Record<string, number> }> {
    return this.get('/stats/severity_distribution');
  }

  async getRulePerformance(): Promise<{ success: boolean; rules: Array<{
    rule_id: string; name: string; attack_type: string | null; severity: string | null;
    threshold: number | null; window_seconds: number | null; is_builtin: boolean;
    enabled: boolean | null; fire_count: number; total_occurrences: number;
    last_fired: string | null; avg_confidence: number | null;
  }> }> {
    return this.get('/stats/rule_performance');
  }

  async exportAlertsCsv(days: number = 30): Promise<void> {
    const response = await fetch(`${this.baseUrl}/alerts/export?days=${days}`, {
      headers: { ...this.authHeaders() },
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Export failed (${response.status})`);
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nids-alerts-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  }

  async getAlertTimeline(hours: number = 24): Promise<{ success: boolean; groups: Array<{
    source_ip: string; alert_count: number; first_seen: string; last_seen: string;
    severities: string[]; attack_types: string[]; alerts: Alert[];
  }> }> {
    return this.get(`/alerts/timeline?hours=${hours}`);
  }

  // Capture endpoints
  async startCapture(interfaceName: string = 'eth0', filter?: string): Promise<{ success: boolean; message: string }> {
    return this.post('/capture/start', { interface: interfaceName, filter });
  }

  async stopCapture(): Promise<{ success: boolean; message: string; stats: any }> {
    return this.post('/capture/stop');
  }

  async getCaptureStatus(): Promise<{ success: boolean; is_capturing: boolean; stats: any }> {
    return this.get('/capture/status');
  }

  async getInterfaces(): Promise<{ success: boolean; interfaces: string[] }> {
    return this.get('/capture/interfaces');
  }

  // Prediction endpoint
  async predict(features: Record<string, any>): Promise<{ success: boolean; result: PredictionResult }> {
    return this.post('/predict', { features });
  }

  async getModelStatus(): Promise<ModelStatus> {
    try {
      return await this.get('/model/status');
    } catch (err: any) {
      return { loaded: false, error: err?.message || 'Model status unavailable' };
    }
  }

  async installModel(): Promise<ModelStatus> {
    try {
      return await this.post('/model/install');
    } catch (err: any) {
      return { loaded: false, error: err?.message || 'Model installation failed' };
    }
  }

  // Health check
  async healthCheck(): Promise<{ status: string; service: string; version: string }> {
    return this.get('/health');
  }

  // System status
  async systemStatus(): Promise<{ status: string; timestamp: string; alerts: AlertStats }> {
    return this.get('/status');
  }

  // --- Auth ---------------------------------------------------------------
  async register(username: string, email: string, password: string): Promise<AuthResponse> {
    const res = await this.post<AuthResponse>('/auth/register', { username, email, password });
    this.setSession(res);
    return res;
  }

  async login(emailOrUsername: string, password: string): Promise<AuthResponse> {
    const res = await this.post<AuthResponse>('/auth/login', { email: emailOrUsername, password });
    this.setSession(res);
    return res;
  }

  async loginWithGoogle(idToken: string): Promise<AuthResponse> {
    const res = await this.post<AuthResponse>('/auth/google', { id_token: idToken });
    this.setSession(res);
    return res;
  }

  async logout(): Promise<void> {
    const refreshToken = this.getRefreshToken();
    try {
      await this.post('/auth/logout', { refresh_token: refreshToken });
    } finally {
      this.clearSession();
    }
  }

  async me(): Promise<{ success: boolean; user: AuthUser }> {
    return this.get('/auth/me');
  }

  // --- Billing / tier upgrade (dummy card validation only) ----------------
  async upgradeTier(
    tier: Tier,
    card: { cardNumber: string; expMonth: number; expYear: number; cvc: string }
  ): Promise<{ success: boolean; user: AuthUser; token: string }> {
    const res = await this.post<{ success: boolean; user: AuthUser; token: string }>('/auth/upgrade', {
      tier,
      card_number: card.cardNumber,
      exp_month: card.expMonth,
      exp_year: card.expYear,
      cvc: card.cvc,
    });
    this.updateToken(res.token, res.user);
    return res;
  }

  async downgradeTier(): Promise<{ success: boolean; user: AuthUser; token: string }> {
    const res = await this.post<{ success: boolean; user: AuthUser; token: string }>('/auth/downgrade', {});
    this.updateToken(res.token, res.user);
    return res;
  }

  // --- Custom rule/signature builder ---------------------------------------
  async getRuleFields(): Promise<{ success: boolean; fields: string[] }> {
    return this.get('/rules/fields');
  }

  async validateRule(
    ruleText: string
  ): Promise<{ success: boolean; valid: boolean; error?: string; ast?: any; normalized?: string }> {
    return this.post('/rules/validate', { rule_text: ruleText });
  }

  async getRules(): Promise<{ success: boolean; count: number; rules: Rule[] }> {
    return this.get('/rules/');
  }

  async createRule(rule: {
    name: string;
    description?: string;
    rule_text: string;
    severity: string;
    enabled?: boolean;
  }): Promise<{ success: boolean; rule: Rule }> {
    return this.post('/rules/', rule);
  }

  async updateRule(id: number, rule: Partial<Rule>): Promise<{ success: boolean; rule: Rule }> {
    return this.put(`/rules/${id}`, rule);
  }

  async deleteRule(id: number): Promise<{ success: boolean; message: string }> {
    return this.delete(`/rules/${id}`);
  }
}

export const api = new ApiClient();
export default api;
