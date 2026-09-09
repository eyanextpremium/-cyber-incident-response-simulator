/**
 * api.js — Cyber Incident Response Simulator
 * Enterprise Security REST API Client with Token Authentication & Auto-Lockout Defense
 */

const BASE = '/api';

class ApiClient {
  constructor() {
    this._sessionId = null;
    this._token = localStorage.getItem('sim_auth_token') || null;
    this._user = JSON.parse(localStorage.getItem('sim_auth_user') || 'null');
  }

  get sessionId() { return this._sessionId; }
  set sessionId(id) { this._sessionId = id; }

  get token() { return this._token; }
  set token(t) {
    this._token = t;
    if (t) localStorage.setItem('sim_auth_token', t);
    else localStorage.removeItem('sim_auth_token');
  }

  get user() { return this._user; }
  set user(u) {
    this._user = u;
    if (u) localStorage.setItem('sim_auth_user', JSON.stringify(u));
    else localStorage.removeItem('sim_auth_user');
  }

  // ── Generic request ────────────────────────────────────────
  async _req(method, path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (this._token) {
      headers['Authorization'] = `Bearer ${this._token}`;
    }

    const opts = { method, headers };
    if (body !== undefined) opts.body = JSON.stringify(body);

    const res = await fetch(`${BASE}${path}`, opts);
    const data = await res.json().catch(() => ({}));

    if (res.status === 401) {
      if (window.showAuthModal) window.showAuthModal();
      throw new Error(data.error || 'Yetkisiz erişim. Lütfen giriş yapın.');
    }

    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  get(path)         { return this._req('GET',    path); }
  post(path, body)  { return this._req('POST',   path, body); }
  put(path, body)   { return this._req('PUT',    path, body); }
  del(path)         { return this._req('DELETE', path); }

  // ── Authentication & 2FA ─────────────────────────────────
  async login(username, password, totpCode) {
    const body = { username, password };
    if (totpCode) body.totp_code = totpCode;
    const res = await this.post('/auth/login', body);
    if (res.token) {
      this.token = res.token;
      this.user = { username: res.username, role: res.role };
    }
    return res;
  }

  async setup2FA(username) {
    return this.post('/auth/2fa/setup', { username });
  }

  async enable2FA(username, code) {
    return this.post('/auth/2fa/enable', { username, code });
  }

  async register(username, password, role) {
    const res = await this.post('/auth/register', { username, password, role });
    if (res.token) {
      this.token = res.token;
      this.user = res.user;
    }
    return res;
  }

  logout() {
    this.token = null;
    this.user = null;
    if (window.showAuthModal) window.showAuthModal();
  }

  // ── Health ─────────────────────────────────────────────────
  health()     { return this.get('/health'); }
  stats()      { return this.get('/stats'); }

  // ── Scenarios & Custom Scenario Editor ─────────────────────
  scenarios()  { return this.get('/scenarios'); }
  createCustomScenario(scenarioData) {
    return this.post('/scenarios/custom', scenarioData);
  }

  // ── Live Network Ingest ────────────────────────────────────
  ingestLog(logPayload) {
    return this.post('/ingest/logs', logPayload);
  }

  // ── Sessions ───────────────────────────────────────────────
  createSession(scenarioId, analystName) {
    return this.post('/sessions', { scenario_id: scenarioId, analyst_name: analystName });
  }
  listSessions()         { return this.get('/sessions'); }
  getSession(id)         { return this.get(`/sessions/${id}`); }
  finalizeSession(id)    { return this.post(`/sessions/${id}/finalize`); }
  getScore(id)           { return this.get(`/sessions/${id}/score`); }

  // ── Events ─────────────────────────────────────────────────
  listEvents(sid)        { return this.get(`/sessions/${sid}/events`); }

  // ── Alerts ─────────────────────────────────────────────────
  listAlerts(sid)        { return this.get(`/sessions/${sid}/alerts`); }
  acknowledgeAlert(sid, alertId) {
    return this.post(`/sessions/${sid}/alerts/${alertId}/acknowledge`);
  }
  updateAlert(sid, alertId, status) {
    return this.put(`/sessions/${sid}/alerts/${alertId}`, { status });
  }

  // ── Incidents ──────────────────────────────────────────────
  listIncidents(sid)     { return this.get(`/sessions/${sid}/incidents`); }
  createIncident(sid, title, severity, description) {
    return this.post(`/sessions/${sid}/incidents`, { title, severity, description });
  }
  updateIncident(sid, incId, status) {
    return this.put(`/sessions/${sid}/incidents/${incId}`, { status });
  }

  // ── Investigation ──────────────────────────────────────────
  getTimeline(sid)       { return this.get(`/sessions/${sid}/timeline`); }
  getInvestigationSummary(sid) { return this.get(`/sessions/${sid}/investigation/summary`); }
  listEvidence(sid)      { return this.get(`/sessions/${sid}/evidence`); }
  collectEvidence(sid)   { return this.post(`/sessions/${sid}/evidence/collect`); }

  // ── Response actions ───────────────────────────────────────
  executeAction(sid, action, target, incidentId, details) {
    return this.post(`/sessions/${sid}/actions`, {
      action, target,
      incident_id: incidentId || undefined,
      details: details || undefined,
    });
  }
  listActions(sid)       { return this.get(`/sessions/${sid}/actions`); }

  // ── Assets ─────────────────────────────────────────────────
  listAssets()           { return this.get('/assets'); }

  // ── Self-Audit ─────────────────────────────────────────────
  runSelfAudit()         { return this.post('/audit/run'); }
  auditQuickCheck()      { return this.get('/audit/quick'); }
  mitreCategories()      { return this.get('/scenarios/mitre'); }
}

// Singleton
window.api = new ApiClient();
