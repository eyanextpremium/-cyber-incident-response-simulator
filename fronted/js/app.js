/**
 * app.js — Cyber Incident Response Simulator
 * Core application controller: routing, auth modal, WebSocket live feed, session state
 */

class App {
  constructor() {
    this.sessionId       = null;
    this.sessionStartedAt = null;
    this.scenarioName    = '';
    this.timerInterval   = null;
    this.pollInterval    = null;
    this.currentView     = 'dashboard';
    this.ws              = null;

    this._views = ['dashboard','scenarios','events','alerts','incidents','investigation','response','scoring','scenario-editor','self-audit'];
    this._init();
  }

  // ── Initialization ─────────────────────────────────────────
  _init() {
    // Clock
    this._tickClock();
    setInterval(() => this._tickClock(), 1000);

    // Nav wiring
    document.querySelectorAll('.nav-item').forEach(btn => {
      btn.addEventListener('click', () => this.showView(btn.dataset.view));
    });

    // Scenario start modal
    document.getElementById('modal-close-btn').addEventListener('click', () => this._closeModal());
    document.getElementById('modal-cancel-btn').addEventListener('click', () => this._closeModal());
    document.getElementById('modal-start-btn').addEventListener('click', () => this._startSession());
    document.getElementById('btn-finish-session').addEventListener('click', () => this._finalize());

    // Login Form Wiring
    const authForm = document.getElementById('auth-login-form');
    if (authForm) {
      authForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const u = document.getElementById('auth-user-input').value.trim();
        const p = document.getElementById('auth-pass-input').value.trim();
        const totpInput = document.getElementById('auth-totp-input');
        const totpContainer = document.getElementById('auth-totp-container');
        const totpCode = totpInput ? totpInput.value.trim() : null;
        const errDiv = document.getElementById('auth-error-msg');
        errDiv.textContent = 'Giriş yapılıyor...';
        try {
          const res = await window.api.login(u, p, totpCode);
          if (res.requires_2fa) {
            if (totpContainer) totpContainer.style.display = 'block';
            errDiv.textContent = '🔑 2FA Aktif: Lütfen 6 haneli doğrulama kodunuzu giriniz.';
            return;
          }
          errDiv.textContent = '';
          this.hideAuthModal();
          this.toast(`Hoş geldiniz ${u}! Oturum açıldı.`, 'success');
          this.showView(this.currentView);
        } catch (err) {
          errDiv.textContent = `❌ ${err.message}`;
        }
      });
    }

    // Check Auth on Start
    if (!window.api.token) {
      this.showAuthModal();
    }

    // Connect WebSocket
    this._connectWebSocket();

    // Load scenarios immediately
    window.dashboard?.loadScenarios();

    // Restore session from sessionStorage
    const saved = sessionStorage.getItem('sim_session');
    if (saved) {
      try {
        const s = JSON.parse(saved);
        this._setSession(s.sessionId, s.scenarioName, new Date(s.startedAt));
      } catch(_) { sessionStorage.removeItem('sim_session'); }
    }

    this.showView('dashboard');
  }

  showAuthModal() {
    const modal = document.getElementById('auth-modal');
    if (modal) modal.classList.remove('hidden');
  }

  hideAuthModal() {
    const modal = document.getElementById('auth-modal');
    if (modal) modal.classList.add('hidden');
  }

  // ── WebSocket Real-Time Feed ───────────────────────────────
  _connectWebSocket() {
    try {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${proto}//${location.host}/api/ws`;
      this.ws = new WebSocket(wsUrl);

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'alert') {
            this.toast(`🚨 KRİTİK ALARM: [${data.rule_id}] ${data.title}`, 'error');
            if (this.sessionId) this._poll();
          }
        } catch(_) {}
      };

      this.ws.onclose = () => {
        setTimeout(() => this._connectWebSocket(), 5000); // Auto reconnect
      };
    } catch(_) {}
  }

  // ── View routing ───────────────────────────────────────────
  showView(name) {
    if (!this._views.includes(name)) name = 'dashboard';
    this.currentView = name;

    this._views.forEach(v => {
      document.getElementById(`view-${v}`)?.classList.toggle('hidden', v !== name);
      document.getElementById(`nav-${v}`)?.classList.toggle('active', v === name);
    });

    const titles = {
      dashboard:         ['SOC Dashboard',         'Security Operations Center'],
      scenarios:         ['Scenario Library',       'Select an incident response exercise'],
      events:            ['Live Event Feed',        'Real-time security events'],
      alerts:            ['Alert Queue',            'Active alerts requiring review'],
      incidents:         ['Incident Management',    'Open incident tracking & lifecycle'],
      investigation:     ['Investigation Workbench','Timeline analysis & evidence'],
      response:          ['Response Playbook',      'Execute containment & recovery actions'],
      scoring:           ['Performance Report',     'Session score and analyst ranking'],
      'scenario-editor': ['Görsel Senaryo Editörü', 'Özel senaryo ve saldırı simülasyonu tasarımı'],
      'self-audit':      ['Self-Audit Modülü',      'Proje güvenlik taraması ve sahte saldırı simülasyonu'],
    };

    const [title, sub] = titles[name] || ['Dashboard',''];
    document.getElementById('page-title').textContent = title;
    document.getElementById('page-sub').textContent   = sub;

    if (name === 'scenario-editor') {
      if (window.initScenarioEditor) window.initScenarioEditor();
    }

    // Lazy-load view data
    if (this.sessionId) {
      switch (name) {
        case 'events':        window.dashboard?.loadEvents(); break;
        case 'alerts':        window.incident?.loadAlerts(); break;
        case 'incidents':     window.incident?.loadIncidents(); break;
        case 'investigation': window.investigation?.load(); break;
        case 'response':      window.response?.load(); break;
        case 'scoring':       this._loadScore(); break;
      }
    }
    if (name === 'scenarios') window.dashboard?.loadScenarios();
    if (name === 'dashboard') window.dashboard?.loadDashboard();
  }

  // ── Session management ─────────────────────────────────────
  async launchScenario(scenarioId, scenarioName, desc, objective) {
    document.getElementById('modal-scenario-name').textContent      = scenarioName;
    document.getElementById('modal-scenario-desc').textContent      = desc;
    document.getElementById('modal-scenario-objective').textContent = objective;
    document.getElementById('analyst-name-input').value             = window.api.user?.username || 'Analyst';
    document.getElementById('start-modal').dataset.scenarioId       = scenarioId;
    document.getElementById('start-modal').classList.remove('hidden');
  }

  async _startSession() {
    const scenarioId   = document.getElementById('start-modal').dataset.scenarioId;
    const analystName  = document.getElementById('analyst-name-input').value.trim() || 'Analyst';
    const scenarioName = document.getElementById('modal-scenario-name').textContent;

    const btn = document.getElementById('modal-start-btn');
    btn.disabled = true;
    btn.querySelector('span').textContent = 'Starting…';

    try {
      const data = await api.createSession(scenarioId, analystName);
      api.sessionId = data.session_id;
      this._setSession(data.session_id, scenarioName, new Date(data.started_at));
      this._closeModal();
      this.showView('dashboard');
      this.toast(`Scenario "${scenarioName}" started!`, 'success');
      window.dashboard?.loadDashboard();
    } catch (e) {
      this.toast(`Failed to start: ${e.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.querySelector('span').textContent = 'Launch Scenario';
    }
  }

  _setSession(id, name, startedAt) {
    this.sessionId        = id;
    this.scenarioName     = name;
    this.sessionStartedAt = startedAt;
    api.sessionId         = id;

    sessionStorage.setItem('sim_session', JSON.stringify({
      sessionId: id, scenarioName: name, startedAt: startedAt.toISOString()
    }));

    document.getElementById('session-empty-state').classList.add('hidden');
    document.getElementById('session-active-state').classList.remove('hidden');
    document.getElementById('session-scenario-name').textContent = name;

    // Start timer
    clearInterval(this.timerInterval);
    this.timerInterval = setInterval(() => this._updateTimer(), 1000);
    this._updateTimer();

    // Start polling
    this._startPolling();
  }

  async _finalize() {
    if (!this.sessionId) return;
    const btn = document.getElementById('btn-finish-session');
    btn.disabled = true;
    btn.textContent = 'Calculating…';
    try {
      const result = await api.finalizeSession(this.sessionId);
      this._clearSession();
      window.scoring?.render(result);
      this.showView('scoring');
      this.toast('Session finalized! Check your score.', 'success');
    } catch(e) {
      this.toast(`Finalize failed: ${e.message}`, 'error');
      btn.disabled = false;
      btn.textContent = 'Finalize & Score';
    }
  }

  _clearSession() {
    clearInterval(this.timerInterval);
    clearInterval(this.pollInterval);
    this.sessionId = null;
    this.sessionStartedAt = null;
    api.sessionId = null;
    sessionStorage.removeItem('sim_session');
    document.getElementById('session-empty-state').classList.remove('hidden');
    document.getElementById('session-active-state').classList.add('hidden');
    document.getElementById('session-timer').textContent = '00:00';
    document.getElementById('btn-finish-session').disabled = false;
    document.getElementById('btn-finish-session').textContent = 'Finalize & Score';
  }

  // ── Polling ────────────────────────────────────────────────
  _startPolling() {
    clearInterval(this.pollInterval);
    this.pollInterval = setInterval(() => this._poll(), 5000);
  }

  async _poll() {
    if (!this.sessionId) return;
    try {
      const [alertsData, eventsData] = await Promise.all([
        api.listAlerts(this.sessionId),
        api.listEvents(this.sessionId),
      ]);
      const alerts = alertsData.alerts || [];
      const events = eventsData.events || [];

      // Update badges
      const newAlerts = alerts.filter(a => a.status === 'new').length;
      document.getElementById('alerts-badge').textContent  = newAlerts  || '0';
      document.getElementById('events-badge').textContent  = events.length || '0';

      // Threat level indicator
      this._updateThreatLevel(alerts);

      // Metric counters
      document.getElementById('metric-events-value').textContent   = events.length;
      document.getElementById('metric-alerts-value').textContent   = newAlerts;

      // Live feed (dashboard)
      if (this.currentView === 'dashboard') {
        window.dashboard?.renderEventFeed(events.slice(-40).reverse());
        window.dashboard?.renderAlertSummary(alerts.slice(0, 8));
      }

      // Refresh current view
      if (this.currentView === 'alerts')        window.incident?.renderAlerts(alerts);
      if (this.currentView === 'events')        window.dashboard?.renderEventsTable(events);
    } catch(_) { /* silent poll failure */ }
  }

  // ── Timer ──────────────────────────────────────────────────
  _updateTimer() {
    if (!this.sessionStartedAt) return;
    const secs = Math.floor((Date.now() - this.sessionStartedAt.getTime()) / 1000);
    const m = String(Math.floor(secs / 60)).padStart(2, '0');
    const s = String(secs % 60).padStart(2, '0');
    document.getElementById('session-timer').textContent = `${m}:${s}`;
  }

  _tickClock() {
    const now = new Date();
    document.getElementById('topbar-clock').textContent =
      now.toLocaleTimeString('en-GB', { hour12: false });
  }

  // ── Threat level ───────────────────────────────────────────
  _updateThreatLevel(alerts) {
    const el   = document.getElementById('threat-level-indicator');
    const lbl  = document.getElementById('threat-level-text');
    const crit = alerts.filter(a => a.severity === 'critical' && a.status === 'new').length;
    const high = alerts.filter(a => a.severity === 'high'     && a.status === 'new').length;
    el.className = 'threat-level';
    if (crit > 0) {
      el.classList.add('danger');  lbl.textContent = 'CRITICAL';
    } else if (high > 0) {
      el.classList.add('warning'); lbl.textContent = 'ELEVATED';
    } else {
      lbl.textContent = 'NOMINAL';
    }
  }

  // ── Score ──────────────────────────────────────────────────
  async _loadScore() {
    if (!this.sessionId) return;
    try {
      const data = await api.getScore(this.sessionId);
      if (data && data.total_score !== undefined) {
        document.getElementById('metric-score-value').textContent =
          data.total_score.toFixed(1);
      }
    } catch(_) {}
  }

  // ── Modal helpers ──────────────────────────────────────────
  _closeModal() {
    document.getElementById('start-modal').classList.add('hidden');
  }

  // ── Toast notifications ────────────────────────────────────
  toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = `toast ${type}`;

    const icon = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' }[type] || 'ℹ';
    el.innerHTML = `<span style="font-size:16px;opacity:0.8">${icon}</span><span>${message}</span>`;

    container.appendChild(el);
    setTimeout(() => {
      el.classList.add('toast-out');
      el.addEventListener('animationend', () => el.remove());
    }, 3500);
  }

  // ── Notification banner ────────────────────────────────────
  notify(message) {
    const banner = document.getElementById('notification-banner');
    document.getElementById('notification-text').textContent = message;
    banner.classList.remove('hidden');
    setTimeout(() => banner.classList.add('hidden'), 6000);
  }

  // ── Utility ────────────────────────────────────────────────
  formatTime(isoStr) {
    if (!isoStr) return '—';
    return new Date(isoStr).toLocaleTimeString('en-GB', { hour12: false });
  }

  formatDatetime(isoStr) {
    if (!isoStr) return '—';
    const d = new Date(isoStr);
    return d.toLocaleDateString('en-GB') + ' ' + d.toLocaleTimeString('en-GB', { hour12: false });
  }

  severityBadge(sev) {
    return `<span class="severity-badge sev-${sev}">${sev}</span>`;
  }

  statusChip(status) {
    return `<span class="status-chip status-${status}">${status}</span>`;
  }
}

window.app = new App();
window.showAuthModal = () => window.app.showAuthModal();
