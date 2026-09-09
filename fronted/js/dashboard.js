/**
 * dashboard.js — Scenario library, event feed, metrics rendering
 */

class Dashboard {
  constructor() {
    this._allScenarios = [];
    this._allEvents    = [];
    this._mitreCategories = [];
    this._currentFilter = 'all';
    this._currentMitreCategory = '';
    this._eventsFilter = { source: '', text: '', maliciousOnly: false };

    // Scenario filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this._currentFilter = btn.dataset.filter;
        this._currentMitreCategory = '';
        const mitreFilter = document.getElementById('mitre-category-filter');
        if (mitreFilter) {
          mitreFilter.classList.toggle('hidden', this._currentFilter !== 'mitre');
        }
        this._applyScenarioFilter();
      });
    });

    // Event table search
    document.getElementById('events-search')?.addEventListener('input', e => {
      this._eventsFilter.text = e.target.value.toLowerCase();
      this._applyEventFilter();
    });
    document.getElementById('events-source-filter')?.addEventListener('change', e => {
      this._eventsFilter.source = e.target.value;
      this._applyEventFilter();
    });
    document.getElementById('malicious-only-toggle')?.addEventListener('change', e => {
      this._eventsFilter.maliciousOnly = e.target.checked;
      this._applyEventFilter();
    });
  }

  // ── Dashboard ──────────────────────────────────────────────
  async loadDashboard() {
    if (!app.sessionId) return;
    try {
      const [evRes, alRes, incRes] = await Promise.all([
        api.listEvents(app.sessionId),
        api.listAlerts(app.sessionId),
        api.listIncidents(app.sessionId),
      ]);
      const events    = evRes.events    || [];
      const alerts    = alRes.alerts    || [];
      const incidents = incRes.incidents || [];

      document.getElementById('metric-events-value').textContent    = events.length;
      document.getElementById('metric-alerts-value').textContent    = alerts.filter(a => a.status === 'new').length;
      document.getElementById('metric-incidents-value').textContent = incidents.filter(i => i.status !== 'closed').length;
      document.getElementById('feed-count').textContent             = `${events.length} events`;

      this.renderEventFeed(events.slice(-40).reverse());
      this.renderAlertSummary(alerts.slice(0, 8));
    } catch(e) {
      console.error('Dashboard load error:', e);
    }
  }

  // ── Live event feed (dashboard panel) ─────────────────────
  renderEventFeed(events) {
    const feed = document.getElementById('event-feed');
    if (!events || events.length === 0) {
      feed.innerHTML = '<div class="feed-empty"><p>No events yet</p></div>';
      return;
    }
    feed.innerHTML = events.map(ev => this._feedItem(ev)).join('');
  }

  _feedItem(ev) {
    const srcClass = this._sourceClass(ev.source);
    const srcLabel = this._sourceLabel(ev.source);
    const time     = app.formatTime(ev.timestamp);
    const msg      = this._esc(ev.message);
    const malClass = ev.is_malicious ? ' malicious' : '';
    const mitre    = ev.mitre_technique
      ? `<span class="mitre-tag">${ev.mitre_technique}</span>` : '';
    return `
      <div class="feed-item${malClass}">
        <span class="feed-time">${time}</span>
        <span class="feed-source-tag ${srcClass}">${srcLabel}</span>
        <span class="feed-msg" title="${msg}">${msg}</span>
        ${mitre}
      </div>`;
  }

  // ── Alert summary (dashboard panel) ───────────────────────
  renderAlertSummary(alerts) {
    const el = document.getElementById('alerts-summary-list');
    if (!alerts || alerts.length === 0) {
      el.innerHTML = '<div class="feed-empty"><p>No alerts</p></div>';
      return;
    }
    el.innerHTML = alerts.map(a => `
      <div class="alert-summary-item" onclick="app.showView('alerts')">
        ${app.severityBadge(a.severity)}
        <span class="alert-title">${this._esc(a.title)}</span>
        <span class="alert-time">${app.formatTime(a.created_at)}</span>
      </div>`).join('');
  }

  // ── Events table view ─────────────────────────────────────
  async loadEvents() {
    if (!app.sessionId) return;
    try {
      const data = await api.listEvents(app.sessionId);
      this._allEvents = data.events || [];
      this._applyEventFilter();
    } catch(e) {
      app.toast(`Events load failed: ${e.message}`, 'error');
    }
  }

  renderEventsTable(events) {
    this._allEvents = events;
    this._applyEventFilter();
  }

  _applyEventFilter() {
    let filtered = this._allEvents;
    if (this._eventsFilter.maliciousOnly) filtered = filtered.filter(e => e.is_malicious);
    if (this._eventsFilter.source)        filtered = filtered.filter(e => e.source === this._eventsFilter.source);
    if (this._eventsFilter.text)          filtered = filtered.filter(e =>
      e.message.toLowerCase().includes(this._eventsFilter.text) ||
      e.host.toLowerCase().includes(this._eventsFilter.text));

    const tbody = document.getElementById('events-tbody');
    if (!tbody) return;
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:24px">No events match filter</td></tr>';
      return;
    }
    tbody.innerHTML = filtered.map(ev => {
      const mal = ev.is_malicious ? ' class="malicious"' : '';
      const mitre = ev.mitre_technique
        ? `<span class="mitre-tag">${ev.mitre_technique}</span>` : '—';
      const srcTag = `<span class="feed-source-tag ${this._sourceClass(ev.source)}">${this._sourceLabel(ev.source)}</span>`;
      return `<tr${mal}>
        <td><span style="font-family:var(--font-mono);font-size:11px">${app.formatTime(ev.timestamp)}</span></td>
        <td>${srcTag}</td>
        <td>${this._esc(ev.event_type)}</td>
        <td><code style="font-size:11px;color:var(--accent-bright)">${this._esc(ev.host)}</code></td>
        <td><code style="font-size:11px">${this._esc(ev.source_ip || '—')}</code></td>
        <td title="${this._esc(ev.message)}">${this._esc(ev.message)}</td>
        <td>${mitre}</td>
      </tr>`;
    }).join('');
  }

  // ── Scenario library ───────────────────────────────────────
  async loadScenarios() {
    const grid = document.getElementById('scenario-grid');
    grid.innerHTML = '<div class="loading-spinner">Loading scenarios…</div>';
    try {
      const data = await api.scenarios();
      this._allScenarios = data.scenarios || [];
      this._mitreCategories = data.mitre_categories || [];
      this._renderMitreCategoryFilter();
      this._applyScenarioFilter();
    } catch(e) {
      grid.innerHTML = `<div class="feed-empty"><p>Failed to load scenarios: ${e.message}</p></div>`;
    }
  }

  _renderMitreCategoryFilter() {
    const el = document.getElementById('mitre-category-filter');
    if (!el || !this._mitreCategories.length) return;
    const labels = {
      reconnaissance: 'Keşif', resource_development: 'Kaynak Geliştirme',
      initial_access: 'İlk Erişim', execution: 'İdam', persistence: 'Süreklilik',
      privilege_escalation: 'Ayrıcalık Yükseltme', defense_evasion: 'Savunma Kaçışı',
      credential_access: 'Kimlik Erişimi', discovery: 'Keşif (Discovery)',
      lateral_movement: 'Yan Hareket', collection: 'Koleksiyon',
      command_and_control: 'Komuta ve Kontrol', exfiltration: 'Çıkarma', impact: 'Impact',
    };
    el.innerHTML = `<button class="filter-btn mitre-cat-btn active" data-mitre-cat="">Tüm MITRE</button>` +
      this._mitreCategories.map(c =>
        `<button class="filter-btn mitre-cat-btn" data-mitre-cat="${c.category}">${labels[c.category] || c.category} (${c.count})</button>`
      ).join('');
    el.querySelectorAll('.mitre-cat-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        el.querySelectorAll('.mitre-cat-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this._currentMitreCategory = btn.dataset.mitreCat;
        this._applyScenarioFilter();
      });
    });
  }

  _applyScenarioFilter() {
    let filtered = this._allScenarios;
    if (this._currentFilter === 'mitre') {
      filtered = filtered.filter(s => s.is_mitre || s.id.startsWith('mitre-'));
      if (this._currentMitreCategory) {
        filtered = filtered.filter(s => s.category === this._currentMitreCategory);
      }
    } else if (this._currentFilter !== 'all') {
      filtered = filtered.filter(s => s.difficulty === this._currentFilter);
    }
    this._renderScenarios(filtered);
  }

  filterScenarios(difficulty) {
    this._currentFilter = difficulty;
    this._applyScenarioFilter();
  }

  _renderScenarios(scenarios) {
    const grid = document.getElementById('scenario-grid');
    if (!scenarios.length) {
      grid.innerHTML = '<div class="feed-empty"><p>No scenarios found</p></div>';
      return;
    }
    grid.innerHTML = scenarios.map(s => this._scenarioCard(s)).join('');
  }

  _scenarioCard(s) {
    const diffClass = `diff-${s.difficulty}`;
    const mins      = Math.round((s.time_limit_secs || 1800) / 60);
    const cardClass = `difficulty-${s.difficulty}`;
    const isMitre   = s.is_mitre || s.id?.startsWith('mitre-');
    const mitreBadge = isMitre ? '<span class="mitre-badge">MITRE</span>' : '';
    return `
      <div class="scenario-card ${cardClass}" onclick="app.launchScenario('${s.id}','${this._esc(s.name)}','${this._esc(s.description)}','${this._esc(s.objective)}')">
        <div class="scenario-card-header">
          <div class="scenario-card-title">${this._esc(s.name)} ${mitreBadge}</div>
          <span class="difficulty-badge ${diffClass}">${s.difficulty}</span>
        </div>
        <div class="scenario-card-desc">${this._esc(s.description)}</div>
        <div class="scenario-card-meta">
          <span class="meta-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            ${mins} min
          </span>
          <span class="meta-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            ${s.category}
          </span>
        </div>
        <div class="scenario-card-footer">
          <span class="category-tag">${s.scenario_type || s.category}</span>
          <span class="btn-launch">Launch →</span>
        </div>
      </div>`;
  }

  // ── Helpers ────────────────────────────────────────────────
  _sourceClass(src) {
    const map = {
      authentication: 'src-auth',
      firewall:       'src-firewall',
      endpoint:       'src-endpoint',
      network:        'src-network',
      web_server:     'src-web',
      email:          'src-email',
      dns:            'src-dns',
    };
    return map[src] || 'src-endpoint';
  }

  _sourceLabel(src) {
    const map = {
      authentication: 'AUTH',
      firewall:       'FW',
      endpoint:       'EDR',
      network:        'NET',
      web_server:     'WEB',
      email:          'MAIL',
      dns:            'DNS',
    };
    return map[src] || src?.toUpperCase() || '?';
  }

  _esc(s) {
    if (!s) return '';
    return String(s)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;')
      .replace(/'/g,'&#39;');
  }
}

window.dashboard = new Dashboard();
