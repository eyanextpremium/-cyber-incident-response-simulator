/**
 * incident.js — Alert queue & incident lifecycle management
 */

class IncidentController {
  constructor() {
    this._selectedIncidentId = null;
    this._allAlerts   = [];
    this._allIncidents = [];

    document.getElementById('btn-create-incident')?.addEventListener('click', () => this._showCreateModal());
    document.getElementById('alerts-search')?.addEventListener('input', e => this._filterAlerts(e.target.value));
    document.getElementById('alerts-status-filter')?.addEventListener('change', e => this._filterAlerts(null, e.target.value));
  }

  // ── Alerts ─────────────────────────────────────────────────
  async loadAlerts() {
    if (!app.sessionId) return;
    try {
      const data = await api.listAlerts(app.sessionId);
      this._allAlerts = data.alerts || [];
      this.renderAlerts(this._allAlerts);
    } catch(e) {
      app.toast(`Alerts load failed: ${e.message}`, 'error');
    }
  }

  renderAlerts(alerts) {
    this._allAlerts = alerts;
    const list = document.getElementById('alerts-list');
    if (!list) return;
    if (!alerts || alerts.length === 0) {
      list.innerHTML = '<div class="feed-empty"><p>No alerts for this session</p></div>';
      return;
    }

    // Sort: critical first, then by time desc
    const sorted = [...alerts].sort((a, b) => {
      const sevOrder = { critical:0, high:1, medium:2, low:3 };
      const sd = (sevOrder[a.severity]||4) - (sevOrder[b.severity]||4);
      if (sd !== 0) return sd;
      return new Date(b.created_at) - new Date(a.created_at);
    });

    list.innerHTML = sorted.map(a => this._alertCard(a)).join('');
  }

  _alertCard(a) {
    const isNew = a.status === 'new';
    const source = a.source ? `<span>Source: ${this._esc(a.source)}</span>` : '';
    const timeStr = app.formatDatetime(a.created_at);
    const ackBtn = isNew
      ? `<button class="btn-ack" onclick="incident.ackAlert('${a.id}',this)">Acknowledge</button>` : '';
    const fpBtn = isNew || a.status === 'acknowledged'
      ? `<button class="btn-fp" onclick="incident.markFP('${a.id}',this)">False Positive</button>` : '';

    return `
      <div class="alert-card sev-${a.severity}" id="alert-card-${a.id}">
        <div class="alert-card-body">
          <div class="alert-card-title">${this._esc(a.title)}</div>
          <div class="alert-card-desc">${this._esc(a.description)}</div>
          <div class="alert-card-meta">
            ${app.severityBadge(a.severity)}
            ${app.statusChip(a.status)}
            ${source}
            <span>${timeStr}</span>
          </div>
        </div>
        <div class="alert-card-actions">
          ${ackBtn}
          ${fpBtn}
        </div>
      </div>`;
  }

  async ackAlert(alertId, btn) {
    btn.disabled = true;
    try {
      await api.acknowledgeAlert(app.sessionId, alertId);
      app.toast('Alert acknowledged', 'success');
      await this.loadAlerts();
    } catch(e) {
      app.toast(`Acknowledge failed: ${e.message}`, 'error');
      btn.disabled = false;
    }
  }

  async markFP(alertId, btn) {
    btn.disabled = true;
    try {
      await api.updateAlert(app.sessionId, alertId, 'false_positive');
      app.toast('Marked as false positive', 'info');
      await this.loadAlerts();
    } catch(e) {
      app.toast(`Update failed: ${e.message}`, 'error');
      btn.disabled = false;
    }
  }

  _filterAlerts(text, status) {
    let filtered = this._allAlerts;
    const searchText  = text !== null ? text : (document.getElementById('alerts-search')?.value || '');
    const statusFilter = status !== undefined ? status : (document.getElementById('alerts-status-filter')?.value || '');
    if (searchText) {
      const lower = searchText.toLowerCase();
      filtered = filtered.filter(a =>
        a.title?.toLowerCase().includes(lower) ||
        a.description?.toLowerCase().includes(lower));
    }
    if (statusFilter) {
      filtered = filtered.filter(a => a.status === statusFilter);
    }
    this.renderAlerts(filtered);
  }

  // ── Incidents ──────────────────────────────────────────────
  async loadIncidents() {
    if (!app.sessionId) return;
    try {
      const data = await api.listIncidents(app.sessionId);
      this._allIncidents = data.incidents || [];
      this._renderIncidentList(this._allIncidents);
      document.getElementById('metric-incidents-value').textContent =
        this._allIncidents.filter(i => i.status !== 'closed').length;
    } catch(e) {
      app.toast(`Incidents load failed: ${e.message}`, 'error');
    }
  }

  _renderIncidentList(incidents) {
    const panel = document.getElementById('incidents-list-panel');
    if (!panel) return;
    if (!incidents || incidents.length === 0) {
      panel.innerHTML = '<div class="feed-empty"><p>No incidents yet</p></div>';
      return;
    }
    panel.innerHTML = incidents.map(i => `
      <div class="incident-list-item ${this._selectedIncidentId === i.id ? 'selected' : ''}"
           onclick="incident.selectIncident('${i.id}')">
        <div class="incident-item-header">
          <span class="incident-item-title">${this._esc(i.title)}</span>
          ${app.severityBadge(i.severity)}
        </div>
        <div class="incident-item-meta">
          ${app.statusChip(i.status)}
          <span>${app.formatTime(i.created_at)}</span>
        </div>
      </div>`).join('');
  }

  selectIncident(id) {
    this._selectedIncidentId = id;
    const inc = this._allIncidents.find(i => i.id === id);
    if (!inc) return;
    this._renderIncidentList(this._allIncidents);
    this._renderIncidentDetail(inc);
    document.getElementById('incident-detail-panel').classList.remove('hidden');
  }

  _renderIncidentDetail(inc) {
    const STEPS = ['new','investigating','contained','eradicated','recovered','closed'];
    const curIdx = STEPS.indexOf(inc.status);

    const pipeline = STEPS.map((s, i) => {
      const stateClass = i < curIdx ? 'done' : (i === curIdx ? 'active' : '');
      const icons = { new:'🔴', investigating:'🔍', contained:'🔒', eradicated:'🧹', recovered:'✅', closed:'📁' };
      return `<div class="pipeline-step ${stateClass}">
        <span class="pipeline-step-icon">${icons[s]}</span>
        <span class="pipeline-step-label">${s}</span>
      </div>`;
    }).join('');

    const nextStatus = { new:'investigating', investigating:'contained', contained:'eradicated', eradicated:'recovered', recovered:'closed' };
    const next = nextStatus[inc.status];
    const advanceBtn = next
      ? `<button class="btn-advance critical" onclick="incident.advanceIncident('${inc.id}','${next}')">
           Advance to: ${next.charAt(0).toUpperCase() + next.slice(1)} →
         </button>` : '';

    document.getElementById('incident-detail-content').innerHTML = `
      <div class="incident-detail-header">
        <div>
          <div class="incident-detail-title">${this._esc(inc.title)}</div>
          <div class="incident-detail-meta" style="margin-top:10px">
            ${app.severityBadge(inc.severity)}
            ${app.statusChip(inc.status)}
          </div>
        </div>
      </div>
      <div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px">IR Progress</div>
        <div class="ir-pipeline">${pipeline}</div>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);line-height:1.6;padding:12px;background:var(--bg-card);border-radius:8px;border:1px solid var(--border-subtle)">
        ${this._esc(inc.description) || 'No description provided.'}
      </div>
      <div class="incident-actions">
        ${advanceBtn}
      </div>
      <div style="font-size:11px;color:var(--text-muted)">
        Created: ${app.formatDatetime(inc.created_at)} &nbsp;|&nbsp; Updated: ${app.formatDatetime(inc.updated_at)}
      </div>`;
  }

  async advanceIncident(incId, targetStatus) {
    try {
      await api.updateIncident(app.sessionId, incId, targetStatus);
      app.toast(`Incident advanced to ${targetStatus}`, 'success');
      await this.loadIncidents();
      const updated = this._allIncidents.find(i => i.id === incId);
      if (updated) this._renderIncidentDetail(updated);
    } catch(e) {
      app.toast(`Update failed: ${e.message}`, 'error');
    }
  }

  _showCreateModal() {
    const title    = prompt('Incident title:');
    if (!title) return;
    const severity = prompt('Severity (low/medium/high/critical):', 'medium');
    const desc     = prompt('Description (optional):', '');
    this._createIncident(title, severity || 'medium', desc || '');
  }

  async _createIncident(title, severity, description) {
    try {
      await api.createIncident(app.sessionId, title, severity, description);
      app.toast('Incident created', 'success');
      await this.loadIncidents();
    } catch(e) {
      app.toast(`Create failed: ${e.message}`, 'error');
    }
  }

  _esc(s) {
    if (!s) return '';
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }
}

window.incident = new IncidentController();
