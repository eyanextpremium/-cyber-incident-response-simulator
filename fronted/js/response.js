/**
 * response.js — Response playbook actions, action log, scoring render
 */

const RESPONSE_ACTIONS = [
  { action: 'acknowledge',     name: 'Acknowledge Alert',    icon: '🔔', desc: 'Mark an alert as seen',          category: 'investigate', targetLabel: 'Alert ID or title' },
  { action: 'investigate',     name: 'Investigate',          icon: '🔍', desc: 'Begin formal investigation',     category: 'investigate', targetLabel: 'Target / host' },
  { action: 'isolate_host',    name: 'Isolate Host',         icon: '🔌', desc: 'Cut host from network',          category: 'containment', targetLabel: 'Hostname or IP' },
  { action: 'block_ip',        name: 'Block IP Address',     icon: '🚫', desc: 'Firewall block attacker IP',     category: 'containment', targetLabel: 'IP address' },
  { action: 'contain',         name: 'Contain Incident',     icon: '🔒', desc: 'Apply containment measures',    category: 'containment', targetLabel: 'Incident ID' },
  { action: 'disable_account', name: 'Disable Account',      icon: '👤', desc: 'Disable compromised account',   category: 'eradication', targetLabel: 'Username / account' },
  { action: 'quarantine_file', name: 'Quarantine File',      icon: '📦', desc: 'Quarantine malicious file',     category: 'eradication', targetLabel: 'File path' },
  { action: 'eradicate',       name: 'Eradicate Threat',     icon: '🧹', desc: 'Remove all attacker footholds', category: 'eradication', targetLabel: 'Incident ID' },
  { action: 'recover',         name: 'Recover Systems',      icon: '✅', desc: 'Restore to operational state',  category: 'recovery',    targetLabel: 'Incident ID' },
  { action: 'close_incident',  name: 'Close Incident',       icon: '📁', desc: 'Formally close the incident',   category: 'recovery',    targetLabel: 'Incident ID' },
];

class Response {
  constructor() {
    this._pendingAction = null;

    // Action modal buttons
    document.getElementById('action-modal-close')?.addEventListener('click',   () => this._closeActionModal());
    document.getElementById('action-modal-cancel')?.addEventListener('click',  () => this._closeActionModal());
    document.getElementById('action-modal-execute')?.addEventListener('click', () => this._executeAction());
  }

  async load() {
    this._renderActionGrid();
    if (app.sessionId) await this._loadActionLog();
  }

  // ── Action grid ────────────────────────────────────────────
  _renderActionGrid() {
    const grid = document.getElementById('response-action-grid');
    if (!grid) return;
    grid.innerHTML = RESPONSE_ACTIONS.map(a => `
      <button class="action-btn ${a.category}" onclick="response.openAction('${a.action}')">
        <div class="action-btn-icon">${a.icon}</div>
        <div class="action-btn-name">${a.name}</div>
        <div class="action-btn-desc">${a.desc}</div>
      </button>`).join('');
  }

  openAction(actionType) {
    if (!app.sessionId) { app.toast('No active session — start a scenario first', 'warning'); return; }
    const def = RESPONSE_ACTIONS.find(a => a.action === actionType);
    if (!def) return;

    this._pendingAction = actionType;
    document.getElementById('action-modal-title').textContent = `${def.icon} ${def.name}`;
    document.getElementById('action-target-label').textContent = def.targetLabel;
    document.getElementById('action-target-input').value   = '';
    document.getElementById('action-incident-input').value = '';
    document.getElementById('action-details-input').value  = '';
    document.getElementById('action-modal').classList.remove('hidden');
    document.getElementById('action-target-input').focus();
  }

  _closeActionModal() {
    document.getElementById('action-modal').classList.add('hidden');
    this._pendingAction = null;
  }

  async _executeAction() {
    if (!this._pendingAction || !app.sessionId) return;
    const target     = document.getElementById('action-target-input').value.trim();
    const incidentId = document.getElementById('action-incident-input').value.trim() || null;
    const details    = document.getElementById('action-details-input').value.trim()  || null;

    if (!target) { app.toast('Target is required', 'warning'); return; }

    const btn = document.getElementById('action-modal-execute');
    btn.disabled = true;
    btn.textContent = 'Executing…';

    try {
      await api.executeAction(app.sessionId, this._pendingAction, target, incidentId, details);
      const def = RESPONSE_ACTIONS.find(a => a.action === this._pendingAction);
      app.toast(`${def?.icon || ''} ${def?.name || this._pendingAction} executed`, 'success');
      this._closeActionModal();
      await this._loadActionLog();
    } catch(e) {
      app.toast(`Action failed: ${e.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Execute';
    }
  }

  // ── Action log ─────────────────────────────────────────────
  async _loadActionLog() {
    try {
      const data = await api.listActions(app.sessionId);
      this._renderActionLog(data.actions || []);
    } catch(e) {
      console.error('Action log load:', e);
    }
  }

  _renderActionLog(actions) {
    const log = document.getElementById('action-log');
    if (!log) return;
    if (!actions.length) {
      log.innerHTML = '<div class="feed-empty"><p>No actions performed yet</p></div>';
      return;
    }
    const sorted = [...actions].sort((a,b) => new Date(b.performed_at) - new Date(a.performed_at));
    log.innerHTML = sorted.map(a => `
      <div class="action-log-entry">
        <div class="log-header">
          <span class="action-type-badge action-type-${a.action_type}">${a.action_type.replace(/_/g,' ')}</span>
          <span class="log-time">${app.formatDatetime(a.performed_at)}</span>
        </div>
        <div class="log-target">${this._esc(a.target)}</div>
        <div class="log-details">${this._esc(a.details)}</div>
      </div>`).join('');
  }

  _esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
}

window.response = new Response();

// ── Scoring renderer (called from app.js _finalize) ──────────
window.scoring = {
  render(result) {
    const { metrics, ranking } = result;
    const container = document.getElementById('scoring-container');
    if (!container || !ranking) return;

    const gradeColors = { S:'#a5b4fc', A:'#6ee7b7', B:'#93c5fd', C:'#fbbf24', D:'#fb923c', F:'#f87171' };
    const color = gradeColors[ranking.grade?.grade || ranking.grade] || '#a5b4fc';

    const bars = [
      { label: 'Detection',     val: metrics.detection_score,     max: 40 },
      { label: 'Investigation', val: metrics.investigation_score,  max: 20 },
      { label: 'Containment',   val: metrics.containment_score,    max: 25 },
      { label: 'Recovery',      val: metrics.recovery_score,       max: 15 },
    ];

    container.innerHTML = `
      <div class="score-report">
        <div class="score-grade-card">
          <div class="score-grade" style="-webkit-text-fill-color:${color}">${ranking.grade?.as_str || ranking.grade || 'B'}</div>
          <div class="score-grade-label">${ranking.label || ''}</div>
          <div class="score-total">${(metrics.total_score || 0).toFixed(1)} / 100</div>
          <div class="score-feedback">${ranking.feedback || ''}</div>
        </div>

        <div class="score-metrics-grid">
          ${bars.map(b => `
            <div class="score-metric-item">
              <div class="score-metric-label">${b.label}</div>
              <div class="score-metric-value">${(b.val||0).toFixed(1)}<span style="font-size:14px;color:var(--text-muted)"> / ${b.max}</span></div>
              <div class="score-bar-track">
                <div class="score-bar-fill" style="width:${Math.min(100,(b.val/b.max)*100).toFixed(1)}%"></div>
              </div>
            </div>`).join('')}
          <div class="score-metric-item">
            <div class="score-metric-label">Time Elapsed</div>
            <div class="score-metric-value" style="font-size:18px">${_fmtTime(metrics.time_elapsed_secs||0)}</div>
          </div>
          <div class="score-metric-item">
            <div class="score-metric-label">Penalties</div>
            <div class="score-metric-value" style="color:var(--danger)">
              -${((metrics.time_penalty||0)+(metrics.false_positive_penalty||0)).toFixed(1)}
            </div>
          </div>
        </div>
      </div>`;
  }
};

function _fmtTime(secs) {
  const m = Math.floor(secs/60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}
