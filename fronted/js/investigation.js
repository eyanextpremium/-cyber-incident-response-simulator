/**
 * investigation.js — Timeline, evidence collection, investigation summary
 */

class Investigation {
  constructor() {
    document.getElementById('btn-collect-evidence')?.addEventListener('click', () => this._collectEvidence());
  }

  async load() {
    if (!app.sessionId) return;
    await Promise.all([
      this._loadTimeline(),
      this._loadEvidence(),
      this._loadSummary(),
    ]);
  }

  // ── Timeline ───────────────────────────────────────────────
  async _loadTimeline() {
    try {
      const data = await api.getTimeline(app.sessionId);
      this._renderTimeline(data.timeline || []);
    } catch(e) {
      app.toast(`Timeline load failed: ${e.message}`, 'error');
    }
  }

  _renderTimeline(entries) {
    const container = document.getElementById('timeline-container');
    if (!container) return;
    if (!entries.length) {
      container.innerHTML = '<div class="feed-empty"><p>No events on timeline</p></div>';
      return;
    }

    container.innerHTML = entries.map(e => {
      const malClass = e.is_malicious ? ' malicious' : '';
      const mitre    = e.mitre_technique
        ? `<span class="mitre-tag">${e.mitre_technique}</span>` : '';
      const srcBadge = `<span class="feed-source-tag ${this._srcClass(e.source)}">${e.source?.toUpperCase().substring(0,4) || '?'}</span>`;

      return `
        <div class="timeline-entry${malClass}">
          <div class="timeline-entry-time">${app.formatDatetime(e.timestamp)}</div>
          <div class="timeline-entry-card">
            <div class="timeline-entry-header">
              ${srcBadge}
              <span class="timeline-entry-host">${this._esc(e.host)}</span>
              <span class="timeline-entry-type">${this._esc(e.event_type)}</span>
              ${mitre}
            </div>
            <div class="timeline-entry-desc">${this._esc(e.description)}</div>
          </div>
        </div>`;
    }).join('');
  }

  // ── Evidence ───────────────────────────────────────────────
  async _loadEvidence() {
    try {
      const data = await api.listEvidence(app.sessionId);
      this._renderEvidence(data.evidence || []);
    } catch(e) {
      console.error('Evidence load:', e);
    }
  }

  _renderEvidence(evidence) {
    const list = document.getElementById('evidence-list');
    if (!list) return;
    if (!evidence.length) {
      list.innerHTML = '<div class="feed-empty"><p>No evidence collected</p></div>';
      return;
    }
    list.innerHTML = evidence.map(e => {
      const iocClass = e.ioc_match ? ' ioc-hit' : '';
      const iocBadge = e.ioc_match
        ? '<span style="font-size:9px;color:var(--danger);font-weight:700">⚠ IOC</span>' : '';
      return `
        <div class="evidence-item${iocClass}">
          <div class="evidence-item-title">${this._esc(e.title)}</div>
          <div class="evidence-item-meta">
            <span class="evidence-type-badge">${this._esc(e.evidence_type)}</span>
            <span>${this._esc(e.source_host)}</span>
            ${iocBadge}
          </div>
        </div>`;
    }).join('');
  }

  async _collectEvidence() {
    if (!app.sessionId) {
      app.toast('No active session', 'warning');
      return;
    }
    const btn = document.getElementById('btn-collect-evidence');
    btn.disabled = true;
    btn.textContent = 'Collecting…';
    try {
      const data = await api.collectEvidence(app.sessionId);
      app.toast(`Collected ${data.collected} evidence items`, 'success');
      await this._loadEvidence();
      await this._loadSummary();
    } catch(e) {
      app.toast(`Collection failed: ${e.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Auto-Collect Evidence`;
    }
  }

  // ── Summary ────────────────────────────────────────────────
  async _loadSummary() {
    try {
      const data = await api.getInvestigationSummary(app.sessionId);
      this._renderSummary(data);
    } catch(_) {}
  }

  _renderSummary(s) {
    const el = document.getElementById('investigation-summary');
    if (!el) return;
    el.classList.remove('hidden');
    el.innerHTML = `
      <div class="panel-title" style="margin-bottom:8px">Summary</div>
      ${this._summaryRow('Total Events',       s.total_events       || 0)}
      ${this._summaryRow('Malicious Events',   s.malicious_events   || 0)}
      ${this._summaryRow('Compromised Hosts',  (s.compromised_hosts || []).length)}
      ${this._summaryRow('Attacker IPs',       (s.attacker_ips      || []).length)}
      ${this._summaryRow('Evidence Items',     s.evidence_count     || 0)}
      ${this._summaryRow('IOC Matches',        s.ioc_matches        || 0)}
      ${s.attacker_ips?.length ? `
        <div style="margin-top:8px;font-size:11px;color:var(--text-muted)">Attacker IPs:</div>
        ${(s.attacker_ips||[]).map(ip => `<code style="font-size:11px;color:var(--danger)">${ip}</code>`).join('<br>')}
      ` : ''}
      ${s.compromised_hosts?.length ? `
        <div style="margin-top:8px;font-size:11px;color:var(--text-muted)">Affected Hosts:</div>
        ${(s.compromised_hosts||[]).map(h => `<code style="font-size:11px;color:var(--warning)">${h}</code>`).join('<br>')}
      ` : ''}
    `;
  }

  _summaryRow(key, val) {
    return `<div class="summary-row"><span class="summary-key">${key}</span><span class="summary-val">${val}</span></div>`;
  }

  _srcClass(src) {
    const map = { authentication:'src-auth', firewall:'src-firewall', endpoint:'src-endpoint',
                  network:'src-network', web_server:'src-web', email:'src-email', dns:'src-dns' };
    return map[src] || 'src-endpoint';
  }

  _esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
}

window.investigation = new Investigation();
