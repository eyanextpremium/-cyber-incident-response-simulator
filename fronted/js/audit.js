/**
 * audit.js — Self-Audit module UI
 * Runs simulated attacks and static scans against the project itself
 */

class SelfAudit {
  constructor() {
    this._lastReport = null;
    document.getElementById('btn-run-audit')?.addEventListener('click', () => this.runAudit());
    document.getElementById('btn-quick-audit')?.addEventListener('click', () => this.quickCheck());
  }

  async runAudit() {
    const btn = document.getElementById('btn-run-audit');
    const resultsEl = document.getElementById('audit-results');
    btn.disabled = true;
    btn.querySelector('span').textContent = 'Tarama yapılıyor…';
    resultsEl.innerHTML = '<div class="loading-spinner">Self-audit çalışıyor — dosyalar taranıyor, sahte saldırılar simüle ediliyor…</div>';

    try {
      const report = await api.runSelfAudit();
      this._lastReport = report;
      this._renderReport(report);
      app.toast(`Self-audit tamamlandı — Güvenlik skoru: ${report.summary.security_score}/100`, report.summary.security_score >= 70 ? 'success' : 'error');
    } catch (e) {
      resultsEl.innerHTML = `<div class="feed-empty"><p>Audit başarısız: ${e.message}</p></div>`;
      app.toast(`Audit hatası: ${e.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.querySelector('span').textContent = 'Tam Self-Audit Başlat';
    }
  }

  async quickCheck() {
    try {
      const summary = await api.auditQuickCheck();
      this._renderQuickSummary(summary);
      app.toast(`Hızlı kontrol — Skor: ${summary.security_score}/100`, summary.security_score >= 70 ? 'success' : 'warning');
    } catch (e) {
      app.toast(`Hızlı kontrol hatası: ${e.message}`, 'error');
    }
  }

  _renderQuickSummary(summary) {
    const el = document.getElementById('audit-score-display');
    if (!el) return;
    el.innerHTML = this._scoreCard(summary);
  }

  _renderReport(report) {
    const el = document.getElementById('audit-results');
    if (!el) return;

    const s = report.summary;
    const scoreClass = s.security_score >= 80 ? 'score-good' : s.security_score >= 50 ? 'score-warn' : 'score-bad';

    let html = `
      <div class="audit-summary-grid">
        <div class="audit-score-card ${scoreClass}">
          <div class="audit-score-value">${s.security_score}</div>
          <div class="audit-score-label">Güvenlik Skoru</div>
        </div>
        <div class="audit-stat-card">
          <div class="audit-stat-value">${s.files_scanned}</div>
          <div class="audit-stat-label">Taranan Dosya</div>
        </div>
        <div class="audit-stat-card">
          <div class="audit-stat-value">${s.total_findings}</div>
          <div class="audit-stat-label">Bulgu</div>
        </div>
        <div class="audit-stat-card">
          <div class="audit-stat-value">${s.attack_tests_passed}/${s.attack_tests_run}</div>
          <div class="audit-stat-label">Saldırı Testi Geçti</div>
        </div>
      </div>

      <div class="audit-severity-bar">
        ${s.critical ? `<span class="sev-critical">${s.critical} Kritik</span>` : ''}
        ${s.high ? `<span class="sev-high">${s.high} Yüksek</span>` : ''}
        ${s.medium ? `<span class="sev-medium">${s.medium} Orta</span>` : ''}
        ${s.low ? `<span class="sev-low">${s.low} Düşük</span>` : ''}
        ${s.info ? `<span class="sev-info">${s.info} Bilgi</span>` : ''}
      </div>

      <div class="audit-meta">
        Audit ID: <code>${report.audit_id}</code> |
        Süre: ${report.duration_ms}ms |
        ${report.started_at}
      </div>`;

    // Attack test results
    if (report.attack_results?.length) {
      html += `<h3 class="audit-section-title">Saldırı Simülasyonları (${report.attack_results.length})</h3>
        <div class="audit-attack-grid">`;
      for (const t of report.attack_results) {
        const cls = t.passed ? 'attack-pass' : 'attack-fail';
        const icon = t.passed ? '✓' : '✗';
        html += `
          <div class="audit-attack-item ${cls}">
            <div class="attack-header">
              <span class="attack-icon">${icon}</span>
              <span class="attack-name">${this._esc(t.name)}</span>
              <span class="mitre-tag">${t.mitre_technique}</span>
            </div>
            <div class="attack-details">${this._esc(t.details)}</div>
          </div>`;
      }
      html += '</div>';
    }

    // Findings
    if (report.findings?.length) {
      html += `<h3 class="audit-section-title">Güvenlik Bulguları (${report.findings.length})</h3>
        <div class="audit-findings-list">`;
      for (const f of report.findings) {
        html += `
          <div class="audit-finding sev-${f.severity}">
            <div class="finding-header">
              <span class="finding-severity">${f.severity.toUpperCase()}</span>
              <span class="finding-title">${this._esc(f.title)}</span>
              ${f.mitre_technique ? `<span class="mitre-tag">${f.mitre_technique}</span>` : ''}
            </div>
            <div class="finding-desc">${this._esc(f.description)}</div>
            ${f.file_path ? `<div class="finding-location"><code>${this._esc(f.file_path)}${f.line_number ? ':' + f.line_number : ''}</code></div>` : ''}
            ${f.evidence ? `<div class="finding-evidence"><code>${this._esc(f.evidence)}</code></div>` : ''}
            <div class="finding-rec"><strong>Öneri:</strong> ${this._esc(f.recommendation)}</div>
          </div>`;
      }
      html += '</div>';
    } else {
      html += '<div class="feed-empty"><p>Güvenlik bulgusu tespit edilmedi — harika!</p></div>';
    }

    el.innerHTML = html;

    const scoreEl = document.getElementById('audit-score-display');
    if (scoreEl) scoreEl.innerHTML = this._scoreCard(s);
  }

  _scoreCard(s) {
    const scoreClass = s.security_score >= 80 ? 'score-good' : s.security_score >= 50 ? 'score-warn' : 'score-bad';
    return `
      <div class="audit-score-card ${scoreClass}" style="display:inline-block;padding:16px 24px;">
        <div class="audit-score-value" style="font-size:36px;">${s.security_score}</div>
        <div class="audit-score-label">/100</div>
      </div>
      <span style="margin-left:12px;color:var(--text-muted);font-size:13px;">
        ${s.critical} kritik, ${s.high} yüksek, ${s.total_findings} toplam bulgu
      </span>`;
  }

  _esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
}

window.selfAudit = new SelfAudit();
