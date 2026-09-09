/**
 * scenario_editor.js — Visual Scenario Editor Module
 * Allows analysts and admins to visually build custom attack scenarios
 */

window.initScenarioEditor = function() {
  const container = document.getElementById('scenario-editor-container');
  if (!container) return;

  container.innerHTML = `
    <div class="editor-card" style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 12px; padding: 24px; backdrop-filter: blur(12px);">
      <h2 style="color: #6366f1; margin-top: 0; display: flex; align-items: center; gap: 10px;">
        🎨 Görsel Senaryo Editörü (Custom Scenario Builder)
      </h2>
      <p style="color: #94a3b8; font-size: 14px;">
        Kendi özel siber saldırı simülasyon senaryonuzu görsel olarak tasarlayın, olay zamanlamalarını ve MITRE ATT&CK tekniklerini belirleyerek doğrudan kaydedin.
      </p>

      <form id="scenario-builder-form" style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px;">
        <div>
          <label style="display: block; color: #cbd5e1; font-weight: 600; margin-bottom: 6px;">Senaryo Kimliği (ID)</label>
          <input type="text" id="editor-scen-id" placeholder="ör. custom_apt_attack" required style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc;">
        </div>

        <div>
          <label style="display: block; color: #cbd5e1; font-weight: 600; margin-bottom: 6px;">Senaryo Başlığı (Name)</label>
          <input type="text" id="editor-scen-name" placeholder="ör. Gelişmiş Ransomware & SQLi Saldırısı" required style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc;">
        </div>

        <div>
          <label style="display: block; color: #cbd5e1; font-weight: 600; margin-bottom: 6px;">Zorluk Seviyesi</label>
          <select id="editor-scen-difficulty" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc;">
            <option value="beginner">Beginner (Başlangıç)</option>
            <option value="intermediate">Intermediate (Orta Seviye)</option>
            <option value="advanced">Advanced (İleri Seviye)</option>
            <option value="expert">Expert (Uzman - APT)</option>
          </select>
        </div>

        <div>
          <label style="display: block; color: #cbd5e1; font-weight: 600; margin-bottom: 6px;">Saldırı Kategorisi</label>
          <input type="text" id="editor-scen-category" placeholder="ör. Ransomware / Lateral Movement" required style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc;">
        </div>

        <div style="grid-column: span 2;">
          <label style="display: block; color: #cbd5e1; font-weight: 600; margin-bottom: 6px;">Açıklama & Detaylar</label>
          <textarea id="editor-scen-desc" rows="3" placeholder="Senaryo arka planı, etkilenen sistemler ve hedefler..." style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc;"></textarea>
        </div>

        <div style="grid-column: span 2;">
          <label style="display: block; color: #cbd5e1; font-weight: 600; margin-bottom: 6px;">Analist Hedefi (Objective)</label>
          <input type="text" id="editor-scen-objective" placeholder="ör. Zararlı IP'yi engelle ve etkilenen web sunucusunu izole et." required style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc;">
        </div>

        <div>
          <label style="display: block; color: #cbd5e1; font-weight: 600; margin-bottom: 6px;">Süre Sınırı (Saniye)</label>
          <input type="number" id="editor-scen-timelimit" value="1800" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc;">
        </div>

        <div style="grid-column: span 2; margin-top: 10px;">
          <button type="submit" style="background: linear-gradient(135deg, #6366f1, #4f46e5); color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 8px;">
            💾 Senaryoyu Kaydet ve Kütüphaneye Ekle
          </button>
        </div>
      </form>
      <div id="editor-status-msg" style="margin-top: 15px; font-weight: 600;"></div>
    </div>
  `;

  document.getElementById('scenario-builder-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const statusMsg = document.getElementById('editor-status-msg');
    statusMsg.style.color = '#38bdf8';
    statusMsg.textContent = 'Senaryo kaydediliyor...';

    const payload = {
      id: document.getElementById('editor-scen-id').value.trim(),
      name: document.getElementById('editor-scen-name').value.trim(),
      difficulty: document.getElementById('editor-scen-difficulty').value,
      category: document.getElementById('editor-scen-category').value.trim(),
      description: document.getElementById('editor-scen-desc').value.trim(),
      objective: document.getElementById('editor-scen-objective').value.trim(),
      time_limit_secs: parseInt(document.getElementById('editor-scen-timelimit').value, 10) || 1800,
    };

    try {
      const res = await window.api.createCustomScenario(payload);
      statusMsg.style.color = '#4ade80';
      statusMsg.textContent = `✅ Senaryo başarıyla oluşturuldu! ID: ${res.scenario_id}`;
      // Refresh scenario list if function exists
      if (window.loadScenarios) window.loadScenarios();
    } catch (err) {
      statusMsg.style.color = '#f87171';
      statusMsg.textContent = `❌ Hata: ${err.message}`;
    }
  });
};
