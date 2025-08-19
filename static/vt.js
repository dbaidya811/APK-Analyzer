(function(){
  const sha = window.__SHA256__;
  const $ = (sel) => document.querySelector(sel);
  const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };

  const formatDate = (ts) => ts ? new Date(ts * 1000).toLocaleString() : '-';
  const formatBytes = (b) => {
    if (b == null) return '-';
    const units = ['B','KB','MB','GB'];
    let i = 0; let n = Number(b);
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(1)} ${units[i]} (${b})`;
  };

  async function load() {
    setText('sha256', sha);
    // External VirusTotal link removed per requirements

    try {
      const res = await fetch(`/api/virustotal/${encodeURIComponent(sha)}`);
      const vt = await res.json();
      const statusEl = $('#status');
      statusEl.classList.remove('low','medium','high','neutral');

      if (!res.ok) {
        statusEl.textContent = vt && vt.error ? vt.error : `HTTP ${res.status}`;
        statusEl.classList.add('neutral');
        return;
      }

      if (vt.enabled === false) {
        statusEl.textContent = 'Disabled (No API key)';
        statusEl.classList.add('neutral');
        return;
      }
      if (vt.error) {
        statusEl.textContent = vt.error;
        statusEl.classList.add('neutral');
        return;
      }
      if (vt.found === false) {
        statusEl.textContent = 'Not found on VirusTotal';
        statusEl.classList.add('neutral');
        return;
      }

      statusEl.textContent = 'Found';

      // Stats and badge color
      const stats = vt.stats || {};
      $('#stats').textContent = JSON.stringify(stats, null, 2);
      const mal = Number(stats.malicious || 0);
      const susp = Number(stats.suspicious || 0);
      if (mal >= 10 || (mal >= 5 && susp >= 3)) statusEl.classList.add('high');
      else if (mal >= 3 || susp >= 2) statusEl.classList.add('medium');
      else statusEl.classList.add('low');

      // File info
      setText('meaningful_name', vt.meaningful_name || '-');
      setText('type_description', vt.type_description || '-');
      setText('magic', vt.magic || '-');
      setText('size', formatBytes(vt.size));
      setText('times_submitted', vt.times_submitted ?? '-');
      setText('first_submission_date', formatDate(vt.first_submission_date));
      setText('last_submission_date', formatDate(vt.last_submission_date));

      // Votes & tags
      $('#votes').textContent = JSON.stringify(vt.total_votes || {}, null, 2);
      $('#tags').textContent = JSON.stringify(vt.tags || [], null, 2);

      // Threat classification
      $('#threat_classification').textContent = JSON.stringify(vt.popular_threat_classification || {}, null, 2);

      // Engines table
      const tbody = $('#engines_table tbody');
      const results = vt.last_analysis_results || {};
      const rows = Object.entries(results).sort((a,b)=>{
        // malicious first, then suspicious, then others
        const order = {malicious:0, suspicious:1, undetected:2, harmless:3, timeout:4, failure:5, type_unsupported:6};
        const ca = order[(a[1]||{}).category] ?? 99;
        const cb = order[(b[1]||{}).category] ?? 99;
        if (ca !== cb) return ca - cb;
        return a[0].localeCompare(b[0]);
      });
      for (const [engine, r] of rows) {
        const tr = document.createElement('tr');
        const cat = (r && r.category) || '-';
        tr.classList.add(`cat-${cat}`);
        tr.innerHTML = `
          <td>${engine}</td>
          <td>${cat}</td>
          <td>${(r && (r.result || r.engine_name || '-')) || '-'}</td>
          <td>${(r && r.method) || '-'}</td>
          <td>${(r && r.engine_version) || '-'}</td>
          <td>${(r && r.engine_update) || '-'}</td>
        `;
        tbody.appendChild(tr);
      }
    } catch (e) {
      const statusEl = $('#status');
      statusEl.textContent = 'Failed to load VirusTotal data';
      statusEl.classList.add('neutral');
    }
  }

  document.addEventListener('DOMContentLoaded', load);
})();
