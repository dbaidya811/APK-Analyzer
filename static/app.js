const form = document.getElementById('uploadForm');
const fileInput = document.getElementById('fileInput');
const statusEl = document.getElementById('status');
const resultsSection = document.getElementById('results');
const introEl = document.getElementById('intro');
const rawJsonEl = document.getElementById('rawJson');

function setText(selector, value) {
  const el = document.querySelector(`[data-field="${selector}"]`);
  if (el) el.textContent = value ?? '-';
}

function setList(name, arr) {
  const el = document.querySelector(`[data-list="${name}"]`);
  if (!el) return;
  el.innerHTML = '';
  if (!arr || arr.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'None';
    el.appendChild(li);
    return;
  }
  for (const item of arr) {
    const li = document.createElement('li');
    if (typeof item === 'object' && item !== null) {
      li.textContent = JSON.stringify(item);
    } else {
      li.textContent = String(item);
    }
    el.appendChild(li);
  }
}

function setBadge(label) {
  const badge = document.querySelector('[data-field="risk_label"]');
  badge.textContent = label || '-';
  badge.classList.remove('low', 'medium', 'high');
  if (!label) return;
  const cls = label.toLowerCase();
  if (['low','medium','high'].includes(cls)) badge.classList.add(cls);
}

function setRecommendation(recText, riskLabel, reason) {
  const rec = document.querySelector('[data-field="recommendation"]');
  const recReason = document.querySelector('[data-field="recommendation_reason"]');
  rec.textContent = recText || '-';
  rec.classList.remove('low','medium','high');
  if (riskLabel) {
    const cls = String(riskLabel).toLowerCase();
    if (['low','medium','high'].includes(cls)) rec.classList.add(cls);
  }
  if (recReason) recReason.textContent = reason || '';
}

// Chart helpers
function destroyCharts() {
  if (!window.__charts) return;
  Object.values(window.__charts).forEach(ch => { try { ch.destroy(); } catch(e){} });
  window.__charts = {};
}

function renderRiskChart(score) {
  const ctx = document.getElementById('chart_risk');
  if (!ctx || typeof Chart === 'undefined') return;
  const s = Math.max(0, Math.min(10, Number(score || 0)));
  let color = '#86efac';
  if (s >= 6) color = '#fca5a5';
  else if (s >= 3) color = '#fde68a';
  const ch = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Risk','Remaining'],
      datasets: [{ data: [s, 10 - s], backgroundColor: [color, 'rgba(148,163,184,0.25)'], borderWidth: 0 }]
    },
    options: {
      plugins: {
        legend: { display: false },
        tooltip: { enabled: true }
      },
      cutout: '70%'
    }
  });
  (window.__charts ||= {}).risk = ch;
}

function renderPermissionsChart(total, dangerous) {
  const ctx = document.getElementById('chart_permissions');
  if (!ctx || typeof Chart === 'undefined') return;
  const dang = Math.max(0, Number(dangerous||0));
  const tot = Math.max(0, Number(total||0));
  const normal = Math.max(0, tot - dang);
  const ch = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Dangerous','Normal'],
      datasets: [{ data: [dang, normal], backgroundColor: ['#fbbf24','#60a5fa'], borderWidth: 0 }]
    },
    options: { plugins: { legend: { position: 'bottom' } }, cutout: '55%' }
  });
  (window.__charts ||= {}).perms = ch;
}

function renderComponentsChart(counts) {
  const ctx = document.getElementById('chart_components');
  if (!ctx || typeof Chart === 'undefined') return;
  const labels = ['Activities','Services','Receivers','URLs','Certificates'];
  const data = [
    (counts.activities||[]).length,
    (counts.services||[]).length,
    (counts.receivers||[]).length,
    (counts.urls||[]).length,
    (counts.certificates||[]).length,
  ];
  const ch = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Count', data, backgroundColor: '#a78bfa' }] },
    options: {
      plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: '#cbd5e1' } }, y: { beginAtZero: true, ticks: { stepSize: 1, color: '#cbd5e1' } } }
    }
  });
  (window.__charts ||= {}).components = ch;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!fileInput.files || fileInput.files.length === 0) {
    statusEl.textContent = 'Please choose an .apk file.';
    return;
  }
  const file = fileInput.files[0];
  if (!file.name.toLowerCase().endsWith('.apk')) {
    statusEl.textContent = 'Only .apk files are allowed.';
    return;
  }

  const data = new FormData();
  data.append('file', file);

  statusEl.textContent = 'Uploading and analyzing...';
  form.querySelector('button[type="submit"]').disabled = true;
  try {
    const res = await fetch('/upload', { method: 'POST', body: data });

    // Try to parse JSON safely
    let json = null;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try { json = await res.json(); } catch (_) { json = null; }
    } else {
      // Non-JSON response
      const text = await res.text();
      json = { ok: false, error: text || `HTTP ${res.status}` };
    }

    form.querySelector('button[type="submit"]').disabled = false;

    if (!res.ok || !json.ok) {
      // Special-case large file
      if (res.status === 413) {
        statusEl.textContent = 'File too large. Max allowed is 100 MB.';
      } else {
        statusEl.textContent = (json && json.error) ? json.error : `Upload failed (HTTP ${res.status})`;
      }
      resultsSection.classList.add('hidden');
    if (introEl) introEl.classList.remove('hidden');
      return;
    }

    statusEl.textContent = 'Analysis complete';

    // Summary
    setText('filename', json.filename);
    setText('app_name', json.app_name);
    setText('package_name', json.package_name);
    setText('version_name', json.version_name);
    setText('version_code', json.version_code);
    setText('debuggable', json.debuggable);
    setText('risk_score', json.risk_score);
    setBadge(json.risk_label);
    setRecommendation(json.recommendation, json.risk_label, json.recommendation_reason);

    // Lists
    setList('dangerous_permissions', json.dangerous_permissions);
    setList('permissions', json.permissions);
    setList('urls', json.urls);
    setList('activities', json.activities);
    setList('services', json.services);
    setList('receivers', json.receivers);
    setList('certificates', json.certificates);
    setList('risk_reasons', json.risk_reasons);

    rawJsonEl.textContent = JSON.stringify(json, null, 2);
    resultsSection.classList.remove('hidden');
    if (introEl) introEl.classList.add('hidden');

    // Render charts
    destroyCharts();
    renderRiskChart(json.risk_score);
    renderPermissionsChart((json.permissions||[]).length, (json.dangerous_permissions||[]).length);
    renderComponentsChart({
      activities: json.activities,
      services: json.services,
      receivers: json.receivers,
      urls: json.urls,
      certificates: json.certificates,
    });

  } catch (err) {
    form.querySelector('button[type="submit"]').disabled = false;
    statusEl.textContent = (err && err.message) ? err.message : 'Network or server error';
    resultsSection.classList.add('hidden');
  }
});
