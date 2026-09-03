/**
 * Intrusion Detection System (IDS) - Dashboard Application JS
 */

document.addEventListener('DOMContentLoaded', () => {
  let currentSeverity = 'all';
  let searchQuery = '';
  let pollInterval = null;

  // DOM Elements
  const totalAlertsEl = document.getElementById('stat-total-alerts');
  const criticalCountEl = document.getElementById('stat-critical-count');
  const uniqueSourcesEl = document.getElementById('stat-unique-sources');
  const activeFlowsEl = document.getElementById('stat-active-flows');
  const alertsTbody = document.getElementById('alerts-tbody');
  const attackerListEl = document.getElementById('attacker-list');
  const searchInput = document.getElementById('search-input');
  const pillGroup = document.getElementById('pill-group');
  const btnSimulate = document.getElementById('btn-simulate');
  const btnClear = document.getElementById('btn-clear');
  const btnRefresh = document.getElementById('btn-refresh');

  // Fetch Dashboard Stats
  async function fetchStats() {
    try {
      const res = await fetch('/api/stats');
      const data = await res.json();
      if (data.status === 'success') {
        totalAlertsEl.textContent = data.total_alerts;
        criticalCountEl.textContent = data.severities.critical + data.severities.high;
        uniqueSourcesEl.textContent = data.unique_sources;
        activeFlowsEl.textContent = data.active_flows || 0;

        renderTopAttackers(data.top_sources);
      }
    } catch (err) {
      console.error('Error fetching stats:', err);
    }
  }

  // Fetch Alerts List
  async function fetchAlerts() {
    try {
      const url = `/api/alerts?severity=${encodeURIComponent(currentSeverity)}&search=${encodeURIComponent(searchQuery)}&limit=100`;
      const res = await fetch(url);
      const data = await res.json();

      if (data.status === 'success') {
        renderAlertsTable(data.alerts);
      }
    } catch (err) {
      console.error('Error fetching alerts:', err);
    }
  }

  // Render Alerts Table
  function renderAlertsTable(alerts) {
    if (!alerts || alerts.length === 0) {
      alertsTbody.innerHTML = `
        <tr>
          <td colspan="5">
            <div class="empty-state">
              <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
              <span>No alerts found matching current filters</span>
            </div>
          </td>
        </tr>`;
      return;
    }

    const rowsHtml = alerts.map(a => {
      const sevClass = (a.severity || 'low').toLowerCase();
      return `
        <tr>
          <td><span class="time-tag">${escapeHtml(a.timestamp || '')}</span></td>
          <td><span class="badge-sev ${sevClass}">${escapeHtml(a.severity || 'low')}</span></td>
          <td><strong style="color: #fff">${escapeHtml(a.name || 'Detection')}</strong> <span style="font-size:0.75rem; color:var(--text-dim);">(${escapeHtml(a.rule_id || '')})</span></td>
          <td><span class="ip-tag">${escapeHtml(a.source || 'N/A')}</span></td>
          <td style="color: var(--text-muted); font-size: 0.82rem;">${escapeHtml(a.message || '')}</td>
        </tr>
      `;
    }).join('');

    alertsTbody.innerHTML = rowsHtml;
  }

  // Render Top Attacker IPs
  function renderTopAttackers(topSources) {
    if (!topSources || topSources.length === 0) {
      attackerListEl.innerHTML = `<div class="empty-state" style="padding:20px;"><span>No active threat sources</span></div>`;
      return;
    }

    const html = topSources.map(s => `
      <div class="attacker-item">
        <span class="attacker-ip">${escapeHtml(s.ip)}</span>
        <span class="attacker-count">${s.count} alerts</span>
      </div>
    `).join('');

    attackerListEl.innerHTML = html;
  }

  // Helper HTML Escaping
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Event Listeners
  pillGroup.addEventListener('click', (e) => {
    if (e.target.classList.contains('pill')) {
      document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      e.target.classList.add('active');
      currentSeverity = e.target.dataset.sev;
      fetchAlerts();
    }
  });

  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.trim();
    fetchAlerts();
  });

  btnSimulate.addEventListener('click', async () => {
    btnSimulate.disabled = true;
    btnSimulate.style.opacity = '0.6';
    try {
      await fetch('/api/alerts/simulate', { method: 'POST' });
      await fetchStats();
      await fetchAlerts();
    } catch (err) {
      console.error('Simulation failed:', err);
    } finally {
      btnSimulate.disabled = false;
      btnSimulate.style.opacity = '1';
    }
  });

  btnClear.addEventListener('click', async () => {
    if (confirm('Clear all logged alerts?')) {
      try {
        await fetch('/api/alerts/clear', { method: 'POST' });
        await fetchStats();
        await fetchAlerts();
      } catch (err) {
        console.error('Clear failed:', err);
      }
    }
  });

  btnRefresh.addEventListener('click', () => {
    fetchStats();
    fetchAlerts();
  });

  // Initial Load & Automatic 2-Second Refresh Loop
  fetchStats();
  fetchAlerts();
  pollInterval = setInterval(() => {
    fetchStats();
    fetchAlerts();
  }, 2000);
});
