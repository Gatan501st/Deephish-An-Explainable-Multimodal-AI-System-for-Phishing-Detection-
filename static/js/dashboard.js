// Dashboard JavaScript

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
  initializeDashboard();
  loadDashboardData();
  setInterval(loadDashboardData, 30000); // Refresh every 30 seconds
});

// Initialize charts
function initializeDashboard() {
  initializeDetectionChart();
  initializeThreatChart();
}

// Global chart instances
let detectionChart = null;
let threatChart = null;

// Load dashboard data from API
async function loadDashboardData() {
  try {
    const token = localStorage.getItem("access_token");
    if (!token) {
      // Not logged in, show public dashboard
      loadPublicDashboard();
      return;
    }

    // Load statistics from API
    const statsResponse = await fetch('/api/statistics?days=30', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (statsResponse.ok) {
      const stats = await statsResponse.json();
      updateStatsFromAPI(stats);
      updateChartsFromAPI(stats);
    }

    // Load recent history for activity
    const historyResponse = await fetch('/api/history?limit=10', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (historyResponse.ok) {
      const historyData = await historyResponse.json();
      updateActivityFromHistory(historyData.history || []);
    }
    
    // Load model performance (if available)
    loadModelPerformance();
  } catch (error) {
    console.error('Error loading dashboard data:', error);
    // Fallback to public dashboard
    loadPublicDashboard();
  }
}

// Load public dashboard (no auth required)
async function loadPublicDashboard() {
  try {
    const response = await fetch('/api/last_result');
    const data = await response.json();
    
    if (data && !data.message) {
      updateStats(data);
      updateActivity(data);
    }
  } catch (error) {
    console.error('Error loading public dashboard:', error);
  }
}

// Update stats from API statistics
function updateStatsFromAPI(stats) {
  document.getElementById('totalEmails').textContent = stats.total_analyses || 0;
  document.getElementById('phishingDetected').textContent = stats.phishing_detected || 0;
  
  // Calculate URLs and attachments from analysis types
  const urlCount = stats.by_type?.url || 0;
  const attachmentCount = stats.by_type?.attachment || 0;
  document.getElementById('urlsScanned').textContent = urlCount;
  document.getElementById('attachmentsScanned').textContent = attachmentCount;
}

// Update charts from API statistics
function updateChartsFromAPI(stats) {
  // Update detection chart with daily counts
  if (stats.daily_counts && detectionChart) {
    const dates = Object.keys(stats.daily_counts).sort();
    const counts = dates.map(date => stats.daily_counts[date]);
    
    detectionChart.data.labels = dates.map(date => new Date(date).toLocaleDateString());
    detectionChart.data.datasets[0].data = counts;
    detectionChart.update();
  }

  // Update threat distribution chart
  if (threatChart) {
    const phishing = stats.phishing_detected || 0;
    const safe = stats.safe_detected || 0;
    const total = stats.total_analyses || 1;
    const suspicious = total - phishing - safe;

    threatChart.data.datasets[0].data = [phishing, safe, suspicious];
    threatChart.update();
  }
}

// Update activity from history
function updateActivityFromHistory(history) {
  const activityList = document.getElementById('activityList');
  activityList.innerHTML = '';

  if (history.length === 0) {
    activityList.innerHTML = '<div class="activity-item"><div class="activity-content"><p>No recent activity</p></div></div>';
    return;
  }

  history.forEach(item => {
    const activityItem = document.createElement('div');
    activityItem.className = 'activity-item';
    
    const isPhishing = item.is_phishing;
    const status = isPhishing ? 'Phishing Detected' : 'Safe Email';
    const statusClass = isPhishing ? 'phishing' : 'safe';
    const timestamp = new Date(item.created_at).toLocaleString();
    const type = item.analysis_type.toUpperCase();
    
    activityItem.innerHTML = `
      <div class="activity-icon ${statusClass}" data-status="${isPhishing ? 'PH' : 'OK'}"></div>
      <div class="activity-content">
        <p><strong>${status}</strong> - ${type}</p>
        <small>${timestamp}</small>
        ${item.risk_level ? `<span class="risk-badge risk-${item.risk_level.toLowerCase()}">${item.risk_level}</span>` : ''}
      </div>
    `;
    
    activityList.appendChild(activityItem);
  });
}

// Update statistics cards
function updateStats(data) {
  // Update emails analyzed
  const totalEmails = parseInt(localStorage.getItem('totalEmails') || '0') + 1;
  localStorage.setItem('totalEmails', totalEmails);
  const totalEmailsEl = document.getElementById('totalEmails');
  if (totalEmailsEl) {
    totalEmailsEl.textContent = totalEmails;
  }
  
  // Update phishing detected
  if (data.nlu_analysis?.is_phishing || data.dnn_analysis?.is_phishing) {
    const phishingCount = parseInt(localStorage.getItem('phishingDetected') || '0') + 1;
    localStorage.setItem('phishingDetected', phishingCount);
    const phishingDetectedEl = document.getElementById('phishingDetected');
    if (phishingDetectedEl) {
      phishingDetectedEl.textContent = phishingCount;
    }
  }
  
  // Update URLs scanned
  if (data.url_extraction?.url_count) {
    const urlsScanned = parseInt(localStorage.getItem('urlsScanned') || '0') + data.url_extraction.url_count;
    localStorage.setItem('urlsScanned', urlsScanned);
    const urlsScannedEl = document.getElementById('urlsScanned');
    if (urlsScannedEl) {
      urlsScannedEl.textContent = urlsScanned;
    }
  }
  
  // Update attachments scanned
  if (data.email_parsing?.attachments_count) {
    const attachmentsScanned = parseInt(localStorage.getItem('attachmentsScanned') || '0') + data.email_parsing.attachments_count;
    localStorage.setItem('attachmentsScanned', attachmentsScanned);
    const attachmentsScannedEl = document.getElementById('attachmentsScanned');
    if (attachmentsScannedEl) {
      attachmentsScannedEl.textContent = attachmentsScanned;
    }
  }
}

// Update recent activity
function updateActivity(data) {
  const activityList = document.getElementById('activityList');
  
  if (!data.analysis_timestamp) return;
  
  const activityItem = document.createElement('div');
  activityItem.className = 'activity-item';
  
  const isPhishing = data.nlu_analysis?.is_phishing || data.dnn_analysis?.is_phishing;
  const status = isPhishing ? 'Phishing Detected' : 'Safe Email';
  const statusClass = isPhishing ? 'phishing' : 'safe';
  const timestamp = new Date(data.analysis_timestamp).toLocaleString();
  
  activityItem.innerHTML = `
    <div class="activity-icon ${statusClass}" data-status="${isPhishing ? 'PH' : 'OK'}"></div>
    <div class="activity-content">
      <p><strong>${status}</strong></p>
      <small>${timestamp}</small>
    </div>
  `;
  
  // Add to top of list
  activityList.insertBefore(activityItem, activityList.firstChild);
  
  // Keep only last 10 activities
  while (activityList.children.length > 10) {
    activityList.removeChild(activityList.lastChild);
  }
}

// Initialize detection rate chart
function initializeDetectionChart() {
  const ctx = document.getElementById('detectionChart');
  if (!ctx) return;
  
  detectionChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Analyses per Day',
        data: [],
        borderColor: '#667eea',
        backgroundColor: 'rgba(102, 126, 234, 0.1)',
        tension: 0.4,
        fill: true
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: 'top',
        },
        title: {
          display: false
        },
        tooltip: {
          mode: 'index',
          intersect: false
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            stepSize: 1
          }
        },
        x: {
          ticks: {
            maxRotation: 45,
            minRotation: 45
          }
        }
      },
      interaction: {
        mode: 'nearest',
        axis: 'x',
        intersect: false
      }
    }
  });
}

// Initialize threat distribution chart
function initializeThreatChart() {
  const ctx = document.getElementById('threatChart');
  if (!ctx) return;
  
  threatChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Phishing', 'Safe', 'Suspicious'],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: [
          '#e74c3c',
          '#2ecc71',
          '#f39c12'
        ],
        borderWidth: 2,
        borderColor: '#fff',
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: 'bottom',
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              const label = context.label || '';
              const value = context.parsed || 0;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
              return `${label}: ${value} (${percentage}%)`;
            }
          }
        }
      }
    }
  });
}

// Load model performance metrics
async function loadModelPerformance() {
  // These would typically come from evaluation results
  // For now, using placeholder values
  const nluMetrics = {
    accuracy: '92.5%',
    precision: '89.3%',
    recall: '87.8%'
  };
  
  const dnnMetrics = {
    accuracy: '88.2%',
    precision: '85.1%',
    recall: '83.4%'
  };
  
  document.getElementById('nluAccuracy').textContent = nluMetrics.accuracy;
  document.getElementById('nluPrecision').textContent = nluMetrics.precision;
  document.getElementById('nluRecall').textContent = nluMetrics.recall;
  
  document.getElementById('dnnAccuracy').textContent = dnnMetrics.accuracy;
  document.getElementById('dnnPrecision').textContent = dnnMetrics.precision;
  document.getElementById('dnnRecall').textContent = dnnMetrics.recall;
}

// Initialize stats from localStorage on page load
function initializeStats() {
  document.getElementById('totalEmails').textContent = localStorage.getItem('totalEmails') || '0';
  document.getElementById('phishingDetected').textContent = localStorage.getItem('phishingDetected') || '0';
  document.getElementById('urlsScanned').textContent = localStorage.getItem('urlsScanned') || '0';
  document.getElementById('attachmentsScanned').textContent = localStorage.getItem('attachmentsScanned') || '0';
}

// Initialize on load
initializeStats();

