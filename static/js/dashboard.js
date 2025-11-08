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

// Load dashboard data from API
async function loadDashboardData() {
  try {
    // Load last result for stats
    const response = await fetch('/api/last_result');
    const data = await response.json();
    
    if (data && !data.message) {
      updateStats(data);
      updateActivity(data);
    }
    
    // Load model performance (if available)
    loadModelPerformance();
  } catch (error) {
    console.error('Error loading dashboard data:', error);
  }
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
  
  // Sample data - replace with real data from API
  const chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
      datasets: [{
        label: 'Phishing Detected',
        data: [12, 19, 15, 25, 22, 18, 24],
        borderColor: '#e74c3c',
        backgroundColor: 'rgba(231, 76, 60, 0.1)',
        tension: 0.4
      }, {
        label: 'Safe Emails',
        data: [88, 81, 85, 75, 78, 82, 76],
        borderColor: '#2ecc71',
        backgroundColor: 'rgba(46, 204, 113, 0.1)',
        tension: 0.4
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
        }
      },
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}

// Initialize threat distribution chart
function initializeThreatChart() {
  const ctx = document.getElementById('threatChart');
  if (!ctx) return;
  
  const chart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Phishing', 'Safe', 'Suspicious'],
      datasets: [{
        data: [25, 60, 15],
        backgroundColor: [
          '#e74c3c',
          '#2ecc71',
          '#f39c12'
        ],
        borderWidth: 2,
        borderColor: '#fff'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: 'bottom',
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

