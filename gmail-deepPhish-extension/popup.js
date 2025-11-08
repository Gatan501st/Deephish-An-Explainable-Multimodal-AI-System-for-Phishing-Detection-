// Popup script for DeepPhish extension
// Cross-browser compatible

// Get browser API (polyfill handles chrome/browser difference)
const browserAPI = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;

document.addEventListener('DOMContentLoaded', async () => {
  // Check authentication first
  await checkAuth();
  
  // Check API connection
  checkConnection();
  
  // Load stats
  loadStats();
  
  // Event listeners
  document.getElementById('scanCurrentEmail').addEventListener('click', scanCurrentEmail);
  document.getElementById('viewSettings').addEventListener('click', openSettings);
  
  // Auth button listeners
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  if (loginBtn) {
    loginBtn.addEventListener('click', () => {
      browserAPI.tabs.create({ url: 'http://localhost:5000/login' });
    });
  }
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }
});

async function checkAuth() {
  try {
    const response = await browserAPI.runtime.sendMessage({ action: 'checkAuth' });
    const authStatus = document.getElementById('authStatus');
    const loginBtn = document.getElementById('loginBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const userEmail = document.getElementById('userEmail');
    
    if (response && response.authenticated) {
      // User is authenticated
      authStatus.textContent = 'Authenticated';
      authStatus.className = 'auth-status authenticated';
      if (loginBtn) loginBtn.style.display = 'none';
      if (logoutBtn) logoutBtn.style.display = 'block';
      
      // Get user email from storage
      const storage = await browserAPI.storage.local.get(['user_email']);
      if (storage.user_email && userEmail) {
        userEmail.textContent = storage.user_email;
        userEmail.style.display = 'block';
      }
    } else {
      // User is not authenticated
      authStatus.textContent = 'Not authenticated';
      authStatus.className = 'auth-status not-authenticated';
      if (loginBtn) loginBtn.style.display = 'block';
      if (logoutBtn) logoutBtn.style.display = 'none';
      if (userEmail) userEmail.style.display = 'none';
    }
  } catch (error) {
    console.error('Auth check error:', error);
    const authStatus = document.getElementById('authStatus');
    authStatus.textContent = 'Auth check failed';
    authStatus.className = 'auth-status error';
  }
}

async function logout() {
  try {
    await browserAPI.runtime.sendMessage({ action: 'clearAuth' });
    await browserAPI.storage.local.remove(['user_email', 'user_id']);
    await checkAuth();
  } catch (error) {
    console.error('Logout error:', error);
  }
}

async function checkConnection() {
  const statusIndicator = document.querySelector('.status-dot');
  const statusText = document.getElementById('statusText');
  
  try {
    const response = await fetch('http://localhost:5000/api/last_result', {
      method: 'GET',
      mode: 'cors'
    });
    if (response.ok) {
      statusIndicator.classList.add('connected');
      statusText.textContent = 'Connected to DeepPhish API';
    } else {
      throw new Error('API not responding');
    }
  } catch (error) {
    statusIndicator.classList.add('disconnected');
    statusText.textContent = 'Cannot connect to API';
    console.error('Connection error:', error);
  }
}

async function loadStats() {
  try {
    const stats = await browserAPI.storage.local.get(['emailsScanned', 'threatsFound']);
    document.getElementById('emailsScanned').textContent = stats.emailsScanned || 0;
    document.getElementById('threatsFound').textContent = stats.threatsFound || 0;
  } catch (error) {
    console.error('Error loading stats:', error);
  }
}

async function scanCurrentEmail() {
  const button = document.getElementById('scanCurrentEmail');
  const originalText = button.textContent;
  button.textContent = 'Scanning...';
  button.disabled = true;
  
  try {
    // Send message to content script to scan current email
    const tabs = await browserAPI.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    
    if (!tab.url || !tab.url.includes('mail.google.com')) {
      alert('Please open Gmail to scan an email');
      button.textContent = originalText;
      button.disabled = false;
      return;
    }
    
    browserAPI.tabs.sendMessage(tab.id, { action: 'scanCurrentEmail' }, (response) => {
      if (browserAPI.runtime.lastError) {
        console.error('Error:', browserAPI.runtime.lastError);
        alert('Error scanning email. Make sure you have an email open in Gmail.');
        button.textContent = originalText;
        button.disabled = false;
        return;
      }
      
      if (response && response.success) {
        // Fetch the latest result from API
        setTimeout(() => {
          fetch('http://localhost:5000/api/last_result')
            .then(res => res.json())
            .then(result => {
              displayResults(result);
              updateStats(result);
            })
            .catch(error => {
              console.error('Error fetching results:', error);
            });
        }, 500);
      }
      button.textContent = originalText;
      button.disabled = false;
    });
  } catch (error) {
    console.error('Scan error:', error);
    alert('Error scanning email: ' + error.message);
    button.textContent = originalText;
    button.disabled = false;
  }
}

function displayResults(result) {
  const resultsSection = document.getElementById('resultsSection');
  const resultsContent = document.getElementById('resultsContent');
  
  // Remove hidden class and add visible class to trigger animation
  resultsSection.classList.remove('hidden');
  
  // Use requestAnimationFrame to ensure smooth animation
  requestAnimationFrame(() => {
    resultsSection.classList.add('visible');
    
    // Smooth scroll to results after animation
    setTimeout(() => {
      resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 300);
  });
  
  const isPhishing = result.nlu_analysis?.is_phishing || false;
  const confidence = result.nlu_analysis?.confidence || 0;
  const explainability = result.nlu_analysis?.explainability;
  
  // Remove emojis, use text instead
  const statusText = isPhishing ? 'SUSPICIOUS EMAIL DETECTED' : 'EMAIL APPEARS SAFE';
  
  resultsContent.innerHTML = `
    <div class="result-card ${isPhishing ? 'phishing' : 'safe'}">
      <h4>${statusText}</h4>
      <p class="confidence">Confidence: ${(confidence * 100).toFixed(1)}%</p>
      ${explainability && explainability.top_concerns ? `
        <div class="concerns">
          <strong>Suspicious Indicators:</strong>
          <ul>
            ${explainability.top_concerns.slice(0, 3).map(c => 
              `<li><strong>${c.word}</strong>: ${c.explanation || 'Suspicious pattern detected'}</li>`
            ).join('')}
          </ul>
        </div>
      ` : ''}
      ${result.risk_assessment ? `
        <div class="risk-assessment">
          <strong>Risk Level:</strong> ${result.risk_assessment.risk_level || 'UNKNOWN'}
          <br>
          <small>${result.risk_assessment.recommendation || ''}</small>
        </div>
      ` : ''}
    </div>
  `;
}

function updateStats(result) {
  browserAPI.storage.local.get(['emailsScanned', 'threatsFound'], (stats) => {
    const scanned = (stats.emailsScanned || 0) + 1;
    const threats = (stats.threatsFound || 0) + (result.nlu_analysis?.is_phishing ? 1 : 0);
    
    browserAPI.storage.local.set({ emailsScanned: scanned, threatsFound: threats });
    loadStats();
  });
}

function openSettings() {
  // For now, just show an alert
  // In the future, this could open an options page
  alert('Settings page coming soon!\n\nMake sure DeepPhish API is running at http://localhost:5000');
}
