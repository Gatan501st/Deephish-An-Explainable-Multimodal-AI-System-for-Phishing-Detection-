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
  document.getElementById('viewProfile').addEventListener('click', openProfile);
  
  // Auth button listeners
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  if (loginBtn) {
    loginBtn.addEventListener('click', () => {
      showLoginForm();
    });
  }
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }
  
  // Login form submission
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
  }
});

async function checkAuth() {
  try {
    console.log('Checking authentication...');
    const response = await browserAPI.runtime.sendMessage({ action: 'checkAuth' });
    console.log('Auth check response:', response);
    
    const authStatus = document.getElementById('authStatus');
    const loginBtn = document.getElementById('loginBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const userEmail = document.getElementById('userEmail');
    const authStatusContainer = document.getElementById('authStatusContainer');
    const loginFormContainer = document.getElementById('loginFormContainer');
    
    if (response && response.authenticated) {
      // User is authenticated
      authStatus.textContent = 'Authenticated';
      authStatus.className = 'auth-status authenticated';
      if (loginBtn) loginBtn.style.display = 'none';
      if (logoutBtn) logoutBtn.style.display = 'block';
      if (authStatusContainer) authStatusContainer.style.display = 'flex';
      if (loginFormContainer) loginFormContainer.style.display = 'none';
      
      // Get user email from storage
      const storage = await browserAPI.storage.local.get(['user_email']);
      console.log('User storage:', storage);
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
      if (authStatusContainer) authStatusContainer.style.display = 'flex';
      // Don't auto-show login form, let user click Login button
      if (loginFormContainer) loginFormContainer.style.display = 'none';
    }
  } catch (error) {
    console.error('Auth check error:', error);
    const authStatus = document.getElementById('authStatus');
    authStatus.textContent = 'Auth check failed';
    authStatus.className = 'auth-status error';
  }
}

function showLoginForm() {
  const authStatusContainer = document.getElementById('authStatusContainer');
  const loginFormContainer = document.getElementById('loginFormContainer');
  if (authStatusContainer) authStatusContainer.style.display = 'none';
  if (loginFormContainer) loginFormContainer.style.display = 'block';
}

function hideLoginForm() {
  const authStatusContainer = document.getElementById('authStatusContainer');
  const loginFormContainer = document.getElementById('loginFormContainer');
  if (authStatusContainer) authStatusContainer.style.display = 'flex';
  if (loginFormContainer) loginFormContainer.style.display = 'none';
}

async function handleLogin(e) {
  e.preventDefault();
  console.log('Handling login...');
  
  const loginError = document.getElementById('loginError');
  const loginSubmitBtn = document.getElementById('loginSubmitBtn');
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;
  
  // Hide error
  if (loginError) {
    loginError.style.display = 'none';
    loginError.textContent = '';
  }
  
  // Disable button
  if (loginSubmitBtn) {
    loginSubmitBtn.disabled = true;
    loginSubmitBtn.textContent = 'Logging in...';
  }
  
  try {
    const response = await fetch('http://localhost:5000/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    
    const data = await response.json();
    console.log('Login response:', data);
    
    if (response.ok && data.access_token) {
      const hasUserObject = data.user && typeof data.user === 'object';
      if (!hasUserObject) {
        console.warn('Login response missing user object, falling back to form values.');
      }
      
      const userEmail = hasUserObject && data.user.email ? data.user.email : email;
      const userId = hasUserObject && data.user.id ? data.user.id : null;

      // Store token in extension storage
      const storagePayload = {
        access_token: data.access_token,
        refresh_token: data.refresh_token || null,
        user_email: userEmail
      };
      if (userId) {
        storagePayload.user_id = userId;
      }
      
      await browserAPI.storage.local.set(storagePayload);
      
      // Store token via background script
      await browserAPI.runtime.sendMessage({
        action: 'setAuthToken',
        token: data.access_token
      });
      
      console.log('Token stored successfully');
      
      // Hide login form and refresh auth status
      hideLoginForm();
      await checkAuth();
    } else {
      // Show error
      const errorMsg = data.error || 'Login failed. Please check your credentials.';
      if (loginError) {
        loginError.textContent = errorMsg;
        loginError.style.display = 'block';
      }
      if (loginSubmitBtn) {
        loginSubmitBtn.disabled = false;
        loginSubmitBtn.textContent = 'Login';
      }
    }
  } catch (error) {
    console.error('Login error:', error);
    if (loginError) {
      loginError.textContent = 'Network error. Please try again.';
      loginError.style.display = 'block';
    }
    if (loginSubmitBtn) {
      loginSubmitBtn.disabled = false;
      loginSubmitBtn.textContent = 'Login';
    }
  }
}

async function logout() {
  try {
    console.log('Logging out...');
    await browserAPI.runtime.sendMessage({ action: 'clearAuth' });
    await browserAPI.storage.local.remove(['access_token', 'refresh_token', 'user_email', 'user_id']);
    hideLoginForm();
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
    // Check authentication first
    const authResponse = await browserAPI.runtime.sendMessage({ action: 'checkAuth' });
    if (!authResponse || !authResponse.authenticated) {
      alert('Please login first to scan emails. Click the Login button to authenticate.');
      button.textContent = originalText;
      button.disabled = false;
      return;
    }
    
    // Send message to content script to scan current email
    const tabs = await browserAPI.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    
    if (!tab.url || !tab.url.includes('mail.google.com')) {
      alert('Please open Gmail (mail.google.com) to scan an email.');
      button.textContent = originalText;
      button.disabled = false;
      return;
    }
    
    // Use promise-based message sending for better error handling
    try {
      const response = await new Promise((resolve, reject) => {
        browserAPI.tabs.sendMessage(tab.id, { action: 'scanCurrentEmail' }, (response) => {
          if (browserAPI.runtime.lastError) {
            reject(new Error(browserAPI.runtime.lastError.message));
            return;
          }
          resolve(response);
        });
      });
      
      if (response && response.success) {
        // Fetch the latest result from API
        setTimeout(async () => {
          try {
            const resultResponse = await fetch('http://localhost:5000/api/last_result');
            const result = await resultResponse.json();
            displayResults(result);
            updateStats(result);
            button.textContent = 'Scan Complete';
            setTimeout(() => {
              button.textContent = originalText;
            }, 2000);
          } catch (error) {
            console.error('Error fetching results:', error);
            button.textContent = originalText;
          }
        }, 1000);
      } else {
        const errorMsg = response?.error || 'Failed to scan email';
        alert(`Scan failed: ${errorMsg}`);
        button.textContent = originalText;
        button.disabled = false;
      }
    } catch (error) {
      console.error('Message send error:', error);
      // Content script might not be loaded - try to inject it or show helpful message
      if (error.message.includes('Could not establish connection')) {
        alert('Extension content script not loaded. Please refresh the Gmail page and try again.');
      } else {
        alert(`Error: ${error.message}\n\nPlease make sure:\n1. You have an email open in Gmail\n2. The Gmail page is fully loaded\n3. Try refreshing the page`);
      }
      button.textContent = originalText;
      button.disabled = false;
    }
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
      ${renderIndicatorDetails(result)}
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

function openProfile() {
  browserAPI.tabs.create({ url: 'http://localhost:5000/profile' });
}

function renderIndicatorDetails(result) {
  const explainability = result.nlu_analysis?.explainability;
  const languageIndicators = [];
  if (explainability) {
    if (Array.isArray(explainability.top_concerns) && explainability.top_concerns.length) {
      explainability.top_concerns.slice(0, 4).forEach((concern) => {
        if (!concern || !concern.word) return;
        languageIndicators.push(
          `<li><span class="indicator-word">${concern.word}</span><span class="indicator-text">${concern.explanation || 'Flagged as suspicious'}</span></li>`
        );
      });
    } else if (Array.isArray(explainability.word_importance) && explainability.word_importance.length) {
      explainability.word_importance.slice(0, 4).forEach((token) => {
        if (!token || !token.token) return;
        const impact = token.importance ? ` (impact ${(token.importance * 100).toFixed(1)}%)` : '';
        languageIndicators.push(
          `<li><span class="indicator-word">${token.token}</span><span class="indicator-text">Contributed to phishing score${impact}</span></li>`
        );
      });
    }
  }

  const dnnIndicatorsRaw =
    result.dnn_analysis?.detailed?.top_phishing_indicators ||
    result.dnn_analysis?.top_phishing_indicators ||
    [];
  const dnnSummary = result.dnn_analysis?.summary?.key_concerns || [];
  const dnnIndicators = [];
  if (dnnSummary.length) {
    dnnSummary.slice(0, 4).forEach((summary) => {
      dnnIndicators.push(`<li><span class="indicator-text">${summary}</span></li>`);
    });
  } else if (dnnIndicatorsRaw.length) {
    dnnIndicatorsRaw.slice(0, 4).forEach((indicator) => {
      const feature = indicator.feature || indicator.name || 'Indicator';
      const description = indicator.description || 'Flagged by URL analysis';
      const weight = indicator.contribution
        ? ` (impact ${(indicator.contribution * 100).toFixed(1)}%)`
        : '';
      dnnIndicators.push(
        `<li><span class="indicator-word">${feature}</span><span class="indicator-text">${description}${weight}</span></li>`
      );
    });
  }

  if (!languageIndicators.length && !dnnIndicators.length) {
    return `<p class="indicators-empty">No detailed indicators were provided for this scan.</p>`;
  }

  return `
    <div class="indicator-grid">
      ${languageIndicators.length ? `
        <div class="indicator-panel">
          <h5>Language Signals</h5>
          <ul>${languageIndicators.join('')}</ul>
        </div>
      ` : ''}
      ${dnnIndicators.length ? `
        <div class="indicator-panel">
          <h5>URL / Structure Checks</h5>
          <ul>${dnnIndicators.join('')}</ul>
        </div>
      ` : ''}
    </div>
  `;
}
