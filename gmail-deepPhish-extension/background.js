// Background service worker for DeepPhish extension
// Cross-browser compatible (Chrome, Edge, Firefox)

// Get browser API (polyfill handles chrome/browser difference)
const browserAPI = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;

const DEEPPHISH_API = 'http://localhost:5000';

// Get access token from storage
async function getAccessToken() {
  try {
    const result = await browserAPI.storage.local.get(['access_token']);
    return result.access_token || null;
  } catch (error) {
    console.error('Error getting access token:', error);
    return null;
  }
}

// Check if user is authenticated
async function isAuthenticated() {
  const token = await getAccessToken();
  if (!token) return false;
  
  try {
    const response = await fetch(`${DEEPPHISH_API}/api/auth/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token })
    });
    
    const data = await response.json();
    return data.valid === true;
  } catch (error) {
    console.error('Auth verification error:', error);
    return false;
  }
}

// Listen for extension installation
browserAPI.runtime.onInstalled.addListener(() => {
  console.log('DeepPhish extension installed');
});

// Handle messages from content script
browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeEmail') {
    analyzeEmail(request.emailData)
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep channel open for async response
  }
  
  if (request.action === 'scanAttachment') {
    scanAttachment(request.fileData)
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  
  if (request.action === 'analyzeURL') {
    analyzeURL(request.url)
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});

// Analyze email content using DeepPhish API
async function analyzeEmail(emailData) {
  // Check authentication first
  const authenticated = await isAuthenticated();
  if (!authenticated) {
    throw new Error('Authentication required. Please login at http://localhost:5000/login');
  }
  
  const token = await getAccessToken();
  
  try {
    const response = await fetch(`${DEEPPHISH_API}/analyze/nlu`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        text: emailData.text
      })
    });
    
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login at http://localhost:5000/login');
      }
      throw new Error(`API error: ${response.status}`);
    }
    
    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Email analysis error:', error);
    throw error;
  }
}

// Scan attachment using DeepPhish API
async function scanAttachment(fileData) {
  const authenticated = await isAuthenticated();
  if (!authenticated) {
    throw new Error('Authentication required. Please login at http://localhost:5000/login');
  }
  
  const token = await getAccessToken();
  
  try {
    const formData = new FormData();
    const blob = new Blob([fileData.content], { type: fileData.type });
    formData.append('file', blob, fileData.name);
    
    const response = await fetch(`${DEEPPHISH_API}/scan/attachment`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: formData
    });
    
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login at http://localhost:5000/login');
      }
      throw new Error(`API error: ${response.status}`);
    }
    
    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Attachment scan error:', error);
    throw error;
  }
}

// Analyze URLs found in email
async function analyzeURL(url) {
  const authenticated = await isAuthenticated();
  if (!authenticated) {
    throw new Error('Authentication required. Please login at http://localhost:5000/login');
  }
  
  const token = await getAccessToken();
  
  try {
    const response = await fetch(`${DEEPPHISH_API}/analyze/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ url })
    });
    
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Authentication required. Please login at http://localhost:5000/login');
      }
      throw new Error(`API error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('URL analysis error:', error);
    throw error;
  }
}

// Handle authentication requests from popup
browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkAuth') {
    isAuthenticated().then(authenticated => {
      sendResponse({ authenticated });
    });
    return true;
  }
  
  if (request.action === 'setAuthToken') {
    browserAPI.storage.local.set({ access_token: request.token }).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
  
  if (request.action === 'clearAuth') {
    browserAPI.storage.local.remove(['access_token']).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
});
