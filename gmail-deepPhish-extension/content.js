// Content script that runs on Gmail pages
// Optimized for performance with debouncing and cross-browser support

// Get browser API (polyfill handles chrome/browser difference)
const browserAPI = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;

console.log('DeepPhish content script loaded');

// Performance optimization: Debounce function
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Track scanned emails to avoid duplicates
const scannedEmails = new Set();

// Wait for Gmail to load
function waitForGmail() {
  return new Promise((resolve) => {
    if (document.querySelector('[role="main"]')) {
      resolve();
    } else {
      const observer = new MutationObserver(() => {
        if (document.querySelector('[role="main"]')) {
          observer.disconnect();
          resolve();
        }
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }
  });
}

// Extract email data from Gmail (optimized)
function extractEmailData(emailElement) {
  const emailData = {
    subject: '',
    from: '',
    body: '',
    urls: [],
    attachments: []
  };
  
  // Extract subject - try multiple selectors
  const subjectSelectors = ['h2', '[data-thread-perm-id] h2', '.hP', 'div[data-thread-perm-id]'];
  for (const selector of subjectSelectors) {
    const subjectEl = emailElement.querySelector(selector);
    if (subjectEl && subjectEl.textContent.trim()) {
      emailData.subject = subjectEl.textContent.trim();
      break;
    }
  }
  
  // Extract sender
  const fromSelectors = ['[email]', '.go', '.gD'];
  for (const selector of fromSelectors) {
    const fromEl = emailElement.querySelector(selector);
    if (fromEl) {
      emailData.from = fromEl.getAttribute('email') || fromEl.textContent.trim();
      if (emailData.from) break;
    }
  }
  
  // Extract body text - use most reliable selector first
  const bodySelectors = ['.a3s', '[role="main"] .ii', '.adn'];
  for (const selector of bodySelectors) {
    const bodyEl = emailElement.querySelector(selector);
    if (bodyEl && bodyEl.textContent.trim()) {
      emailData.body = bodyEl.textContent.trim();
      // Extract URLs from this body
      const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g;
      const matches = bodyEl.textContent.match(urlRegex);
      if (matches) {
        emailData.urls = [...new Set(matches)]; // Remove duplicates
      }
      break;
    }
  }
  
  // Extract attachment info (limit to first 10 for performance)
  const attachmentEls = emailElement.querySelectorAll('[data-attachment-id], .aZo');
  const maxAttachments = Math.min(attachmentEls.length, 10);
  for (let i = 0; i < maxAttachments; i++) {
    const el = attachmentEls[i];
    const name = el.getAttribute('data-attachment-name') || 
                 el.getAttribute('aria-label') || 
                 el.textContent.trim() || 
                 'unknown';
    emailData.attachments.push({
      name: name,
      size: el.getAttribute('data-attachment-size') || '0'
    });
  }
  
  return emailData;
}

// Create unique identifier for email
function getEmailId(emailElement) {
  const subject = emailElement.querySelector('h2, .hP')?.textContent || '';
  const from = emailElement.querySelector('[email]')?.getAttribute('email') || '';
  return `${from}-${subject}`.substring(0, 100);
}

// Highlight malicious words in email body
function highlightMaliciousWords(emailElement, analysisResult) {
  const explainability = analysisResult.nlu_analysis?.explainability;
  if (!explainability || !explainability.top_concerns) {
    return;
  }
  
  const topConcerns = explainability.top_concerns.slice(0, 10); // Top 10 malicious words
  if (topConcerns.length === 0) {
    return;
  }
  
  // Get email body elements
  const bodySelectors = ['.a3s', '[role="main"] .ii', '.adn'];
  let bodyElement = null;
  
  for (const selector of bodySelectors) {
    bodyElement = emailElement.querySelector(selector);
    if (bodyElement && bodyElement.textContent.trim()) {
      break;
    }
  }
  
  if (!bodyElement) return;
  
  // Create a map of words to highlight
  const wordsToHighlight = new Map();
  topConcerns.forEach((concern, index) => {
    const word = concern.word.toLowerCase();
    wordsToHighlight.set(word, {
      explanation: concern.explanation,
      importance: concern.importance,
      index: index
    });
  });
  
  // Highlight words in body text
  const originalHTML = bodyElement.innerHTML;
  let highlightedHTML = originalHTML;
  
  wordsToHighlight.forEach((data, word) => {
    // Create regex to match word boundaries (case-insensitive)
    const regex = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
    
    highlightedHTML = highlightedHTML.replace(regex, (match) => {
      // Skip if already wrapped in a highlight
      if (match.includes('deepphish-highlight')) {
        return match;
      }
      
      const intensity = Math.min(data.importance * 2, 1); // Scale importance to 0-1
      const opacity = 0.3 + (intensity * 0.4); // 0.3 to 0.7 opacity
      
      return `<mark class="deepphish-highlight" 
                     style="background-color: rgba(231, 76, 60, ${opacity}); 
                            padding: 2px 4px; 
                            border-radius: 3px;
                            cursor: help;" 
                     title="${data.explanation}" 
                     data-importance="${data.importance.toFixed(3)}">${match}</mark>`;
    });
  });
  
  // Only update if something changed
  if (highlightedHTML !== originalHTML) {
    bodyElement.innerHTML = highlightedHTML;
  }
}

// Add security badge to email (optimized)
function addSecurityBadge(emailElement, analysisResult) {
  // Remove existing badge if present
  const existingBadge = emailElement.querySelector('.deepphish-badge');
  if (existingBadge) {
    existingBadge.remove();
  }
  
  const badge = document.createElement('div');
  badge.className = 'deepphish-badge';
  
  const isPhishing = analysisResult.nlu_analysis?.is_phishing || false;
  const confidence = analysisResult.nlu_analysis?.confidence || 0;
  const explainability = analysisResult.nlu_analysis?.explainability;
  
  // Remove emojis, use text indicators instead
  const statusText = isPhishing ? 'SUSPICIOUS' : 'SAFE';
  const statusClass = isPhishing ? 'phishing' : 'safe';
  
  // Build concerns list if available
  let concernsHTML = '';
  if (explainability && explainability.top_concerns && explainability.top_concerns.length > 0) {
    const topConcerns = explainability.top_concerns.slice(0, 5);
    concernsHTML = '<div class="deepphish-concerns"><strong>Key Concerns:</strong><ul>';
    topConcerns.forEach(concern => {
      concernsHTML += `<li>${concern.word}: ${concern.explanation}</li>`;
    });
    concernsHTML += '</ul></div>';
  }
  
  badge.innerHTML = `
    <div class="deepphish-badge-content ${statusClass}">
      <span class="deepphish-icon">${statusText}</span>
      <span class="deepphish-text">
        ${isPhishing ? 'Suspicious Email' : 'Safe Email'}
      </span>
      <span class="deepphish-confidence">${(confidence * 100).toFixed(0)}%</span>
    </div>
    ${concernsHTML}
  `;
  
  // Insert badge at the top of email - try multiple locations
  const emailHeader = emailElement.querySelector('.gD, .gs, .hP')?.parentElement || 
                      emailElement.querySelector('[role="main"] > div > div:first-child');
  if (emailHeader) {
    emailHeader.insertBefore(badge, emailHeader.firstChild);
  } else {
    // Fallback: insert at the beginning of main content
    const mainContent = emailElement.querySelector('[role="main"]');
    if (mainContent) {
      mainContent.insertBefore(badge, mainContent.firstChild);
    }
  }
  
  // Highlight malicious words in body
  if (isPhishing && explainability) {
    highlightMaliciousWords(emailElement, analysisResult);
  }
}

// Scan email when opened (optimized with caching)
async function scanEmail(emailElement) {
  const emailId = getEmailId(emailElement);
  
  // Skip if already scanned
  if (scannedEmails.has(emailId)) {
    return;
  }
  
  // Mark as scanning to avoid duplicate scans
  if (emailElement.dataset.deepphishScanning === 'true') {
    return;
  }
  emailElement.dataset.deepphishScanning = 'true';
  
  const emailData = extractEmailData(emailElement);
  
  // Combine subject and body for analysis
  const fullText = `${emailData.subject}\n\n${emailData.body}`;
  
  if (!fullText.trim() || fullText.length < 10) {
    console.log('No email content to analyze');
    emailElement.dataset.deepphishScanning = 'false';
    return;
  }
  
  try {
    // Send to background script for analysis
    const response = await browserAPI.runtime.sendMessage({
      action: 'analyzeEmail',
      emailData: { text: fullText }
    });
    
    if (response && response.success) {
      addSecurityBadge(emailElement, response.result);
      scannedEmails.add(emailId);
      emailElement.dataset.deepphishScanned = 'true';
    } else if (response && response.error) {
      // Handle authentication errors
      if (response.error.includes('Authentication required')) {
        const errorBadge = document.createElement('div');
        errorBadge.className = 'deepphish-badge';
        errorBadge.innerHTML = `
          <div class="deepphish-badge-content error">
            <span class="deepphish-text">
              Please login at <a href="http://localhost:5000/login" target="_blank">localhost:5000/login</a> to use DeepPhish
            </span>
          </div>
        `;
        const emailHeader = emailElement.querySelector('.gD, .gs, .hP')?.parentElement || 
                            emailElement.querySelector('[role="main"] > div > div:first-child');
        if (emailHeader) {
          emailHeader.insertBefore(errorBadge, emailHeader.firstChild);
        }
      }
      scannedEmails.add(emailId);
      
      // Analyze URLs if found (limit to 3 for performance)
      if (emailData.urls.length > 0) {
        const urlsToScan = emailData.urls.slice(0, 3);
        // Process URLs in parallel but limit concurrency
        const urlPromises = urlsToScan.map(async (url) => {
          try {
            const urlResponse = await browserAPI.runtime.sendMessage({
              action: 'analyzeURL',
              url: url
            });
            // Add URL warnings if needed
            if (urlResponse && urlResponse.success && urlResponse.result.dnn_analysis?.is_phishing) {
              highlightSuspiciousURL(url, emailElement);
            }
          } catch (error) {
            console.error('URL analysis error:', error);
          }
        });
        
        // Don't wait for all URL scans to complete
        Promise.all(urlPromises).catch(err => console.error('URL scan error:', err));
      }
    } else {
      console.error('Email analysis failed:', response?.error);
    }
  } catch (error) {
    console.error('Email scan error:', error);
  } finally {
    emailElement.dataset.deepphishScanning = 'false';
  }
}

// Highlight suspicious URLs in email
function highlightSuspiciousURL(url, emailElement) {
  // Only highlight if not already highlighted
  if (emailElement.querySelector(`.deepphish-suspicious-url[data-url="${url}"]`)) {
    return;
  }
  
  const urlRegex = new RegExp(url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
  const bodySelectors = ['.a3s', '[role="main"] .ii', '.adn'];
  
  for (const selector of bodySelectors) {
    const bodyEl = emailElement.querySelector(selector);
    if (bodyEl && bodyEl.innerHTML.includes(url)) {
      bodyEl.innerHTML = bodyEl.innerHTML.replace(urlRegex, (match) => {
        return `<span class="deepphish-suspicious-url" data-url="${url}" title="Suspicious URL detected by DeepPhish">${match}</span>`;
      });
      break;
    }
  }
}

// Debounced scan function to avoid excessive scanning
const debouncedScan = debounce((emailElement) => {
  if (emailElement && !emailElement.dataset.deepphishScanned) {
    emailElement.dataset.deepphishScanned = 'true';
    scanEmail(emailElement);
  }
}, 500);

// Listen for messages from popup
browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanCurrentEmail') {
    const currentEmail = document.querySelector('[role="main"]');
    if (currentEmail) {
      // Clear cached scan for manual rescan
      const emailId = getEmailId(currentEmail);
      scannedEmails.delete(emailId);
      currentEmail.dataset.deepphishScanned = 'false';
      
      scanEmail(currentEmail).then(() => {
        sendResponse({ success: true });
      }).catch(error => {
        sendResponse({ success: false, error: error.message });
      });
      return true;
    } else {
      sendResponse({ success: false, error: 'No email open' });
    }
  }
});

// Optimized observer with debouncing
function initializeObserver() {
  let lastEmailElement = null;
  
  const observer = new MutationObserver((mutations) => {
    // Use requestIdleCallback for better performance if available
    const processMutation = () => {
      const currentEmail = document.querySelector('[role="main"]');
      
      // Only process if email changed
      if (currentEmail && currentEmail !== lastEmailElement) {
        lastEmailElement = currentEmail;
        const emailId = getEmailId(currentEmail);
        
        // Skip if already scanned
        if (!scannedEmails.has(emailId) && !currentEmail.dataset.deepphishScanned) {
          debouncedScan(currentEmail);
        }
      }
    };
    
    // Use requestIdleCallback for non-blocking processing
    if (window.requestIdleCallback) {
      requestIdleCallback(processMutation, { timeout: 1000 });
    } else {
      setTimeout(processMutation, 100);
    }
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
  return observer;
}

// Initialize when Gmail loads
waitForGmail().then(() => {
  console.log('Gmail loaded, initializing DeepPhish scanner');
  
  // Initialize observer
  initializeObserver();
  
  // Scan current email if already open (with delay to ensure content is loaded)
  setTimeout(() => {
    const currentEmail = document.querySelector('[role="main"]');
    if (currentEmail) {
      scanEmail(currentEmail);
    }
  }, 1500);
});
