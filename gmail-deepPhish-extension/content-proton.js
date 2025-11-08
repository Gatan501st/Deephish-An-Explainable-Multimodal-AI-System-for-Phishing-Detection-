// Content script for Proton Mail
// Optimized for performance with debouncing and cross-browser support

// Get browser API (polyfill handles chrome/browser difference)
const browserAPI = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;

console.log('DeepPhish Proton Mail content script loaded');

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

// Extract email data from Proton Mail
function extractEmailData(emailElement) {
  const emailData = {
    subject: '',
    from: '',
    body: '',
    urls: [],
    attachments: []
  };
  
  // Extract subject - Proton Mail uses different selectors
  const subjectSelectors = ['h1[data-testid="message-view:header-subject"]', '.message-header-subject', 'h1'];
  for (const selector of subjectSelectors) {
    const subjectEl = emailElement.querySelector(selector);
    if (subjectEl && subjectEl.textContent.trim()) {
      emailData.subject = subjectEl.textContent.trim();
      break;
    }
  }
  
  // Extract sender - Proton Mail sender info
  const fromSelectors = [
    '[data-testid="message-header:sender-address"]',
    '.message-header-sender',
    '[data-testid="message-header:from"]'
  ];
  for (const selector of fromSelectors) {
    const fromEl = emailElement.querySelector(selector);
    if (fromEl) {
      emailData.from = fromEl.textContent.trim();
      if (emailData.from) break;
    }
  }
  
  // Extract body text - Proton Mail body selectors
  const bodySelectors = [
    '[data-testid="message-view:body-content"]',
    '.message-content-body',
    '.proton-mail_text-break'
  ];
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
  
  // Extract attachment info (Proton Mail attachments)
  const attachmentEls = emailElement.querySelectorAll('[data-testid="message-view:attachment"]');
  const maxAttachments = Math.min(attachmentEls.length, 10);
  for (let i = 0; i < maxAttachments; i++) {
    const el = attachmentEls[i];
    const name = el.getAttribute('aria-label') || 
                 el.textContent.trim() || 
                 'unknown';
    emailData.attachments.push({
      name: name,
      size: '0'
    });
  }
  
  return emailData;
}

// Create unique identifier for email
function getEmailId(emailElement) {
  const subject = emailElement.querySelector('h1[data-testid="message-view:header-subject"]')?.textContent || '';
  const from = emailElement.querySelector('[data-testid="message-header:sender-address"]')?.textContent || '';
  return `${from}-${subject}`.substring(0, 100);
}

// Highlight malicious words in email body (same as Gmail version)
function highlightMaliciousWords(emailElement, analysisResult) {
  const explainability = analysisResult.nlu_analysis?.explainability;
  if (!explainability || !explainability.top_concerns) {
    return;
  }
  
  const topConcerns = explainability.top_concerns.slice(0, 10);
  if (topConcerns.length === 0) {
    return;
  }
  
  const bodySelectors = [
    '[data-testid="message-view:body-content"]',
    '.message-content-body',
    '.proton-mail_text-break'
  ];
  let bodyElement = null;
  
  for (const selector of bodySelectors) {
    bodyElement = emailElement.querySelector(selector);
    if (bodyElement && bodyElement.textContent.trim()) {
      break;
    }
  }
  
  if (!bodyElement) return;
  
  const wordsToHighlight = new Map();
  topConcerns.forEach((concern, index) => {
    const word = concern.word.toLowerCase();
    wordsToHighlight.set(word, {
      explanation: concern.explanation,
      importance: concern.importance,
      index: index
    });
  });
  
  const originalHTML = bodyElement.innerHTML;
  let highlightedHTML = originalHTML;
  
  wordsToHighlight.forEach((data, word) => {
    const regex = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
    
    highlightedHTML = highlightedHTML.replace(regex, (match) => {
      if (match.includes('deepphish-highlight')) {
        return match;
      }
      
      const intensity = Math.min(data.importance * 2, 1);
      const opacity = 0.3 + (intensity * 0.4);
      
      return `<mark class="deepphish-highlight" 
                     style="background-color: rgba(231, 76, 60, ${opacity}); 
                            padding: 2px 4px; 
                            border-radius: 3px;
                            cursor: help;" 
                     title="${data.explanation}" 
                     data-importance="${data.importance.toFixed(3)}">${match}</mark>`;
    });
  });
  
  if (highlightedHTML !== originalHTML) {
    bodyElement.innerHTML = highlightedHTML;
  }
}

// Add security badge to email (Proton Mail version)
function addSecurityBadge(emailElement, analysisResult) {
  const existingBadge = emailElement.querySelector('.deepphish-badge');
  if (existingBadge) {
    existingBadge.remove();
  }
  
  const badge = document.createElement('div');
  badge.className = 'deepphish-badge';
  
  const isPhishing = analysisResult.nlu_analysis?.is_phishing || false;
  const confidence = analysisResult.nlu_analysis?.confidence || 0;
  const explainability = analysisResult.nlu_analysis?.explainability;
  
  const statusText = isPhishing ? 'SUSPICIOUS' : 'SAFE';
  const statusClass = isPhishing ? 'phishing' : 'safe';
  
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
  
  // Insert badge in Proton Mail header area
  const header = emailElement.querySelector('[data-testid="message-view:header"]') ||
                 emailElement.querySelector('.message-header');
  if (header) {
    header.insertBefore(badge, header.firstChild);
  } else {
    const messageView = emailElement.querySelector('[data-testid="message-view"]');
    if (messageView) {
      messageView.insertBefore(badge, messageView.firstChild);
    }
  }
  
  if (isPhishing && explainability) {
    highlightMaliciousWords(emailElement, analysisResult);
  }
}

// Scan email when opened
async function scanEmail(emailElement) {
  const emailId = getEmailId(emailElement);
  
  if (scannedEmails.has(emailId)) {
    return;
  }
  
  if (emailElement.dataset.deepphishScanning === 'true') {
    return;
  }
  emailElement.dataset.deepphishScanning = 'true';
  
  const emailData = extractEmailData(emailElement);
  const fullText = `${emailData.subject}\n\n${emailData.body}`;
  
  if (!fullText.trim() || fullText.length < 10) {
    console.log('No email content to analyze');
    emailElement.dataset.deepphishScanning = 'false';
    return;
  }
  
  try {
    const response = await browserAPI.runtime.sendMessage({
      action: 'analyzeEmail',
      emailData: { text: fullText }
    });
    
    if (response && response.success) {
      addSecurityBadge(emailElement, response.result);
      scannedEmails.add(emailId);
      emailElement.dataset.deepphishScanned = 'true';
    } else if (response && response.error) {
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
        const header = emailElement.querySelector('[data-testid="message-view:header"]');
        if (header) {
          header.insertBefore(errorBadge, header.firstChild);
        }
      }
      scannedEmails.add(emailId);
    }
  } catch (error) {
    console.error('Email scan error:', error);
  } finally {
    emailElement.dataset.deepphishScanning = 'false';
  }
}

// Debounced scan function
const debouncedScan = debounce((emailElement) => {
  if (emailElement && !emailElement.dataset.deepphishScanned) {
    emailElement.dataset.deepphishScanned = 'true';
    scanEmail(emailElement);
  }
}, 500);

// Initialize observer for Proton Mail
function initializeObserver() {
  let lastEmailElement = null;
  
  const observer = new MutationObserver((mutations) => {
    const processMutation = () => {
      const messageView = document.querySelector('[data-testid="message-view"]');
      
      if (messageView && messageView !== lastEmailElement) {
        lastEmailElement = messageView;
        const emailId = getEmailId(messageView);
        
        if (!scannedEmails.has(emailId) && !messageView.dataset.deepphishScanned) {
          debouncedScan(messageView);
        }
      }
    };
    
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

// Initialize when Proton Mail loads
(function init() {
  console.log('Proton Mail loaded, initializing DeepPhish scanner');
  
  initializeObserver();
  
  setTimeout(() => {
    const messageView = document.querySelector('[data-testid="message-view"]');
    if (messageView) {
      scanEmail(messageView);
    }
  }, 1500);
})();

// Listen for messages from popup
browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanCurrentEmail') {
    const messageView = document.querySelector('[data-testid="message-view"]');
    if (messageView) {
      const emailId = getEmailId(messageView);
      scannedEmails.delete(emailId);
      messageView.dataset.deepphishScanned = 'false';
      
      scanEmail(messageView).then(() => {
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

