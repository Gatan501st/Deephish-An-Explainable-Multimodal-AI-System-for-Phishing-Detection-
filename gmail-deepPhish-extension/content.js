// Content script that runs on Gmail pages
// Optimized for performance with debouncing and cross-browser support

// Get browser API (polyfill handles chrome/browser difference)
const browserAPI = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;
const EDUCATION_URL = 'http://localhost:5000/education';
const MAX_EMAIL_TEXT_LENGTH = 20000;

console.log('DeepPhish content script loaded');

// Performance optimization: Debounce + idle scheduling helpers
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

function scheduleIdleTask(task, timeout = 800) {
  const safeTask = () => {
    try {
      task();
    } catch (err) {
      console.error('Idle task error:', err);
    }
  };
  
  if (typeof window !== 'undefined' && window.requestIdleCallback) {
    window.requestIdleCallback(safeTask, { timeout });
  } else {
    setTimeout(safeTask, Math.min(timeout, 500));
  }
}

// Track scanned emails to avoid duplicates
const scannedEmails = new Set();
const urlScanCache = new Map();
let lastEmailElement = null;
let lastEmailId = null;
let mutationScheduled = false;
let gmailObserver = null;

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
  
  if (emailData.body.length > MAX_EMAIL_TEXT_LENGTH) {
    emailData.body = emailData.body.slice(0, MAX_EMAIL_TEXT_LENGTH);
  }
  
  return emailData;
}

// Create unique identifier for email
function getEmailId(emailElement) {
  const subject = emailElement.querySelector('h2, .hP')?.textContent || '';
  const from = emailElement.querySelector('[email]')?.getAttribute('email') || '';
  if (!subject && !from) {
    const bodyPreview = emailElement.querySelector('.a3s')?.textContent?.trim() || emailElement.textContent?.trim() || '';
    if (bodyPreview) {
      return bodyPreview.substring(0, 120);
    }
    return `email-${Date.now()}`;
  }
  return `${from}-${subject}`.substring(0, 120);
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
  
  const nluResult = analysisResult.nlu_analysis;
  const dnnResult = analysisResult.dnn_analysis;
  const isPhishing = (nluResult?.is_phishing) || (dnnResult?.is_phishing) || false;
  const confidence = nluResult?.confidence || dnnResult?.confidence || 0;
  const explainability = nluResult?.explainability;
  
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

  let dnnConcernsHTML = '';
  if (dnnResult) {
    const keyConcerns = dnnResult.summary?.key_concerns || [];
    const indicators = dnnResult.detailed?.top_phishing_indicators || [];
    const combined = keyConcerns.length ? keyConcerns : indicators.map(ind => ind.description || ind.feature || 'Suspicious indicator');
    if (combined.length) {
      dnnConcernsHTML = '<div class="deepphish-concerns"><strong>URL Indicators:</strong><ul>';
      combined.slice(0, 5).forEach(item => {
        dnnConcernsHTML += `<li>${item}</li>`;
      });
      dnnConcernsHTML += '</ul></div>';
    }
  }
  
  let educationHTML = '';
  if (isPhishing) {
    educationHTML = `
      <div class="deepphish-education">
        <span>Learn how to spot similar attacks.</span>
        <a href="${EDUCATION_URL}" target="_blank" rel="noopener noreferrer">
          Open Education Page →
        </a>
      </div>
    `;
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
    ${dnnConcernsHTML}
    ${educationHTML}
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
  
  // Highlight malicious words in body (idle to avoid blocking UI)
  if (isPhishing && explainability) {
    scheduleIdleTask(() => highlightMaliciousWords(emailElement, analysisResult), 1200);
  }
}

function unwrapElements(root, selector) {
  root.querySelectorAll(selector).forEach((el) => {
    const textNode = document.createTextNode(el.textContent || '');
    el.replaceWith(textNode);
  });
}

function cleanupEmailElement(emailElement, emailId) {
  if (!emailElement) return;
  emailElement.querySelectorAll('.deepphish-badge').forEach((badge) => badge.remove());
  unwrapElements(emailElement, '.deepphish-highlight');
  unwrapElements(emailElement, '.deepphish-suspicious-url');
  delete emailElement.dataset.deepphishScanned;
  delete emailElement.dataset.deepphishScanning;
  delete emailElement.dataset.deepphishPending;
  delete emailElement.dataset.deepphishRendered;
  if (emailId && scannedEmails.has(emailId)) {
    scannedEmails.delete(emailId);
  }
}

function findActiveEmailElement() {
  const main = document.querySelector('[role="main"]');
  if (!main) return null;

  const selectorGroups = [
    '.nH.if .nH',
    '.nH.if',
    '.nH.hx',
    '.adn',
    '.nH[role="presentation"]',
    '.aeF'
  ];

  for (const selector of selectorGroups) {
    const candidates = main.querySelectorAll(selector);
    for (const candidate of candidates) {
      if (candidate.querySelector('.a3s')) {
        return candidate;
      }
    }
  }

  if (main.querySelector('.a3s')) {
    return main;
  }

  return null;
}

// Scan email when opened (optimized with caching)
async function scanEmail(emailElement) {
  const emailId = getEmailId(emailElement);
  
  // Skip if already scanned and rendered
  if (scannedEmails.has(emailId) && emailElement.dataset.deepphishRendered === 'true') {
    return;
  }
  
  // Mark as scanning to avoid duplicate scans
  if (emailElement.dataset.deepphishScanning === 'true') {
    return;
  }
  emailElement.dataset.deepphishScanning = 'true';
  
  const emailData = extractEmailData(emailElement);
  
  // Combine subject and body for analysis
  let fullText = `${emailData.subject}\n\n${emailData.body}`;
  if (fullText.length > MAX_EMAIL_TEXT_LENGTH) {
    fullText = fullText.slice(0, MAX_EMAIL_TEXT_LENGTH);
  }
  
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
      emailElement.dataset.deepphishRendered = 'true';
      scheduleIdleTask(() => analyzeUrlsForEmail(emailElement, emailData, response.result), 1400);
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
      scheduleIdleTask(() => analyzeUrlsForEmail(emailElement, emailData, response?.result), 1500);
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
function highlightSuspiciousURL(url, emailElement, warningText) {
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
        const title = warningText || 'Suspicious URL detected by DeepPhish';
        return `<span class="deepphish-suspicious-url" data-url="${url}" title="${title}">${match}</span>`;
      });
      break;
    }
  }
}

async function analyzeUrlsForEmail(emailElement, emailData, baseResult) {
  if (!emailData.urls || emailData.urls.length === 0) return;

  const urlsToScan = emailData.urls.slice(0, 3);
  for (const url of urlsToScan) {
    const cacheKey = `${lastEmailId || ''}-${url}`;
    if (urlScanCache.has(cacheKey)) {
      continue;
    }
    urlScanCache.set(cacheKey, true);
    try {
      const urlResponse = await browserAPI.runtime.sendMessage({
        action: 'analyzeURL',
        url: url
      });
      if (urlResponse && urlResponse.success && urlResponse.result) {
        const urlResult = urlResponse.result;
        const dnnAnalysis = urlResult.dnn_analysis || urlResult;
        if (dnnAnalysis?.is_phishing) {
          highlightSuspiciousURL(
            url,
            emailElement,
            urlResult.summary?.key_concerns?.[0] || 'URL flagged as phishing'
          );
          const combinedResult = {
            ...baseResult,
            dnn_analysis: dnnAnalysis
          };
          addSecurityBadge(emailElement, combinedResult);
          emailElement.dataset.deepphishRendered = 'true';
        }
      }
    } catch (error) {
      console.error('URL analysis error:', error);
    }
  }
}

// Debounced scan function to avoid excessive scanning
const debouncedScan = debounce((emailElement) => {
  if (!emailElement) return;
  if (emailElement.dataset.deepphishPending === 'true') return;
  emailElement.dataset.deepphishPending = 'true';
  scanEmail(emailElement).finally(() => {
    delete emailElement.dataset.deepphishPending;
  });
}, 500);

// Listen for messages from popup
browserAPI.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanCurrentEmail') {
    console.log('Content script: Received scanCurrentEmail request');
    
    // Use async handler for proper response
    (async () => {
      try {
        // Try multiple selectors for Gmail's email view
        const currentEmail = findActiveEmailElement();
        
        if (!currentEmail) {
          console.error('Content script: No email element found');
          sendResponse({ success: false, error: 'No email open. Please open an email in Gmail first.' });
          return;
        }
        
        console.log('Content script: Email element found, starting scan...');
        
        // Clear cached scan for manual rescan
        const emailId = getEmailId(currentEmail);
        scannedEmails.delete(emailId);
        delete currentEmail.dataset.deepphishScanned;
        delete currentEmail.dataset.deepphishScanning;
        delete currentEmail.dataset.deepphishRendered;
        
        await scanEmail(currentEmail);
        console.log('Content script: Scan completed successfully');
        sendResponse({ success: true });
      } catch (error) {
        console.error('Content script: Scan error:', error);
        sendResponse({ success: false, error: error.message || 'Unknown error occurred' });
      }
    })();
    
    return true; // Keep channel open for async response
  }
});

// Optimized observer with debouncing
function handleEmailViewChange() {
  const currentEmail = findActiveEmailElement();

  if (!currentEmail) {
    if (lastEmailElement) {
      cleanupEmailElement(lastEmailElement, lastEmailId);
      lastEmailElement = null;
      lastEmailId = null;
    }
    return;
  }

  const currentId = getEmailId(currentEmail);
  if (!currentId) {
    return;
  }

  if (lastEmailId && currentId !== lastEmailId && lastEmailElement) {
    cleanupEmailElement(lastEmailElement, lastEmailId);
  }

  lastEmailElement = currentEmail;
  lastEmailId = currentId;

  if (!scannedEmails.has(currentId) || currentEmail.dataset.deepphishRendered !== 'true') {
    debouncedScan(currentEmail);
  }
}

function initializeObserver() {
  if (gmailObserver) {
    gmailObserver.disconnect();
  }
  
  gmailObserver = new MutationObserver(() => {
    if (mutationScheduled) return;
    mutationScheduled = true;
    scheduleIdleTask(() => {
      mutationScheduled = false;
      handleEmailViewChange();
    }, 600);
  });
  
  const target = document.querySelector('[role="main"]') || document.body;
  if (target) {
    gmailObserver.observe(target, {
      childList: true,
      subtree: true
    });
  }
  
  return gmailObserver;
}

// Initialize when Gmail loads
waitForGmail().then(() => {
  console.log('Gmail loaded, initializing DeepPhish scanner');
  
  // Initialize observer
  initializeObserver();
  handleEmailViewChange();
  
  // Scan current email if already open (with delay to ensure content is loaded)
  setTimeout(() => {
    const currentEmail = findActiveEmailElement();
    if (currentEmail) {
      debouncedScan(currentEmail);
    }
  }, 1500);
});
