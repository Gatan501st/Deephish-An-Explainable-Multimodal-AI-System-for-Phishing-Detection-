// Browser API polyfill for cross-browser compatibility (Chrome, Edge, Firefox)
// This allows the extension to work with both chrome.* and browser.* APIs

(function() {
  // Use browser API if available (Firefox), otherwise use chrome API
  if (typeof browser !== 'undefined' && browser.runtime) {
    // Firefox uses browser.* API (supports Promises natively)
    window.browserAPI = browser;
  } else if (typeof chrome !== 'undefined' && chrome.runtime) {
    // Chrome/Edge use chrome.* API (modern versions support Promises with async/await)
    window.browserAPI = {
      runtime: chrome.runtime,
      storage: chrome.storage,
      tabs: chrome.tabs,
      action: chrome.action || chrome.browserAction
    };
  } else {
    console.error('DeepPhish: Browser API not found. Extension may not work correctly.');
  }
})();

