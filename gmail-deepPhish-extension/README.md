# DeepPhish Gmail Extension

A Chrome/Edge browser extension that integrates DeepPhish phishing detection with Gmail, providing real-time email security scanning.

## Features

- 🔍 **Automatic Email Scanning**: Scans emails automatically when opened in Gmail
- 🛡️ **Real-time Phishing Detection**: Uses DeepPhish NLU model for content analysis
- 🔗 **URL Analysis**: Analyzes URLs found in emails using DNN model
- 📊 **Security Badges**: Visual indicators showing email safety status
- 📈 **Statistics Tracking**: Tracks scanned emails and detected threats
- ⚡ **Fast Analysis**: Quick scanning without leaving Gmail

## Installation

### Prerequisites

1. **DeepPhish Flask Server**: Make sure the DeepPhish Flask server is running at `http://localhost:5000`

   ```bash
   python app.py
   ```

2. **Install Dependencies**: Install flask-cors if not already installed
   ```bash
   pip install flask-cors
   ```

### Load Extension in Chrome/Edge

1. Open Chrome or Edge browser
2. Navigate to `chrome://extensions/` (or `edge://extensions/` for Edge)
3. Enable **Developer mode** (toggle in top right corner)
4. Click **Load unpacked**
5. Select the `gmail-deepPhish-extension` folder
6. The extension should now appear in your extensions list

### Verify Installation

1. Check that the extension icon appears in your browser toolbar
2. Click the extension icon to open the popup
3. The status should show "Connected to DeepPhish API" if the server is running
4. If it shows "Cannot connect to API", make sure the Flask server is running

## Usage

### Automatic Scanning

1. Open Gmail in your browser (https://mail.google.com)
2. Open any email
3. The extension will automatically scan the email content
4. A security badge will appear at the top of the email showing:
   - ✅ Safe Email (green badge)
   - ⚠️ Suspicious Email (red badge)
   - Confidence percentage

### Manual Scanning

1. Click the extension icon in the toolbar
2. Click "Scan Current Email" button
3. Results will appear in the popup

### Viewing Results

- **Security Badge**: Appears directly in the email view
- **Popup**: Click extension icon to see detailed results
- **Suspicious URLs**: Highlighted in red with warning tooltip

## File Structure

```
gmail-deepPhish-extension/
├── manifest.json          # Extension configuration
├── background.js          # Background service worker
├── content.js             # Content script for Gmail
├── popup.html            # Extension popup UI
├── popup.js              # Popup logic
├── styles/
│   ├── popup.css        # Popup styles
│   └── content.css      # Content script styles
├── icons/
│   ├── icon16.png       # 16x16 icon
│   ├── icon48.png       # 48x48 icon
│   └── icon128.png      # 128x128 icon
└── README.md            # This file
```

## API Integration

The extension communicates with the following DeepPhish API endpoints:

- `POST /analyze/nlu` - Analyze email text content
- `POST /analyze/url` - Analyze URLs found in emails
- `POST /scan/attachment` - Scan email attachments
- `GET /api/last_result` - Get last analysis result

## Troubleshooting

### Extension Not Loading

- Check `manifest.json` syntax for errors
- Verify all files exist in the extension folder
- Check browser console for errors (F12)

### API Connection Failed

- Ensure Flask server is running: `python app.py`
- Verify server is accessible at `http://localhost:5000`
- Check CORS settings in Flask app
- Check browser console for CORS errors

### Gmail Not Detected

- Make sure you're on https://mail.google.com
- Wait for Gmail to fully load
- Refresh the page
- Check content script is injected (F12 → Console)

### Emails Not Scanning

- Open an email in Gmail (not just the inbox view)
- Wait a few seconds for automatic scan
- Try clicking "Scan Current Email" in the popup
- Check browser console for errors

### Icons Not Showing

- Run `python create_icons.py` to generate icons
- Verify icon files exist in `icons/` folder
- Check file permissions

## Development

### Making Changes

1. Edit the relevant files (content.js, background.js, popup.js, etc.)
2. Go to `chrome://extensions/`
3. Click the refresh icon on the extension card
4. Reload Gmail page to test changes

### Debugging

- **Background Script**: Right-click extension → "Inspect service worker"
- **Content Script**: Open Gmail → F12 → Console tab
- **Popup**: Right-click extension icon → "Inspect popup"

### Testing

1. Start Flask server: `python app.py`
2. Load extension in Chrome
3. Open Gmail
4. Test with various email types:
   - Legitimate emails
   - Suspicious/phishing emails
   - Emails with URLs
   - Emails with attachments

## Security Considerations

- The extension only sends email content to the local DeepPhish API
- No data is sent to external servers
- All analysis happens locally on your machine
- Email content is only processed when explicitly scanned

## Future Enhancements

- [ ] Settings page for API endpoint configuration
- [ ] Batch scanning for multiple emails
- [ ] Email filtering based on risk level
- [ ] Whitelist/blacklist functionality
- [ ] Detailed analysis reports
- [ ] Export scan results
- [ ] Notification system for high-risk emails

## License

Part of the DeepPhish project.

## Support

For issues or questions, please refer to the main DeepPhish repository.
