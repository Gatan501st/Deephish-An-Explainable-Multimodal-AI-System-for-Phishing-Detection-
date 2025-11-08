# Quick Start Guide - DeepPhish Gmail Extension

## Step 1: Start the Flask Server

Open a terminal in the project root directory and run:

```bash
python app.py
```

The server should start on `http://localhost:5000`. Keep this terminal open.

## Step 2: Load the Extension in Your Browser

### For Chrome/Edge:

1. **Open Chrome or Edge browser**
2. **Navigate to Extensions Page**:
   - Chrome: Go to `chrome://extensions/`
   - Edge: Go to `edge://extensions/`
3. **Enable Developer Mode**:
   - Toggle the "Developer mode" switch in the top right corner
4. **Load the Extension**:
   - Click "Load unpacked" button
   - Navigate to the `gmail-deepPhish-extension` folder
   - Select the folder and click "Select Folder" (or "Open")

### For Firefox:

1. **Open Firefox browser**
2. **Navigate to Extensions Page**:
   - Go to `about:debugging`
   - Click "This Firefox" in the left sidebar
3. **Load the Extension**:
   - Click "Load Temporary Add-on..."
   - Navigate to the `gmail-deepPhish-extension` folder
   - Select the `manifest.json` file

### Verify Installation:

- The extension should appear in your extensions list
- You should see the DeepPhish icon in your browser toolbar
- Works on Chrome, Edge, and Firefox!

## Step 3: Test the Extension

1. **Open Gmail**:

   - Go to https://mail.google.com
   - Make sure you're logged in

2. **Check Extension Status**:

   - Click the DeepPhish extension icon in the toolbar
   - The popup should show "Connected to DeepPhish API" (green status)
   - If it shows "Cannot connect to API", verify the Flask server is running

3. **Test Email Scanning**:

   - Open any email in Gmail
   - Wait a few seconds
   - You should see a security badge appear at the top of the email:
     - Green badge with "SAFE" for safe emails
     - Red badge with "SUSPICIOUS" for suspicious emails
   - The badge shows the confidence percentage

4. **Manual Scan**:
   - Click the extension icon
   - Click "Scan Current Email" button
   - View detailed results in the popup

## Troubleshooting

### Extension Not Loading

- Check that all files are in the `gmail-deepPhish-extension` folder
- Verify `manifest.json` is valid JSON
- Check browser console for errors (F12)
- **Firefox users**: Make sure you select the `manifest.json` file (not the folder)
- **Chrome/Edge users**: Make sure you select the folder (not individual files)

### API Connection Failed

- Ensure Flask server is running: `python app.py`
- Check server is accessible: Open `http://localhost:5000` in browser
- Verify CORS is enabled (should be automatic with flask-cors)

### Gmail Not Scanning

- Make sure you're on https://mail.google.com
- Open an actual email (not just the inbox)
- Wait a few seconds for automatic scan
- Try clicking "Scan Current Email" manually
- Check browser console (F12) for errors

### Icons Not Showing

- Icons should be in `gmail-deepPhish-extension/icons/` folder
- If missing, you can create simple placeholder icons or use the extension without custom icons

## Next Steps

- Test with various email types (legitimate, phishing, spam)
- Check URL analysis by opening emails with links
- View statistics in the extension popup
- Customize settings (coming soon)

## Support

For issues, check:

- Browser console (F12) for errors
- Flask server logs for API errors
- Extension popup for connection status

Enjoy using DeepPhish!
