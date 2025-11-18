# DeepPhish

An explainable multimodal AI system for detecting phishing emails using deep learning. The project implements two models (NLU for email content and DNN for URL analysis) trained on phishing datasets to classify content and provide detailed risk assessments.

## Project Overview

This system analyzes emails and URLs to detect phishing attempts through multiple detection methods:

**Analysis Types:**

- Email content analysis (NLU-based text classification)
- URL/IP analysis (DNN-based feature extraction)
- Threat intelligence integration (VirusTotal API)
- Attachment scanning (hash-based detection)
- Risk aggregation and scoring

**Models:**

- BERT Fine-tuned for Phishing Detection (NLU) - Text classification using transformer models
- Multilayer Perceptron (DNN) - URL feature-based classification with 16 extracted features

**Features:**

- Explainable AI: Highlights specific words, phrases, and URL features that indicate phishing
- Real-time analysis: Fast analysis with detailed risk assessments
- Multi-modal detection: Combines NLU, DNN, and external threat intelligence
- Browser extensions: Gmail and Proton Mail integration for automatic scanning
- User education: Comprehensive educational content and red flag indicators

## Requirements

- Python 3.8+ (required)
- pip, setuptools, wheel
- Supabase account (free tier works)
- VirusTotal API key (free tier: 4 requests/minute)
- 8GB+ RAM recommended for model loading

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/DeepPhish.git
cd DeepPhish
```

### 2. Create and activate virtual environment

Create virtual environment (all OS):

```bash
python3 -m venv .venv
```

Note: Ensure you have Python 3.8 or later installed. Check your version:

```bash
python3 --version
```

Activate virtual environment:

**macOS/Linux:**

```bash
source .venv/bin/activate
```

**Windows (Command Prompt):**

```bash
.venv\Scripts\activate.bat
```

**Windows (PowerShell):**

```bash
.venv\Scripts\Activate.ps1
```

Note: You should see `(.venv)` in your terminal prompt when activated.

### 3. Install dependencies

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
FLASK_SECRET_KEY=your-secret-key
VIRUSTOTAL_API_KEY=your-vt-api-key
```

Generate Flask secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 5. Setup database

1. Create a Supabase project at https://supabase.com
2. Open the SQL Editor in your Supabase dashboard
3. Run the SQL schema from `database_schema.sql`
4. Verify tables are created: `user_profiles`, `analysis_history`, `threat_rules`, `feedback_reports`, `organizations`

### 6. Verify models

The repository includes pre-trained models in the `models/` directory:

- `dnn_url_classifier.pkl` - DNN model for URL classification
- `dnn_scaler.pkl` - Feature scaler for DNN model

The NLU model (`ealvaradob/bert-finetuned-phishing`) is automatically downloaded from Hugging Face on first use.

### 7. Run the application

```bash
python app.py
```

Server runs at http://127.0.0.1:5000

### 8. Create an account

1. Navigate to http://127.0.0.1:5000/signup
2. Create your account
3. To set admin privileges, run in Supabase SQL Editor:
   ```sql
   UPDATE user_profiles SET role = 'admin' WHERE email = 'your-email@example.com';
   ```

## Browser Extension Setup

### Chrome/Edge Installation

1. Go to `chrome://extensions/` (or `edge://extensions/`)
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `gmail-deepPhish-extension/` folder
5. The extension will appear in your extensions list

### Firefox Installation

1. Go to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Navigate to `gmail-deepPhish-extension/` folder
5. Select `manifest-firefox.json` (NOT `manifest.json`)

### Extension Usage

1. Click the extension icon in your browser toolbar
2. Click "Login" and enter your credentials
3. Open Gmail or Proton Mail
4. Open an email - the extension automatically scans it
5. Security badge appears showing analysis results
6. Click badge for detailed analysis and education links

## API Endpoints

### Authentication

- `POST /api/auth/signup` - Create new user account
- `POST /api/auth/login` - Login and get access token
- `GET /api/auth/verify` - Verify JWT token validity
- `POST /api/auth/refresh` - Refresh access token

### Analysis

- `POST /analyze/full` - Complete email analysis (NLU + DNN + VirusTotal)
- `POST /analyze/nlu` - NLU text analysis only
- `POST /analyze/url` - URL/IP analysis (DNN + VirusTotal)
- `POST /analyze/comprehensive` - Comprehensive analysis with all modules
- `POST /scan/attachment` - Attachment hash scanning

### History & Profile

- `GET /api/history` - Get user's analysis history (paginated)
- `GET /api/history/<id>` - Get specific analysis by ID
- `GET /api/statistics` - Get user statistics and analytics
- `GET /api/profile` - Get current user profile
- `PUT /api/profile` - Update user profile

### Export

- `GET /api/export/<id>?format=pdf` - Export analysis as PDF
- `GET /api/export/<id>?format=csv` - Export analysis as CSV
- `GET /api/export/<id>?format=json` - Export analysis as JSON

### Admin

- `GET /api/admin/users` - List all users (admin only)
- `GET /api/admin/analyses` - List all analyses (admin only)
- `GET /api/admin/statistics` - System-wide statistics (admin only)

## Project Structure

```
DeepPhish/
├── app.py                          # Main Flask application
├── modules/                        # Core business logic
│   ├── auth.py                    # Authentication and authorization
│   ├── database.py                # Database operations (Supabase)
│   ├── nlu_module.py              # NLU text analysis
│   ├── dnn_module.py              # DNN URL analysis
│   ├── vt_client.py               # VirusTotal API client
│   ├── eml_parser_module.py       # Email parsing utilities
│   ├── attachment_scanner.py     # Attachment scanning
│   └── export.py                  # PDF/CSV/JSON export
├── templates/                     # HTML templates
│   ├── index.html                 # Main upload page
│   ├── results.html               # Analysis results display
│   ├── dashboard.html             # Analytics dashboard
│   ├── history.html               # Analysis history
│   ├── profile.html               # User profile
│   ├── education.html             # Educational content
│   └── ...
├── static/                        # Static assets
│   ├── styles.css                 # Main stylesheet
│   ├── theme.js                   # Theme management
│   ├── css/
│   │   └── dashboard.css          # Dashboard styles
│   └── js/
│       └── dashboard.js           # Dashboard scripts
├── gmail-deepPhish-extension/     # Browser extension
│   ├── manifest.json              # Chrome/Edge manifest
│   ├── manifest-firefox.json      # Firefox manifest
│   ├── content.js                 # Gmail content script
│   ├── content-proton.js          # Proton Mail content script
│   ├── background.js              # Background service worker
│   ├── popup.html                 # Extension popup UI
│   ├── popup.js                   # Popup logic
│   └── styles/                    # Extension styles
├── models/                        # Pre-trained models
│   ├── dnn_url_classifier.pkl     # DNN model
│   └── dnn_scaler.pkl             # Feature scaler
├── phishing_model_fast/           # NLU model cache
├── database_schema.sql             # Database schema
├── database_expansions.sql        # Optional database expansions
├── requirements.txt               # Python dependencies
└── .env                           # Environment variables (not in git)
```

## Configuration

### Environment Variables

All configuration is done through environment variables in `.env`:

- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_ANON_KEY` - Supabase anonymous key
- `FLASK_SECRET_KEY` - Flask session secret (generate with Python secrets module)
- `VIRUSTOTAL_API_KEY` - VirusTotal API key for threat intelligence

### Model Configuration

**NLU Model:**

- Model: `ealvaradob/bert-finetuned-phishing` (Hugging Face)
- Automatically downloaded on first use
- Cached in `phishing_model_fast/` directory

**DNN Model:**

- Pre-trained MLP classifier
- 16 URL features extracted per URL
- Models loaded from `models/` directory

## Usage Examples

### Web Application

**Analyze Email:**

1. Navigate to http://localhost:5000
2. Upload `.eml` file or paste email content
3. Click "Full Analysis" or "NLU Analysis"
4. View detailed results with explainability

**View History:**

1. Navigate to http://localhost:5000/history
2. Filter by date, type, or risk level
3. Click on any analysis to view details
4. Export results as PDF, CSV, or JSON

**Dashboard:**

1. Navigate to http://localhost:5000/dashboard
2. View statistics and analytics
3. See charts for analysis trends

### API Usage

**Python Example:**

```python
import requests

# Login
response = requests.post("http://localhost:5000/api/auth/login", json={
    "email": "user@example.com",
    "password": "password"
})
token = response.json()["access_token"]

# Analyze URL
response = requests.post(
    "http://localhost:5000/analyze/url",
    headers={"Authorization": f"Bearer {token}"},
    json={"url": "https://example.com"}
)
result = response.json()
print(result)
```

**cURL Example:**

```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password"}'

# Analyze email content
curl -X POST http://localhost:5000/analyze/nlu \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{"text":"Your email content here"}'
```

## Database Schema

### Core Tables

- `user_profiles` - User accounts and preferences
- `analysis_history` - All analysis results and metadata
- `threat_rules` - Custom whitelist/blacklist rules
- `feedback_reports` - False positive/negative reports
- `organizations` - Organization/team management

### Optional Expansions

See `database_expansions.sql` for additional tables:

- Email similarity and campaign detection
- Domain/IP reputation cache
- Alerts and notifications
- Model performance tracking
- API usage and rate limiting

## Security

- **Authentication**: JWT-based authentication with Supabase
- **Authorization**: Role-based access control (RBAC) with admin/user roles
- **Data Protection**: Row Level Security (RLS) enabled on all Supabase tables
- **API Security**: CORS configured for browser extensions, token verification on protected routes
- **Input Validation**: All user inputs validated and sanitized
- **SQL Injection Prevention**: Parameterized queries via Supabase client

## Development

### Adding New Features

1. **Plan the feature** - Design API endpoints and database schema
2. **Implement in modules/** - Add business logic to appropriate module
3. **Add routes in app.py** - Create Flask routes with proper authentication
4. **Update frontend** - Add UI components in templates and static files
5. **Test thoroughly** - Test all code paths and error cases
6. **Update documentation** - Document new features and API endpoints

### Code Organization

- **Separation of Concerns**: Each module has a single responsibility
- **DRY Principle**: No code duplication, reusable utilities
- **Error Handling**: Consistent error handling and user-friendly messages
- **Type Hints**: Type hints used throughout for clarity
- **Documentation**: All functions documented with docstrings

### Testing

```bash
# Run tests (when implemented)
pytest tests/

# Check code style
flake8 .

# Type checking
mypy .
```

## Performance

### Optimizations

- **Lazy Model Loading**: Models loaded on first use, cached in memory
- **Domain Caching**: VirusTotal results cached to reduce API calls
- **Database Indexes**: Optimized queries with proper indexing
- **Pagination**: Efficient data retrieval with pagination
- **Debouncing**: Extension uses debouncing to reduce API calls
- **Request Batching**: Multiple URLs analyzed in single request

### Monitoring

- API usage logs for debugging
- Error tracking and reporting
- Performance metrics collection
- User feedback system for model improvement

## Hardware Requirements

**Minimum:**

- 8GB RAM
- Any CPU
- Internet connection for model downloads and API calls

**Recommended:**

- 16GB+ RAM for faster model loading
- GPU support optional (speeds up NLU inference)
- Stable internet connection for VirusTotal API

**Developed on:** Various systems with Python 3.8+ support

## Troubleshooting

**Python version error?** This project requires Python 3.8 or later. Check your version:

```bash
python3 --version  # Should show 3.8.x or higher
```

**Virtual environment not active?**

- macOS/Linux: `source .venv/bin/activate`
- Windows (Command Prompt): `.venv\Scripts\activate.bat`
- Windows (PowerShell): `.venv\Scripts\Activate.ps1`

**Model loading errors?** The NLU model downloads automatically from Hugging Face. Ensure you have internet connectivity on first run.

**Database connection errors?** Verify your `.env` file has correct Supabase credentials and that your Supabase project is active.

**Extension not working?**

- Check browser console for errors
- Verify you're logged in via extension popup
- Ensure Flask server is running and accessible
- Check CORS settings in `app.py`

**Port already in use?** Change the port in `app.py`:

```python
app.run(host='0.0.0.0', port=5001, debug=True)
```

**Out of memory during analysis?** Reduce batch sizes or analyze smaller email chunks.

## Contributing

We welcome contributions! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8 style guide
- Use type hints for function parameters and returns
- Document all functions with docstrings
- Write tests for new features
- Ensure all tests pass before submitting PR

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **Hugging Face** - Transformers library and pre-trained BERT models
- **VirusTotal** - Threat intelligence API
- **Supabase** - Authentication and database backend
- **Flask** - Web framework
- **PyTorch** - Deep learning framework
- **scikit-learn** - Machine learning utilities
