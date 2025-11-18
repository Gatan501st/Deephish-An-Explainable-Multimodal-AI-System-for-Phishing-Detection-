# DeepPhish

> An Explainable Multimodal AI System for Phishing Detection

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

DeepPhish is a comprehensive, explainable multimodal AI system for detecting phishing emails. It combines Natural Language Understanding (NLU), Deep Neural Networks (DNN), and external threat intelligence to provide accurate, explainable phishing detection.

## ✨ Features

### Core Analysis

- **Multi-modal Detection**: Combines NLU (text), DNN (URLs/IPs), and VirusTotal (threat intelligence)
- **Explainable AI**: Highlights specific words and phrases that indicate phishing
- **Real-time Analysis**: Fast analysis with detailed risk assessments
- **Multiple Input Types**: Email files (.eml), URLs, IPs, and attachments

### User Features

- **Authentication**: Secure user authentication with Supabase
- **Analysis History**: Persistent storage of all analyses with search and filter
- **Export Capabilities**: Export results as PDF, CSV, or JSON
- **Dashboard Analytics**: Visual charts and statistics
- **Threat Rules**: Custom whitelist/blacklist rules
- **Feedback System**: Report false positives/negatives

### Browser Extensions

- **Gmail Integration**: Real-time scanning in Gmail
- **Proton Mail Integration**: Real-time scanning in Proton Mail
- **Automatic Scanning**: Scans emails as you read them
- **Visual Indicators**: Security badges and highlighted suspicious content
- **Cross-browser**: Works on Chrome, Edge, and Firefox

### Admin Features

- **Full Access**: Access all user data and analyses
- **User Management**: Manage user roles and permissions
- **Analytics**: View system-wide statistics
- **Threat Intelligence**: Monitor threat patterns

##  Quick Start

### Prerequisites

- Python 3.8+
- Supabase account (free tier works)
- VirusTotal API key (free tier: 4 requests/minute)

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/DeepPhish.git
   cd DeepPhish
   ```

2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   pip install pyspark==3.0.2  # Required for NLU
   ```

3. **Configure environment:**

   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

4. **Setup database:**

   - Create Supabase project
   - Run `database_schema.sql` in Supabase SQL Editor
   - See `SETUP_SUPABASE.md` for details

5. **Run the application:**

   ```bash
   python app.py
   ```

6. **Access the application:**
   - Web app: http://localhost:5000
   - Create account at `/signup`
   - Set admin: `UPDATE user_profiles SET role = 'admin' WHERE email = 'your-email@example.com';`



##  Architecture

```
┌─────────────────────────────────────────┐
│         Browser Extensions              │
│  (Gmail, Proton Mail)                    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         Flask API (app.py)              │
│  - Authentication                       │
│  - Analysis Routes                      │
│  - History & Profile                    │
└──────────────┬──────────────────────────┘
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌──────────┐
│  NLU   │ │  DNN   │ │ VirusTotal│
│ Module │ │ Module │ │  Client   │
└────────┘ └────────┘ └──────────┘
    │          │          │
    └──────────┼──────────┘
               ▼
┌─────────────────────────────────────────┐
│         Supabase Database               │
│  - Authentication                       │
│  - Analysis History                     │
│  - User Profiles                        │
└─────────────────────────────────────────┘
```

##  Project Structure

```
DeepPhish/
├── app.py                    # Main Flask application
├── modules/                  # Business logic
│   ├── auth.py              # Authentication
│   ├── database.py          # Database operations
│   ├── nlu_module.py        # NLU analysis
│   ├── dnn_module.py        # DNN analysis
│   ├── vt_client.py         # VirusTotal client
│   ├── export.py            # PDF/CSV export
│   └── ...
├── templates/                # HTML templates
├── static/                   # CSS, JavaScript
├── gmail-deepPhish-extension/ # Browser extension
├── models/                  # Pre-trained models
└── database_schema.sql       # Database schema
```

##  Configuration

### Environment Variables

Create a `.env` file:

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

##  Browser Extension

### Installation

#### Chrome/Edge

1. Go to `chrome://extensions/` (or `edge://extensions/`)
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select `gmail-deepPhish-extension/` folder
5. Use `manifest.json`

#### Firefox

1. Go to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select `manifest-firefox.json` (NOT `manifest.json`)

See [FIREFOX_EXTENSION_SETUP.md](FIREFOX_EXTENSION_SETUP.md) for details.

##  API Endpoints

### Authentication

- `POST /api/auth/signup` - Create account
- `POST /api/auth/login` - Login
- `GET /api/auth/verify` - Verify token

### Analysis

- `POST /analyze/full` - Full email analysis
- `POST /analyze/nlu` - NLU text analysis
- `POST /analyze/url` - URL/IP analysis
- `POST /scan/attachment` - Attachment scan

### History & Profile

- `GET /api/history` - Get analysis history
- `GET /api/history/<id>` - Get specific analysis
- `GET /api/statistics` - Get user statistics
- `GET /api/profile` - Get user profile
- `PUT /api/profile` - Update profile

### Export

- `GET /api/export/<id>?format=pdf` - Export PDF
- `GET /api/export/<id>?format=csv` - Export CSV
- `GET /api/export/<id>?format=json` - Export JSON

### Admin

- `GET /api/admin/users` - List all users
- `GET /api/admin/analyses` - List all analyses

See [COMPLETE_FEATURES_WALKTHROUGH.md](COMPLETE_FEATURES_WALKTHROUGH.md) for complete API reference.

##  Usage Examples

### Web Application

1. **Sign Up/Login:**

   ```
   Go to http://localhost:5000/signup
   Create account or login
   ```

2. **Analyze Email:**

   ```
   Go to http://localhost:5000
   Upload .eml file
   Click "Full Analysis"
   View results
   ```

3. **View History:**
   ```
   Go to http://localhost:5000/history
   Filter and search analyses
   Export results
   ```

### Browser Extension

1. **Install Extension** (see above)
2. **Authenticate:**
   - Click extension icon
   - Click "Login"
   - Enter credentials
3. **Use:**
   - Open Gmail or Proton Mail
   - Open an email
   - Extension automatically scans
   - Security badge appears

### API Usage

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
```

##  Database

### Current Schema

- `organizations` - Organizations/teams
- `analysis_history` - Analysis results
- `user_profiles` - User profiles
- `threat_rules` - Whitelist/blacklist rules
- `feedback_reports` - False positive/negative reports

### Optional Expansions

See [database_expansions.sql](database_expansions.sql) for:

- Email similarity & campaigns
- Domain/IP cache
- Alerts & notifications
- Model performance tracking
- API usage & rate limiting
- And more...

##  Security

- **Authentication**: JWT-based with Supabase
- **Authorization**: Role-based access control (RBAC)
- **Data Protection**: Row Level Security (RLS) on all tables
- **API Security**: CORS configured, token verification
- **Input Validation**: All inputs validated
- **SQL Injection Prevention**: Parameterized queries

## 🛠️ Development

### Adding New Features

1. **Plan the feature**
2. **Design API and database schema**
3. **Implement in modules/**
4. **Add routes in app.py**
5. **Update frontend**
6. **Test thoroughly**
7. **Update documentation**

See [ARCHITECTURE_WALKTHROUGH.md](ARCHITECTURE_WALKTHROUGH.md) for detailed guide.

### Code Organization

- **Separation of Concerns**: Each module has single responsibility
- **DRY Principle**: No code duplication
- **Error Handling**: Consistent error handling
- **Documentation**: All functions documented
- **Type Hints**: Type hints for clarity

### Testing

```bash
# Run tests (when implemented)
pytest tests/

# Check code style
flake8 .

# Type checking
mypy .
```

##  Performance

### Optimizations

- **Lazy Model Loading**: Models loaded on first use
- **Domain Caching**: Cache VirusTotal results
- **Database Indexes**: Optimized queries
- **Pagination**: Efficient data retrieval
- **Debouncing**: Reduced API calls

### Monitoring

- API usage logs
- Error tracking
- Performance metrics
- User feedback

##  Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

### Code Style

- Follow PEP 8
- Use type hints
- Document all functions
- Write tests for new features

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Acknowledgments

- **Hugging Face** - Transformers library for NLU
- **VirusTotal** - Threat intelligence API
- **Supabase** - Authentication and database
- **Flask** - Web framework
- **Chart.js** - Dashboard visualizations

##  Support

- **Documentation**: See documentation files listed above
- **Issues**: Open an issue on GitHub


##  Roadmap

### Planned Features

- [ ] Email notifications
- [ ] Campaign detection
- [ ] Threat intelligence feeds
- [ ] Model retraining with feedback
- [ ] Advanced search
- [ ] Batch export
- [ ] API rate limiting UI
- [ ] Organization management UI

### In Progress

- [x] Authentication system
- [x] Analysis history
- [x] Export functionality
- [x] Dashboard with charts
- [x] Threat rules management
- [x] Browser extensions

##  Statistics

- **Analysis Types**: 5 (full, nlu, url, attachment, comprehensive)
- **API Endpoints**: 20+
- **Database Tables**: 5 (base) + 14 (expansions)
- **Browser Support**: Chrome, Edge, Firefox
- **Email Providers**: Gmail, Proton Mail

---

**Built with ❤️ for better email security**

For detailed information, see the [documentation files](#-documentation).
