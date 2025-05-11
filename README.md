# NMAP-Guard

NMAP-Guard is an enterprise-grade network scanning and vulnerability assessment system that leverages NMAP to continuously monitor, detect, and report potential security vulnerabilities across a global corporate network infrastructure.

## Features

- Intelligent network discovery across diverse corporate environments
- Targeted vulnerability scans without impacting business operations
- Comprehensive reporting and alerting
- Historical analysis and trend detection
- API integration with existing security infrastructure
- Role-based access control
- Secure credential management
- Scheduled scanning capabilities

## Prerequisites

- Python 3.8 or higher
- NMAP installed on the system
- SQLite (default) or PostgreSQL database
- Virtual environment (recommended)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/nmap-guard.git
cd nmap-guard
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
python -m nmap_guard.db.init_db
```

## Configuration

The system can be configured through environment variables or a `.env` file:

- `DATABASE_URL`: Database connection URL (default: sqlite:///./nmap_guard.db)
- `SECRET_KEY`: Secret key for JWT token generation
- `ENCRYPTION_KEY`: Key for credential encryption
- `ENCRYPTION_SALT`: Salt for credential encryption
- `CORS_ORIGINS`: Allowed CORS origins (comma-separated)
- `LOG_LEVEL`: Logging level (default: INFO)

## Usage

1. Start the API server:
```bash
uvicorn nmap_guard.api.main:app --reload
```

2. Access the API documentation:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

3. Create an admin user:
```bash
python -m nmap_guard.scripts.create_create_adminadmin
```

4. Use the API to:
- Create and manage scan configurations
- Execute scans
- Generate reports
- Manage users and permissions

## API Endpoints

### Authentication
- `POST /token`: Get access token
- `POST /users/`: Create new user
- `GET /users/me/`: Get current user info

### Scan Configuration
- `POST /scans/configs/`: Create scan configuration
- `GET /scans/configs/`: List scan configurations
- `GET /scans/configs/{id}`: Get scan configuration
- `PUT /scans/configs/{id}`: Update scan configuration
- `DELETE /scans/configs/{id}`: Delete scan configuration

### Scans
- `POST /scans/`: Create and start scan
- `GET /scans/`: List scans
- `GET /scans/{id}`: Get scan details
- `DELETE /scans/{id}`: Delete scan

### Reports
- `POST /reports/`: Generate report
- `GET /reports/{id}`: Get report
- `GET /reports/`: List reports

## Security Considerations

1. Credential Management
- All sensitive credentials are encrypted at rest
- Credentials are only decrypted during scan execution
- Access to credentials is restricted by user permissions

2. Network Impact
- Scans are rate-limited to prevent network disruption
- Timing templates can be adjusted based on network sensitivity
- Scans can be scheduled during off-hours

3. Access Control
- Role-based access control (RBAC)
- JWT-based authentication
- API key support for integration

## Development

1. Run tests:
```bash
pytest
```

2. Code formatting:
```bash
black .
```

3. Type checking:
```bash
mypy .
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.