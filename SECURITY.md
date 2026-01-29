# EFTSuite Security Guide

This document describes the security features implemented in EFTSuite and provides guidance for secure deployment.

## Security Features

### Authentication System
- **Password Hashing**: All passwords are hashed using bcrypt with automatic salt (12 rounds)
- **JWT Tokens**: Session management uses cryptographically signed JWT tokens
- **Rate Limiting**: Login attempts are limited to prevent brute force attacks
  - 5 failed attempts trigger a 15-minute lockout
  - IP-based rate limiting for API endpoints
- **Session Timeout**: Sessions automatically expire after 2 hours (configurable)

### Data Protection
- **User Isolation**: Each user can only access their own data
- **Secure File Deletion**: Files are overwritten multiple times before deletion (DOD 5220.22-M style)
- **Path Traversal Protection**: All file paths are validated to prevent directory traversal attacks
- **Input Validation**: All inputs are validated and sanitized using Pydantic models

### Network Security
- **HTTPS/TLS**: Production deployment uses nginx with TLS 1.2/1.3
- **Security Headers**: X-Frame-Options, X-Content-Type-Options, HSTS, etc.
- **CORS**: Configurable origin restrictions

### Container Security
- **Non-root User**: Application runs as unprivileged user inside container
- **Health Checks**: Built-in health check endpoint for monitoring
- **Multi-stage Build**: Smaller attack surface with minimal runtime dependencies

## Deployment Guide

### Prerequisites
- Docker and Docker Compose installed
- Valid SSL certificates (Let's Encrypt recommended)
- Firewall configured to allow ports 80 and 443

### Quick Start (Development)

```bash
# Clone the repository
git clone https://github.com/Robbbbbbbbb/EFTSuite-Public.git
cd EFTSuite-Public

# Start in development mode (HTTP only)
docker-compose -f docker-compose.dev.yml up --build

# Access at http://localhost:8080
# Default admin: admin / DevPassword123!
```

### Production Deployment

1. **Prepare SSL Certificates**
   ```bash
   # Create directories
   mkdir -p nginx/ssl

   # Option A: Self-signed (testing only)
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout nginx/ssl/privkey.pem \
     -out nginx/ssl/fullchain.pem \
     -subj "/CN=localhost"

   # Option B: Let's Encrypt (recommended)
   # Place your certificates in nginx/ssl/
   # - fullchain.pem (certificate + chain)
   # - privkey.pem (private key)

   # Generate DH parameters (do this once)
   openssl dhparam -out nginx/dhparam.pem 2048
   ```

2. **Configure Environment**
   ```bash
   # Copy example config
   cp .env.example .env

   # Edit .env with secure values
   # IMPORTANT: Change ADMIN_PASSWORD and AUTH_SECRET_KEY
   nano .env
   ```

3. **Deploy**
   ```bash
   # Build and start
   docker-compose up -d --build

   # Check logs
   docker-compose logs -f

   # Access at https://your-domain.com
   ```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REQUIRE_AUTH` | `true` | Enable authentication requirement |
| `ALLOW_REGISTRATION` | `true` | Allow new user registration |
| `DEFAULT_ADMIN_PASSWORD` | `ChangeMe123!` | Initial admin password |
| `AUTH_SECRET_KEY` | (generated) | JWT signing key |
| `DEBUG` | `false` | Enable debug mode (disable in production!) |
| `MAX_UPLOAD_SIZE_MB` | `50` | Maximum file upload size |
| `SESSION_TIMEOUT_HOURS` | `2` | Session expiration time |
| `ALLOWED_ORIGINS` | (empty) | CORS allowed origins |

### Security Checklist

Before exposing to the internet:

- [ ] Change the default admin password
- [ ] Set a strong AUTH_SECRET_KEY
- [ ] Obtain valid SSL certificates
- [ ] Configure firewall rules
- [ ] Disable registration if not needed (`ALLOW_REGISTRATION=false`)
- [ ] Set DEBUG=false
- [ ] Configure ALLOWED_ORIGINS for CORS
- [ ] Review and test rate limiting
- [ ] Set up monitoring and alerting
- [ ] Plan for regular security updates

### Data Handling

#### Secure Data Wipe
Users can securely delete all their data via:
1. The "Wipe Data" button in the UI
2. The `DELETE /api/delete-all-data` endpoint

This performs a DOD-style secure deletion:
1. Overwrite with zeros
2. Overwrite with ones
3. Overwrite with random data
4. Truncate and delete

#### Session Cleanup
- Sessions automatically expire after the configured timeout
- A background task cleans up expired sessions every 5 minutes
- Session data is securely deleted upon expiration

### Audit Logging

All significant actions are logged to the SQLite database:
- User login/logout
- File uploads
- EFT generation
- Data deletion
- Password changes

Access logs via the database at `/app/data/users.db`:
```sql
SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100;
```

### Updating

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

### Backup

```bash
# Backup user database
docker cp eftsuite-app:/app/data/users.db ./backup/users.db

# Note: Temporary data in /app/temp should NOT be backed up
# It contains sensitive biometric data that should be ephemeral
```

## Vulnerability Reporting

If you discover a security vulnerability, please report it privately:
- Open a security advisory on GitHub
- Or contact the maintainers directly

Do NOT open public issues for security vulnerabilities.

## Known Limitations

1. **Single-node only**: No clustering or horizontal scaling support
2. **SQLite database**: Not suitable for high-concurrency scenarios
3. **In-memory session cache**: Sessions may be lost on container restart
4. **No 2FA**: Two-factor authentication not yet implemented

## Compliance Notes

This application handles sensitive biometric data (fingerprints) and PII (SSN, DOB, etc.). Consider:

- **Data retention policies**: Implement automatic data expiration
- **Access controls**: Limit who can register and access the system
- **Audit trails**: Review logs regularly
- **Encryption at rest**: Consider volume encryption for `/app/data`
- **Network isolation**: Run on isolated network segment if possible
