# API Security Gateway

A comprehensive, production-ready API Security Gateway with advanced threat detection, rate limiting, and monitoring capabilities.

## 🚀 Features

### Security Features
- **Advanced Threat Detection**: SQL injection, XSS, path traversal, command injection, LDAP injection
- **Rate Limiting**: Configurable per-IP rate limiting with burst protection
- **API Key Authentication**: Secure API key validation and management
- **IP Blocking**: Automatic and manual IP blocking with expiration
- **Request Validation**: Input sanitization and size limits
- **CORS Protection**: Configurable cross-origin resource sharing

### Monitoring & Alerting
- **Real-time Dashboard**: Web-based monitoring interface
- **Email Alerts**: SMTP-based alert notifications
- **Webhook Integration**: Slack/Discord webhook support
- **Comprehensive Logging**: Detailed request and threat logging
- **Statistics**: Request analytics and threat intelligence

### Performance
- **High Performance**: Lightweight Python implementation
- **Database Storage**: SQLite for persistence and analytics
- **Configurable**: JSON-based configuration system
- **Health Checks**: Built-in health monitoring endpoints

## 📦 Installation

### Prerequisites
- Python 3.6+
- SQLite3
- Basic system tools (curl, lsof, etc.)

### Quick Start

1. **Clone/Download the project**
```bash
git clone https://github.com/Jybhavsar12/api-security-gateway.git
cd api-security-gateway
```

2. **Make scripts executable**
```bash
chmod +x start-gateway.sh
chmod +x gateway.py
chmod +x monitor.py
```

3. **Start the gateway**
```bash
./start-gateway.sh start
```

4. **Start the monitoring dashboard** (optional)
```bash
python3 monitor.py --port 8001
```

## 🔧 Configuration

Edit `config.json` to customize the gateway behavior:

### Gateway Settings
```json
{
    "gateway": {
        "port": 8000,
        "backend": "localhost:8080",
        "use_https": false,
        "verify_ssl": true,
        "timeout": 30
    }
}
```

### Security Settings
```json
{
    "security": {
        "rate_limit": {
            "requests_per_minute": 100,
            "window_seconds": 60
        },
        "api_keys": [
            "your-api-key-here"
        ],
        "max_request_size": 10485760,
        "auto_block_threshold": 10
    }
}
```

### Alert Configuration
```json
{
    "alerts": {
        "email": {
            "enabled": true,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "username": "your-email@gmail.com",
            "password": "your-app-password",
            "from": "gateway@yourcompany.com",
            "to": "security@yourcompany.com"
        },
        "webhook": {
            "enabled": true,
            "url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
        }
    }
}
```

## 🚀 Usage

### Starting the Gateway
```bash
# Start with default settings
./start-gateway.sh start

# Start with custom port and backend
./start-gateway.sh -p 9000 -b api.example.com:443 start

# Start with custom configuration
./start-gateway.sh -c custom-config.json start
```

### Managing the Gateway
```bash
# Check status
./start-gateway.sh status

# View logs
./start-gateway.sh logs

# Follow logs in real-time
./start-gateway.sh logs -f

# Show statistics
./start-gateway.sh stats

# Test functionality
./start-gateway.sh test

# Stop the gateway
./start-gateway.sh stop

# Restart the gateway
./start-gateway.sh restart
```

### Monitoring Dashboard
```bash
# Start dashboard on port 8001
python3 monitor.py --port 8001

# Access dashboard
open http://localhost:8001
```

## 🔒 Security Features

### Threat Detection Patterns

The gateway detects various attack patterns:

- **SQL Injection**: `union select`, `drop table`, `insert into`, etc.
- **XSS**: `<script>`, `javascript:`, `onload=`, etc.
- **Path Traversal**: `../`, `%2e%2e%2f`, `/etc/passwd`, etc.
- **Command Injection**: `;cat`, `$(...)`, backticks, etc.
- **LDAP Injection**: `*)(`, `)(|`, `admin)(`, etc.

### Rate Limiting

Configurable rate limiting per IP address:
- Requests per minute limit
- Sliding window implementation
- Burst protection
- Automatic blocking for violations

### API Key Authentication

Secure API key validation:
- Header-based authentication (`X-API-Key`)
- Bearer token support
- Configurable key management
- Failed attempt tracking

## 📊 Monitoring

### Dashboard Features
- Real-time statistics
- Threat detection overview
- Blocked IP management
- Performance metrics
- Request analytics

### Key Metrics
- Total requests and success rate
- Threat detection counts by type
- Response time analytics
- Rate limiting violations
- Currently blocked IPs

### Alerting
- Email notifications for critical threats
- Webhook integration for Slack/Discord
- Configurable alert thresholds
- Real-time threat notifications

## 🛠️ API Endpoints

### Health Check
```bash
GET /health
```

### Metrics (if enabled)
```bash
GET /metrics
```

### Dashboard API
```bash
GET /api/stats          # System statistics
GET /api/threats        # Recent threats
GET /api/blocked-ips    # Blocked IP addresses
```

## 📝 Logging

The gateway provides comprehensive logging:

### Log Levels
- `DEBUG`: Detailed debugging information
- `INFO`: General operational messages
- `WARNING`: Warning conditions
- `ERROR`: Error conditions
- `CRITICAL`: Critical error conditions

### Log Format
```
2024-01-15 10:30:45 - INFO - 192.168.1.100 - GET /api/users - 200 - 0.045s
2024-01-15 10:30:46 - WARNING - Threat detected: SQL injection from 192.168.1.101
2024-01-15 10:30:47 - ERROR - Backend connection failed: Connection timeout
```

## 🔧 Troubleshooting

### Common Issues

1. **Port already in use**
```bash
# Check what's using the port
lsof -i :8000

# Use a different port
./start-gateway.sh -p 8001 start
```

2. **Backend connection failed**
- Verify backend server is running
- Check backend URL in configuration
- Verify SSL/TLS settings if using HTTPS

3. **Database errors**
```bash
# Backup and recreate database
./start-gateway.sh backup
rm gateway.db
./start-gateway.sh start
```

4. **Permission denied**
```bash
# Make scripts executable
chmod +x start-gateway.sh gateway.py monitor.py
```

### Debug Mode
```bash
# Enable verbose logging
./start-gateway.sh -v start

# Check logs for detailed information
./start-gateway.sh logs -f
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Check the troubleshooting section
- Review the logs: `./start-gateway.sh logs`
- Test the gateway: `./start-gateway.sh test`
- Check system status: `./start-gateway.sh status`

## 🔄 Updates

To update the gateway:
1. Backup your configuration and database
2. Download the latest version
3. Restore your configuration
4. Restart the gateway

```bash
# Backup
./start-gateway.sh backup
cp config.json config.json.backup

# After update
cp config.json.backup config.json
./start-gateway.sh restart
```
