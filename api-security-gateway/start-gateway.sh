#!/bin/bash

# Advanced API Security Gateway Management Script
# Author: Security Team
# Version: 2.0

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_PORT=8000
BACKEND_HOST="localhost:8080"
CONFIG_FILE="$SCRIPT_DIR/config.json"
LOG_FILE="$SCRIPT_DIR/gateway.log"
PID_FILE="$SCRIPT_DIR/gateway.pid"
DB_FILE="$SCRIPT_DIR/gateway.db"
VENV_DIR="$SCRIPT_DIR/venv"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 API Security Gateway v2.0                   ║"
    echo "║              Advanced Threat Protection System              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check Python version
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [[ $(echo "$python_version < 3.6" | bc -l) -eq 1 ]]; then
        log_error "Python 3.6+ is required (found $python_version)"
        exit 1
    fi
    
    log_info "Python $python_version found"
    
    # Check required system tools
    for tool in curl wget nc lsof; do
        if ! command -v $tool &> /dev/null; then
            log_warn "$tool not found - some features may not work"
        fi
    done
}

# Setup virtual environment
setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
    fi
    
    source "$VENV_DIR/bin/activate"
    
    # Install required packages
    log_info "Installing/updating Python packages..."
    pip install --quiet --upgrade pip
    
    # Create requirements if it doesn't exist
    if [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
        cat > "$SCRIPT_DIR/requirements.txt" << EOF
requests>=2.25.0
urllib3>=1.26.0
sqlite3
smtplib
email
ssl
socket
hashlib
hmac
base64
threading
datetime
EOF
    fi
}

# Check if port is available
check_port() {
    if command -v lsof &> /dev/null; then
        if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1; then
            return 1
        fi
    elif command -v netstat &> /dev/null; then
        if netstat -tuln | grep -q ":$1 "; then
            return 1
        fi
    elif command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":$1 "; then
            return 1
        fi
    else
        log_warn "Cannot check port availability - no suitable tool found"
    fi
    return 0
}

# Generate default configuration
generate_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_info "Generating default configuration..."
        cat > "$CONFIG_FILE" << EOF
{
    "gateway": {
        "port": $GATEWAY_PORT,
        "backend": "$BACKEND_HOST",
        "use_https": false,
        "verify_ssl": true
    },
    "security": {
        "rate_limit": {
            "requests_per_minute": 100,
            "window_seconds": 60
        },
        "api_keys": [
            "demo-key-12345",
            "test-key-67890"
        ],
        "blocked_ips": [],
        "allowed_origins": ["*"],
        "max_request_size": 10485760,
        "auto_block_threshold": 10,
        "block_duration_hours": 24
    },
    "logging": {
        "level": "INFO",
        "file": "$LOG_FILE",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    },
    "alerts": {
        "email": {
            "enabled": false,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "username": "your-email@gmail.com",
            "password": "your-app-password",
            "from": "gateway@yourcompany.com",
            "to": "security@yourcompany.com"
        },
        "webhook_url": "",
        "slack_webhook": ""
    },
    "monitoring": {
        "health_check_interval": 30,
        "metrics_enabled": true,
        "prometheus_port": 9090
    }
}
EOF
        log_info "Configuration created at $CONFIG_FILE"
        log_warn "Please review and update the configuration before starting"
    fi
}

# Health check
health_check() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            # Check if gateway is responding
            if command -v curl &> /dev/null; then
                if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$GATEWAY_PORT/health" | grep -q "200\|404"; then
                    return 0
                fi
            fi
        fi
    fi
    return 1
}

# Start gateway
start_gateway() {
    log_info "Starting API Security Gateway..."
    
    # Check if already running
    if health_check; then
        log_warn "Gateway is already running"
        return 0
    fi
    
    # Check dependencies
    check_dependencies
    
    # Setup virtual environment
    setup_venv
    
    # Generate config if needed
    generate_config
    
    # Check port availability
    if ! check_port "$GATEWAY_PORT"; then
        log_error "Port $GATEWAY_PORT is already in use"
        exit 1
    fi
    
    # Make gateway executable
    chmod +x "$SCRIPT_DIR/gateway.py"
    
    # Start the gateway
    cd "$SCRIPT_DIR"
    
    if [ -n "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    fi
    
    nohup python3 gateway.py \
        --port "$GATEWAY_PORT" \
        --backend "$BACKEND_HOST" \
        --config "$CONFIG_FILE" \
        --db "$DB_FILE" \
        > "$LOG_FILE" 2>&1 &
    
    PID=$!
    echo $PID > "$PID_FILE"
    
    # Wait a moment and check if it started successfully
    sleep 2
    if kill -0 "$PID" 2>/dev/null; then
        log_info "Gateway started successfully (PID: $PID)"
        log_info "Port: $GATEWAY_PORT"
        log_info "Backend: $BACKEND_HOST"
        log_info "Config: $CONFIG_FILE"
        log_info "Logs: $LOG_FILE"
        log_info "Database: $DB_FILE"
        
        # Show quick stats
        show_quick_stats
    else
        log_error "Gateway failed to start"
        if [ -f "$LOG_FILE" ]; then
            log_error "Check logs: tail -f $LOG_FILE"
        fi
        exit 1
    fi
}

# Stop gateway
stop_gateway() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            log_info "Stopping gateway (PID: $PID)..."
            kill "$PID"
            
            # Wait for graceful shutdown
            for i in {1..10}; do
                if ! kill -0 "$PID" 2>/dev/null; then
                    break
                fi
                sleep 1
            done
            
            # Force kill if still running
            if kill -0 "$PID" 2>/dev/null; then
                log_warn "Force killing gateway..."
                kill -9 "$PID"
            fi
            
            rm -f "$PID_FILE"
            log_info "Gateway stopped"
        else
            log_warn "Gateway process not running"
            rm -f "$PID_FILE"
        fi
    else
        log_warn "PID file not found"
    fi
}

# Show status
show_status() {
    echo -e "${PURPLE}=== Gateway Status ===${NC}"
    
    if health_check; then
        PID=$(cat "$PID_FILE")
        echo -e "${GREEN}Status:${NC} Running (PID: $PID)"
        echo -e "${GREEN}Port:${NC} $GATEWAY_PORT"
        echo -e "${GREEN}Backend:${NC} $BACKEND_HOST"
        echo -e "${GREEN}Config:${NC} $CONFIG_FILE"
        echo -e "${GREEN}Database:${NC} $DB_FILE"
        echo -e "${GREEN}Logs:${NC} $LOG_FILE"
        
        # Show uptime
        if command -v ps &> /dev/null; then
            uptime=$(ps -o etime= -p "$PID" 2>/dev/null | tr -d ' ')
            echo -e "${GREEN}Uptime:${NC} $uptime"
        fi
        
        # Show memory usage
        if command -v ps &> /dev/null; then
            memory=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
            if [ -n "$memory" ]; then
                memory_mb=$((memory / 1024))
                echo -e "${GREEN}Memory:${NC} ${memory_mb}MB"
            fi
        fi
        
    else
        echo -e "${RED}Status:${NC} Not running"
    fi
    
    echo ""
    show_quick_stats
}

# Show quick statistics
show_quick_stats() {
    if [ -f "$DB_FILE" ]; then
        echo -e "${PURPLE}=== Quick Stats ===${NC}"
        
        # Total requests today
        today=$(date '+%Y-%m-%d')
        total_requests=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM requests WHERE DATE(timestamp) = '$today';" 2>/dev/null || echo "0")
        echo -e "${CYAN}Requests today:${NC} $total_requests"
        
        # Blocked requests today
        blocked_requests=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM requests WHERE DATE(timestamp) = '$today' AND blocked = 1;" 2>/dev/null || echo "0")
        echo -e "${CYAN}Blocked today:${NC} $blocked_requests"
        
        # Threats detected today
        threats_today=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM threats WHERE DATE(timestamp) = '$today';" 2>/dev/null || echo "0")
        echo -e "${CYAN}Threats today:${NC} $threats_today"
        
        # Currently blocked IPs
        blocked_ips=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM blocked_ips WHERE expires_at > datetime('now') OR permanent = 1;" 2>/dev/null || echo "0")
        echo -e "${CYAN}Blocked IPs:${NC} $blocked_ips"
    fi
}

# Show detailed statistics
show_stats() {
    if [ ! -f "$DB_FILE" ]; then
        log_error "Database file not found: $DB_FILE"
        return 1
    fi
    
    echo -e "${PURPLE}=== Detailed Statistics ===${NC}"
    echo ""
    
    # Requests by day (last 7 days)
    echo -e "${CYAN}Requests by day (last 7 days):${NC}"
    sqlite3 "$DB_FILE" "
        SELECT DATE(timestamp) as date, COUNT(*) as requests, 
               SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
        FROM requests 
        WHERE timestamp >= datetime('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY date DESC;
    " 2>/dev/null | while IFS='|' read -r date requests blocked; do
        echo "  $date: $requests requests ($blocked blocked)"
    done
    echo ""
    
    # Top threat types
    echo -e "${CYAN}Top threat types (last 24h):${NC}"
    sqlite3 "$DB_FILE" "
        SELECT threat_type, COUNT(*) as count, severity
        FROM threats 
        WHERE timestamp >= datetime('now', '-1 day')
        GROUP BY threat_type, severity
        ORDER BY count DESC
        LIMIT 10;
    " 2>/dev/null | while IFS='|' read -r threat_type count severity; do
        echo "  $threat_type ($severity): $count"
    done
    echo ""
    
    # Top blocked IPs
    echo -e "${CYAN}Currently blocked IPs:${NC}"
    sqlite3 "$DB_FILE" "
        SELECT ip_address, reason, blocked_at, 
               CASE WHEN permanent = 1 THEN 'Permanent' ELSE expires_at END as expires
        FROM blocked_ips 
        WHERE expires_at > datetime('now') OR permanent = 1
        ORDER BY blocked_at DESC
        LIMIT 10;
    " 2>/dev/null | while IFS='|' read -r ip reason blocked_at expires; do
        echo "  $ip: $reason (blocked: $blocked_at, expires: $expires)"
    done
}

# Show logs
show_logs() {
    if [ -f "$LOG_FILE" ]; then
        if [ "$1" = "-f" ] || [ "$1" = "--follow" ]; then
            tail -f "$LOG_FILE"
        else
            tail -n 50 "$LOG_FILE"
        fi
    else
        log_error "Log file not found: $LOG_FILE"
    fi
}

# Test gateway
test_gateway() {
    log_info "Testing gateway functionality..."
    
    if ! health_check; then
        log_error "Gateway is not running"
        return 1
    fi
    
    # Test basic connectivity
    if command -v curl &> /dev/null; then
        echo "Testing basic connectivity..."
        response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$GATEWAY_PORT/" 2>/dev/null || echo "000")
        if [ "$response" != "000" ]; then
            log_info "✓ Basic connectivity: HTTP $response"
        else
            log_error "✗ Basic connectivity failed"
        fi
        
        # Test with API key
        echo "Testing API key authentication..."
        response=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: demo-key-12345" "http://localhost:$GATEWAY_PORT/" 2>/dev/null || echo "000")
        if [ "$response" != "000" ]; then
            log_info "✓ API key auth: HTTP $response"
        else
            log_error "✗ API key auth failed"
        fi
        
        # Test threat detection
        echo "Testing threat detection..."
        response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$GATEWAY_PORT/?test=<script>alert('xss')</script>" 2>/dev/null || echo "000")
        if [ "$response" = "403" ] || [ "$response" = "400" ]; then
            log_info "✓ Threat detection: HTTP $response (blocked)"
        else
            log_warn "? Threat detection: HTTP $response (may not be blocked)"
        fi
        
    else
        log_warn "curl not available - cannot run connectivity tests"
    fi
    
    log_info "Test completed"
}

# Backup database
backup_db() {
    if [ -f "$DB_FILE" ]; then
        backup_file="${DB_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$DB_FILE" "$backup_file"
        log_info "Database backed up to: $backup_file"
    else
        log_warn "Database file not found: $DB_FILE"
    fi
}

# Clean old logs and backups
cleanup() {
    log_info "Cleaning up old files..."
    
    # Clean old log files (keep last 7 days)
    find "$SCRIPT_DIR" -name "*.log.*" -mtime +7 -delete 2>/dev/null || true
    
    # Clean old database backups (keep last 30 days)
    find "$SCRIPT_DIR" -name "*.db.backup.*" -mtime +30 -delete 2>/dev/null || true
    
    # Vacuum database
    if [ -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" "VACUUM;" 2>/dev/null || true
        log_info "Database vacuumed"
    fi
    
    log_info "Cleanup completed"
}

# Show help
show_help() {
    echo "Usage: $0 [OPTIONS] COMMAND"
    echo ""
    echo "Commands:"
    echo "  start                Start the gateway"
    echo "  stop                 Stop the gateway"
    echo "  restart              Restart the gateway"
    echo "  status               Show gateway status"
    echo "  stats                Show detailed statistics"
    echo "  logs [-f|--follow]   Show logs (use -f to follow)"
    echo "  test                 Test gateway functionality"
    echo "  backup               Backup database"
    echo "  cleanup              Clean old files"
    echo "  help                 Show this help"
    echo ""
    echo "Options:"
    echo "  -p, --port PORT      Gateway port (default: $GATEWAY_PORT)"
    echo "  -b, --backend HOST   Backend server (default: $BACKEND_HOST)"
    echo "  -c, --config FILE    Configuration file (default: $CONFIG_FILE)"
    echo "  -l, --log FILE       Log file (default: $LOG_FILE)"
    echo "  -d, --db FILE        Database file (default: $DB_FILE)"
    echo "  -v, --verbose        Verbose output"
    echo "  -q, --quiet          Quiet output"
    echo ""
    echo "Examples:"
    echo "  $0 start                           # Start with defaults"
    echo "  $0 -p 9000 -b api.example.com start  # Custom port and backend"
    echo "  $0 logs -f                         # Follow logs"
    echo "  $0 stats                           # Show statistics"
}

# Parse command line arguments
VERBOSE=false
QUIET=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            GATEWAY_PORT="$2"
            shift 2
            ;;
        -b|--backend)
            BACKEND_HOST="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -l|--log)
            LOG_FILE="$2"
            shift 2
            ;;
        -d|--db)
            DB_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        start|stop|restart|status|stats|logs|test|backup|cleanup|help)
            COMMAND="$1"
            shift
            break
            ;;
        -f|--follow)
            FOLLOW_LOGS=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Show banner unless quiet
if [ "$QUIET" != true ]; then
    show_banner
fi

# Default command is start
if [ -z "$COMMAND" ]; then
    COMMAND="start"
fi

# Execute command
case $COMMAND in
    start)
        start_gateway
        ;;
    stop)
        stop_gateway
        ;;
    restart)
        stop_gateway
        sleep 2
        start_gateway
        ;;
    status)
        show_status
        ;;
    stats)
        show_stats
        ;;
    logs)
        if [ "$FOLLOW_LOGS" = true ]; then
            show_logs -f
        else
            show_logs
        fi
        ;;
    test)
        test_gateway
        ;;
    backup)
        backup_db
        ;;
    cleanup)
        cleanup
        ;;
    help)
        show_help
        ;;
    *)
        log_error "Invalid command: $COMMAND"
        show_help
        exit 1
        ;;
esac