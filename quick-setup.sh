#!/bin/bash

# 🛡️ SENTINEL v5.2.0 - Quick Setup Script
# 48 Modül | OWASP Top 10 2025 | Harici Araç Entegrasyonu
# Bu script development ortamınızı hızlıca kurar

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🛡️  SENTINEL v5.2.0 - Security Assessment Platform         ║"
echo "║  48 Modül | OWASP 2025 | Nmap, Nikto, Gobuster Entegre      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_step() {
    echo -e "${BLUE}▶ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    echo ""
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | awk '{print $2}')
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3.10+ required. Please install Python first."
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        print_success "pip3 found"
    else
        print_error "pip3 required. Please install it first."
        exit 1
    fi
}

# Check external security tools
check_external_tools() {
    print_step "Checking external security tools..."
    echo ""
    
    TOOLS_MISSING=0
    
    # Nmap
    if command -v nmap &> /dev/null; then
        NMAP_VERSION=$(nmap --version | head -1)
        print_success "Nmap found: $NMAP_VERSION"
    else
        print_info "Nmap not found (optional - for network scanning)"
        TOOLS_MISSING=1
    fi
    
    # Nikto
    if command -v nikto &> /dev/null; then
        print_success "Nikto found"
    else
        print_info "Nikto not found (optional - for web server scanning)"
        TOOLS_MISSING=1
    fi
    
    # Gobuster
    if command -v gobuster &> /dev/null; then
        print_success "Gobuster found"
    elif command -v dirb &> /dev/null; then
        print_success "Dirb found (Gobuster alternative)"
    else
        print_info "Gobuster/Dirb not found (optional - for directory bruteforce)"
        TOOLS_MISSING=1
    fi
    
    # John the Ripper
    if command -v john &> /dev/null; then
        print_success "John the Ripper found"
    else
        print_info "John not found (optional - for hash cracking)"
        TOOLS_MISSING=1
    fi
    
    # Hashcat
    if command -v hashcat &> /dev/null; then
        print_success "Hashcat found"
    else
        print_info "Hashcat not found (optional - for hash cracking)"
        TOOLS_MISSING=1
    fi
    
    if [ $TOOLS_MISSING -eq 1 ]; then
        echo ""
        print_info "Some external tools are missing. Install them for full functionality:"
        echo ""
        echo "  macOS:  brew install nmap nikto gobuster john hashcat"
        echo "  Linux:  apt install nmap nikto dirb john hashcat"
        echo ""
        print_info "SENTINEL will still work, but some modules will be skipped."
    fi
}

# Install Poetry
install_poetry() {
    if command -v poetry &> /dev/null; then
        print_success "Poetry already installed"
    else
        print_info "Installing Poetry..."
        curl -sSL https://install.python-poetry.org | python3 -
        export PATH="$HOME/.local/bin:$PATH"
        print_success "Poetry installed"
    fi
}

# Install dependencies
install_dependencies() {
    print_step "Installing Python dependencies..."
    echo ""
    
    if command -v poetry &> /dev/null; then
        poetry install
        print_success "Dependencies installed via Poetry"
    else
        pip3 install -r requirements.txt
        print_success "Dependencies installed via pip"
    fi
}

# Setup environment
setup_environment() {
    print_step "Setting up environment..."
    echo ""
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            print_info "Creating .env file from template..."
            cp .env.example .env
            
            # Generate secrets if openssl is available
            if command -v openssl &> /dev/null; then
                SECRET_KEY=$(openssl rand -base64 32 | tr -d '\n')
                JWT_SECRET_KEY=$(openssl rand -base64 32 | tr -d '\n')
                
                # Update .env (macOS compatible)
                if [[ "$OSTYPE" == "darwin"* ]]; then
                    sed -i '' "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env 2>/dev/null || true
                    sed -i '' "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET_KEY/" .env 2>/dev/null || true
                else
                    sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env 2>/dev/null || true
                    sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET_KEY/" .env 2>/dev/null || true
                fi
                
                print_success ".env file created with random secrets"
            else
                print_success ".env file created (update secrets manually)"
            fi
        else
            print_info "No .env.example found, creating minimal .env..."
            cat > .env << 'EOF'
# SENTINEL Environment Configuration
ENVIRONMENT=development
DEBUG=true

# AI Configuration (Optional - for AI reports)
# GOOGLE_AI_API_KEY=your-gemini-api-key-here

# Scanner Configuration
SCANNER_CONCURRENT_REQUESTS=10
SCANNER_TIMEOUT=30
EOF
            print_success "Minimal .env file created"
        fi
    else
        print_success ".env file already exists"
    fi
}

# Create output directories
create_directories() {
    print_step "Creating output directories..."
    echo ""
    
    mkdir -p output/reports
    mkdir -p output/wordlists
    mkdir -p output/logs
    
    print_success "Output directories created"
}

# Verify installation
verify_installation() {
    print_step "Verifying SENTINEL installation..."
    echo ""
    
    python3 -c "
from src.core.scanner_engine import ScannerEngine
from src.core.config import Config
from src.utils.command_runner import ExternalCommandRunner

# Test imports
print('  ✓ Scanner Engine loaded')

# Check external tools
runner = ExternalCommandRunner()
tools = runner.get_available_tools()

available = sum(1 for v in tools.values() if v)
total = len(tools)

print(f'  ✓ External tools: {available}/{total} available')

# Count modules
config = Config()
engine = ScannerEngine(config)
print(f'  ✓ Total modules: {len(engine.modules)}')
" 2>/dev/null || {
    print_error "Verification failed. Check Python dependencies."
    return 1
}
    
    print_success "Installation verified successfully!"
}

# Print external tools status
print_tools_status() {
    echo ""
    print_step "External Tools Status:"
    echo ""
    
    python3 -c "
from src.utils.command_runner import ExternalCommandRunner

runner = ExternalCommandRunner()
tools = runner.get_available_tools()

for tool, available in sorted(tools.items()):
    status = '✅' if available else '❌'
    print(f'  {status} {tool}')
" 2>/dev/null || true
}

# Main setup
main() {
    echo ""
    check_prerequisites
    echo ""
    check_external_tools
    echo ""
    install_poetry
    echo ""
    install_dependencies
    echo ""
    setup_environment
    echo ""
    create_directories
    echo ""
    verify_installation
    print_tools_status
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo -e "║  ${GREEN}✓ SENTINEL Setup Complete!${NC}                                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🚀 Quick Start:"
    echo ""
    echo "  1. Start Web Interface:"
    echo "     ${CYAN}python web_app.py${NC}"
    echo "     Open: http://localhost:8000"
    echo ""
    echo "  2. CLI Scanning:"
    echo "     ${CYAN}python scanner.py -u https://example.com${NC}"
    echo ""
    echo "  3. External Tools Only:"
    echo "     ${CYAN}python scanner.py -u https://example.com -m nmap_scanner,nikto_scanner${NC}"
    echo ""
    echo "  4. Generate Wordlist:"
    echo "     ${CYAN}python scanner.py -u https://example.com -m wordlist_builder${NC}"
    echo ""
    echo "📖 Documentation:"
    echo "   - README.md - Quick start guide"
    echo "   - docs/EXTERNAL_TOOLS.md - External tools usage"
    echo "   - docs/API_REFERENCE.md - API documentation"
    echo ""
    echo "🛠️ Install Missing External Tools:"
    echo "   ${CYAN}brew install nmap nikto gobuster john hashcat${NC}  (macOS)"
    echo "   ${CYAN}apt install nmap nikto dirb john hashcat${NC}       (Linux)"
    echo ""
}

# Run main
main
