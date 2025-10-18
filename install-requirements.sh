#!/bin/bash
# Installation script for PostgreSQL MCP Server requirements

echo "Installing PostgreSQL MCP Server requirements..."

# Check if Python 3.12+ is available
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
required_version="3.12"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Warning: Python 3.12+ is recommended. Current version: $python_version"
fi

# Install requirements based on argument
case "${1:-full}" in
    "minimal")
        echo "Installing minimal requirements for authentication testing..."
        pip install -r requirements-minimal.txt
        ;;
    "dev")
        echo "Installing development requirements..."
        pip install -r requirements-dev.txt
        ;;
    "full"|*)
        echo "Installing full requirements..."
        pip install -r requirements.txt
        ;;
esac

echo "Installation complete!"
echo ""
echo "Usage:"
echo "  ./install-requirements.sh          # Install full requirements"
echo "  ./install-requirements.sh minimal   # Install minimal requirements"
echo "  ./install-requirements.sh dev       # Install development requirements"
