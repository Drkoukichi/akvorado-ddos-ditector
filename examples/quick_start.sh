#!/bin/bash
# Quick start script for DDoS Detector

echo "====================================="
echo "Akvorado DDoS Detector - Quick Start"
echo "====================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    exit 1
fi

# Go to parent directory
cd "$(dirname "$0")/.."

# Create config file if it doesn't exist
if [ ! -f config.yaml ]; then
    echo "Creating configuration file from template..."
    cp config.yaml.example config.yaml
    echo "✓ Created config.yaml"
    echo ""
    echo "⚠️  Please edit config.yaml to set:"
    echo "   - ClickHouse connection details"
    echo "   - Discord and/or Slack webhook URLs"
    echo "   - Detection thresholds"
    echo ""
    read -p "Press Enter to continue after editing config.yaml..."
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✓ Created .env"
    echo ""
    echo "⚠️  Please edit .env to set your webhook URLs and database credentials"
    echo ""
    read -p "Press Enter to continue after editing .env..."
fi

# Create logs directory
mkdir -p logs

# Build and start the detector
echo ""
echo "Building Docker image..."
docker compose build

echo ""
echo "Starting DDoS Detector..."
docker compose up -d

echo ""
echo "✓ DDoS Detector is now running!"
echo ""
echo "To view logs, run:"
echo "  docker compose logs -f ddos-detector"
echo ""
echo "To stop the detector, run:"
echo "  docker compose down"
echo ""
