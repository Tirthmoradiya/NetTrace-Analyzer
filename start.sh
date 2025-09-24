#!/bin/bash

# Network Anomaly Detector - Start Script
echo "🔍 Network Anomaly Detector Startup"
echo "====================================="

# Check if we're in the right directory
if [ ! -f "analyze.py" ]; then
    echo "❌ Error: analyze.py not found. Make sure you're in the project root directory."
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Check if requirements are installed
if ! python -c "import scapy" 2>/dev/null; then
    echo "📥 Installing dependencies..."
    pip install -r requirements.txt
fi

echo "✅ Environment ready! (Code has been fixed for compatibility)"
echo ""

# Show available commands
echo "Available commands:"
echo ""
echo "1️⃣  Basic analysis (JSON + TXT reports):"
echo "   python analyze.py test_pcaps/2019-02-07-cred-stealer-via-FTP-traffic.pcap \\"
echo "     --json-out reports/analysis.json \\"
echo "     --txt-out reports/analysis.txt"
echo ""
echo "2️⃣  Full analysis with HTML visualizations:"
echo "   python example_usage.py --pcap test_pcaps/2019-02-07-cred-stealer-via-FTP-traffic.pcap"
echo ""
echo "3️⃣  Advanced detector with custom settings:"
echo "   python detector.py test_pcaps/2019-02-07-cred-stealer-via-FTP-traffic.pcap \\"
echo "     --json-out report.json --txt-out report.txt"
echo ""
echo "4️⃣  Run tests:"
echo "   pytest -q"
echo ""

# Ask user what they want to do
echo "What would you like to run? (1-4, or 'q' to quit and run manually):"
read -r choice

case $choice in
    1)
        echo "🚀 Running basic analysis..."
        mkdir -p reports
        python analyze.py test_pcaps/2019-02-07-cred-stealer-via-FTP-traffic.pcap \
          --json-out reports/analysis.json \
          --txt-out reports/analysis.txt
        echo "📊 Reports generated in reports/ directory"
        ;;
    2)
        echo "🚀 Running full analysis with HTML visualizations..."
        python example_usage.py --pcap test_pcaps/2019-02-07-cred-stealer-via-FTP-traffic.pcap
        echo "🌐 Open reports/report.html in your browser to view the dashboard"
        ;;
    3)
        echo "🚀 Running advanced detector..."
        python detector.py test_pcaps/2019-02-07-cred-stealer-via-FTP-traffic.pcap \
          --json-out report.json --txt-out report.txt
        echo "📊 Reports generated: report.json, report.txt"
        ;;
    4)
        echo "🧪 Running tests..."
        pytest -q
        ;;
    q|Q)
        echo "🎯 Environment is active. You can now run commands manually."
        echo "💡 Tip: Use 'deactivate' to exit the virtual environment when done."
        ;;
    *)
        echo "❌ Invalid choice. Environment is active - you can run commands manually."
        echo "💡 Tip: Use 'deactivate' to exit the virtual environment when done."
        ;;
esac