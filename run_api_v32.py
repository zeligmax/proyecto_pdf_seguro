#!/usr/bin/env python3
"""
run_api_v32.py - Launch File Secure v3.2 API Server
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from app.api.app import create_app

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 File Secure v3.2 - Enterprise API Server")
    print("=" * 60)
    print()

    app = create_app()

    print("✅ API Server starting...")
    print("   URL: http://localhost:5000")
    print("   Health Check: http://localhost:5000/health")
    print("   API Info: http://localhost:5000/api/v1")
    print()
    print("📝 To initialize the database, run:")
    print("   python -m app.scripts.init_data")
    print()

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
