"""
run_qrintel.py
Unified startup script for QRIntel.
Runs the Flask backend, which serves the production build of the frontend.
"""

import os
import sys

# Add the backend folder to the Python path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend'))
sys.path.insert(0, BACKEND_DIR)

def main():
    # Change working directory to backend so all relative resource lookups resolve correctly
    os.chdir(BACKEND_DIR)
    
    from app import app, init_db
    
    # Initialize SQLite database schema
    init_db()
    
    print("\n" + "="*60)
    print("  QRIntel Platform - Unified Production Server")
    print("  Access the application at: http://localhost:5000")
    print("="*60 + "\n")
    
    # Run the Flask app on port 5000
    app.run(debug=False, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
