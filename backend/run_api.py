"""
Launcher script for the NIDS API
"""
import eventlet
eventlet.monkey_patch(thread=False)

import sys
import os
import logging

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from dotenv import load_dotenv
load_dotenv()

from api import start_api

if __name__ == '__main__':
    logging.basicConfig(
        level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    host = os.getenv('NIDS_API_HOST', '127.0.0.1')
    port = int(os.getenv('NIDS_API_PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

    start_api(host=host, port=port, debug=debug)
