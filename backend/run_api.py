"""
Launcher script for the NIDS API.

IMPORTANT: eventlet.monkey_patch() must be the very first thing that runs,
before Flask, SQLAlchemy, threading, or anything else is imported anywhere
in the process. thread=False is deliberate and load-bearing: by default
monkey_patch() also converts threading.Thread into a cooperative greenlet
sharing one real OS thread with the whole event loop. Scapy's sniff()
reads packets through Npcap via a blocking C-level call that eventlet
can't make cooperative - with the default patch, a quiet capture
interface could freeze the entire server (not just the capture thread),
including the /api/capture/stop request meant to end it. Confirmed on
real hardware; do not remove thread=False.
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
