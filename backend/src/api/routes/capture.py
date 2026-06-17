"""
Packet capture control routes for the NIDS API.

This module provides endpoints for starting, stopping, and monitoring
packet capture.
"""

from flask import Blueprint, request, jsonify
import logging
import threading

logger = logging.getLogger(__name__)

bp = Blueprint('capture', __name__)

# Global capture instance (will be initialized when needed)
capture_instance = None
capture_thread = None
is_capturing = False

@bp.route('/start', methods=['POST'])
def start_capture():
    """Start packet capture."""
    global capture_instance, capture_thread, is_capturing
    
    try:
        if is_capturing:
            return jsonify({
                'success': False,
                'message': 'Capture already running'
            }), 400
        
        data = request.get_json() or {}
        interface = data.get('interface', 'eth0')
        filter_str = data.get('filter', None)
        
        from core.packet_capture import PacketCapture
        
        # Initialize capture
        capture_instance = PacketCapture(
            interface=interface,
            ring_buffer_size=10000,
            promiscuous=False
        )
        
        # Start capture in background thread
        def capture_loop():
            global is_capturing
            try:
                capture_instance.start_capture(filter_str=filter_str)
            except Exception as e:
                logger.error(f"Capture error: {e}")
                is_capturing = False
        
        capture_thread = threading.Thread(target=capture_loop)
        capture_thread.start()
        is_capturing = True
        
        return jsonify({
            'success': True,
            'message': f'Capture started on {interface}',
            'interface': interface,
            'filter': filter_str
        })
        
    except Exception as e:
        logger.error(f"Error starting capture: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture."""
    global capture_instance, is_capturing
    
    try:
        if not is_capturing:
            return jsonify({
                'success': False,
                'message': 'Capture not running'
            }), 400
        
        if capture_instance:
            stats = capture_instance.stop_capture()
            is_capturing = False
            
            return jsonify({
                'success': True,
                'message': 'Capture stopped',
                'stats': stats
            })
        else:
            is_capturing = False
            return jsonify({
                'success': False,
                'message': 'No capture instance found'
            }), 400
            
    except Exception as e:
        logger.error(f"Error stopping capture: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/status', methods=['GET'])
def capture_status():
    """Get capture status."""
    global capture_instance, is_capturing
    
    try:
        if not is_capturing or not capture_instance:
            return jsonify({
                'success': True,
                'is_capturing': False,
                'message': 'Capture is not running'
            })
        
        stats = capture_instance.get_stats()
        
        return jsonify({
            'success': True,
            'is_capturing': is_capturing,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting capture status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces."""
    try:
        import scapy.all as scapy
        interfaces = scapy.get_if_list()
        
        return jsonify({
            'success': True,
            'interfaces': interfaces
        })
        
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500