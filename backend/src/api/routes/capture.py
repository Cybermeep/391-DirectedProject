"""
Packet capture control routes for the NIDS API.

This module provides endpoints for starting, stopping, and monitoring
packet capture.

AUDIT FIX: the original version started PacketCapture with no callback at
all, so packets went into a ring buffer and were never actually analyzed -
there was no live path from capture to detection. /start now builds a
DetectionPipeline (flow tracking -> feature computation -> rule engine +
ML model -> alert creation -> websocket broadcast) and passes its
handle_packet method as the capture callback.
"""

from flask import Blueprint, request, jsonify, current_app
import logging
import threading

logger = logging.getLogger(__name__)

bp = Blueprint('capture', __name__)

# Global capture instance (will be initialized when needed)
capture_instance = None
capture_thread = None
detection_pipeline = None
is_capturing = False

@bp.route('/start', methods=['POST'])
def start_capture():
    """Start packet capture."""
    global capture_instance, capture_thread, detection_pipeline, is_capturing
    
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
        from core.detection_pipeline import DetectionPipeline

        # Initialize capture
        capture_instance = PacketCapture(
            interface=interface,
            ring_buffer_size=10000,
            promiscuous=False
        )

        rule_engine = current_app.config.get('RULE_ENGINE')
        detection_pipeline = DetectionPipeline(rule_engine=rule_engine)

        from rules.models import get_enabled_builtin_codes
        detection_pipeline.load_enabled_builtin_signatures(get_enabled_builtin_codes())

        current_app.config['DETECTION_PIPELINE'] = detection_pipeline
        detection_pipeline.start_reaper()

        # Start capture in background thread
        def capture_loop():
            global is_capturing
            try:
                capture_instance.start_capture(callback=detection_pipeline.handle_packet, filter_str=filter_str)
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
    global capture_instance, detection_pipeline, is_capturing
    
    try:
        if not is_capturing:
            return jsonify({
                'success': False,
                'message': 'Capture not running'
            }), 400
        
        if capture_instance:
            stats = capture_instance.stop_capture()
            is_capturing = False

            if detection_pipeline:
                detection_pipeline.stop_reaper()
                stats['flows_processed'] = detection_pipeline.flows_processed
                stats['alerts_generated'] = detection_pipeline.alerts_generated

            current_app.config['DETECTION_PIPELINE'] = None

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
    global capture_instance, detection_pipeline, is_capturing
    
    try:
        if not is_capturing or not capture_instance:
            return jsonify({
                'success': True,
                'is_capturing': False,
                'message': 'Capture is not running'
            })
        
        stats = capture_instance.get_stats()
        if detection_pipeline:
            stats['flows_processed'] = detection_pipeline.flows_processed
            stats['alerts_generated'] = detection_pipeline.alerts_generated
            stats['active_flows'] = detection_pipeline.tracker.active_flow_count()

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
        import platform
        if platform.system() == 'Windows':
            # scapy's generic get_if_list() returns raw device GUIDs on
            # Windows, meaningless to a human. get_windows_if_list() reads
            # the same friendly names Windows itself shows (e.g. "Wi-Fi"),
            # and scapy's sniff()/conf.iface already accept these friendly
            # names directly on Windows - nothing else needs to change.
            from scapy.arch.windows import get_windows_if_list
            raw_interfaces = get_windows_if_list()
            # Skip virtual/filter pseudo-adapters (WFP filters, QoS
            # schedulers, WAN miniports) that will never see real traffic.
            interfaces = [i['name'] for i in raw_interfaces if i.get('ips')]
            if not interfaces:
                interfaces = [i['name'] for i in raw_interfaces]
        else:
            import scapy.all as scapy
            interfaces = scapy.get_if_list()

        return jsonify({
            'success': True,
            'interfaces': interfaces
        })

    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500