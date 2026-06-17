#!/usr/bin/env python3
"""
Main entry point for the NIDS backend.

This script initializes and runs the Network Intrusion Detection System
backend. It demonstrates packet capture, flow aggregation, and feature
extraction.
"""

import os
import sys
import logging
import time
from dotenv import load_dotenv

# Add src to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.packet_capture import PacketCapture
from core.packet_processor import PacketProcessor
from feature_extraction.extractor import FeatureExtractor
from feature_extraction.flow_builder import FlowBuilder

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def packet_handler(packet, flow_builder, extractor):
    """
    Handle incoming packets for processing.
    
    This callback function is called for each captured packet. It:
    1. Adds the packet to the flow builder for aggregation
    2. Extracts features from the packet
    3. Processes completed flows for feature extraction
    
    Args:
        packet: Scapy packet object
        flow_builder (FlowBuilder): Flow builder instance
        extractor (FeatureExtractor): Feature extractor instance
    """
    # Add packet to flow builder
    completed_flow_id = flow_builder.add_packet(packet)
    
    # Extract features from the packet (for debugging)
    features = extractor.extract_features_from_packet(packet)
    logger.debug(f"Packet features: {features}")
    
    # Check if a flow was completed
    if completed_flow_id:
        # Get completed flows
        completed_flows = flow_builder.get_completed_flows()
        for flow in completed_flows:
            # Extract flow features
            flow_features = extractor.extract_features_from_flow(flow['packets'])
            logger.info(
                f"Flow completed: {flow['flow_id']} - "
                f"{flow_features.get('flow_packet_count', 0)} packets, "
                f"Duration: {flow_features.get('total_duration', 0):.2f}s"
            )


def main():
    """
    Main function to run the NIDS backend demonstration.
    
    This function:
    1. Initializes all components (capture, flow builder, feature extractor)
    2. Starts packet capture
    3. Periodically displays statistics
    4. Handles graceful shutdown on Ctrl+C
    """
    # Get configuration from environment
    interface = os.getenv('NIDS_INTERFACE', 'eth0')
    ring_buffer_size = int(os.getenv('RING_BUFFER_SIZE', 10000))
    promiscuous = os.getenv('NIDS_PROMISCUOUS', 'false').lower() == 'true'
    flow_timeout = int(os.getenv('FLOW_TIMEOUT', 60))
    max_flow_size = int(os.getenv('MAX_FLOW_SIZE', 1000))
    
    logger.info("=" * 60)
    logger.info("NIDS Backend Starting")
    logger.info(f"Interface: {interface}")
    logger.info(f"Ring Buffer Size: {ring_buffer_size}")
    logger.info(f"Promiscuous Mode: {promiscuous}")
    logger.info(f"Flow Timeout: {flow_timeout}s")
    logger.info(f"Max Flow Size: {max_flow_size} packets")
    logger.info("=" * 60)
    
    # Initialize components
    capture = PacketCapture(
        interface=interface,
        ring_buffer_size=ring_buffer_size,
        promiscuous=promiscuous
    )
    
    flow_builder = FlowBuilder(
        flow_timeout=flow_timeout,
        max_flow_size=max_flow_size
    )
    
    extractor = FeatureExtractor()
    
    # Create callback wrapper
    def callback(packet):
        packet_handler(packet, flow_builder, extractor)
    
    try:
        # Start packet capture
        logger.info("Starting packet capture...")
        capture.start_capture(callback=callback)
        
        # Main loop - display statistics
        try:
            while True:
                time.sleep(5)  # Update every 5 seconds
                stats = capture.get_stats()
                flow_stats = flow_builder.get_stats()
                
                logger.info(
                    f"Stats: {stats['packets_captured']} packets captured, "
                    f"{stats['buffer_size']} in buffer, "
                    f"{flow_stats['active_flows']} active flows, "
                    f"{flow_stats['completed_flows']} completed flows"
                )
                
        except KeyboardInterrupt:
            logger.info("\nReceived interrupt signal")
            
    finally:
        # Cleanup
        logger.info("Stopping capture...")
        final_stats = capture.stop_capture()
        
        # Display final statistics
        logger.info("=" * 60)
        logger.info("Final Statistics:")
        logger.info(f"  Total Packets Captured: {final_stats['packets_captured']}")
        logger.info(f"  Total Bytes Captured: {final_stats['bytes_captured']}")
        logger.info(f"  Duration: {final_stats['duration_seconds']:.2f} seconds")
        logger.info(f"  Errors: {final_stats['errors']}")
        logger.info(f"  Buffer Size: {final_stats['buffer_size']}")
        logger.info(f"  Active Flows: {flow_builder.get_stats()['active_flows']}")
        logger.info(f"  Completed Flows: {flow_builder.get_stats()['completed_flows']}")
        logger.info("=" * 60)
        logger.info("NIDS Backend Shutdown Complete")


if __name__ == "__main__":
    main()