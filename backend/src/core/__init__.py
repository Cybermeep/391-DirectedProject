"""
Core packet capture and processing module.

This module provides the foundational components for capturing network packets,
processing them, and storing them in a ring buffer. It serves as the base layer
for the NIDS system's data acquisition pipeline.

Exports:
    PacketCapture: Handles live network capture and PCAP file reading
    PacketProcessor: Extracts and processes packet information
    RingBuffer: Thread-safe circular buffer for packet storage
"""

try:
    from .packet_capture import PacketCapture
except ImportError:

    PacketCapture = None

try:
    from .packet_processor import PacketProcessor
except ImportError:
    PacketProcessor = None

from .ring_buffer import RingBuffer

# Define public interface for this module
__all__ = [
    'PacketCapture',
    'PacketProcessor',
    'RingBuffer'
]