"""
Packet capture engine using Scapy for live capture and PCAP replay.

This module provides the primary interface for capturing network traffic.
It supports live capture from network interfaces as well as reading from
pre-recorded PCAP files. The engine runs in a separate thread and maintains
a ring buffer to prevent memory exhaustion.
"""

import threading
import time
from typing import Optional, Callable, List, Dict, Any
from queue import Queue, Empty
import logging

from scapy.all import sniff, rdpcap, wrpcap, Ether, IP, TCP, UDP, ICMP, Raw
from scapy.layers.inet import IP

from .ring_buffer import RingBuffer

# Configure module-level logger
logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Packet capture engine supporting live capture and PCAP replay.
    
    This class manages the capture of network packets from a specified interface
    or from PCAP files. It operates in a separate thread to avoid blocking the
    main application. Captured packets are stored in a ring buffer and can be
    processed by callback functions.
    
    Features:
        - Live capture from network interface using Scapy
        - PCAP file reading for replay mode
        - Ring buffer for memory management (10k packets default)
        - Callback support for packet processing
        - Thread-safe operation with queue for packet processing
        - Capture statistics tracking
    
    Attributes:
        interface (str): Network interface name for live capture
        ring_buffer (RingBuffer): Storage buffer for captured packets
        promiscuous (bool): Whether to use promiscuous mode
        _is_capturing (bool): Flag indicating active capture state
        _capture_thread (threading.Thread): Background capture thread
        _packet_callback (Callable): Function called for each packet
        _stop_event (threading.Event): Signal for stopping capture
        _packet_queue (Queue): Thread-safe queue for packet processing
        _capture_stats (dict): Statistics about the capture session
    """
    
    def __init__(self, 
                 interface: Optional[str] = None,
                 ring_buffer_size: int = 10000,
                 promiscuous: bool = False):
        """
        Initialize packet capture engine with specified parameters.
        
        Args:
            interface (str, optional): Network interface name (e.g., 'eth0', 'en0')
                                      If None, capture won't start until set
            ring_buffer_size (int): Maximum number of packets in ring buffer
                                   Default is 10,000 packets
            promiscuous (bool): Enable promiscuous mode for capture
                               Default is False
        
        Raises:
            ValueError: If ring_buffer_size is not positive
        """
        if ring_buffer_size <= 0:
            raise ValueError(f"ring_buffer_size must be positive, got {ring_buffer_size}")
        
        self.interface = interface
        self.ring_buffer = RingBuffer(max_size=ring_buffer_size)
        self.promiscuous = promiscuous
        
        # Internal state
        self._is_capturing = False
        self._capture_thread: Optional[threading.Thread] = None
        self._packet_callback: Optional[Callable] = None
        self._stop_event = threading.Event()
        self._packet_queue = Queue(maxsize=1000)  # Prevent memory bloat
        
        # Capture statistics
        self._capture_stats = {
            'packets_captured': 0,
            'bytes_captured': 0,
            'start_time': None,
            'end_time': None,
            'errors': 0
        }
        
        logger.info(f"PacketCapture initialized with interface: {interface}, "
                   f"buffer_size: {ring_buffer_size}, promiscuous: {promiscuous}")
    
    def start_capture(self, 
                     callback: Optional[Callable] = None,
                     filter_str: Optional[str] = None,
                     timeout: Optional[int] = None) -> bool:
        """
        Start live packet capture on the configured interface.
        
        This method launches a background thread that captures packets and
        processes them through the provided callback. The capture continues
        until stop_capture() is called or the optional timeout is reached.
        
        Args:
            callback (Callable, optional): Function to call for each captured packet
                                          The function should accept a single packet parameter
            filter_str (str, optional): BPF filter string (e.g., "tcp port 80")
                                       Limits captured packets to those matching filter
            timeout (int, optional): Capture duration in seconds
                                    If None, capture continues until stopped
            
        Returns:
            bool: True if capture started successfully, False otherwise
            
        Raises:
            RuntimeError: If no interface is configured
        """
        # Validate state
        if self._is_capturing:
            logger.warning("Capture already in progress")
            return False
        
        if not self.interface:
            logger.error("No interface specified for capture")
            return False
        
        # Configure capture parameters
        self._packet_callback = callback
        self._is_capturing = True
        self._stop_event.clear()
        self._capture_stats['start_time'] = time.time()
        self._capture_stats['end_time'] = None
        
        logger.info(f"Starting packet capture on interface: {self.interface} "
                   f"with filter: {filter_str if filter_str else 'none'}")
        
        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(filter_str, timeout),
            daemon=True
        )
        self._capture_thread.start()
        
        return True
    
    def _capture_loop(self, filter_str: Optional[str] = None, 
                      timeout: Optional[int] = None) -> None:
        """
        Main capture loop running in a separate background thread.
        
        This method uses Scapy's sniff function to capture packets and
        processes them through the callback chain. It handles cleanup
        and error recovery.
        
        Args:
            filter_str (str, optional): BPF filter for capture
            timeout (int, optional): Maximum duration for capture in seconds
        """
        try:
            # Start Scapy sniffing
            sniff(
                iface=self.interface,
                prn=self._process_packet,      # Callback for each packet
                filter=filter_str,              # BPF filter
                timeout=timeout,                # Optional timeout
                stop_filter=lambda x: self._stop_event.is_set(),  # Stop condition
                store=False,                    # Don't store internally
                promisc=self.promiscuous        # Promiscuous mode
            )
        except PermissionError as e:
            logger.error(f"Permission denied: Run with sudo or root privileges: {e}")
            self._capture_stats['errors'] += 1
        except Exception as e:
            logger.error(f"Error in capture loop: {e}")
            self._capture_stats['errors'] += 1
        finally:
            self._is_capturing = False
            self._capture_stats['end_time'] = time.time()
            logger.info("Capture loop ended")
    
    def _process_packet(self, packet) -> None:
        """
        Process a single captured packet and route it through the pipeline.
        
        This method handles the incoming packet by:
        1. Adding it to the ring buffer
        2. Updating capture statistics
        3. Calling the user-defined callback if provided
        4. Adding to the processing queue
        
        Args:
            packet: Scapy packet object to process
            
        Raises:
            Exception: Any exception is logged but not propagated to prevent
                      interrupting the capture loop
        """
        try:
            # Store in ring buffer
            self.ring_buffer.add(packet)
            
            # Update statistics
            self._capture_stats['packets_captured'] += 1
            self._capture_stats['bytes_captured'] += len(packet)
            
            # Call user callback if provided
            if self._packet_callback:
                self._packet_callback(packet)
            
            # Add to processing queue (non-blocking)
            try:
                self._packet_queue.put_nowait(packet)
            except:
                # Queue full, drop packet but maintain stats
                # This prevents memory exhaustion from queue buildup
                logger.debug("Packet queue full, dropping packet")
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            self._capture_stats['errors'] += 1
    
    def stop_capture(self) -> Dict[str, Any]:
        """
        Stop the packet capture and return final statistics.
        
        This method signals the capture thread to stop, waits for it to
        complete, and returns capture statistics. If capture is not running,
        it returns current statistics.
        
        Returns:
            Dict[str, Any]: Dictionary containing final capture statistics:
                - is_capturing: False after stop
                - packets_captured: Total packets captured
                - bytes_captured: Total bytes captured
                - buffer_size: Current ring buffer size
                - buffer_capacity: Maximum ring buffer capacity
                - duration_seconds: Total capture duration
                - errors: Number of errors encountered
                - interface: Interface used for capture
                - promiscuous: Whether promiscuous mode was enabled
        """
        if not self._is_capturing:
            logger.warning("Capture not running")
            return self.get_stats()
        
        logger.info("Stopping packet capture...")
        
        # Signal thread to stop
        self._stop_event.set()
        self._is_capturing = False
        
        # Wait for thread to finish
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)
            if self._capture_thread.is_alive():
                logger.warning("Capture thread did not stop gracefully")
        
        self._capture_stats['end_time'] = time.time()
        return self.get_stats()
    
    def read_pcap(self, pcap_path: str, 
                  callback: Optional[Callable] = None,
                  limit: Optional[int] = None) -> int:
        """
        Read and process packets from a PCAP file.
        
        This method loads packets from a PCAP file and processes them as if
        they were captured live. This is useful for testing, demo scenarios,
        and replaying captured traffic.
        
        Args:
            pcap_path (str): Path to the PCAP file to read
            callback (Callable, optional): Function to call for each packet
            limit (int, optional): Maximum number of packets to read
                                  If None, reads all packets in file
            
        Returns:
            int: Number of packets successfully read and processed
            
        Raises:
            FileNotFoundError: If the PCAP file doesn't exist
            IOError: If the file cannot be read
        """
        try:
            logger.info(f"Reading PCAP file: {pcap_path}")
            
            # Read all packets from PCAP
            packets = rdpcap(pcap_path)
            
            # Apply limit if specified
            if limit and limit > 0:
                packets = packets[:limit]
            
            count = 0
            for packet in packets:
                # Add to ring buffer
                self.ring_buffer.add(packet)
                
                # Update stats
                self._capture_stats['packets_captured'] += 1
                self._capture_stats['bytes_captured'] += len(packet)
                
                # Call callback if provided
                if callback:
                    callback(packet)
                
                count += 1
            
            logger.info(f"Successfully read {count} packets from PCAP file")
            return count
            
        except FileNotFoundError as e:
            logger.error(f"PCAP file not found: {pcap_path}")
            raise
        except Exception as e:
            logger.error(f"Error reading PCAP file: {e}")
            self._capture_stats['errors'] += 1
            return 0
    
    def save_pcap(self, pcap_path: str, packets: Optional[List] = None) -> bool:
        """
        Save packets from ring buffer to a PCAP file.
        
        This method writes packets to a PCAP file for later analysis or replay.
        If no packet list is provided, it saves the current ring buffer contents.
        
        Args:
            pcap_path (str): Path where the PCAP file should be saved
            packets (List, optional): List of packets to save
                                     If None, uses current ring buffer contents
            
        Returns:
            bool: True if saved successfully, False otherwise
            
        Raises:
            IOError: If the file cannot be written
        """
        try:
            # Use ring buffer if no packets provided
            if packets is None:
                packets = self.ring_buffer.get_all()
            
            if not packets:
                logger.warning("No packets to save")
                return False
            
            # Write packets to PCAP file
            wrpcap(pcap_path, packets)
            logger.info(f"Saved {len(packets)} packets to {pcap_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving PCAP file: {e}")
            self._capture_stats['errors'] += 1
            return False
    
    def get_next_packet(self, timeout: float = 0.1) -> Optional[Any]:
        """
        Get the next packet from the processing queue.
        
        This method retrieves packets from the internal queue, allowing
        for asynchronous processing. It's useful for applications that
        want to process packets in a separate loop.
        
        Args:
            timeout (float): Maximum time to wait for a packet in seconds
                            Default is 0.1 seconds
            
        Returns:
            Optional[Any]: The next packet if available, None if timeout occurs
            
        Raises:
            ValueError: If timeout is negative
        """
        if timeout < 0:
            raise ValueError(f"timeout must be non-negative, got {timeout}")
        
        try:
            return self._packet_queue.get(timeout=timeout)
        except Empty:
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current capture statistics.
        
        Returns a dictionary with comprehensive capture statistics including
        packet counts, durations, and buffer status.
        
        Returns:
            Dict[str, Any]: Dictionary containing:
                - is_capturing (bool): Whether capture is active
                - packets_captured (int): Total packets captured
                - bytes_captured (int): Total bytes captured
                - buffer_size (int): Current number of packets in buffer
                - buffer_capacity (int): Maximum buffer capacity
                - duration_seconds (float): Capture duration in seconds
                - errors (int): Number of errors encountered
                - interface (str): Network interface used
                - promiscuous (bool): Whether promiscuous mode is enabled
        """
        duration = None
        if self._capture_stats['start_time']:
            end_time = self._capture_stats.get('end_time', time.time())
            duration = end_time - self._capture_stats['start_time']
        
        return {
            'is_capturing': self._is_capturing,
            'packets_captured': self._capture_stats['packets_captured'],
            'bytes_captured': self._capture_stats['bytes_captured'],
            'buffer_size': len(self.ring_buffer),
            'buffer_capacity': self.ring_buffer.max_size,
            'duration_seconds': duration,
            'errors': self._capture_stats['errors'],
            'interface': self.interface,
            'promiscuous': self.promiscuous
        }
    
    def clear_buffer(self) -> None:
        """
        Clear the packet ring buffer.
        
        This removes all packets from the buffer, freeing memory.
        Useful for starting a fresh capture session.
        """
        self.ring_buffer.clear()
        logger.info("Ring buffer cleared")