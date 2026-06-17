"""
Flow builder for aggregating packets into flows and time windows.

This module provides functionality for grouping packets into network flows
based on the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol). It
manages active flows, handles flow timeouts, and provides completed flows
for analysis.
"""

from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import time
from datetime import datetime
import logging
from scapy.all import IP, TCP, UDP

logger = logging.getLogger(__name__)


class FlowBuilder:
    """
    Aggregates packets into flows based on 5-tuple key.
    
    This class manages the lifecycle of network flows. It groups packets
    belonging to the same communication session, handles flow timeouts,
    and provides access to completed flows for feature extraction.
    
    Features:
        - Flow aggregation by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
        - Automatic flow timeout based on inactivity
        - Maximum packet limit per flow to prevent memory issues
        - Completion notification when flows are finalized
        
    Attributes:
        flow_timeout (int): Seconds of inactivity before flow expires
        max_flow_size (int): Maximum packets per flow before force completion
        active_flows (dict): Dictionary of currently active flows
        completed_flows (list): List of completed flows ready for processing
        flow_counter (int): Counter for generating unique flow IDs
    """
    
    def __init__(self, flow_timeout: int = 60, max_flow_size: int = 1000):
        """
        Initialize flow builder with specified parameters.
        
        Args:
            flow_timeout (int): Seconds of inactivity before flow is considered complete
                                Default is 60 seconds
            max_flow_size (int): Maximum packets per flow before force completion
                                Default is 1000 packets
                                
        Raises:
            ValueError: If flow_timeout <= 0 or max_flow_size <= 0
        """
        if flow_timeout <= 0:
            raise ValueError(f"flow_timeout must be positive, got {flow_timeout}")
        if max_flow_size <= 0:
            raise ValueError(f"max_flow_size must be positive, got {max_flow_size}")
        
        self.flow_timeout = flow_timeout
        self.max_flow_size = max_flow_size
        self.active_flows: Dict[str, Dict] = {}
        self.completed_flows: List[Dict] = []
        self.flow_counter = 0
        
        logger.info(f"FlowBuilder initialized with timeout: {flow_timeout}s, "
                   f"max_size: {max_flow_size}")
    
    def get_flow_key(self, packet) -> Optional[Tuple[str, str, int, int, int]]:
        """
        Generate a flow key from a packet.
        
        The flow key is the 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol).
        Direction is normalized so that the smaller IP address is first for consistency.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Optional[Tuple[str, str, int, int, int]]: Flow key tuple or None if packet
            doesn't contain required layers (e.g., no IP layer)
            
        Note:
            - Direction is normalized (src_ip < dst_ip) to ensure bidirectional flows
              are grouped together regardless of which side initiated the communication
            - For non-TCP/UDP protocols, ports are set to 0
        """
        try:
            if IP not in packet:
                return None
            
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            protocol = ip.proto
            
            # Get ports if available
            src_port = 0
            dst_port = 0
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Normalize flow direction (smallest IP first for bidirectional flows)
            if src_ip > dst_ip:
                src_ip, dst_ip = dst_ip, src_ip
                src_port, dst_port = dst_port, src_port
            elif src_ip == dst_ip and src_port > dst_port:
                src_port, dst_port = dst_port, src_port
            
            return (src_ip, dst_ip, src_port, dst_port, protocol)
            
        except Exception as e:
            logger.error(f"Error generating flow key: {e}")
            return None
    
    def add_packet(self, packet) -> Optional[str]:
        """
        Add a packet to the flow builder.
        
        This method processes an incoming packet, either adding it to an
        existing flow or creating a new flow. If a flow is completed as a
        result (due to timeout or max size), its ID is returned.
        
        Args:
            packet: Scapy packet object to add
            
        Returns:
            Optional[str]: Flow ID if a flow was completed, None otherwise
            
        Note:
            - New flows are created with the packet as the first packet
            - Existing flows have their last_seen time updated
            - Flows are completed when they exceed max_flow_size or timeout
        """
        flow_key = self.get_flow_key(packet)
        if not flow_key:
            return None
        
        flow_id = self._generate_flow_id(flow_key)
        
        # Update or create flow
        if flow_id in self.active_flows:
            flow = self.active_flows[flow_id]
            flow['packets'].append(packet)
            flow['last_seen'] = time.time()
            flow['packet_count'] += 1
            
            # Check if flow should be completed
            if (len(flow['packets']) >= self.max_flow_size or 
                (time.time() - flow['last_seen']) >= self.flow_timeout):
                return self._complete_flow(flow_id)
        else:
            # Create new flow
            self.active_flows[flow_id] = {
                'flow_id': flow_id,
                'flow_key': flow_key,
                'packets': [packet],
                'first_seen': time.time(),
                'last_seen': time.time(),
                'packet_count': 1,
                'src_ip': flow_key[0],
                'dst_ip': flow_key[1],
                'src_port': flow_key[2],
                'dst_port': flow_key[3],
                'protocol': flow_key[4],
                'status': 'active'
            }
        
        return None
    
    def _complete_flow(self, flow_id: str) -> str:
        """
        Complete a flow and move it to the completed flows list.
        
        This method marks a flow as completed, calculates its duration,
        and moves it from active to completed for processing.
        
        Args:
            flow_id (str): ID of the flow to complete
            
        Returns:
            str: The flow ID that was completed
            
        Note:
            If flow_id doesn't exist in active_flows, it returns the ID
            without doing anything.
        """
        if flow_id not in self.active_flows:
            return flow_id
        
        flow = self.active_flows.pop(flow_id)
        flow['status'] = 'completed'
        flow['duration'] = flow['last_seen'] - flow['first_seen']
        self.completed_flows.append(flow)
        
        logger.debug(f"Flow {flow_id} completed with {flow['packet_count']} packets")
        return flow_id
    
    def get_completed_flows(self, clear: bool = True) -> List[Dict]:
        """
        Get and optionally clear completed flows.
        
        Args:
            clear (bool): Whether to clear the completed flows list after retrieval
                         Default is True
            
        Returns:
            List[Dict]: List of completed flow dictionaries
            
        Note:
            Each flow dictionary contains:
                - flow_id: Unique flow identifier
                - flow_key: 5-tuple flow key
                - packets: List of packets in the flow
                - first_seen: Timestamp of first packet
                - last_seen: Timestamp of last packet
                - packet_count: Number of packets in flow
                - src_ip, dst_ip, src_port, dst_port, protocol
                - status: 'completed'
                - duration: Flow duration in seconds
        """
        flows = self.completed_flows.copy()
        if clear:
            self.completed_flows.clear()
        return flows
    
    def get_all_flows(self) -> List[Dict]:
        """
        Get all flows (active and completed).
        
        Returns:
            List[Dict]: List of all flow dictionaries (active + completed)
        """
        flows = list(self.active_flows.values()) + self.completed_flows
        return flows
    
    def expire_old_flows(self) -> List[str]:
        """
        Expire flows that have exceeded the timeout threshold.
        
        This method checks all active flows and completes those that haven't
        seen a packet in longer than flow_timeout.
        
        Returns:
            List[str]: List of expired flow IDs
            
        Note:
            This is typically called periodically to clean up old flows.
        """
        expired = []
        current_time = time.time()
        
        for flow_id, flow in list(self.active_flows.items()):
            if current_time - flow['last_seen'] >= self.flow_timeout:
                self._complete_flow(flow_id)
                expired.append(flow_id)
        
        if expired:
            logger.debug(f"Expired {len(expired)} flows due to timeout")
        
        return expired
    
    def _generate_flow_id(self, flow_key: Tuple) -> str:
        """
        Generate a unique flow ID from the flow key.
        
        Args:
            flow_key (Tuple): Flow key tuple (src_ip, dst_ip, src_port, dst_port, protocol)
            
        Returns:
            str: Unique flow identifier
            
        Note:
            The flow ID includes a counter for uniqueness even if the same
            flow key appears multiple times (e.g., after flow reset).
        """
        self.flow_counter += 1
        return f"flow_{self.flow_counter}_{hash(flow_key)}"
    
    def clear(self) -> None:
        """Clear all flows (active and completed)."""
        self.active_flows.clear()
        self.completed_flows.clear()
        logger.info("All flows cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get flow builder statistics.
        
        Returns:
            Dict[str, Any]: Dictionary containing:
                - active_flows (int): Number of active flows
                - completed_flows (int): Number of completed flows
                - total_flows (int): Total flows (active + completed)
                - flow_timeout (int): Configured timeout in seconds
                - max_flow_size (int): Configured max packet count per flow
        """
        return {
            'active_flows': len(self.active_flows),
            'completed_flows': len(self.completed_flows),
            'total_flows': len(self.active_flows) + len(self.completed_flows),
            'flow_timeout': self.flow_timeout,
            'max_flow_size': self.max_flow_size
        }