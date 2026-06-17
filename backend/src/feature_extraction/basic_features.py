"""
Basic feature extraction for packets and flows.

This module extracts fundamental network features including IP addresses,
ports, protocol information, and basic packet characteristics. These features
form the foundation for more complex analysis.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP
import logging

logger = logging.getLogger(__name__)


class BasicFeatureExtractor:
    """
    Extracts basic network features from packets and flows.
    
    This class provides methods for extracting fundamental features such as
    source/destination IP addresses, port numbers, protocol types, and
    packet length statistics. These features are used as input for both
    rule-based and ML-based detection.
    """
    
    @staticmethod
    def extract_packet_features(packet) -> Dict[str, Any]:
        """
        Extract basic features from a single packet.
        
        Features extracted include:
            - Packet length and size metrics
            - Source and destination IP addresses
            - Protocol type (TCP, UDP, ICMP)
            - Source and destination ports
            - IP flags and TTL values
            - Protocol presence flags
        
        Args:
            packet: Scapy packet object to analyze
            
        Returns:
            Dict[str, Any]: Dictionary of basic packet features:
                - packet_length (int): Total packet length in bytes
                - protocol (str): Protocol name (TCP, UDP, ICMP, etc.)
                - src_ip (str): Source IP address
                - dst_ip (str): Destination IP address
                - src_port (int): Source port number (0 if not applicable)
                - dst_port (int): Destination port number (0 if not applicable)
                - ip_flags (int): IP flags field
                - ttl (int): Time To Live value
                - is_ipv4 (bool): True if IPv4 packet
                - is_ipv6 (bool): True if IPv6 packet
                - has_tcp (bool): True if TCP layer present
                - has_udp (bool): True if UDP layer present
                - has_icmp (bool): True if ICMP layer present
        """
        features = {
            'packet_length': len(packet),
            'protocol': 'unknown',
            'src_ip': '0.0.0.0',
            'dst_ip': '0.0.0.0',
            'src_port': 0,
            'dst_port': 0,
            'ip_flags': 0,
            'ttl': 0,
            'is_ipv4': False,
            'is_ipv6': False,
            'has_tcp': False,
            'has_udp': False,
            'has_icmp': False,
        }
        
        try:
            # Extract IP layer information
            if IP in packet:
                ip = packet[IP]
                features['src_ip'] = ip.src
                features['dst_ip'] = ip.dst
                features['protocol'] = BasicFeatureExtractor._get_protocol_name(ip.proto)
                features['ip_flags'] = ip.flags
                features['ttl'] = ip.ttl
                features['is_ipv4'] = True
                
                # Extract transport layer
                if TCP in packet:
                    tcp = packet[TCP]
                    features['has_tcp'] = True
                    features['src_port'] = tcp.sport
                    features['dst_port'] = tcp.dport
                elif UDP in packet:
                    udp = packet[UDP]
                    features['has_udp'] = True
                    features['src_port'] = udp.sport
                    features['dst_port'] = udp.dport
                elif ICMP in packet:
                    features['has_icmp'] = True
                    
        except Exception as e:
            logger.error(f"Error extracting basic features: {e}")
            
        return features
    
    @staticmethod
    def _get_protocol_name(protocol_num: int) -> str:
        """
        Map protocol number to human-readable name.
        
        Args:
            protocol_num (int): IP protocol number
            
        Returns:
            str: Protocol name or 'unknown-{num}' if not recognized
        """
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            89: 'OSPF',
            132: 'SCTP'
        }
        return protocol_map.get(protocol_num, f'unknown-{protocol_num}')
    
    @staticmethod
    def extract_flow_features(flow_packets: List) -> Dict[str, Any]:
        """
        Extract aggregate basic features from a flow of packets.
        
        Computes statistics across all packets in a flow including:
            - Packet count and total bytes
            - Average, min, max, and standard deviation of packet sizes
            - Protocols used in the flow
        
        Args:
            flow_packets (List): List of packets belonging to the same flow
            
        Returns:
            Dict[str, Any]: Dictionary of flow-level features:
                - flow_packet_count (int): Total packets in flow
                - flow_total_bytes (int): Total bytes in flow
                - flow_avg_packet_size (float): Average packet size
                - flow_min_packet_size (int): Minimum packet size
                - flow_max_packet_size (int): Maximum packet size
                - flow_std_packet_size (float): Standard deviation of packet sizes
                - flow_src_ip (str): Source IP of flow
                - flow_dst_ip (str): Destination IP of flow
                - flow_protocols (List[str]): Protocols used in flow
        """
        if not flow_packets:
            return {}
        
        features = {
            'flow_packet_count': len(flow_packets),
            'flow_total_bytes': sum(len(p) for p in flow_packets),
            'flow_avg_packet_size': 0.0,
            'flow_min_packet_size': float('inf'),
            'flow_max_packet_size': 0,
            'flow_std_packet_size': 0.0,
            'flow_protocols': set(),
        }
        
        packet_sizes = []
        first_packet = flow_packets[0]
        
        # Get flow identifier from first packet
        if IP in first_packet:
            features['flow_src_ip'] = first_packet[IP].src
            features['flow_dst_ip'] = first_packet[IP].dst
        
        # Collect statistics
        for packet in flow_packets:
            size = len(packet)
            packet_sizes.append(size)
            
            if IP in packet:
                features['flow_protocols'].add(
                    BasicFeatureExtractor._get_protocol_name(packet[IP].proto)
                )
            
            # Update min/max
            features['flow_min_packet_size'] = min(features['flow_min_packet_size'], size)
            features['flow_max_packet_size'] = max(features['flow_max_packet_size'], size)
        
        # Calculate statistical measures
        if packet_sizes:
            features['flow_avg_packet_size'] = float(np.mean(packet_sizes))
            features['flow_std_packet_size'] = float(np.std(packet_sizes))
        
        # Convert set to list for serialization
        features['flow_protocols'] = list(features['flow_protocols'])
        
        return features
    
    @staticmethod
    def create_basic_feature_vector(packet_features: Dict[str, Any]) -> pd.Series:
        """
        Create a pandas Series from packet features for ML input.
        
        Args:
            packet_features (Dict[str, Any]): Dictionary of features from extract_packet_features()
            
        Returns:
            pd.Series: Series with standardized feature columns and values
            
        Note:
            Missing features are filled with default values (0 or 'unknown')
        """
        # Define expected feature columns in standard order
        feature_columns = [
            'packet_length', 'protocol', 'src_ip', 'dst_ip', 
            'src_port', 'dst_port', 'ttl', 'is_ipv4',
            'has_tcp', 'has_udp', 'has_icmp'
        ]
        
        # Create series with default values
        series = pd.Series(index=feature_columns, dtype=object)
        
        # Fill with values from packet features
        for col in feature_columns:
            series[col] = packet_features.get(col, 0 if col != 'protocol' else 'unknown')
        
        return series
    
    @staticmethod
    def basic_feature_names() -> List[str]:
        """
        Get list of basic feature names in standard order.
        
        Returns:
            List[str]: List of feature column names
        """
        return [
            'packet_length',
            'protocol',
            'src_ip',
            'dst_ip',
            'src_port',
            'dst_port',
            'ttl',
            'is_ipv4',
            'has_tcp',
            'has_udp',
            'has_icmp'
        ]