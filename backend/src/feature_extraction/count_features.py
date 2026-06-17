"""
Count-based features for traffic analysis.

This module extracts features related to packet counts, flag statistics,
and protocol-specific counts. These features are useful for detecting
certain attack patterns like SYN floods, port scans, and DoS attacks.
"""

from typing import Dict, Any, List, Tuple
import numpy as np
from collections import Counter
from scapy.all import TCP, IP
import logging

logger = logging.getLogger(__name__)


class CountFeatureExtractor:
    """
    Extracts count-based features from network traffic flows.
    
    This class provides methods for counting various packet attributes
    including TCP flags, protocol types, port usage, and calculating
    statistical measures like variance and skewness of packet sizes.
    
    Key features extracted:
        - Total packet counts
        - TCP flag counts (SYN, RST, FIN, ACK)
        - Protocol distribution
        - Port usage patterns
        - Packet size statistics
    """
    
    @staticmethod
    def extract_count_features(packets: List) -> Dict[str, Any]:
        """
        Extract comprehensive count-based features from a flow of packets.
        
        Features computed include:
            - Total packet count
            - TCP flag counts (SYN, RST, FIN, ACK)
            - Packet size variance and skewness
            - Protocol and port distributions
            - IPv4 vs IPv6 counts
            - Flag ratios (SYN/total, RST/total, etc.)
        
        Args:
            packets (List): List of packets in the flow
            
        Returns:
            Dict[str, Any]: Dictionary of count features:
                - total_packets (int): Total packets in flow
                - syn_count (int): Number of SYN packets
                - rst_count (int): Number of RST packets
                - fin_count (int): Number of FIN packets
                - ack_count (int): Number of ACK packets
                - packet_size_variance (float): Variance of packet sizes
                - packet_size_skewness (float): Skewness of packet sizes
                - syn_ratio (float): SYN count / total packets
                - rst_ratio (float): RST count / total packets
                - fin_ratio (float): FIN count / total packets
                - ack_ratio (float): ACK count / total packets
                - ipv4_packets (int): Number of IPv4 packets
                - ipv6_packets (int): Number of IPv6 packets
                - protocol_counts (dict): Counts by protocol
                - port_counts (dict): Counts by port pair
        """
        if not packets:
            return {}
        
        features = {
            'total_packets': len(packets),
            'syn_count': 0,
            'rst_count': 0,
            'fin_count': 0,
            'ack_count': 0,
            'packet_size_variance': 0.0,
            'packet_size_skewness': 0.0,
            'protocol_counts': {},
            'port_counts': {},
            'ipv4_packets': 0,
            'ipv6_packets': 0,
        }
        
        # Initialize counters
        packet_sizes = []
        protocol_counter = Counter()
        port_counter = Counter()
        
        # Process each packet
        for packet in packets:
            size = len(packet)
            packet_sizes.append(size)
            
            # Count IP versions
            if IP in packet:
                features['ipv4_packets'] += 1
            else:
                features['ipv6_packets'] += 1
            
            # Count TCP flags
            if TCP in packet:
                tcp = packet[TCP]
                flags = tcp.flags
                if flags & 0x02:  # SYN flag (0x02 = 00000010)
                    features['syn_count'] += 1
                if flags & 0x04:  # RST flag (0x04 = 00000100)
                    features['rst_count'] += 1
                if flags & 0x01:  # FIN flag (0x01 = 00000001)
                    features['fin_count'] += 1
                if flags & 0x10:  # ACK flag (0x10 = 00010000)
                    features['ack_count'] += 1
                
                # Count port pairs
                port_counter[f"{tcp.sport}_{tcp.dport}"] += 1
            
            # Count protocols
            if IP in packet:
                proto = packet[IP].proto
                protocol_counter[proto] += 1
        
        # Calculate statistical features
        if packet_sizes:
            features['packet_size_variance'] = float(np.var(packet_sizes))
            # Calculate skewness: measure of distribution asymmetry
            if np.std(packet_sizes) > 0:
                features['packet_size_skewness'] = float(
                    np.mean((packet_sizes - np.mean(packet_sizes)) ** 3) / 
                    (np.std(packet_sizes) ** 3)
                )
            else:
                features['packet_size_skewness'] = 0.0
        
        # Convert counters to dictionaries for serialization
        features['protocol_counts'] = dict(protocol_counter)
        features['port_counts'] = dict(port_counter)
        
        # Calculate ratios
        total = features['total_packets']
        if total > 0:
            features['syn_ratio'] = features['syn_count'] / total
            features['rst_ratio'] = features['rst_count'] / total
            features['fin_ratio'] = features['fin_count'] / total
            features['ack_ratio'] = features['ack_count'] / total
        
        return features
    
    @staticmethod
    def calculate_direction_counts(packets: List, 
                                  src_ip: str, 
                                  dst_ip: str) -> Dict[str, int]:
        """
        Count packets by traffic direction.
        
        Determines whether packets are flowing from source to destination,
        destination to source, or are unknown direction.
        
        Args:
            packets (List): List of packets
            src_ip (str): Source IP address of the flow
            dst_ip (str): Destination IP address of the flow
            
        Returns:
            Dict[str, int]: Dictionary with direction counts:
                - src_to_dst: Packets from source to destination
                - dst_to_src: Packets from destination to source
                - unknown: Packets where direction couldn't be determined
        """
        direction_counts = {
            'src_to_dst': 0,
            'dst_to_src': 0,
            'unknown': 0
        }
        
        for packet in packets:
            if IP not in packet:
                direction_counts['unknown'] += 1
                continue
            
            packet_src = packet[IP].src
            if packet_src == src_ip:
                direction_counts['src_to_dst'] += 1
            elif packet_src == dst_ip:
                direction_counts['dst_to_src'] += 1
            else:
                direction_counts['unknown'] += 1
        
        return direction_counts
    
    @staticmethod
    def get_unique_ports(packets: List) -> Tuple[int, int]:
        """
        Count unique source and destination ports in a packet list.
        
        Args:
            packets (List): List of packets
            
        Returns:
            Tuple[int, int]: (unique_src_ports, unique_dst_ports)
            
        Note:
            This is useful for detecting port scans where many different
            destination ports are being contacted from a single source.
        """
        src_ports = set()
        dst_ports = set()
        
        for packet in packets:
            if TCP in packet:
                src_ports.add(packet[TCP].sport)
                dst_ports.add(packet[TCP].dport)
            elif hasattr(packet, 'sport'):  # UDP or other transport protocols
                src_ports.add(packet.sport)
                dst_ports.add(packet.dport)
        
        return len(src_ports), len(dst_ports)
    
    @staticmethod
    def count_feature_names() -> List[str]:
        """
        Get list of count feature names in standard order.
        
        Returns:
            List[str]: List of feature column names
        """
        return [
            'total_packets',
            'syn_count',
            'rst_count',
            'fin_count',
            'ack_count',
            'packet_size_variance',
            'packet_size_skewness',
            'syn_ratio',
            'rst_ratio',
            'fin_ratio',
            'ack_ratio',
            'ipv4_packets',
            'ipv6_packets'
        ]