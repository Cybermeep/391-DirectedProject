"""
Payload-based feature extraction for network traffic.

This module extracts features from packet payloads including length statistics,
entropy measurements, ASCII character percentages, and pattern detection.
These features help identify encrypted traffic, malware, and anomalous payloads.
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from collections import Counter
from scapy.all import Raw, IP, TCP, UDP
import logging

logger = logging.getLogger(__name__)


class PayloadFeatureExtractor:
    """
    Extracts payload-based features from packets and flows.
    
    This class provides methods for analyzing the content of packet payloads.
    Features extracted include payload length, entropy, ASCII percentage,
    and payload patterns that help identify traffic types.
    
    Key features extracted:
        - Payload length statistics
        - Shannon entropy of payload data
        - Percentage of ASCII printable characters
        - Payload pattern classification (http, dns, tls, encrypted, text, etc.)
        - Payload size class (tiny, small, medium, large, huge)
        - Flow-level aggregate payload metrics
    """
    
    # Set of ASCII printable characters (32-126) plus tab, newline, carriage return
    ASCII_PRINTABLE = set(range(32, 127)) | {9, 10, 13}
    
    @staticmethod
    def extract_payload_features(packet) -> Dict[str, Any]:
        """
        Extract features from a single packet's payload.
        
        Features extracted include:
            - Whether the packet has a payload
            - Payload length and size classification
            - Shannon entropy (randomness measure)
            - Percentage of ASCII printable characters
            - Payload pattern classification
            
        Args:
            packet: Scapy packet object to analyze
            
        Returns:
            Dict[str, Any]: Dictionary of payload features:
                - has_payload (bool): True if packet has payload
                - payload_length (int): Length of payload in bytes
                - payload_entropy (float): Shannon entropy (0-8)
                - ascii_percentage (float): Percentage of ASCII chars
                - non_ascii_count (int): Number of non-ASCII bytes
                - payload_pattern (str): Pattern classification
                - payload_size_class (str): Size category
        """
        features = {
            'has_payload': False,
            'payload_length': 0,
            'payload_entropy': 0.0,
            'ascii_percentage': 0.0,
            'non_ascii_count': 0,
            'payload_pattern': 'unknown',
            'payload_size_class': 'none',
        }
        
        try:
            # Check for Raw payload layer
            if Raw in packet:
                raw_data = bytes(packet[Raw])
                features['has_payload'] = True
                features['payload_length'] = len(raw_data)
                
                if len(raw_data) > 0:
                    # Calculate Shannon entropy
                    features['payload_entropy'] = PayloadFeatureExtractor._calculate_entropy(raw_data)
                    
                    # Calculate ASCII percentage
                    ascii_chars = sum(1 for b in raw_data if b in PayloadFeatureExtractor.ASCII_PRINTABLE)
                    features['ascii_percentage'] = (ascii_chars / len(raw_data)) * 100
                    features['non_ascii_count'] = len(raw_data) - ascii_chars
                    
                    # Determine payload pattern/type
                    features['payload_pattern'] = PayloadFeatureExtractor._determine_payload_pattern(raw_data)
                    
                    # Determine size class
                    features['payload_size_class'] = PayloadFeatureExtractor._get_size_class(len(raw_data))
                
        except Exception as e:
            logger.error(f"Error extracting payload features: {e}")
            
        return features
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of byte data.
        
        Shannon entropy measures the randomness of data. Higher entropy
        indicates more random data (e.g., encrypted traffic), while lower
        entropy indicates structured data (e.g., text, protocols).
        
        Args:
            data (bytes): Bytes to calculate entropy for
            
        Returns:
            float: Entropy value between 0 and 8
            
        Note:
            - 0: All bytes identical (completely structured)
            - 8: All byte values equally likely (completely random)
        """
        if not data:
            return 0.0
        
        byte_counts = Counter(data)
        total = len(data)
        entropy = 0.0
        
        for count in byte_counts.values():
            probability = count / total
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    @staticmethod
    def _determine_payload_pattern(data: bytes) -> str:
        """
        Determine the pattern/type of payload data.
        
        Analyzes the payload to classify it into common traffic types:
            - HTTP: GET, POST, or HTTP headers
            - DNS: DNS query/response
            - TLS: SSL/TLS handshake
            - SSH: SSH protocol
            - Text: Mostly ASCII printable characters
            - Encrypted: High entropy, low ASCII
            - Compressed: Low entropy
            - Mixed: Other patterns
        
        Args:
            data (bytes): Payload bytes to analyze
            
        Returns:
            str: Pattern classification string
        """
        if not data:
            return 'empty'
        
        # Check for HTTP
        if data.startswith(b'GET ') or data.startswith(b'POST ') or data.startswith(b'HTTP/'):
            return 'http'
        
        # Check for DNS (first two bytes are transaction ID, 0x00 0x01 for query)
        if len(data) >= 12 and data[:2] in [b'\x00\x01', b'\x00\x02']:
            return 'dns'
        
        # Check for TLS/SSL handshake (first byte 0x16)
        if data[0] == 0x16 and len(data) > 5:
            return 'tls'
        
        # Check for SSH (starts with SSH-)
        if data.startswith(b'SSH-'):
            return 'ssh'
        
        # Calculate metrics for pattern classification
        ascii_percentage = PayloadFeatureExtractor._calculate_ascii_percentage(data)
        entropy = PayloadFeatureExtractor._calculate_entropy(data)
        
        # Classify based on ASCII percentage and entropy
        if ascii_percentage > 80:
            return 'text'
        elif entropy > 7 and ascii_percentage < 30:
            return 'encrypted'
        elif entropy < 4:
            return 'compressed'
        else:
            return 'mixed'
    
    @staticmethod
    def _calculate_ascii_percentage(data: bytes) -> float:
        """
        Calculate percentage of ASCII printable characters in payload.
        
        Args:
            data (bytes): Payload bytes to analyze
            
        Returns:
            float: Percentage of ASCII printable characters (0-100)
        """
        if not data:
            return 0.0
        
        ascii_count = sum(1 for b in data if b in PayloadFeatureExtractor.ASCII_PRINTABLE)
        return (ascii_count / len(data)) * 100
    
    @staticmethod
    def _get_size_class(length: int) -> str:
        """
        Classify payload size into categories.
        
        Args:
            length (int): Payload length in bytes
            
        Returns:
            str: Size classification:
                - tiny: < 64 bytes
                - small: 64-255 bytes
                - medium: 256-1023 bytes
                - large: 1024-4095 bytes
                - huge: >= 4096 bytes
        """
        if length < 64:
            return 'tiny'
        elif length < 256:
            return 'small'
        elif length < 1024:
            return 'medium'
        elif length < 4096:
            return 'large'
        else:
            return 'huge'
    
    @staticmethod
    def extract_flow_payload_features(packets: List) -> Dict[str, Any]:
        """
        Extract aggregate payload features across a flow of packets.
        
        Computes statistics across all packets in a flow including:
            - Total payload bytes and length statistics
            - Average and maximum entropy
            - Average ASCII percentage
            - Distribution of payload patterns
            - Encrypted vs text packet ratios
        
        Args:
            packets (List): List of packets in the flow
            
        Returns:
            Dict[str, Any]: Dictionary of aggregate payload features:
                - total_payload_bytes (int): Total payload bytes in flow
                - avg_payload_length (float): Average payload length
                - std_payload_length (float): Standard deviation of lengths
                - max_payload_length (int): Maximum payload length
                - min_payload_length (int): Minimum payload length
                - avg_entropy (float): Average entropy across packets
                - max_entropy (float): Maximum entropy observed
                - avg_ascii_percentage (float): Average ASCII percentage
                - payload_patterns (dict): Counts of each pattern type
                - encrypted_ratio (float): Ratio of encrypted packets
                - text_ratio (float): Ratio of text packets
                - encrypted_packets (int): Count of encrypted packets
                - text_packets (int): Count of text packets
        """
        if not packets:
            return {}
        
        features = {
            'total_payload_bytes': 0,
            'avg_payload_length': 0.0,
            'std_payload_length': 0.0,
            'max_payload_length': 0,
            'min_payload_length': float('inf'),
            'avg_entropy': 0.0,
            'max_entropy': 0.0,
            'avg_ascii_percentage': 0.0,
            'payload_patterns': {},
            'encrypted_packets': 0,
            'text_packets': 0,
            'encrypted_ratio': 0.0,
            'text_ratio': 0.0,
        }
        
        payload_lengths = []
        entropies = []
        ascii_percentages = []
        pattern_counts = Counter()
        
        # Process each packet
        for packet in packets:
            features_packet = PayloadFeatureExtractor.extract_payload_features(packet)
            
            if features_packet['has_payload']:
                length = features_packet['payload_length']
                payload_lengths.append(length)
                
                if length > 0:
                    entropy = features_packet['payload_entropy']
                    entropies.append(entropy)
                    ascii_percentages.append(features_packet['ascii_percentage'])
                    pattern_counts[features_packet['payload_pattern']] += 1
                    
                    # Track encrypted vs text packets
                    if features_packet['payload_pattern'] == 'encrypted':
                        features['encrypted_packets'] += 1
                    elif features_packet['payload_pattern'] in ['text', 'http']:
                        features['text_packets'] += 1
        
        # Calculate statistical measures
        if payload_lengths:
            features['total_payload_bytes'] = sum(payload_lengths)
            features['avg_payload_length'] = float(np.mean(payload_lengths))
            features['std_payload_length'] = float(np.std(payload_lengths))
            features['max_payload_length'] = int(np.max(payload_lengths))
            features['min_payload_length'] = int(np.min(payload_lengths))
        
        if entropies:
            features['avg_entropy'] = float(np.mean(entropies))
            features['max_entropy'] = float(np.max(entropies))
        
        if ascii_percentages:
            features['avg_ascii_percentage'] = float(np.mean(ascii_percentages))
        
        features['payload_patterns'] = dict(pattern_counts)
        
        # Calculate ratios
        total_packets = len(packets)
        if total_packets > 0:
            features['encrypted_ratio'] = features['encrypted_packets'] / total_packets
            features['text_ratio'] = features['text_packets'] / total_packets
        
        return features
    
    @staticmethod
    def payload_feature_names() -> List[str]:
        """
        Get list of payload feature names in standard order.
        
        Returns:
            List[str]: List of feature column names
        """
        return [
            'payload_length',
            'payload_entropy',
            'ascii_percentage',
            'non_ascii_count',
            'payload_pattern',
            'payload_size_class',
            'total_payload_bytes',
            'avg_payload_length',
            'std_payload_length',
            'max_payload_length',
            'min_payload_length',
            'avg_entropy',
            'max_entropy',
            'avg_ascii_percentage',
            'encrypted_ratio',
            'text_ratio'
        ]