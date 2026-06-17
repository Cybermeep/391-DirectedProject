"""
Main feature extraction coordinator.

This module provides the primary interface for feature extraction, combining
all individual feature extractors (basic, count, temporal, payload) into a
unified pipeline. It can extract features from individual packets, flows,
or time windows.
"""

from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import numpy as np
from datetime import datetime
import logging
import time

# Import from the same package using relative imports
from .basic_features import BasicFeatureExtractor
from .count_features import CountFeatureExtractor
from .temporal_features import TemporalFeatureExtractor
from .payload_features import PayloadFeatureExtractor

# Import from core using absolute import (since src is in sys.path)
try:
    # Try relative import first (works when running as package)
    from ..core.packet_processor import PacketProcessor
except ImportError:
    # Fall back to absolute import (works when running from backend directory)
    try:
        from core.packet_processor import PacketProcessor
    except ImportError:
        # Ultimate fallback - try to import with full path
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from core.packet_processor import PacketProcessor

# Also need to import IP, TCP for the _get_flow_key method
from scapy.all import IP, TCP, UDP

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Main feature extraction engine that coordinates all feature extractors.
    
    This class serves as the central coordinator for all feature extraction
    operations. It combines basic, count, temporal, and payload features into
    complete feature vectors for packets, flows, and time windows.
    
    Attributes:
        basic_extractor (BasicFeatureExtractor): Extracts IP, port, protocol features
        count_extractor (CountFeatureExtractor): Extracts count-based features
        temporal_extractor (TemporalFeatureExtractor): Extracts timing features
        payload_extractor (PayloadFeatureExtractor): Extracts payload features
        packet_processor (PacketProcessor): Processes packet information
    """
    
    def __init__(self):
        """Initialize feature extractor with all sub-extractors."""
        self.basic_extractor = BasicFeatureExtractor()
        self.count_extractor = CountFeatureExtractor()
        self.temporal_extractor = TemporalFeatureExtractor()
        self.payload_extractor = PayloadFeatureExtractor()
        self.packet_processor = PacketProcessor()
        
        logger.info("FeatureExtractor initialized with all sub-extractors")
    
    def extract_features_from_packet(self, packet) -> Dict[str, Any]:
        """
        Extract complete feature set from a single packet.
        
        Combines features from:
            - Basic packet info (IP, ports, protocol)
            - Basic features (length, flags, TTL)
            - Payload features (entropy, ASCII percentage, patterns)
        
        Args:
            packet: Scapy packet object to analyze
            
        Returns:
            Dict[str, Any]: Complete packet feature dictionary including:
                - Packet information (src_ip, dst_ip, ports, protocol)
                - Basic features (packet_length, TTL, flags)
                - Payload features (entropy, ASCII percentage, patterns)
                - Timestamp of extraction
        """
        features = {}
        
        # Extract basic packet info
        packet_info = self.packet_processor.extract_packet_info(packet)
        features.update(packet_info)
        
        # Extract basic features
        basic_features = self.basic_extractor.extract_packet_features(packet)
        features.update(basic_features)
        
        # Extract payload features
        payload_features = self.payload_extractor.extract_payload_features(packet)
        features.update(payload_features)
        
        # Add extraction timestamp
        features['timestamp'] = time.time()
        
        return features
    
    def extract_features_from_flow(self, flow_packets: List) -> Dict[str, Any]:
        """
        Extract features from a complete flow of packets.
        
        Combines features from:
            - Basic flow statistics (packet count, total bytes, size stats)
            - Count features (flag counts, protocol distribution)
            - Temporal features (inter-arrival times, burstiness)
            - Payload features (entropy, pattern distribution)
        
        Args:
            flow_packets (List): List of packets belonging to the same flow
            
        Returns:
            Dict[str, Any]: Complete flow feature dictionary
        """
        if not flow_packets:
            return {}
        
        features = {}
        
        # Basic flow features
        basic_flow_features = self.basic_extractor.extract_flow_features(flow_packets)
        features.update(basic_flow_features)
        
        # Count features
        count_features = self.count_extractor.extract_count_features(flow_packets)
        features.update(count_features)
        
        # Temporal features
        temporal_features = self.temporal_extractor.extract_temporal_features(flow_packets)
        features.update(temporal_features)
        
        # Payload features
        payload_features = self.payload_extractor.extract_flow_payload_features(flow_packets)
        features.update(payload_features)
        
        # Add flow metadata
        features['flow_packet_count'] = len(flow_packets)
        features['flow_duration'] = temporal_features.get('total_duration', 0.0)
        
        return features
    
    def extract_features_from_window(self, packets: List, 
                                    window_start: float, 
                                    window_end: float) -> Dict[str, Any]:
        """
        Extract features from a time window of packets.
        
        Computes aggregate statistics for a group of packets within a
        specified time window. Useful for detecting anomalies in traffic
        patterns over time.
        
        Args:
            packets (List): List of packets in the window
            window_start (float): Start time of window in seconds
            window_end (float): End time of window in seconds
            
        Returns:
            Dict[str, Any]: Dictionary of window-level features:
                - window_duration (float): Duration of window
                - packet_count (int): Total packets in window
                - bytes_total (int): Total bytes in window
                - packet_rate (float): Packets per second
                - unique_flows (int): Number of unique flows
                - unique_ips (int): Number of unique IP addresses
                - unique_protocols (int): Number of unique protocols
        """
        features = {
            'window_duration': window_end - window_start,
            'packet_count': len(packets),
            'bytes_total': sum(len(p) for p in packets),
            'packet_rate': 0.0,
            'unique_flows': 0,
            'unique_ips': 0,
            'unique_protocols': 0,
        }
        
        if features['window_duration'] > 0:
            features['packet_rate'] = features['packet_count'] / features['window_duration']
        
        # Extract unique identifiers
        flows = set()
        unique_ips = set()
        unique_protocols = set()
        
        for packet in packets:
            if IP in packet:
                ip = packet[IP]
                unique_ips.add(ip.src)
                unique_ips.add(ip.dst)
                unique_protocols.add(ip.proto)
                
                flow_key = self._get_flow_key(packet)
                if flow_key:
                    flows.add(flow_key)
        
        features['unique_flows'] = len(flows)
        features['unique_ips'] = len(unique_ips)
        features['unique_protocols'] = len(unique_protocols)
        
        return features
    
    def _get_flow_key(self, packet) -> Optional[Tuple]:
        """
        Generate a flow key from a packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Optional[Tuple]: Flow key or None if no IP layer
            
        Note:
            This is a simplified version of the flow key generation used
            in FlowBuilder. It's used for counting unique flows in a window.
        """
        try:
            if IP not in packet:
                return None
            
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto
            
            # Get ports
            src_port = 0
            dst_port = 0
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Normalize direction
            if src_ip > dst_ip:
                src_ip, dst_ip = dst_ip, src_ip
                src_port, dst_port = dst_port, src_port
            
            return (src_ip, dst_ip, src_port, dst_port, proto)
        except Exception:
            return None
    
    def create_feature_dataframe(self, packets: List) -> pd.DataFrame:
        """
        Create a pandas DataFrame from a list of packets.
        
        Args:
            packets (List): List of packets to convert
            
        Returns:
            pd.DataFrame: DataFrame with features for each packet
            
        Note:
            Returns empty DataFrame if no packets provided
        """
        feature_list = []
        for packet in packets:
            features = self.extract_features_from_packet(packet)
            feature_list.append(features)
        
        if not feature_list:
            return pd.DataFrame()
        
        return pd.DataFrame(feature_list)
    
    def create_flow_dataframe(self, flows: List[Dict]) -> pd.DataFrame:
        """
        Create a pandas DataFrame from a list of flows.
        
        Args:
            flows (List[Dict]): List of flow dictionaries from FlowBuilder
            
        Returns:
            pd.DataFrame: DataFrame with flow features
            
        Note:
            Returns empty DataFrame if no flows provided
        """
        flow_features = []
        for flow in flows:
            packets = flow.get('packets', [])
            features = self.extract_features_from_flow(packets)
            # Add flow identification
            features['flow_id'] = flow.get('flow_id', 'unknown')
            features['src_ip'] = flow.get('src_ip', '0.0.0.0')
            features['dst_ip'] = flow.get('dst_ip', '0.0.0.0')
            features['src_port'] = flow.get('src_port', 0)
            features['dst_port'] = flow.get('dst_port', 0)
            features['protocol'] = flow.get('protocol', 0)
            flow_features.append(features)
        
        if not flow_features:
            return pd.DataFrame()
        
        return pd.DataFrame(flow_features)
    
    def normalize_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize numerical features in a DataFrame using z-score.
        
        Args:
            df (pd.DataFrame): DataFrame with features
            
        Returns:
            pd.DataFrame: Normalized DataFrame with z-scores
            
        Note:
            - Only numerical columns are normalized
            - Columns with zero standard deviation are left unchanged
            - Returns a copy of the DataFrame (doesn't modify original)
        """
        df_normalized = df.copy()
        
        # Select numerical columns
        numerical_cols = df_normalized.select_dtypes(include=[np.number]).columns
        
        # Normalize using z-score: (x - mean) / std
        for col in numerical_cols:
            mean = df_normalized[col].mean()
            std = df_normalized[col].std()
            if std > 0:
                df_normalized[col] = (df_normalized[col] - mean) / std
            else:
                # If std is 0, leave values as is (all values are identical)
                pass
        
        return df_normalized
    
    def get_feature_names(self) -> Dict[str, List[str]]:
        """
        Get lists of feature names by category.
        
        Returns:
            Dict[str, List[str]]: Dictionary mapping categories to feature name lists:
                - basic: Basic feature names
                - count: Count feature names
                - temporal: Temporal feature names
                - payload: Payload feature names
        """
        return {
            'basic': self.basic_extractor.basic_feature_names(),
            'count': self.count_extractor.count_feature_names(),
            'temporal': self.temporal_extractor.temporal_feature_names(),
            'payload': self.payload_extractor.payload_feature_names(),
        }
    
    def get_all_feature_names(self) -> List[str]:
        """
        Get all feature names from all categories.
        
        Returns:
            List[str]: List of all feature names
        """
        all_features = []
        for category, features in self.get_feature_names().items():
            all_features.extend(features)
        return all_features