"""
Temporal feature extraction for traffic analysis.

This module extracts timing-related features from network traffic including
inter-arrival times, packet rates, burstiness metrics, and traffic patterns.
These features are crucial for detecting certain types of attacks and anomalies.
"""

from typing import Dict, Any, List, Optional
import numpy as np
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class TemporalFeatureExtractor:
    """
    Extracts temporal features from packet flows.
    
    This class provides methods for analyzing the timing characteristics of
    network traffic. Features extracted include inter-arrival times, packet
    rates, burstiness, and periodic patterns in traffic.
    
    Key features extracted:
        - Inter-arrival time statistics (mean, std, min, max)
        - Packet rate (packets per second)
        - Burstiness metric (coefficient of variation)
        - Time window variance
        - Traffic pattern detection (periodicity, bursts)
    """
    
    @staticmethod
    def extract_temporal_features(packets: List) -> Dict[str, Any]:
        """
        Extract comprehensive temporal features from a flow of packets.
        
        Features computed include:
            - Total duration of flow
            - Inter-arrival time statistics
            - Packet rate metrics
            - Burstiness and variation metrics
            - Window-based variance
        
        Args:
            packets (List): List of packets in the flow (must have timestamp)
            
        Returns:
            Dict[str, Any]: Dictionary of temporal features:
                - total_duration (float): Total time from first to last packet
                - mean_inter_arrival_time (float): Average time between packets
                - std_inter_arrival_time (float): Standard deviation of intervals
                - min_inter_arrival_time (float): Minimum interval between packets
                - max_inter_arrival_time (float): Maximum interval between packets
                - packet_rate (float): Packets per second
                - burstiness_metric (float): Coefficient of variation
                - inter_arrival_skewness (float): Skewness of interval distribution
                - inter_arrival_kurtosis (float): Kurtosis of interval distribution
                - time_window_variance (float): Variance of packet counts per window
                
        Note:
            Returns empty dict if fewer than 2 packets (can't compute intervals)
        """
        if not packets:
            return {}
        
        features = {
            'total_duration': 0.0,
            'mean_inter_arrival_time': 0.0,
            'std_inter_arrival_time': 0.0,
            'min_inter_arrival_time': 0.0,
            'max_inter_arrival_time': 0.0,
            'packet_rate': 0.0,
            'burstiness_metric': 0.0,
            'inter_arrival_skewness': 0.0,
            'inter_arrival_kurtosis': 0.0,
            'time_window_variance': 0.0,
        }
        
        # Extract timestamps
        timestamps = TemporalFeatureExtractor._extract_timestamps(packets)
        
        # Need at least 2 packets for inter-arrival calculations
        if len(timestamps) < 2:
            return features
        
        # Calculate total duration
        features['total_duration'] = timestamps[-1] - timestamps[0]
        
        # Calculate inter-arrival times
        inter_arrival_times = np.diff(timestamps)
        
        if len(inter_arrival_times) > 0:
            features['mean_inter_arrival_time'] = float(np.mean(inter_arrival_times))
            features['std_inter_arrival_time'] = float(np.std(inter_arrival_times))
            features['min_inter_arrival_time'] = float(np.min(inter_arrival_times))
            features['max_inter_arrival_time'] = float(np.max(inter_arrival_times))
            
            # Calculate skewness (asymmetry of distribution)
            if np.std(inter_arrival_times) > 0:
                features['inter_arrival_skewness'] = float(
                    np.mean((inter_arrival_times - np.mean(inter_arrival_times)) ** 3) /
                    (np.std(inter_arrival_times) ** 3)
                )
                # Calculate kurtosis (tail heaviness of distribution)
                features['inter_arrival_kurtosis'] = float(
                    np.mean((inter_arrival_times - np.mean(inter_arrival_times)) ** 4) /
                    (np.std(inter_arrival_times) ** 4) - 3
                )
        
        # Calculate packet rate (packets per second)
        if features['total_duration'] > 0:
            features['packet_rate'] = len(packets) / features['total_duration']
        
        # Calculate burstiness metric (coefficient of variation)
        # >1 indicates bursty traffic, <1 indicates regular traffic
        if features['mean_inter_arrival_time'] > 0:
            features['burstiness_metric'] = (
                features['std_inter_arrival_time'] / features['mean_inter_arrival_time']
            )
        
        # Calculate time window variance (variation in packet counts per window)
        features['time_window_variance'] = TemporalFeatureExtractor._calculate_window_variance(
            timestamps
        )
        
        return features
    
    @staticmethod
    def _extract_timestamps(packets: List) -> List[float]:
        """
        Extract and sort timestamps from a list of packets.
        
        Attempts to extract timestamps from various packet attributes.
        If no timestamp is available, generates synthetic timestamps.
        
        Args:
            packets (List): List of packet objects
            
        Returns:
            List[float]: Sorted list of timestamps in seconds
        """
        timestamps = []
        for packet in packets:
            try:
                if hasattr(packet, 'time'):
                    timestamps.append(float(packet.time))
                elif hasattr(packet, 'timestamp'):
                    timestamps.append(float(packet.timestamp))
                else:
                    # Use a default increment of 1ms if no timestamp available
                    timestamps.append(timestamps[-1] + 0.001 if timestamps else 0.0)
            except Exception as e:
                logger.warning(f"Error extracting timestamp: {e}")
                timestamps.append(timestamps[-1] + 0.001 if timestamps else 0.0)
        
        return sorted(timestamps)
    
    @staticmethod
    def _calculate_window_variance(timestamps: List[float], 
                                   window_size: float = 1.0) -> float:
        """
        Calculate variance of packet counts across fixed time windows.
        
        This measures how much packet counts vary from window to window,
        which is useful for detecting traffic pattern changes.
        
        Args:
            timestamps (List[float]): List of packet timestamps
            window_size (float): Size of each time window in seconds
                                Default is 1.0 seconds
            
        Returns:
            float: Variance of packet counts per window
            
        Note:
            Returns 0 if there are no timestamps or duration is 0.
        """
        if not timestamps:
            return 0.0
        
        total_duration = timestamps[-1] - timestamps[0]
        if total_duration <= 0:
            return 0.0
        
        # Calculate number of windows
        num_windows = max(1, int(total_duration / window_size))
        window_counts = np.zeros(num_windows)
        
        # Count packets in each window
        for ts in timestamps:
            window_idx = min(
                int((ts - timestamps[0]) / window_size),
                num_windows - 1
            )
            window_counts[window_idx] += 1
        
        # Calculate and return variance
        return float(np.var(window_counts))
    
    @staticmethod
    def find_traffic_patterns(timestamps: List[float]) -> Dict[str, Any]:
        """
        Identify traffic patterns in a sequence of timestamps.
        
        Detects periodicity (regular intervals) and bursts (clusters of
        packets with very short intervals).
        
        Args:
            timestamps (List[float]): List of packet timestamps in seconds
            
        Returns:
            Dict[str, Any]: Dictionary containing pattern information:
                - is_periodic (bool): Whether traffic shows periodic pattern
                - period_seconds (float): Detected period in seconds
                - has_bursts (bool): Whether traffic has bursty patterns
                - burst_count (int): Number of detected bursts
                - avg_burst_duration (float): Average duration of bursts
                
        Note:
            Periodicity detection uses autocorrelation and is heuristic-based.
            Bursts are detected as clusters of packets with intervals below
            the 25th percentile.
        """
        patterns = {
            'is_periodic': False,
            'period_seconds': 0.0,
            'has_bursts': False,
            'burst_count': 0,
            'avg_burst_duration': 0.0
        }
        
        if len(timestamps) < 3:
            return patterns
        
        # Calculate inter-arrival times
        inter_arrivals = np.diff(timestamps)
        
        # Detect periodicity using autocorrelation
        if len(inter_arrivals) > 10:
            # Calculate autocorrelation
            autocorr = np.correlate(inter_arrivals, inter_arrivals, mode='same')
            # Find second peak (excluding the first peak at lag 0)
            if len(autocorr) > 1:
                # Normalize autocorrelation
                max_autocorr = np.max(autocorr)
                if max_autocorr > 0:
                    autocorr = autocorr / max_autocorr
                    # Look for peaks above 0.5 (strong correlation)
                    peaks = np.where(autocorr > 0.5)[0]
                    if len(peaks) > 1:
                        # Period is the distance between peaks
                        period_lag = peaks[1] - peaks[0]
                        if 1 <= period_lag < len(inter_arrivals):
                            patterns['is_periodic'] = True
                            patterns['period_seconds'] = float(np.mean(inter_arrivals[::period_lag]))
        
        # Detect bursts (clusters of packets with very short inter-arrival times)
        if len(inter_arrivals) > 0:
            # Threshold: 25th percentile of inter-arrival times
            burst_threshold = np.percentile(inter_arrivals, 25)
            burst_count = 0
            burst_durations = []
            current_burst = False
            burst_start = 0.0
            
            for i, interval in enumerate(inter_arrivals):
                if interval < burst_threshold and not current_burst:
                    # Start of a burst
                    current_burst = True
                    burst_start = timestamps[i]
                    burst_count += 1
                elif interval >= burst_threshold and current_burst:
                    # End of a burst
                    current_burst = False
                    burst_durations.append(timestamps[i] - burst_start)
            
            patterns['has_bursts'] = burst_count > 0
            patterns['burst_count'] = burst_count
            if burst_durations:
                patterns['avg_burst_duration'] = float(np.mean(burst_durations))
        
        return patterns
    
    @staticmethod
    def temporal_feature_names() -> List[str]:
        """
        Get list of temporal feature names in standard order.
        
        Returns:
            List[str]: List of feature column names
        """
        return [
            'total_duration',
            'mean_inter_arrival_time',
            'std_inter_arrival_time',
            'min_inter_arrival_time',
            'max_inter_arrival_time',
            'packet_rate',
            'burstiness_metric',
            'inter_arrival_skewness',
            'inter_arrival_kurtosis',
            'time_window_variance'
        ]