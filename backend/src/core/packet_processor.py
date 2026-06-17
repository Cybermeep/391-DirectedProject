"""
Packet processor for handling raw packets and extracting basic information.

This module provides utilities for parsing and extracting information from
raw network packets. It handles various protocol layers including Ethernet,
IP, TCP, UDP, ICMP, DNS, and extracts relevant fields for analysis.
"""

import socket
from typing import Optional, Dict, Any, Tuple, List
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, Raw, ARP, DNS
import logging

logger = logging.getLogger(__name__)


class PacketProcessor:
    """
    Process and extract information from raw packets.
    
    This class provides static methods for parsing network packets and
    extracting information from various protocol layers. It handles
    both IPv4 and IPv6 packets and supports TCP, UDP, and ICMP protocols.
    
    Attributes:
        PROTOCOL_MAP (dict): Mapping of protocol numbers to names
    """
    
    # Protocol number to name mapping
    PROTOCOL_MAP = {
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
    
    @staticmethod
    def extract_packet_info(packet) -> Dict[str, Any]:
        """
        Extract comprehensive information from a packet.
        
        This method parses all available protocol layers and extracts
        relevant fields including addresses, ports, flags, and payload data.
        
        Args:
            packet: Scapy packet object to analyze
            
        Returns:
            Dict[str, Any]: Dictionary containing extracted information:
                - timestamp: Packet timestamp
                - length: Packet length in bytes
                - protocol: Protocol name (TCP, UDP, etc.)
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - src_port: Source port number
                - dst_port: Destination port number
                - flags: IP flags
                - payload: Raw payload data
                - ether_type: Ethernet type
                - is_ipv4: Whether packet is IPv4
                - is_ipv6: Whether packet is IPv6
                - has_tcp: Whether packet has TCP layer
                - has_udp: Whether packet has UDP layer
                - has_icmp: Whether packet has ICMP layer
                - has_raw: Whether packet has raw payload
                - tcp_flags: Dictionary of TCP flags (if TCP)
                - icmp_type: ICMP type (if ICMP)
                - dns_query: DNS query name (if DNS)
        """
        info = {
            'timestamp': None,
            'length': len(packet),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': [],
            'payload': None,
            'ether_type': None,
            'is_ipv4': False,
            'is_ipv6': False,
            'has_tcp': False,
            'has_udp': False,
            'has_icmp': False,
            'has_raw': False,
            'error': None
        }
        
        try:
            # Extract Ethernet layer
            if Ether in packet:
                eth = packet[Ether]
                info['ether_type'] = hex(eth.type)
                info['src_mac'] = eth.src
                info['dst_mac'] = eth.dst
            
            # Extract IP layer
            if IP in packet:
                ip = packet[IP]
                info['is_ipv4'] = True
                info['src_ip'] = ip.src
                info['dst_ip'] = ip.dst
                info['protocol'] = PacketProcessor.PROTOCOL_MAP.get(ip.proto, str(ip.proto))
                info['ttl'] = ip.ttl
                info['tos'] = ip.tos
                info['flags'] = ip.flags
                
            elif IPv6 in packet:
                ipv6 = packet[IPv6]
                info['is_ipv6'] = True
                info['src_ip'] = ipv6.src
                info['dst_ip'] = ipv6.dst
                info['protocol'] = PacketProcessor.PROTOCOL_MAP.get(ipv6.nh, str(ipv6.nh))
                info['ttl'] = ipv6.hlim
                info['flags'] = []
            
            # Extract TCP layer
            if TCP in packet:
                tcp = packet[TCP]
                info['has_tcp'] = True
                info['src_port'] = tcp.sport
                info['dst_port'] = tcp.dport
                info['tcp_flags'] = {
                    'syn': bool(tcp.flags & 0x02),
                    'ack': bool(tcp.flags & 0x10),
                    'rst': bool(tcp.flags & 0x04),
                    'fin': bool(tcp.flags & 0x01),
                    'psh': bool(tcp.flags & 0x08),
                    'urg': bool(tcp.flags & 0x20),
                    'ece': bool(tcp.flags & 0x40),
                    'cwr': bool(tcp.flags & 0x80)
                }
                info['sequence'] = tcp.seq
                info['acknowledgment'] = tcp.ack
                info['window'] = tcp.window
                
            # Extract UDP layer
            elif UDP in packet:
                udp = packet[UDP]
                info['has_udp'] = True
                info['src_port'] = udp.sport
                info['dst_port'] = udp.dport
                info['length'] = udp.len
                
            # Extract ICMP layer
            elif ICMP in packet:
                icmp = packet[ICMP]
                info['has_icmp'] = True
                info['icmp_type'] = icmp.type
                info['icmp_code'] = icmp.code
                info['icmp_id'] = getattr(icmp, 'id', None)
            
            # Extract Raw payload
            if Raw in packet:
                info['has_raw'] = True
                raw_data = bytes(packet[Raw])
                info['payload'] = raw_data
                info['payload_length'] = len(raw_data)
                # Store first 100 bytes in hex for display
                info['payload_hex'] = raw_data.hex()[:100]
                
            # Extract DNS if present
            if DNS in packet:
                dns = packet[DNS]
                info['has_dns'] = True
                info['dns_qr'] = 'response' if dns.qr else 'query'
                info['dns_id'] = dns.id
                if dns.qd:
                    # Decode DNS query name
                    qname = dns.qd.qname
                    if hasattr(qname, 'decode'):
                        info['dns_query'] = qname.decode('utf-8')
                    else:
                        info['dns_query'] = str(qname)
                    info['dns_qtype'] = dns.qd.qtype
                    info['dns_qclass'] = dns.qd.qclass
                    
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            info['error'] = str(e)
        
        return info
    
    @staticmethod
    def get_packet_size_distribution(packets: list) -> Dict[str, int]:
        """
        Calculate size distribution of a packet list.
        
        Groups packets into size categories: small (<100 bytes),
        medium (100-500 bytes), large (500-1500 bytes), jumbo (>1500 bytes).
        
        Args:
            packets (list): List of packet objects
            
        Returns:
            Dict[str, int]: Dictionary with size categories and counts:
                - small: Packets under 100 bytes
                - medium: Packets 100-500 bytes
                - large: Packets 500-1500 bytes
                - jumbo: Packets over 1500 bytes
        """
        distribution = {
            'small': 0,    # < 100 bytes
            'medium': 0,   # 100-500 bytes
            'large': 0,    # 500-1500 bytes
            'jumbo': 0     # > 1500 bytes
        }
        
        for packet in packets:
            size = len(packet)
            if size < 100:
                distribution['small'] += 1
            elif size < 500:
                distribution['medium'] += 1
            elif size < 1500:
                distribution['large'] += 1
            else:
                distribution['jumbo'] += 1
        
        return distribution
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of byte data.
        
        Shannon entropy measures the randomness or unpredictability of data.
        Higher entropy (closer to 8) indicates more random data, lower entropy
        (closer to 0) indicates more structured data.
        
        Args:
            data (bytes): Bytes to calculate entropy for
            
        Returns:
            float: Entropy value between 0 and 8
            
        Note:
            - 0: All bytes are the same (completely predictable)
            - 8: All byte values equally likely (completely random)
        """
        if not data:
            return 0.0
        
        from collections import Counter
        import math
        
        byte_counts = Counter(data)
        total = len(data)
        
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def is_ip_address(ip_str: str) -> bool:
        """
        Validate if a string is a valid IP address (IPv4 or IPv6).
        
        Args:
            ip_str (str): String to validate
            
        Returns:
            bool: True if valid IP address, False otherwise
        """
        # Check IPv4
        try:
            socket.inet_aton(ip_str)
            return True
        except socket.error:
            pass
        
        # Check IPv6
        try:
            socket.inet_pton(socket.AF_INET6, ip_str)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def extract_flow_key(packet_info: Dict[str, Any]) -> Tuple[str, str, int, int, str]:
        """
        Extract a unique flow identifier from packet information.
        
        A flow is identified by the 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol).
        This is used to group packets belonging to the same communication session.
        
        Args:
            packet_info (Dict[str, Any]): Packet information dictionary from extract_packet_info()
            
        Returns:
            Tuple[str, str, int, int, str]: Flow key as (src_ip, dst_ip, src_port, dst_port, protocol)
        """
        return (
            packet_info.get('src_ip', '0.0.0.0'),
            packet_info.get('dst_ip', '0.0.0.0'),
            packet_info.get('src_port', 0),
            packet_info.get('dst_port', 0),
            packet_info.get('protocol', 'unknown')
        )