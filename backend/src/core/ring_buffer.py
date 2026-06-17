"""
Ring buffer implementation for packet storage to prevent memory exhaustion.

This module provides a thread-safe circular buffer that maintains a fixed-size
collection of packets. When the buffer reaches capacity, oldest packets are
automatically overwritten, preventing memory exhaustion during long capture
sessions.
"""

from collections import deque
import threading
from typing import Optional, List, Any
import logging

# Configure module-level logger
logger = logging.getLogger(__name__)


class RingBuffer:
    """
    Thread-safe ring buffer for storing packets with fixed maximum size.
    
    This buffer uses a deque with maxlen to automatically handle overflow.
    All operations are protected by a reentrant lock to ensure thread safety
    in a multi-threaded capture environment.
    
    Attributes:
        max_size (int): Maximum number of items the buffer can hold
        buffer (deque): Internal deque storage with maxlen constraint
        lock (threading.RLock): Reentrant lock for thread-safe operations
        _total_added (int): Total items added over buffer lifetime
    """
    
    def __init__(self, max_size: int = 10000):
        """
        Initialize a new ring buffer with specified capacity.
        
        Args:
            max_size (int): Maximum number of items to store before overwriting
                           Default is 10,000 packets.
        
        Raises:
            ValueError: If max_size is less than or equal to 0
        """
        if max_size <= 0:
            raise ValueError(f"max_size must be positive, got {max_size}")
        
        self.max_size = max_size
        self.buffer = deque(maxlen=max_size)
        self.lock = threading.RLock()
        self._total_added = 0
        
        logger.info(f"RingBuffer initialized with max_size={max_size}")
    
    def add(self, item: Any) -> bool:
        """
        Add an item to the ring buffer.
        
        If the buffer is at capacity, the oldest item is automatically removed.
        This operation is thread-safe.
        
        Args:
            item (Any): The item to add to the buffer (typically a packet)
            
        Returns:
            bool: True if item was added successfully, False otherwise
        """
        with self.lock:
            self.buffer.append(item)
            self._total_added += 1
            return True
    
    def get_all(self) -> List[Any]:
        """
        Retrieve all items currently in the buffer.
        
        Returns a copy of the buffer contents to prevent external modification
        of the internal buffer. Thread-safe.
        
        Returns:
            List[Any]: A list containing all items in the buffer in order
        """
        with self.lock:
            return list(self.buffer)
    
    def get_latest(self, count: int) -> List[Any]:
        """
        Retrieve the most recent N items from the buffer.
        
        Args:
            count (int): Number of items to retrieve from the end of buffer
            
        Returns:
            List[Any]: List of the most recent items (in chronological order)
            
        Raises:
            ValueError: If count is less than 0
        """
        if count < 0:
            raise ValueError(f"count must be non-negative, got {count}")
        
        with self.lock:
            if count >= len(self.buffer):
                return list(self.buffer)
            return list(self.buffer)[-count:]
    
    def clear(self) -> None:
        """Remove all items from the buffer. Thread-safe."""
        with self.lock:
            self.buffer.clear()
            logger.debug("Ring buffer cleared")
    
    def __len__(self) -> int:
        """
        Get the current number of items in the buffer.
        
        Returns:
            int: Current buffer size
        """
        with self.lock:
            return len(self.buffer)
    
    def is_full(self) -> bool:
        """
        Check if the buffer has reached its maximum capacity.
        
        Returns:
            bool: True if buffer is full, False otherwise
        """
        with self.lock:
            return len(self.buffer) >= self.max_size
    
    @property
    def total_added(self) -> int:
        """
        Get the total number of items added to buffer since creation.
        
        Returns:
            int: Total items added over the buffer's lifetime
        """
        return self._total_added