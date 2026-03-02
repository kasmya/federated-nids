#!/usr/bin/env python3
"""
Federated NIDS - Day 3: Packet Replay Engine
Feeds packets to clients at controlled rates for realistic simulation
"""

import time
import threading
from typing import List, Dict, Any, Optional, Callable
from collections import deque
import logging

logger = logging.getLogger(__name__)


class PacketReplayEngine:
    """
    Manages packet replay with controlled rates and tracking.
    
    Features:
    - Configurable packet rate (packets per second)
    - Track processed packets
    - Pause/resume between rounds
    - Callback support for processing
    """
    
    def __init__(
        self,
        packets: List[Dict[str, Any]],
        rate: float = 10.0,
        callback: Optional[Callable] = None
    ):
        """
        Initialize packet replay engine.
        
        Args:
            packets: List of packet dictionaries
            rate: Packets per second
            callback: Function to call for each packet
        """
        self.packets = packets
        self.rate = rate
        self.callback = callback
        
        # State
        self.current_index = 0
        self.is_paused = True
        self.is_running = False
        
        # Tracking
        self.processed_packets = []
        self.failed_packets = []
        self.detected_anomalies = []
        
        # Statistics
        self.stats = {
            'total_packets': len(packets),
            'processed': 0,
            'failed': 0,
            'anomalies_detected': 0,
            'start_time': None,
            'end_time': None,
        }
        
        # Thread control
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
    
    def start(self) -> None:
        """Start packet replay."""
        with self._lock:
            if self.is_running:
                return
            
            self.is_running = True
            self.is_paused = False
            self.stats['start_time'] = time.time()
            self._stop_event.clear()
            
            # Start replay thread
            self._thread = threading.Thread(target=self._replay_loop, daemon=True)
            self._thread.start()
            
            logger.info(f"Packet replay started at {self.rate} pps")
    
    def pause(self) -> None:
        """Pause packet replay."""
        with self._lock:
            self.is_paused = True
            logger.info("Packet replay paused")
    
    def resume(self) -> None:
        """Resume packet replay."""
        with self._lock:
            self.is_paused = False
            logger.info("Packet replay resumed")
    
    def stop(self) -> None:
        """Stop packet replay."""
        self._stop_event.set()
        with self._lock:
            self.is_running = False
            self.stats['end_time'] = time.time()
            logger.info("Packet replay stopped")
    
    def reset(self) -> None:
        """Reset to beginning."""
        with self._lock:
            self.current_index = 0
            self.processed_packets = []
            self.failed_packets = []
            self.detected_anomalies = []
            logger.info("Packet replay reset")
    
    def set_rate(self, rate: float) -> None:
        """Change packet rate."""
        self.rate = max(0.1, min(rate, 1000.0))
        logger.info(f"Packet rate changed to {self.rate} pps")
    
    def get_remaining(self) -> int:
        """Get number of remaining packets."""
        return len(self.packets) - self.current_index
    
    def _replay_loop(self) -> None:
        """Main replay loop (runs in background thread)."""
        interval = 1.0 / self.rate if self.rate > 0 else 0
        
        while not self._stop_event.is_set():
            # Check if paused
            if self.is_paused:
                time.sleep(0.1)
                continue
            
            # Check if done
            if self.current_index >= len(self.packets):
                self.stop()
                break
            
            # Get packet
            packet = self.packets[self.current_index]
            self.current_index += 1
            
            # Process packet
            try:
                if self.callback:
                    result = self.callback(packet)
                    
                    # Track result
                    self.processed_packets.append({
                        'packet': packet,
                        'result': result,
                        'timestamp': time.time()
                    })
                    
                    if result is not None:
                        self.detected_anomalies.append(result)
                        self.stats['anomalies_detected'] += 1
                    
                    self.stats['processed'] += 1
                else:
                    self.stats['processed'] += 1
                    
            except Exception as e:
                self.failed_packets.append({
                    'packet': packet,
                    'error': str(e),
                    'timestamp': time.time()
                })
                self.stats['failed'] += 1
                logger.error(f"Packet processing failed: {e}")
            
            # Sleep for rate limiting
            if interval > 0:
                time.sleep(interval)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        stats = self.stats.copy()
        
        if stats['start_time'] and not stats['end_time']:
            elapsed = time.time() - stats['start_time']
            stats['elapsed_seconds'] = elapsed
            if elapsed > 0:
                stats['actual_rate'] = stats['processed'] / elapsed
        elif stats['start_time'] and stats['end_time']:
            elapsed = stats['end_time'] - stats['start_time']
            stats['elapsed_seconds'] = elapsed
            if elapsed > 0:
                stats['actual_rate'] = stats['processed'] / elapsed
        
        stats['remaining_packets'] = self.get_remaining()
        stats['progress_percent'] = (
            self.current_index / len(self.packets) * 100 
            if len(self.packets) > 0 else 0
        )
        
        return stats
    
    def process_batch(self, num_packets: int) -> Dict[str, Any]:
        """
        Process a specific number of packets (synchronous).
        
        Args:
            num_packets: Number of packets to process
            
        Returns:
            Batch processing results
        """
        results = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'rules_generated': 0,
            'packets': []
        }
        
        end_index = min(self.current_index + num_packets, len(self.packets))
        
        while self.current_index < end_index:
            packet = self.packets[self.current_index]
            self.current_index += 1
            
            try:
                if self.callback:
                    result = self.callback(packet)
                    results['packets'].append({
                        'packet': packet,
                        'result': result
                    })
                    
                    if result is not None:
                        results['anomalies_detected'] += 1
                
                results['packets_processed'] += 1
                
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                results['packets_processed'] += 1
        
        self.stats['processed'] += results['packets_processed']
        self.stats['anomalies_detected'] += results['anomalies_detected']
        
        return results


class ClientPacketManager:
    """
    Manages packet data for a federated client.
    
    Handles loading, partitioning, and replay of client-specific data.
    """
    
    def __init__(self, client_id: str, data_file: str = None):
        """
        Initialize client packet manager.
        
        Args:
            client_id: Client identifier
            data_file: Path to packet data file
        """
        self.client_id = client_id
        self.data_file = data_file
        self.packets = []
        self.replay_engine = None
        
        # Load data if provided
        if data_file:
            self.load_data(data_file)
    
    def load_data(self, filepath: str) -> None:
        """Load packet data from file."""
        import json
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.packets = data['packets']
        self.metadata = data.get('metadata', {})
        
        logger.info(f"Loaded {len(self.packets)} packets for {self.client_id}")
    
    def create_replay_engine(
        self,
        rate: float = 10.0,
        callback: Optional[Callable] = None
    ) -> PacketReplayEngine:
        """Create a replay engine for this client's data."""
        self.replay_engine = PacketReplayEngine(
            packets=self.packets,
            rate=rate,
            callback=callback
        )
        return self.replay_engine
    
    def get_partition_stats(self) -> Dict[str, Any]:
        """Get statistics about this client's data."""
        if not self.packets:
            return {'total_packets': 0}
        
        attack_counts = {}
        proto_counts = {}
        
        for pkt in self.packets:
            at = pkt.get('attack_type', 'benign')
            at = at if at else 'benign'
            attack_counts[at] = attack_counts.get(at, 0) + 1
            
            proto = pkt.get('proto', 'unknown')
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
        
        return {
            'client_id': self.client_id,
            'total_packets': len(self.packets),
            'attack_distribution': attack_counts,
            'protocol_distribution': proto_counts,
            'attack_packet_count': sum(
                v for k, v in attack_counts.items() if k != 'benign'
            ),
            'attack_percentage': (
                sum(v for k, v in attack_counts.items() if k != 'benign') 
                / len(self.packets) * 100
            ) if self.packets else 0
        }
    
    def get_packets_for_round(self, round_num: int, packets_per_round: int) -> List[Dict]:
        """
        Get packets for a specific federated round.
        
        Uses different slices for each round to simulate
        time-ordered data arrival.
        
        Args:
            round_num: Federated round number (0-indexed)
            packets_per_round: Number of packets per round
            
        Returns:
            List of packets for this round
        """
        # Distribute packets across rounds
        total_rounds_estimated = len(self.packets) // packets_per_round
        
        if round_num >= total_rounds_estimated:
            # Return remaining packets
            return self.packets[round_num * packets_per_round:]
        
        start_idx = round_num * packets_per_round
        end_idx = start_idx + packets_per_round
        
        return self.packets[start_idx:end_idx]


# ============================================================================
# TEST
# ============================================================================

if __name__ == '__main__':
    # Test packet replay
    print("Testing Packet Replay Engine...")
    
    # Create sample packets
    packets = []
    for i in range(100):
        packets.append({
            'src': f'192.168.1.{i % 10}',
            'dst': f'10.0.0.{i % 5}',
            'proto': 'tcp',
            'sport': 1000 + i,
            'dport': 80,
            'flags': 'PA',
            'length': 500,
            'timestamp': time.time() + i,
            'attack_type': 'port_scan' if i % 10 == 0 else None
        })
    
    # Track what we process
    processed = []
    
    def process_fn(packet):
        processed.append(packet)
        if packet.get('attack_type'):
            return {'anomaly': packet['attack_type'], 'packet': packet}
        return None
    
    # Create engine
    engine = PacketReplayEngine(packets, rate=20.0, callback=process_fn)
    
    print(f"Starting replay with {len(packets)} packets at 20 pps...")
    engine.start()
    
    # Let it run for a bit
    time.sleep(2.0)
    engine.pause()
    
    stats = engine.get_stats()
    print(f"\nAfter 2 seconds (paused):")
    print(f"  Processed: {stats['processed']}")
    print(f"  Anomalies: {stats['anomalies_detected']}")
    print(f"  Progress: {stats['progress_percent']:.1f}%")
    
    # Process a batch
    print("\nProcessing batch of 30 packets...")
    batch_results = engine.process_batch(30)
    print(f"  Batch processed: {batch_results['packets_processed']}")
    print(f"  Batch anomalies: {batch_results['anomalies_detected']}")
    
    engine.stop()
    print(f"\nFinal stats: {engine.get_stats()}")
    
    print("\n✓ Packet replay test complete!")

