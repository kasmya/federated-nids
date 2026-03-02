#!/usr/bin/env python3
"""
Day 3: Dataset Generator for Federated NIDS
Generates realistic network traffic data with various attack patterns

Since downloading real CICIDS2017 requires external resources,
this script generates a realistic synthetic dataset that mimics
the structure of CICIDS2017 for federated NIDS testing.
"""

import json
import os
import random
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import hashlib


# Attack types based on CICIDS2017
ATTACK_TYPES = {
    'benign': {'proto': ['tcp', 'udp'], 'flags': ['PA', 'PA', 'PA', 'A'], 'dport': [80, 443, 22, 8080, 53]},
    'port_scan': {'proto': ['tcp'], 'flags': ['S'], 'dport': list(range(1, 100))},
    'syn_flood': {'proto': ['tcp'], 'flags': ['S'], 'dport': [80, 443, 22]},
    'brute_force': {'proto': ['tcp'], 'flags': ['S', 'PA'], 'dport': [22, 23, 3389, 21]},
    'xss': {'proto': ['tcp'], 'flags': ['PA'], 'dport': [80, 443, 8080]},
    'sql_injection': {'proto': ['tcp'], 'flags': ['PA'], 'dport': [80, 443, 8080]},
    'ddos': {'proto': ['tcp', 'udp', 'icmp'], 'flags': ['S', 'PA'], 'dport': [80, 443]},
    'web_attack': {'proto': ['tcp'], 'flags': ['PA'], 'dport': [80, 443]},
}

# Normal traffic patterns
NORMAL_PATTERNS = {
    'web_browsing': {'proto': ['tcp'], 'flags': ['PA'], 'dport': [80, 443], 'length': (200, 1500)},
    'email': {'proto': ['tcp'], 'flags': ['PA'], 'dport': [25, 110, 143, 993], 'length': (100, 500)},
    'dns': {'proto': ['udp'], 'flags': [''], 'dport': [53], 'length': (50, 200)},
    'ssh': {'proto': ['tcp'], 'flags': ['S', 'PA', 'A'], 'dport': [22], 'length': (50, 300)},
    'ftp': {'proto': ['tcp'], 'flags': ['PA', 'A'], 'dport': [20, 21], 'length': (50, 1500)},
}


def generate_ip(prefix: str = "192.168.1", exclude: List[str] = None) -> str:
    """Generate random IP address."""
    exclude = exclude or []
    while True:
        ip = f"{prefix}.{random.randint(1, 254)}"
        if ip not in exclude:
            return ip


def generate_packet(
    attack_type: Optional[str] = None,
    timestamp: float = None,
    src_ip: str = None,
    dst_ip: str = None
) -> Dict[str, Any]:
    """
    Generate a single packet dictionary.
    
    Args:
        attack_type: Type of attack (None for normal traffic)
        timestamp: Packet timestamp
        src_ip: Source IP (optional)
        dst_ip: Destination IP (optional)
    
    Returns:
        Packet dictionary in NIDS format
    """
    if timestamp is None:
        timestamp = time.time()
    
    # Determine if this is attack or normal
    is_attack = attack_type is not None and attack_type != 'benign'
    
    # Select pattern based on attack type
    if is_attack and attack_type in ATTACK_TYPES:
        pattern = ATTACK_TYPES[attack_type]
        # Add some randomness to make it less deterministic
        pattern = {k: v if isinstance(v, list) else [v] for k, v in pattern.items()}
    else:
        # Normal traffic
        pattern_name = random.choice(list(NORMAL_PATTERNS.keys()))
        pattern = NORMAL_PATTERNS[pattern_name]
    
    # Generate IPs
    if src_ip is None:
        if is_attack:
            src_ip = "192.168.1.100"  # Attacker IP
        else:
            src_ip = generate_ip("192.168.1", ["192.168.1.100", "192.168.1.200"])
    
    if dst_ip is None:
        dst_ip = generate_ip("10.0.0", [])
    
    # Generate packet
    packet = {
        'src': src_ip,
        'dst': dst_ip,
        'proto': random.choice(pattern.get('proto', ['tcp'])),
        'sport': random.randint(1024, 65535),
        'dport': random.choice(pattern.get('dport', [80])),
        'flags': random.choice(pattern.get('flags', ['PA'])),
        'length': random.randint(
            pattern.get('length', [64, 1500])[0],
            pattern.get('length', [64, 1500])[1]
        ) if 'length' in pattern else random.randint(64, 1500),
        'timestamp': timestamp,
        'attack_type': attack_type if is_attack else None,
    }
    
    return packet


def generate_dataset(
    num_packets: int = 10000,
    attack_distribution: Dict[str, float] = None,
    start_time: float = None
) -> List[Dict[str, Any]]:
    """
    Generate a complete dataset of packets.
    
    Args:
        num_packets: Total number of packets to generate
        attack_distribution: Dict of attack_type -> probability
        start_time: Starting timestamp
    
    Returns:
        List of packet dictionaries
    """
    if attack_distribution is None:
        attack_distribution = {
            'benign': 0.7,
            'port_scan': 0.1,
            'syn_flood': 0.1,
            'brute_force': 0.05,
            'ddos': 0.05,
        }
    
    # Normalize distribution
    total = sum(attack_distribution.values())
    attack_distribution = {k: v/total for k, v in attack_distribution.items()}
    
    packets = []
    if start_time is None:
        start_time = time.time() - 3600  # Start 1 hour ago
    
    # Generate packets
    for i in range(num_packets):
        # Select attack type based on distribution
        rand = random.random()
        cumulative = 0
        attack_type = 'benign'
        
        for at, prob in attack_distribution.items():
            cumulative += prob
            if rand <= cumulative:
                attack_type = at
                break
        
        # Generate packet with slight timing variation
        packet_timestamp = start_time + (i * 0.36)  # ~10 packets/sec
        packet = generate_packet(
            attack_type=attack_type,
            timestamp=packet_timestamp
        )
        
        packets.append(packet)
    
    return packets


def generate_client_partition(
    client_id: str,
    num_packets: int = 5000,
    attack_focus: str = None,
    attack_ratio: float = 0.3
) -> List[Dict[str, Any]]:
    """
    Generate a data partition for a specific client.
    
    Args:
        client_id: Client identifier
        num_packets: Number of packets for this client
        attack_focus: Primary attack type for this client
        attack_ratio: Ratio of attack packets (0.0 - 1.0)
    
    Returns:
        List of packets
    """
    packets = []
    start_time = time.time() - 1800  # 30 minutes ago
    
    # Attack distribution based on focus
    if attack_focus == 'port_scan':
        attack_dist = {
            'benign': 1.0 - attack_ratio,
            'port_scan': attack_ratio * 0.8,
            'syn_flood': attack_ratio * 0.1,
            'brute_force': attack_ratio * 0.1,
        }
    elif attack_focus == 'syn_flood':
        attack_dist = {
            'benign': 1.0 - attack_ratio,
            'syn_flood': attack_ratio * 0.8,
            'port_scan': attack_ratio * 0.1,
            'brute_force': attack_ratio * 0.1,
        }
    elif attack_focus == 'mixed':
        attack_dist = {
            'benign': 1.0 - attack_ratio,
            'port_scan': attack_ratio * 0.25,
            'syn_flood': attack_ratio * 0.25,
            'brute_force': attack_ratio * 0.25,
            'ddos': attack_ratio * 0.25,
        }
    else:  # normal
        attack_dist = {
            'benign': 1.0 - attack_ratio * 0.5,
            'port_scan': attack_ratio * 0.5 * 0.33,
            'syn_flood': attack_ratio * 0.5 * 0.33,
            'brute_force': attack_ratio * 0.5 * 0.34,
        }
    
    # Generate packets
    for i in range(num_packets):
        # Select attack type
        rand = random.random()
        cumulative = 0
        attack_type = 'benign'
        
        for at, prob in attack_dist.items():
            cumulative += prob
            if rand <= cumulative:
                attack_type = at
                break
        
        # Generate packet with client-specific IPs
        packet = generate_packet(
            attack_type=attack_type,
            timestamp=start_time + (i * 0.36),
            src_ip=f"192.168.1.{10 + hash(client_id) % 240}"  # Client-specific IP range
        )
        
        packets.append(packet)
    
    return packets


def get_partition_stats(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Get statistics for a packet partition."""
    stats = {
        'total_packets': len(packets),
        'attack_types': {},
        'protocols': {},
        'flags': {},
    }
    
    for packet in packets:
        # Count attack types
        at = packet.get('attack_type', 'benign')
        at = at if at else 'benign'
        stats['attack_types'][at] = stats['attack_types'].get(at, 0) + 1
        
        # Count protocols
        proto = packet.get('proto', 'unknown')
        stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
        
        # Count flags
        flags = packet.get('flags', 'unknown')
        stats['flags'][flags] = stats['flags'].get(flags, 0) + 1
    
    # Calculate percentages
    total = stats['total_packets']
    stats['attack_percent'] = sum(
        v for k, v in stats['attack_types'].items() if k != 'benign'
    ) / total * 100 if total > 0 else 0
    
    return stats


def save_partition(packets: List[Dict[str, Any]], filepath: str) -> None:
    """Save packet partition to JSON file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Get stats
    stats = get_partition_stats(packets)
    
    # Save with metadata
    data = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'num_packets': len(packets),
            'stats': stats,
        },
        'packets': packets
    }
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Saved {len(packets)} packets to {filepath}")
    print(f"  Attack %: {stats['attack_percent']:.1f}%")
    print(f"  Top attacks: {dict(sorted(stats['attack_types'].items(), key=lambda x: -x[1])[:3])}")


def load_partition(filepath: str) -> List[Dict[str, Any]]:
    """Load packet partition from JSON file."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data['packets']


# ============================================================================
# MAIN: Generate datasets for 3 clients
# ============================================================================

def generate_all_partitions(
    output_dir: str = "federated/data",
    packets_per_client: int = 5000
) -> Dict[str, str]:
    """
    Generate partitions for all 3 clients with different attack patterns.
    
    Returns:
        Dict mapping client_id to filepath
    """
    os.makedirs(output_dir, exist_ok=True)
    
    partitions = {}
    
    # Client A: Port scan focus
    print("\n" + "="*60)
    print("Generating Client A partition (Port Scan Focus)")
    print("="*60)
    packets_a = generate_client_partition(
        client_id='client_A',
        num_packets=packets_per_client,
        attack_focus='port_scan',
        attack_ratio=0.3
    )
    filepath_a = os.path.join(output_dir, 'client_A_packets.json')
    save_partition(packets_a, filepath_a)
    partitions['client_A'] = filepath_a
    
    # Client B: SYN flood focus
    print("\n" + "="*60)
    print("Generating Client B partition (SYN Flood Focus)")
    print("="*60)
    packets_b = generate_client_partition(
        client_id='client_B',
        num_packets=packets_per_client,
        attack_focus='syn_flood',
        attack_ratio=0.3
    )
    filepath_b = os.path.join(output_dir, 'client_B_packets.json')
    save_partition(packets_b, filepath_b)
    partitions['client_B'] = filepath_b
    
    # Client C: Mixed attacks (control)
    print("\n" + "="*60)
    print("Generating Client C partition (Mixed Attacks)")
    print("="*60)
    packets_c = generate_client_partition(
        client_id='client_C',
        num_packets=packets_per_client,
        attack_focus='mixed',
        attack_ratio=0.3
    )
    filepath_c = os.path.join(output_dir, 'client_C_packets.json')
    save_partition(packets_c, filepath_c)
    partitions['client_C'] = filepath_c
    
    # Save partition info
    info = {
        'generated_at': datetime.now().isoformat(),
        'packets_per_client': packets_per_client,
        'partitions': partitions,
        'scenario': 'Non-IID (different attack patterns per client)'
    }
    
    with open(os.path.join(output_dir, 'partition_info.json'), 'w') as f:
        json.dump(info, f, indent=2)
    
    print("\n" + "="*60)
    print("ALL PARTITIONS GENERATED")
    print("="*60)
    print(f"Output directory: {output_dir}")
    print(f"Files: {list(partitions.values())}")
    
    return partitions


def generate_iid_partitions(
    output_dir: str = "federated/data_iid",
    packets_per_client: int = 5000
) -> Dict[str, str]:
    """Generate IID partitions (similar attack distribution)."""
    os.makedirs(output_dir, exist_ok=True)
    
    partitions = {}
    
    # Same distribution for all clients
    for client_id in ['client_A', 'client_B', 'client_C']:
        print(f"\nGenerating {client_id} partition (IID)...")
        
        packets = generate_client_partition(
            client_id=client_id,
            num_packets=packets_per_client,
            attack_focus='mixed',  # Same for all
            attack_ratio=0.3
        )
        
        filepath = os.path.join(output_dir, f'{client_id}_packets.json')
        save_partition(packets, filepath)
        partitions[client_id] = filepath
    
    # Save info
    info = {
        'generated_at': datetime.now().isoformat(),
        'partitions': partitions,
        'scenario': 'IID (same attack distribution)'
    }
    
    with open(os.path.join(output_dir, 'partition_info.json'), 'w') as f:
        json.dump(info, f, indent=2)
    
    return partitions


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate federated NIDS datasets')
    parser.add_argument('--iid', action='store_true', help='Generate IID partitions')
    parser.add_argument('--packets', type=int, default=5000, help='Packets per client')
    
    args = parser.parse_args()
    
    if args.iid:
        print("\n" + "="*60)
        print("GENERATING IID DATASET")
        print("="*60)
        generate_iid_partitions(packets_per_client=args.packets)
    else:
        print("\n" + "="*60)
        print("GENERATING NON-IID DATASET")
        print("="*60)
        generate_all_partitions(packets_per_client=args.packets)
    
    print("\n✓ Dataset generation complete!")

