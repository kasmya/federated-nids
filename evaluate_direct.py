#!/usr/bin/env python3
"""
Direct Feature-Based NIDS Evaluation
Tests detection directly on extracted features with proper thresholds
Shows ALL detected anomaly types per IP
"""

import os
import sys
import random
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from closed_loop.traffic_analyzer import TrafficFeatureExtractor, FeatureVector


def generate_test_traffic():
    """Generate traffic with clear attack patterns"""
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP
    
    packets = []
    
    # Normal traffic
    print("Generating normal traffic...")
    normal_ips = [f"192.168.1.{i}" for i in range(10, 30)]
    servers = [f"10.0.0.{i}" for i in range(1, 10)]
    
    for i in range(300):
        src = random.choice(normal_ips)
        dst = random.choice(servers)
        pkt = scapy.Ether()/IP(src=src, dst=dst)/TCP(
            sport=random.randint(49152,65535),
            dport=random.choice([80, 443, 22]),
            flags=random.choice(['S', 'A', 'PA'])
        )
        packets.append(pkt)
    
    # Attack 1: Port Scan
    print("Generating port scan traffic...")
    attacker1 = "192.168.1.100"
    for i in range(50):
        pkt = scapy.Ether()/IP(src=attacker1, dst="8.8.8.8")/TCP(
            sport=50000 + i,
            dport=20 + i,
            flags='S'
        )
        packets.append(pkt)
    
    # Attack 2: SYN Flood
    print("Generating SYN flood traffic...")
    for i in range(50):
        pkt = scapy.Ether()/IP(src=attacker1, dst="10.0.0.1")/TCP(
            sport=60000 + i,
            dport=80,
            flags='S'
        )
        packets.append(pkt)
    
    # Attack 3: DDoS
    print("Generating DDoS traffic...")
    for i in range(40):
        src = f"10.0.0.{50 + i}"
        pkt = scapy.Ether()/IP(src=src, dst="10.0.0.1")/TCP(
            sport=random.randint(49152,65535),
            dport=80,
            flags='S'
        )
        packets.append(pkt)
    
    # Attack 4: ICMP Flood
    print("Generating ICMP flood traffic...")
    for i in range(30):
        pkt = scapy.Ether()/IP(src=attacker1, dst="10.0.0.1")/scapy.ICMP()
        packets.append(pkt)
    
    random.shuffle(packets)
    return packets


def extract_features(pkt):
    if 'IP' not in pkt:
        return None
    proto = 'tcp' if pkt.haslayer('TCP') else 'udp' if pkt.haslayer('UDP') else 'icmp' if pkt.haslayer('ICMP') else 'other'
    return {
        'src': pkt['IP'].src,
        'dst': pkt['IP'].dst,
        'proto': proto,
        'sport': pkt.sport if pkt.haslayer('TCP') or pkt.haslayer('UDP') else 0,
        'dport': pkt.dport if pkt.haslayer('TCP') or pkt.haslayer('UDP') else 0,
        'flags': str(pkt['TCP'].flags) if pkt.haslayer('TCP') else '',
        'length': len(pkt)
    }


def build_feature_sets(packets):
    extractor = TrafficFeatureExtractor(window_size_seconds=10)
    for pkt in packets:
        features_dict = extract_features(pkt)
        if features_dict:
            extractor.extract_features(features_dict)
    return extractor.get_all_features()


def create_ground_truth(packets):
    ground_truth = {}
    attacker_ips = {"192.168.1.100"}
    ddos_ips = {f"10.0.0.{i}" for i in range(50, 90)}
    
    for i, pkt in enumerate(packets):
        if 'IP' not in pkt:
            continue
        src = pkt['IP'].src
        is_attack = False
        if src in attacker_ips or src in ddos_ips:
            is_attack = True
        if pkt.haslayer('TCP') and str(pkt['TCP'].flags) == 'S':
            if src in attacker_ips or src in ddos_ips:
                is_attack = True
        if pkt.haslayer('ICMP') and src in attacker_ips:
            is_attack = True
        if is_attack:
            ground_truth[i] = ['attack']
    return ground_truth


def run_direct_detection(all_features, threshold=0.3):
    """Run detection - returns ALL anomaly types for each flagged IP"""
    alerts = []
    
    for src_ip, features in all_features.items():
        fv = FeatureVector(features)
        fv.calculate_anomaly_scores()
        max_score = fv.get_max_score()
        
        if max_score >= threshold:
            alerts.append({
                'src_ip': src_ip,
                'anomaly_type': fv.get_primary_anomaly(),
                'anomaly_types': fv.anomaly_types,  # ALL types
                'all_scores': fv.anomaly_scores,     # ALL scores
                'score': max_score,
                'features': {
                    'port_diversity': features.get('port_diversity', 0),
                    'connection_rate': features.get('connection_rate', 0),
                    'packet_rate': features.get('packet_rate', 0),
                    'unique_dst_ips': features.get('unique_dst_ips', 0),
                    'icmp_count': features.get('icmp_count', 0)
                }
            })
    
    return alerts


def match_alerts_to_packets(alerts, packets):
    alert_indices = set()
    alert_ips = {alert['src_ip'] for alert in alerts}
    for i, pkt in enumerate(packets):
        if 'IP' not in pkt:
            continue
        if pkt['IP'].src in alert_ips:
            alert_indices.add(i)
    return alert_indices


def evaluate(alert_indices, ground_truth):
    true_positives = 0
    false_positives = 0
    detected = set()
    
    for idx in alert_indices:
        if idx in ground_truth:
            true_positives += 1
            detected.add(idx)
        else:
            false_positives += 1
    
    false_negatives = len(ground_truth) - len(detected)
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {'tp': true_positives, 'fp': false_positives, 'fn': false_negatives, 'precision': precision, 'recall': recall, 'f1': f1}


def main():
    print("="*60)
    print("DIRECT FEATURE-BASED NIDS EVALUATION")
    print("="*60)
    
    packets = generate_test_traffic()
    print(f"\nTotal packets: {len(packets)}")
    
    ground_truth = create_ground_truth(packets)
    print(f"Attack packets: {len(ground_truth)}")
    
    print("\nBuilding feature sets...")
    all_features = build_feature_sets(packets)
    print(f"Unique IPs tracked: {len(all_features)}")
    
    # Show key feature stats
    print("\nKey features per IP:")
    for src_ip, features in all_features.items():
        pd = features.get('port_diversity', 0)
        cr = features.get('connection_rate', 0)
        pr = features.get('packet_rate', 0)
        ud = features.get('unique_dst_ips', 0)
        ic = features.get('icmp_count', 0)
        if pd > 10 or cr > 10 or pr > 5 or ic > 5:  # Show interesting IPs
            print(f"  {src_ip}: port_div={pd}, conn_rate={cr:.1f}, pkt_rate={pr:.1f}, unique_dst={ud}, icmp={ic}")
    
    print("\n" + "="*60)
    print("DETECTION RESULTS")
    print("="*60)
    
    best_f1 = 0
    best_threshold = 0
    
    for threshold in [0.1, 0.2, 0.3, 0.4, 0.5]:
        alerts = run_direct_detection(all_features, threshold=threshold)
        alert_indices = match_alerts_to_packets(alerts, packets)
        metrics = evaluate(alert_indices, ground_truth)
        
        print(f"\nThreshold: {threshold}")
        print(f"  Alerts: {len(alerts)}, TP: {metrics['tp']}, FP: {metrics['fp']}, FN: {metrics['fn']}")
        print(f"  Precision: {metrics['precision']:.4f}, Recall: {metrics['recall']:.4f}, F1: {metrics['f1']:.4f}")
        
        if metrics['f1'] > best_f1:
            best_f1 = metrics['f1']
            best_threshold = threshold
    
    print("\n" + "="*60)
    print(f"BEST: threshold={best_threshold}, F1={best_f1:.4f}")
    print("="*60)
    
    # Show ALL detected anomaly types
    print("\n*** DETECTED ANOMALIES (Generalized Detection) ***")
    alerts = run_direct_detection(all_features, threshold=best_threshold)
    for alert in alerts:
        print(f"\nIP: {alert['src_ip']}")
        print(f"  Primary: {alert['anomaly_type']} (score={alert['score']:.2f})")
        print(f"  ALL anomaly types detected: {alert['anomaly_types']}")
        print(f"  ALL scores: {alert['all_scores']}")
        print(f"  Features: port_div={alert['features']['port_diversity']}, " +
              f"conn_rate={alert['features']['connection_rate']:.1f}, " +
              f"pkt_rate={alert['features']['packet_rate']:.1f}, " +
              f"unique_dst={alert['features']['unique_dst_ips']}, " +
              f"icmp={alert['features']['icmp_count']}")
    
    return best_f1


if __name__ == '__main__':
    main()

