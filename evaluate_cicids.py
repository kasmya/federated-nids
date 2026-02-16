#!/usr/bin/env python3
"""
CICIDS2017 Dataset Evaluation - Practical Version
Evaluates NIDS detection capabilities on captured traffic
Shows what the system detects and allows manual verification
"""

import os
import sys
import json
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from closed_loop.traffic_analyzer import TrafficFeatureExtractor, FeatureVector


def load_json_packets(json_file):
    """Load packets from JSON file"""
    print(f"Loading: {json_file}")
    
    with open(json_file) as f:
        data = json.load(f)
    
    packets = data.get('packets', [])
    print(f"  Loaded {len(packets)} packets")
    
    return packets


def analyze_traffic(packets):
    """Analyze traffic and show statistics"""
    
    # Collect per-IP statistics
    ip_stats = defaultdict(lambda: {
        'packet_count': 0,
        'ports': set(),
        'dst_ips': set(),
        'tcp_syn_count': 0,
        'icmp_count': 0,
        'bytes': 0
    })
    
    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        
        src = pkt.get('src', '')
        proto = pkt.get('proto', '').lower()
        
        ip_stats[src]['packet_count'] += 1
        ip_stats[src]['ports'].add(pkt.get('dport', 0))
        ip_stats[src]['dst_ips'].add(pkt.get('dst', ''))
        ip_stats[src]['bytes'] += pkt.get('length', 64)
        
        if proto == 'tcp' and pkt.get('flags', '') == 'S':
            ip_stats[src]['tcp_syn_count'] += 1
        if proto == 'icmp':
            ip_stats[src]['icmp_count'] += 1
    
    return ip_stats


def run_detection_optimized(packets, threshold_config='balanced'):
    """Run detection with different threshold configurations"""
    
    # Extract features
    extractor = TrafficFeatureExtractor(window_size_seconds=10)
    
    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        
        features = {
            'src': pkt.get('src', ''),
            'dst': pkt.get('dst', ''),
            'proto': pkt.get('proto', 'other'),
            'sport': pkt.get('sport', 0),
            'dport': pkt.get('dport', 0),
            'flags': pkt.get('flags', ''),
            'length': pkt.get('length', 64)
        }
        
        extractor.extract_features(features)
    
    # Get all features before detection
    all_features = extractor.get_all_features()
    
    # Configure thresholds based on mode
    if threshold_config == 'sensitive':  # More alerts, higher recall
        thresholds = {
            'port_scan': {'port_diversity': 30, 'connection_rate': 3},
            'syn_flood': {'connection_rate': 5, 'packet_rate': 10},
            'ddos': {'packet_rate': 10, 'unique_dst_ips': 5},
            'icmp_flood': {'icmp_count': 8, 'packet_rate': 8}
        }
        FeatureVector.set_learned_thresholds(thresholds)
        FeatureVector.disable_adaptive_thresholds()
    elif threshold_config == 'balanced':  # Balanced
        thresholds = {
            'port_scan': {'port_diversity': 50, 'connection_rate': 5},
            'syn_flood': {'connection_rate': 10, 'packet_rate': 20},
            'ddos': {'packet_rate': 25, 'unique_dst_ips': 10},
            'icmp_flood': {'icmp_count': 15, 'packet_rate': 15}
        }
        FeatureVector.set_learned_thresholds(thresholds)
        FeatureVector.disable_adaptive_thresholds()
    elif threshold_config == 'conservative':  # Fewer alerts, higher precision
        thresholds = {
            'port_scan': {'port_diversity': 70, 'connection_rate': 8},
            'syn_flood': {'connection_rate': 15, 'packet_rate': 30},
            'ddos': {'packet_rate': 40, 'unique_dst_ips': 15},
            'icmp_flood': {'icmp_count': 25, 'packet_rate': 25}
        }
        FeatureVector.set_learned_thresholds(thresholds)
        FeatureVector.disable_adaptive_thresholds()
    elif threshold_config == 'adaptive':  # NEW: Use adaptive outlier-based detection
        FeatureVector.use_default_thresholds()
        FeatureVector.enable_adaptive_thresholds(multiplier=2.0)
        # Compute adaptive thresholds based on traffic distribution
        FeatureVector.compute_adaptive_thresholds(all_features)
    
    # Run detection
    results = {
        'total_alerts': 0,
        'by_type': defaultdict(int),
        'by_ip': defaultdict(list),
        'details': []
    }
    
    for src_ip, features in all_features.items():
        fv = FeatureVector(features)
        fv.calculate_anomaly_scores()
        
        max_score = fv.get_max_score()
        
        if max_score >= 0.3:  # Detection threshold
            for anomaly_type in fv.anomaly_types:
                results['by_type'][anomaly_type] += 1
                results['by_ip'][src_ip].append({
                    'type': anomaly_type,
                    'score': max_score
                })
                results['total_alerts'] += 1
                results['details'].append({
                    'ip': src_ip,
                    'type': anomaly_type,
                    'score': max_score,
                    'features': {
                        'port_diversity': features.get('port_diversity', 0),
                        'connection_rate': features.get('connection_rate', 0),
                        'packet_rate': features.get('packet_rate', 0)
                    }
                })
    
    FeatureVector.use_default_thresholds()
    
    return results


def main():
    print("="*60)
    print("CICIDS2017 EVALUATION - PRACTICAL DETECTION TEST")
    print("="*60)
    
    json_file = 'saved_pcap/nids_capture_2026-02-15T19-35-51.json'
    
    if not os.path.exists(json_file):
        print("No JSON file found!")
        return
    
    packets = load_json_packets(json_file)
    
    if not packets:
        print("No packets loaded!")
        return
    
    # Analyze traffic
    print("\n" + "="*60)
    print("TRAFFIC ANALYSIS")
    print("="*60)
    
    ip_stats = analyze_traffic(packets)
    
    print(f"\nTotal unique IPs: {len(ip_stats)}")
    
    # Show top traffic sources
    print("\nTop 10 IPs by packet count:")
    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]['packet_count'], reverse=True)
    
    for ip, stats in sorted_ips[:10]:
        print(f"  {ip}: {stats['packet_count']} packets, {len(stats['ports'])} unique ports, "
              f"{stats['tcp_syn_count']} SYNs, {len(stats['dst_ips'])} dst IPs")
    
    # Run detection with different configs
    configs = ['sensitive', 'balanced', 'conservative', 'adaptive']
    
    print("\n" + "="*60)
    print("DETECTION RESULTS BY CONFIGURATION")
    print("="*60)
    
    best_config = None
    best_alerts = 0
    
    for config in configs:
        print(f"\n--- {config.upper()} Configuration ---")
        
        results = run_detection_optimized(packets, threshold_config=config)
        
        print(f"Total Alerts: {results['total_alerts']}")
        
        if results['total_alerts'] > 0:
            print("By Anomaly Type:")
            for atype, count in results['by_type'].items():
                print(f"  {atype}: {count}")
            
            print("IPs with Alerts:")
            for ip, alerts in results['by_ip'].items():
                types = set(a['type'] for a in alerts)
                print(f"  {ip}: {', '.join(types)} (score: {alerts[0]['score']:.2f})")
        
        # Track best (balanced is default)
        if config == 'balanced':
            best_config = results
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Total Packets: {len(packets)}")
    print(f"Unique Source IPs: {len(ip_stats)}")
    print(f"Balanced Detection Alerts: {best_config['total_alerts']}")
    
    if best_config['total_alerts'] > 0:
        print(f"\nDetection Breakdown (balanced):")
        for atype, count in best_config['by_type'].items():
            print(f"  {atype}: {count} alerts")
        
        print(f"\nAlerted IPs ({len(best_config['by_ip'])} total):")
        for ip in sorted(best_config['by_ip'].keys())[:10]:
            alerts = best_config['by_ip'][ip]
            types = ', '.join(set(a['type'] for a in alerts))
            print(f"  {ip}: {types}")
    
    print("\n" + "="*60)
    print("CONFIGURATION RECOMMENDATIONS")
    print("="*60)
    print("""
- Use 'sensitive' config for high recall (catch more attacks, more FPs)
- Use 'balanced' config for general purpose detection
- Use 'conservative' config for high precision (fewer FPs, may miss some attacks)

To reduce false positives:
1. Increase detection threshold (e.g., from 0.3 to 0.5)
2. Use 'conservative' threshold configuration  
3. Enable adaptive learning from your network traffic
4. Adjust FeatureVector.DEFAULT_THRESHOLDS in traffic_analyzer.py
    """)
    
    print("="*60)


if __name__ == '__main__':
    main()

