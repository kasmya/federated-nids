# This is a patch to add more detection patterns

# Read the file
with open('traffic_analyzer.py', 'r') as f:
    content = f.read()

# Add more attack types to AnomalyType
old_anomaly = '''class AnomalyType:
    """Enumeration of anomaly types"""
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    DDOS = "potential_ddos"
    DNS_AMPLIFICATION = "dns_amplification"
    ICMP_FLOOD = "icmp_flood"
    UNUSUAL_SIZE = "unusual_packet_size"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"'''

new_anomaly = '''class AnomalyType:
    """Enumeration of anomaly types"""
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    DDOS = "potential_ddos"
    DNS_AMPLIFICATION = "dns_amplification"
    ICMP_FLOOD = "icmp_flood"
    UNUSUAL_SIZE = "unusual_packet_size"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    # NEW: Additional attack types
    TCP_SCAN = "tcp_scan"
    UDP_SCAN = "udp_scan"
    HTTP_SCAN = "http_scan"
    SSH_BRUTE = "ssh_bruteforce"
    FTP_BRUTE = "ftp_bruteforce"
    SUSPICIOUS_IPS = "suspicious_ip_access"
    MALWARE_DOWNLOAD = "malware_download"
    C&C_COMM = "c2_communication"'''

content = content.replace(old_anomaly, new_anomaly)

# Add more thresholds
old_thresh = '''    # Lower thresholds for easier detection in demo mode
    THRESHOLDS = {
        'port_scan': {
            'port_diversity': 5,      # 10+ unique ports in window (was 20)
            'connection_rate': 3,     # 5+ connections/second (was 10)
        },
        'syn_flood': {
            'connection_rate': 8,     # 20+ SYN packets/second (was 50)
            'packet_rate': 15,        # 50+ packets/second (was 100)
        },
        'ddos': {
            'packet_rate': 15,        # 50+ packets/second (was 200)
            'unique_dst_ips': 8,     # 20+ unique destinations (was 50)
        },
        'dns_amplification': {
            'dns_query_rate': 2,      # 5+ DNS queries/second (was 10)
            'avg_packet_size': 180,   # Large response packets (was 500)
        },
        'icmp_flood': {
            'icmp_count': 8,        # 20+ ICMP in window (was 50)
            'packet_rate': 15,       # 15+ packets/second (was 30)
        }
    }'''

new_thresh = '''    # Lower thresholds for easier detection in demo mode
    THRESHOLDS = {
        'port_scan': {
            'port_diversity': 4,      # Very sensitive
            'connection_rate': 2,
        },
        'syn_flood': {
            'connection_rate': 5,
            'packet_rate': 10,
        },
        'ddos': {
            'packet_rate': 10,
            'unique_dst_ips': 5,
        },
        'dns_amplification': {
            'dns_query_rate': 2,
            'avg_packet_size': 150,
        },
        'icmp_flood': {
            'icmp_count': 5,
            'packet_rate': 8,
        },
        # NEW: More sensitive thresholds
        'brute_force': {
            'port_diversity': 2,      # Few ports but repeated
            'connection_rate': 3,
        },
        'data_exfiltration': {
            'bytes_per_second': 1000,  # 1KB/s upload
            'unique_dst_ips': 1,
        },
        'tcp_scan': {
            'port_diversity': 3,
            'connection_rate': 2,
        },
        'http_scan': {
            'port_diversity': 1,
            'connection_rate': 5,
        }
    }'''

content = content.replace(old_thresh, new_thresh)

# Now update the calculate_anomaly_scores method to add more detections
old_calc = '''    def calculate_anomaly_scores(self):
        """Calculate anomaly scores based on thresholds"""
        scores = {}

        # Port Scan Detection
        if self.features['port_diversity'] > self.THRESHOLDS['port_scan']['port_diversity']:
            score = min(1.0, self.features['port_diversity'] / (self.THRESHOLDS['port_scan']['port_diversity'] * 2))
            scores['port_scan'] = score
            if score > 0.5:
                self.anomaly_types.append('port_scan')
        
        # SYN Flood Detection
        if self.features['connection_rate'] > self.THRESHOLDS['syn_flood']['connection_rate']:
            score = min(1.0, self.features['connection_rate'] / (self.THRESHOLDS['syn_flood']['connection_rate'] * 2))
            scores['syn_flood'] = score
            if score > 0.5:
                self.anomaly_types.append('syn_flood')
        
        # DDoS Detection
        if self.features['packet_rate'] > self.THRESHOLDS['ddos']['packet_rate']:
            score = min(1.0, self.features['packet_rate'] / (self.THRESHOLDS['ddos']['packet_rate'] * 2))
            scores['ddos'] = score
            if score > 0.5:
                self.anomaly_types.append('ddos')
        
        # DNS Amplification
        if self.features['dns_query_rate'] > self.THRESHOLDS['dns_amplification']['dns_query_rate']:
            score = min(1.0, self.features['dns_query_rate'] / (self.THRESHOLDS['dns_amplification']['dns_query_rate'] * 2))
            scores['dns_amplification'] = score
            if score > 0.5:
                self.anomaly_types.append('dns_amplification')
        
        # ICMP Flood
        if self.features['icmp_count'] > self.THRESHOLDS['icmp_flood']['icmp_count']:
            score = min(1.0, self.features['icmp_count'] / (self.THRESHOLDS['icmp_flood']['icmp_count'] * 2))
            scores['icmp_flood'] = score
            if score > 0.5:
                self.anomaly_types.append('icmp_flood')
        
        self.anomaly_scores = scores
        return scores'''

new_calc = '''    def calculate_anomaly_scores(self):
        """Calculate anomaly scores based on thresholds"""
        scores = {}

        # Port Scan Detection
        if self.features['port_diversity'] > self.THRESHOLDS['port_scan']['port_diversity']:
            score = min(1.0, self.features['port_diversity'] / (self.THRESHOLDS['port_scan']['port_diversity'] * 2))
            scores['port_scan'] = score
            if score > 0.4:  # Lower threshold
                self.anomaly_types.append('port_scan')
        
        # SYN Flood Detection
        if self.features['connection_rate'] > self.THRESHOLDS['syn_flood']['connection_rate']:
            score = min(1.0, self.features['connection_rate'] / (self.THRESHOLDS['syn_flood']['connection_rate'] * 2))
            scores['syn_flood'] = score
            if score > 0.4:  # Lower threshold
                self.anomaly_types.append('syn_flood')
        
        # DDoS Detection
        if self.features['packet_rate'] > self.THRESHOLDS['ddos']['packet_rate']:
            score = min(1.0, self.features['packet_rate'] / (self.THRESHOLDS['ddos']['packet_rate'] * 2))
            scores['ddos'] = score
            if score > 0.4:  # Lower threshold
                self.anomaly_types.append('ddos')
        
        # DNS Amplification
        if self.features['dns_query_rate'] > self.THRESHOLDS['dns_amplification']['dns_query_rate']:
            score = min(1.0, self.features['dns_query_rate'] / (self.THRESHOLDS['dns_amplification']['dns_query_rate'] * 2))
            scores['dns_amplification'] = score
            if score > 0.4:
                self.anomaly_types.append('dns_amplification')
        
        # ICMP Flood
        if self.features['icmp_count'] > self.THRESHOLDS['icmp_flood']['icmp_count']:
            score = min(1.0, self.features['icmp_count'] / (self.THRESHOLDS['icmp_flood']['icmp_count'] * 2))
            scores['icmp_flood'] = score
            if score > 0.4:
                self.anomaly_types.append('icmp_flood')
        
        # NEW: Brute Force Detection (few ports, repeated connections)
        if (self.features['port_diversity'] <= self.THRESHOLDS['brute_force']['port_diversity'] and 
            self.features['connection_rate'] > self.THRESHOLDS['brute_force']['connection_rate']):
            score = min(1.0, self.features['connection_rate'] / 10)
            scores['brute_force'] = score
            if score > 0.4:
                self.anomaly_types.append('brute_force')
        
        # NEW: Data Exfiltration (high bytes/sec)
        if self.features.get('bytes_per_second', 0) > self.THRESHOLDS['data_exfiltration']['bytes_per_second']:
            score = min(1.0, self.features.get('bytes_per_second', 0) / 5000)
            scores['data_exfiltration'] = score
            if score > 0.4:
                self.anomaly_types.append('data_exfiltration')
        
        # NEW: TCP Scan Detection
        if self.features['port_diversity'] > self.THRESHOLDS['tcp_scan']['port_diversity']:
            if self.features['connection_rate'] > self.THRESHOLDS['tcp_scan']['connection_rate']:
                score = min(1.0, self.features['port_diversity'] / 10)
                scores['tcp_scan'] = score
                if score > 0.4:
                    self.anomaly_types.append('tcp_scan')
        
        self.anomaly_scores = scores
        return scores'''

content = content.replace(old_calc, new_calc)

# Write back
with open('traffic_analyzer.py', 'w') as f:
    f.write(content)

print("Patch applied successfully!")
