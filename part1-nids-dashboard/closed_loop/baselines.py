#!/usr/bin/env python3
"""
Baselines - Adaptive Baseline Management
Maintains moving averages and adapts to normal traffic patterns over time
"""

import time
import threading
import logging
from collections import deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class AdaptiveBaseline:
    """Manages adaptive baselines for network traffic features"""
    
    def __init__(self, history_size=100, adaptation_rate=0.1):
        """
        Args:
            history_size: Number of samples to keep for baseline calculation
            adaptation_rate: How fast the baseline adapts (0.0-1.0)
        """
        self.history_size = history_size
        self.adaptation_rate = adaptation_rate
        
        # Per-feature baselines
        self.baselines = {
            'packet_rate': {'value': 5.0, 'std': 3.0},      # Normal: 5 pps, std: 3
            'port_diversity': {'value': 3.0, 'std': 2.0},   # Normal: 3 ports
            'connection_rate': {'value': 2.0, 'std': 2.0},   # Normal: 2 conn/sec
            'bytes_per_second': {'value': 1000.0, 'std': 500}, # Normal: 1KB/s
            'dns_query_rate': {'value': 0.5, 'std': 0.5},    # Normal: 0.5 qps
            'icmp_count': {'value': 1.0, 'std': 1.0},        # Normal: 1 ICMP
        }
        
        # History for each feature
        self.history = {key: deque(maxlen=history_size) for key in self.baselines}
        
        # Per-IP baselines (for more granular detection)
        self.ip_baselines = {}
        
        # Lock for thread safety
        self.lock = threading.RLock()
        
        # Learning mode flag
        self.learning_mode = True
        self.learning_samples = 0
        self.min_learning_samples = 50
    
    def update_baseline(self, feature_name, value):
        """Update baseline with a new sample"""
        with self.lock:
            if feature_name not in self.baselines:
                return
            
            baseline = self.baselines[feature_name]
            
            if self.learning_mode:
                # In learning mode, just add to history
                self.history[feature_name].append(value)
                self.learning_samples += 1
                
                # Calculate new baseline from history
                if len(self.history[feature_name]) >= 10:
                    values = list(self.history[feature_name])
                    baseline['value'] = sum(values) / len(values)
                    # Calculate std dev
                    mean = baseline['value']
                    variance = sum((x - mean) ** 2 for x in values) / len(values)
                    baseline['std'] = max(0.5, variance ** 0.5)
                
                # Exit learning mode after enough samples
                if self.learning_samples >= self.min_learning_samples:
                    self.learning_mode = False
                    logger.info(f"Learning complete: {self.learning_samples} samples processed")
            else:
                # In detection mode, adapt slowly
                old_value = baseline['value']
                old_std = baseline['std']
                
                # Exponential moving average for value
                baseline['value'] = old_value + self.adaptation_rate * (value - old_value)
                
                # Gradually increase std if current value is outside range
                z_score = abs(value - baseline['value']) / max(0.1, baseline['std'])
                if z_score > 2.0:
                    # Slowly expand std to account for new normal
                    baseline['std'] = old_std + 0.01 * (abs(value - baseline['value']) - old_std)
                    baseline['std'] = max(0.5, min(100, baseline['std']))  # Clamp std
                
                # Add to history for reference
                self.history[feature_name].append(value)
    
    def update_from_features(self, features):
        """Update all baselines from a feature dictionary"""
        self.update_baseline('packet_rate', features.get('packet_rate', 0))
        self.update_baseline('port_diversity', features.get('port_diversity', 0))
        self.update_baseline('connection_rate', features.get('connection_rate', 0))
        self.update_baseline('bytes_per_second', features.get('bytes_per_second', 0))
        self.update_baseline('dns_query_rate', features.get('dns_query_rate', 0))
        self.update_baseline('icmp_count', features.get('icmp_count', 0))
    
    def get_z_score(self, feature_name, value):
        """Calculate z-score for a value against the baseline"""
        with self.lock:
            if feature_name not in self.baselines:
                return 0.0
            baseline = self.baselines[feature_name]
            if baseline['std'] < 0.1:
                return 0.0
            return (value - baseline['value']) / baseline['std']
    
    def is_anomalous(self, feature_name, value, threshold=3.0):
        """Check if a value is anomalous based on z-score"""
        z = self.get_z_score(feature_name, value)
        return abs(z) > threshold
    
    def get_baseline_stats(self):
        """Get current baseline statistics"""
        with self.lock:
            return {k: {'mean': round(v['value'], 3), 'std': round(v['std'], 3)} 
                    for k, v in self.baselines.items()}
    
    def reset(self):
        """Reset all baselines to default values"""
        with self.lock:
            self.baselines = {
                'packet_rate': {'value': 5.0, 'std': 3.0},
                'port_diversity': {'value': 3.0, 'std': 2.0},
                'connection_rate': {'value': 2.0, 'std': 2.0},
                'bytes_per_second': {'value': 1000.0, 'std': 500},
                'dns_query_rate': {'value': 0.5, 'std': 0.5},
                'icmp_count': {'value': 1.0, 'std': 1.0},
            }
            self.history = {key: deque(maxlen=self.history_size) for key in self.baselines}
            self.learning_mode = True
            self.learning_samples = 0
            self.ip_baselines = {}
            logger.info("Baselines reset")


class IPBaselineManager:
    """Manages per-IP baselines for more granular detection"""
    
    def __init__(self, baseline_class=AdaptiveBaseline, max_ips=1000):
        self.baselines = {}  # ip -> AdaptiveBaseline
        self.baseline_class = baseline_class
        self.max_ips = max_ips
        self.lock = threading.RLock()
    
    def get_or_create_baseline(self, ip):
        """Get baseline for an IP, create if doesn't exist"""
        with self.lock:
            if ip not in self.baselines:
                # Remove oldest if at capacity
                if len(self.baselines) >= self.max_ips:
                    oldest_ip = min(self.baselines.keys(), 
                                   key=lambda x: self.baselines[x].last_update)
                    del self.baselines[oldest_ip]
                
                self.baselines[ip] = self.baseline_class()
            return self.baselines[ip]
    
    def remove_ip(self, ip):
        """Remove baseline for an IP"""
        with self.lock:
            if ip in self.baselines:
                del self.baselines[ip]
    
    def get_all_baselines(self):
        """Get all IP baselines"""
        with self.lock:
            return {ip: {'stats': baseline.get_baseline_stats()} 
                    for ip, baseline in self.baselines.items()}
    
    def clear_stale(self, max_age_seconds=3600):
        """Remove baselines for IPs with no recent activity"""
        with self.lock:
            now = time.time()
            stale = [ip for ip, b in self.baselines.items() 
                    if hasattr(b, 'last_update') and (now - b.last_update) > max_age_seconds]
            for ip in stale:
                del self.baselines[ip]


# Simple Moving Average calculator
class SimpleMovingAverage:
    """Simple moving average calculator for any metric"""
    
    def __init__(self, window_size=10):
        self.window_size = window_size
        self.values = deque(maxlen=window_size)
        self.lock = threading.Lock()
    
    def add(self, value):
        """Add a value and return current average"""
        with self.lock:
            self.values.append(value)
            return self.get_average()
    
    def get_average(self):
        """Get current average"""
        with self.lock:
            if not self.values:
                return 0.0
            return sum(self.values) / len(self.values)
    
    def get_std(self):
        """Get current standard deviation"""
        with self.lock:
            if len(self.values) < 2:
                return 0.0
            avg = sum(self.values) / len(self.values)
            variance = sum((x - avg) ** 2 for x in self.values) / len(self.values)
            return variance ** 0.5
    
    def reset(self):
        """Reset the calculator"""
        with self.lock:
            self.values.clear()


# Exponential Moving Average
class ExponentialMovingAverage:
    """Exponential moving average for smoother baseline tracking"""
    
    def __init__(self, alpha=0.3):
        self.alpha = alpha
        self.value = None
        self.lock = threading.Lock()
    
    def add(self, new_value):
        """Add a value and return updated EMA"""
        with self.lock:
            if self.value is None:
                self.value = new_value
            else:
                self.value = self.alpha * new_value + (1 - self.alpha) * self.value
            return self.value
    
    def get_value(self):
        """Get current EMA value"""
        with self.lock:
            return self.value
    
    def reset(self):
        """Reset the EMA"""
        with self.lock:
            self.value = None


if __name__ == '__main__':
    # Test the baseline system
    baseline = AdaptiveBaseline()
    
    # Simulate normal traffic
    for i in range(60):
        baseline.update_baseline('packet_rate', 5 + (hash(str(i)) % 5))
        time.sleep(0.05)
    
    print("After learning:")
    print(baseline.get_baseline_stats())
    
    # Test anomaly detection
    baseline.learning_mode = False
    
    print("\nNormal traffic z-score:", baseline.get_z_score('packet_rate', 5.0))
    print("Anomalous traffic z-score:", baseline.get_z_score('packet_rate', 50.0))
    print("Is 50 anomalous?", baseline.is_anomalous('packet_rate', 50.0))

