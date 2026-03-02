#!/usr/bin/env python3
"""
Learning Database - Tracks learning metrics and anomaly history
Simple SQLite-based storage for the closed-loop learning system
"""

import sqlite3
import json
import threading
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class LearningDB:
    """Database for tracking learning metrics and history"""
    
    def __init__(self, db_path='learning.db'):
        self.db_path = db_path
        self.lock = threading.RLock()
        self._init_db()
        
        logger.info(f"LearningDB initialized: {db_path}")
    
    def _init_db(self):
        """Initialize database schema"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Anomalies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    score REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT,
                    features TEXT,
                    rule_generated INTEGER DEFAULT 0,
                    rule_id TEXT
                )
            ''')
            
            # Auto-generated rules table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auto_rules (
                    id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    rule_string TEXT NOT NULL,
                    score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    hit_count INTEGER DEFAULT 0,
                    last_hit TEXT
                )
            ''')
            
            # Learning metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learning_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    details TEXT
                )
            ''')
            
            # Learning sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learning_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    packets_processed INTEGER DEFAULT 0,
                    anomalies_detected INTEGER DEFAULT 0,
                    rules_generated INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_ip ON anomalies(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_type ON anomalies(anomaly_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_time ON anomalies(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_ip ON auto_rules(src_ip)')
            
            conn.commit()
            conn.close()
    
    # ==================== Anomalies ====================
    
    def record_anomaly(self, anomaly_dict):
        """Record a detected anomaly"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO anomalies (id, src_ip, anomaly_type, score, timestamp, severity, features, rule_generated, rule_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                anomaly_dict.get('id'),
                anomaly_dict.get('src_ip'),
                anomaly_dict.get('anomaly_type'),
                anomaly_dict.get('score'),
                anomaly_dict.get('timestamp'),
                anomaly_dict.get('severity'),
                json.dumps(anomaly_dict.get('features', {})),
                1 if anomaly_dict.get('rule_generated') else 0,
                anomaly_dict.get('rule_id')
            ))
            
            conn.commit()
            conn.close()
    
    def get_anomalies(self, limit=100, src_ip=None, anomaly_type=None):
        """Get recorded anomalies"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM anomalies'
            params = []
            
            if src_ip or anomaly_type:
                conditions = []
                if src_ip:
                    conditions.append('src_ip = ?')
                    params.append(src_ip)
                if anomaly_type:
                    conditions.append('anomaly_type = ?')
                    params.append(anomaly_type)
                query += ' WHERE ' + ' AND '.join(conditions)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    
    def update_anomaly_rule(self, anomaly_id, rule_id):
        """Update anomaly with generated rule ID"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('UPDATE anomalies SET rule_generated = 1, rule_id = ? WHERE id = ?', 
                          (rule_id, anomaly_id))
            
            conn.commit()
            conn.close()
    
    # ==================== Auto Rules ====================
    
    def record_rule(self, rule_dict):
        """Record an auto-generated rule"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO auto_rules 
                (id, src_ip, anomaly_type, rule_string, score, created_at, enabled, hit_count, last_hit)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule_dict.get('id'),
                rule_dict.get('src_ip'),
                rule_dict.get('anomaly_type'),
                rule_dict.get('rule_string'),
                rule_dict.get('score'),
                rule_dict.get('created_at'),
                1 if rule_dict.get('enabled', True) else 0,
                rule_dict.get('hit_count', 0),
                rule_dict.get('last_hit')
            ))
            
            conn.commit()
            conn.close()
    
    def get_rules(self, limit=100, enabled_only=False):
        """Get recorded rules"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM auto_rules'
            if enabled_only:
                query += ' WHERE enabled = 1'
            
            query += ' ORDER BY created_at DESC LIMIT ?'
            
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    
    def update_rule_hit(self, rule_id):
        """Update rule hit count"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('UPDATE auto_rules SET hit_count = hit_count + 1, last_hit = ? WHERE id = ?',
                         (datetime.now().isoformat(), rule_id))
            
            conn.commit()
            conn.close()
    
    def delete_rule(self, rule_id):
        """Delete a rule"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM auto_rules WHERE id = ?', (rule_id,))
            
            conn.commit()
            conn.close()
    
    # ==================== Learning Metrics ====================
    
    def record_metric(self, metric_name, metric_value, details=None):
        """Record a learning metric"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO learning_metrics (timestamp, metric_name, metric_value, details)
                VALUES (?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                metric_name,
                metric_value,
                json.dumps(details) if details else None
            ))
            
            conn.commit()
            conn.close()
    
    def get_metrics(self, metric_name=None, hours=24, limit=100):
        """Get learning metrics"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM learning_metrics'
            params = []
            
            if metric_name:
                query += ' WHERE metric_name = ?'
                params.append(metric_name)
                
                # Add time filter
                if hours:
                    query += ' AND timestamp > ?'
                    params.append((datetime.now() - timedelta(hours=hours)).isoformat())
            elif hours:
                query += ' WHERE timestamp > ?'
                params.append((datetime.now() - timedelta(hours=hours)).isoformat())
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    
    def get_metric_summary(self, hours=24):
        """Get summary of metrics"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT metric_name, COUNT(*) as count, AVG(metric_value) as avg_value,
                       MIN(metric_value) as min_value, MAX(metric_value) as max_value
                FROM learning_metrics
                WHERE timestamp > ?
                GROUP BY metric_name
            ''', ((datetime.now() - timedelta(hours=hours)).isoformat(),))
            
            rows = cursor.fetchall()
            conn.close()
            
            return {row[0]: {'count': row[1], 'avg': row[2], 'min': row[3], 'max': row[4]} for row in rows}
    
    # ==================== Learning Sessions ====================
    
    def start_session(self):
        """Start a new learning session"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO learning_sessions (start_time, status)
                VALUES (?, 'active')
            ''', (datetime.now().isoformat(),))
            
            session_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return session_id
    
    def end_session(self, session_id, status='completed'):
        """End a learning session"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE learning_sessions 
                SET end_time = ?, status = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), status, session_id))
            
            conn.commit()
            conn.close()
    
    def update_session_stats(self, session_id, packets=None, anomalies=None, rules=None):
        """Update session statistics"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if packets is not None:
                cursor.execute('UPDATE learning_sessions SET packets_processed = ? WHERE id = ?',
                             (packets, session_id))
            if anomalies is not None:
                cursor.execute('UPDATE learning_sessions SET anomalies_detected = ? WHERE id = ?',
                             (anomalies, session_id))
            if rules is not None:
                cursor.execute('UPDATE learning_sessions SET rules_generated = ? WHERE id = ?',
                             (rules, session_id))
            
            conn.commit()
            conn.close()
    
    # ==================== Statistics ====================
    
    def get_statistics(self):
        """Get overall statistics"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            stats = {}
            
            # Count anomalies
            cursor.execute('SELECT COUNT(*) FROM anomalies')
            stats['total_anomalies'] = cursor.fetchone()[0]
            
            # Count rules
            cursor.execute('SELECT COUNT(*) FROM auto_rules WHERE enabled = 1')
            stats['active_rules'] = cursor.fetchone()[0]
            
            # Count rules with hits
            cursor.execute('SELECT COUNT(*) FROM auto_rules WHERE hit_count > 0')
            stats['rules_triggered'] = cursor.fetchone()[0]
            
            # Anomalies by type
            cursor.execute('''
                SELECT anomaly_type, COUNT(*) as count 
                FROM anomalies 
                GROUP BY anomaly_type
            ''')
            stats['anomalies_by_type'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Recent activity
            cursor.execute('''
                SELECT DATE(timestamp) as date, COUNT(*) as count 
                FROM anomalies 
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY DATE(timestamp)
            ''')
            stats['recent_anomalies'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            conn.close()
            
            return stats
    
    def clear_old_data(self, days=30):
        """Clear data older than specified days"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute('DELETE FROM anomalies WHERE timestamp < ?', (cutoff,))
            cursor.execute('DELETE FROM learning_metrics WHERE timestamp < ?', (cutoff,))
            
            deleted_anomalies = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            logger.info(f"Cleared {deleted_anomalies} old anomaly records")
            return deleted_anomalies


# Singleton instance
_instance = None
_instance_lock = threading.Lock()


def get_learning_db(db_path='learning.db'):
    """Get or create singleton LearningDB instance"""
    global _instance
    
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = LearningDB(db_path)
    
    return _instance


if __name__ == '__main__':
    # Test the learning database
    db = LearningDB('test_learning.db')
    
    # Record test anomaly
    db.record_anomaly({
        'id': 'test_anomaly_001',
        'src_ip': '192.168.1.100',
        'anomaly_type': 'port_scan',
        'score': 0.85,
        'timestamp': datetime.now().isoformat(),
        'severity': 'high',
        'features': {'port_diversity': 25, 'connection_rate': 15}
    })
    
    # Record test rule
    db.record_rule({
        'id': 'test_rule_001',
        'src_ip': '192.168.1.100',
        'anomaly_type': 'port_scan',
        'rule_string': 'alert tcp 192.168.1.100 any --> any any AUTO_PORT_SCAN_001',
        'score': 0.85,
        'created_at': datetime.now().isoformat(),
        'enabled': True
    })
    
    # Record metrics
    db.record_metric('packet_rate', 10.5, {'ip': '192.168.1.100'})
    db.record_metric('anomaly_score', 0.85, {'type': 'port_scan'})
    
    print("\nStatistics:", db.get_statistics())
    print("\nAnomalies:", db.get_anomalies())
    print("\nRules:", db.get_rules())
    print("\nMetrics:", db.get_metrics())

