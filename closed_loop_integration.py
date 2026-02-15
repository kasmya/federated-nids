#!/usr/bin/env python3
"""
Closed-Loop NIDS Integration
Adds API endpoints and packet processing integration for the closed-loop system
"""

import logging

logger = logging.getLogger(__name__)

# Global references (set by nids_server.py)
closed_loop_nids = None
anomaly_detector = None
rule_generator = None
learning_db = None
capture_state = None
rules_state = None
app = None

# Store references from main server
def integrate_with_server(server_app, nids_state, nids_rules, nids_closed_loop):
    """Integrate closed-loop endpoints with the main server"""
    global app, capture_state, rules_state, closed_loop_nids, anomaly_detector, rule_generator, learning_db
    
    app = server_app
    capture_state = nids_state
    rules_state = nids_rules
    closed_loop_nids = nids_closed_loop
    
    if nids_closed_loop:
        anomaly_detector = nids_closed_loop.detector
        rule_generator = nids_closed_loop.rule_generator
        learning_db = nids_closed_loop.learning_db
    
    _register_routes()
    logger.info("Closed-Loop API endpoints registered")


def _register_routes():
    """Register Flask routes for closed-loop API"""
    from flask import jsonify, request
    
    @app.route('/api/closed-loop/status')
    def api_closed_loop_status():
        """Get closed-loop system status"""
        if not closed_loop_nids:
            return jsonify({'error': 'Closed-loop not available'}), 500
        
        return jsonify(closed_loop_nids.get_status())
    
    @app.route('/api/closed-loop/anomalies')
    def api_closed_loop_anomalies():
        """Get recent anomalies"""
        if not anomaly_detector:
            return jsonify({'error': 'Anomaly detector not available'}), 500
        
        limit = request.args.get('limit', 20, type=int)
        return jsonify({'anomalies': anomaly_detector.get_recent_anomalies(limit)})
    
    @app.route('/api/closed-loop/rules')
    def api_closed_loop_rules():
        """Get auto-generated rules"""
        if not rule_generator:
            return jsonify({'error': 'Rule generator not available'}), 500
        
        return jsonify({'rules': rule_generator.get_all_rules()})
    
    @app.route('/api/closed-loop/rules/<rule_id>', methods=['POST'])
    def api_closed_loop_rule_action(rule_id):
        """Enable/disable an auto-generated rule"""
        if not rule_generator:
            return jsonify({'error': 'Rule generator not available'}), 500
        
        data = request.json
        action = data.get('action')
        
        if action == 'enable':
            rule_generator.enable_rule(rule_id)
            return jsonify({'status': 'enabled'})
        elif action == 'disable':
            rule_generator.disable_rule(rule_id)
            return jsonify({'status': 'disabled'})
        elif action == 'delete':
            rule_generator.delete_rule(rule_id)
            return jsonify({'status': 'deleted'})
        
        return jsonify({'error': 'Unknown action'}), 400
    
    @app.route('/api/closed-loop/config', methods=['GET', 'POST'])
    def api_closed_loop_config():
        """Get or update closed-loop configuration"""
        global closed_loop_nids, anomaly_detector
        
        if not closed_loop_nids:
            return jsonify({'error': 'Closed-loop not available'}), 500
        
        if request.method == 'GET':
            return jsonify({
                'auto_generate_rules': closed_loop_nids.auto_generate_rules,
                'detector_enabled': anomaly_detector.enabled if anomaly_detector else False,
                'threshold': anomaly_detector.detection_threshold if anomaly_detector else 0.5
            })
        
        # POST - update config
        data = request.json
        
        if 'auto_generate_rules' in data:
            closed_loop_nids.auto_generate_rules = data['auto_generate_rules']
        
        if 'detector_enabled' in data:
            if data['detector_enabled']:
                anomaly_detector.enable()
            else:
                anomaly_detector.disable()
        
        if 'threshold' in data and anomaly_detector:
            anomaly_detector.detection_threshold = data['threshold']
        
        return jsonify({'status': 'updated'})
    
    @app.route('/api/closed-loop/reset', methods=['POST'])
    def api_closed_loop_reset():
        """Reset the closed-loop system"""
        global closed_loop_nids, anomaly_detector
        
        if not closed_loop_nids:
            return jsonify({'error': 'Closed-loop not available'}), 500
        
        anomaly_detector.reset()
        return jsonify({'status': 'reset'})
    
    @app.route('/api/closed-loop/learning-stats')
    def api_closed_loop_learning_stats():
        """Get learning statistics from database"""
        if not learning_db:
            return jsonify({'error': 'Learning DB not available'}), 500
        
        return jsonify(learning_db.get_statistics())


def process_packet_with_closed_loop(pkt_data):
    """Process a packet through the closed-loop system"""
    global closed_loop_nids, anomaly_detector, rule_generator
    
    if not closed_loop_nids or not anomaly_detector:
        return None
    
    # Convert packet to dict format if needed
    if not isinstance(pkt_data, dict):
        return None
    
    # Process through anomaly detector
    anomaly = anomaly_detector.process_packet(pkt_data)
    
    # If rule was auto-generated, reload rules
    if anomaly and anomaly.rule_generated:
        logger.info(f"Auto-generated rule for anomaly: {anomaly.anomaly_type}")
    
    return anomaly


def get_closed_loop_status():
    """Get status for display"""
    if not closed_loop_nids:
        return {
            'available': False,
            'message': 'Closed-loop system not available'
        }
    
    status = closed_loop_nids.get_status()
    status['available'] = True
    return status
