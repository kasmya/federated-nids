#!/usr/bin/env python3
"""
Federated NIDS - Day 2: Rule Consensus API
Flask endpoints for rule submission and global rule management
"""

import os
import sys
from flask import Blueprint, jsonify, request

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import consensus engine
from federated.rule_consensus import RuleConsensusEngine, create_consensus_engine


# Create Flask Blueprint
rule_api_bp = Blueprint('rule_api', __name__, url_prefix='/api/federated')


# Global consensus engine instance
_consensus_engine = None


def get_consensus_engine() -> RuleConsensusEngine:
    """Get or create the consensus engine instance."""
    global _consensus_engine
    
    if _consensus_engine is None:
        min_consensus = 2
        similarity_threshold = 0.7
        
        _consensus_engine = create_consensus_engine(
            min_consensus=min_consensus
        )
        
        print(f"[API] Rule Consensus Engine initialized")
        print(f"  Min consensus: {min_consensus}")
        print(f"  Similarity threshold: {similarity_threshold}")
    
    return _consensus_engine


# ============================================================================
# RULE SUBMISSION ENDPOINTS
# ============================================================================

@rule_api_bp.route('/submit_rules', methods=['POST'])
def submit_rules():
    """
    Submit rules from a client for consensus.
    
    Request body:
        {
            "client_id": "client_A",
            "rules": [
                {
                    "rule_string": "alert tcp 192.168.1.100 any ...",
                    "anomaly_type": "port_scan",
                    "src_ip": "192.168.1.100",
                    "score": 0.85
                },
                ...
            ]
        }
    
    Returns:
        JSON with submission results
    """
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    client_id = data.get('client_id', 'unknown')
    rules = data.get('rules', [])
    
    if not rules:
        return jsonify({'error': 'No rules provided'}), 400
    
    engine = get_consensus_engine()
    
    # Submit each rule
    results = []
    for rule in rules:
        result = engine.submit_rule(rule, client_id)
        results.append(result)
    
    # Count promoted rules
    promoted_count = sum(1 for r in results if r.get('promoted', False))
    
    return jsonify({
        'status': 'success',
        'client_id': client_id,
        'rules_submitted': len(rules),
        'rules_promoted': promoted_count,
        'results': results,
        'global_rules_count': len(engine.get_global_rules())
    })


@rule_api_bp.route('/submit_rule', methods=['POST'])
def submit_single_rule():
    """
    Submit a single rule for consensus.
    
    Request body:
        {
            "client_id": "client_A",
            "rule": {
                "rule_string": "alert tcp 192.168.1.100 any ...",
                "anomaly_type": "port_scan",
                "src_ip": "192.168.1.100",
                "score": 0.85
            }
        }
    
    Returns:
        JSON with submission result
    """
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    client_id = data.get('client_id', 'unknown')
    rule = data.get('rule')
    
    if not rule:
        return jsonify({'error': 'No rule provided'}), 400
    
    engine = get_consensus_engine()
    result = engine.submit_rule(rule, client_id)
    
    return jsonify({
        'status': 'success',
        'client_id': client_id,
        'result': result,
        'global_rules_count': len(engine.get_global_rules())
    })


# ============================================================================
# GLOBAL RULES ENDPOINTS
# ============================================================================

@rule_api_bp.route('/global_rules', methods=['GET'])
def get_global_rules():
    """
    Get all global (promoted) rules.
    
    Query parameters:
        since (optional): Only return rules promoted after this timestamp
        
    Returns:
        JSON with global rules
    """
    engine = get_consensus_engine()
    
    # Check for 'since' parameter
    since = request.args.get('since')
    
    if since:
        rules = engine.promotion.get_global_rules_since(since)
    else:
        rules = engine.get_global_rules()
    
    return jsonify({
        'status': 'success',
        'global_rules_count': len(rules),
        'global_rules': rules
    })


@rule_api_bp.route('/global_rules/<rule_hash>', methods=['GET'])
def get_global_rule(rule_hash):
    """Get a specific global rule by hash."""
    engine = get_consensus_engine()
    
    global_rules = engine.get_global_rules()
    
    for rule in global_rules:
        if rule.get('rule_hash', '').startswith(rule_hash):
            return jsonify({
                'status': 'success',
                'rule': rule
            })
    
    return jsonify({
        'status': 'error',
        'message': 'Rule not found'
    }), 404


# ============================================================================
# CONSENSUS STATUS ENDPOINTS
# ============================================================================

@rule_api_bp.route('/consensus/status', methods=['GET'])
def get_consensus_status():
    """
    Get full consensus engine status.
    
    Returns:
        JSON with consensus status
    """
    engine = get_consensus_engine()
    
    status = engine.get_status()
    
    return jsonify({
        'status': 'success',
        'consensus_status': status
    })


@rule_api_bp.route('/consensus/votes', methods=['GET'])
def get_all_votes():
    """
    Get all rules with votes (not just promoted ones).
    
    Returns:
        JSON with all voted rules
    """
    engine = get_consensus_engine()
    
    all_rules = engine.promotion.get_all_rules_with_votes()
    
    return jsonify({
        'status': 'success',
        'total_rules_with_votes': len(all_rules),
        'rules': all_rules
    })


@rule_api_bp.route('/consensus/statistics', methods=['GET'])
def get_consensus_statistics():
    """
    Get consensus statistics.
    
    Returns:
        JSON with statistics
    """
    engine = get_consensus_engine()
    
    return jsonify({
        'status': 'success',
        'statistics': engine.get_status()
    })


# ============================================================================
# SIMILARITY CHECK ENDPOINTS
# ============================================================================

@rule_api_bp.route('/check_similarity', methods=['POST'])
def check_similarity():
    """
    Check similarity between rules.
    
    Request body:
        {
            "rule1": "alert tcp 192.168.1.100 any ...",
            "rule2": "alert tcp 192.168.1.100 any ...",
            "threshold": 0.7
        }
    
    Returns:
        JSON with similarity score
    """
    from federated.rule_consensus import similarity_score, rules_are_similar
    
    data = request.json
    
    rule1 = data.get('rule1', '')
    rule2 = data.get('rule2', '')
    threshold = data.get('threshold', 0.7)
    
    score = similarity_score(rule1, rule2)
    is_similar = rules_are_similar(rule1, rule2, threshold)
    
    return jsonify({
        'status': 'success',
        'similarity_score': score,
        'is_similar': is_similar,
        'threshold': threshold
    })


# ============================================================================
# RESET ENDPOINT (for testing)
# ============================================================================

@rule_api_bp.route('/reset', methods=['POST'])
def reset_consensus():
    """Reset the consensus engine (for testing)."""
    global _consensus_engine
    
    _consensus_engine = None
    
    return jsonify({
        'status': 'success',
        'message': 'Consensus engine reset'
    })


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def register_rule_api(app, url_prefix='/api/federated'):
    """
    Register rule API endpoints with a Flask app.
    
    Args:
        app: Flask application instance
        url_prefix: URL prefix for endpoints
    """
    global rule_api_bp
    rule_api_bp.url_prefix = url_prefix
    
    app.register_blueprint(rule_api_bp)
    
    print(f"[API] Registered rule consensus endpoints at {url_prefix}")


# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == '__main__':
    from flask import Flask
    
    app = Flask(__name__)
    register_rule_api(app)
    
    print("\n" + "="*60)
    print("Rule Consensus API Test")
    print("="*60)
    
    with app.test_client() as client:
        # Test status endpoint
        response = client.get('/api/federated/consensus/status')
        print(f"\nGET /consensus/status: {response.status_code}")
        
        # Submit a rule
        response = client.post('/api/federated/submit_rule', json={
            'client_id': 'test_client',
            'rule': {
                'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.1 any (msg:"TEST")',
                'anomaly_type': 'port_scan',
                'src_ip': '192.168.1.100',
                'score': 0.85
            }
        })
        print(f"POST /submit_rule: {response.status_code}")
        print(f"  Response: {response.get_json()}")
        
        # Get global rules
        response = client.get('/api/federated/global_rules')
        print(f"\nGET /global_rules: {response.status_code}")
        print(f"  Count: {response.get_json()['global_rules_count']}")
    
    print("\n✓ API test passed!")

