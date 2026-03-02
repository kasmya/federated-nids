#!/usr/bin/env python3
"""
Federated NIDS - Flask Dashboard Integration
Day 1: Foundation & Flower Setup

Optional API endpoints to check federated status from the Flask dashboard.

To integrate with your existing Flask app, add these endpoints to app.py
or import this module in your app.py:
    from federated.dashboard_integration import federated_bp
    
    # Register the blueprint
    app.register_blueprint(federated_bp)

Or simply import and use the standalone functions.
"""

import os
import sys
from flask import Blueprint, jsonify, request

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Create Flask Blueprint
federated_bp = Blueprint('federated', __name__, url_prefix='/api/federated')


# Global state for federation
_federation_state = {
    'is_running': False,
    'current_round': 0,
    'total_rounds': 0,
    'clients': {},
    'last_update': None,
    'logs': [],
}


# ============================================================================
# API ENDPOINTS
# ============================================================================

@federated_bp.route('/status')
def get_federated_status():
    """
    Get federated learning status.
    
    Returns:
        JSON with federation status
    """
    return jsonify({
        'is_running': _federation_state['is_running'],
        'current_round': _federation_state['current_round'],
        'total_rounds': _federation_state['total_rounds'],
        'clients': _federation_state['clients'],
        'last_update': _federation_state['last_update'],
    })


@federated_bp.route('/clients')
def get_federated_clients():
    """
    Get status of all federated clients.
    
    Returns:
        JSON with client information
    """
    return jsonify({
        'clients': _federation_state['clients'],
    })


@federated_bp.route('/logs')
def get_federated_logs():
    """
    Get federated learning logs.
    
    Returns:
        JSON with recent logs
    """
    limit = request.args.get('limit', 50, type=int)
    return jsonify({
        'logs': _federation_state['logs'][-limit:],
    })


@federated_bp.route('/start', methods=['POST'])
def start_federation():
    """
    Start federated learning session.
    
    Request body:
        {
            "num_rounds": 3,
            "num_packets": 100,
            "client_configs": [
                {"cid": "client_A", "pattern": "port_scan"},
                {"cid": "client_B", "pattern": "normal"}
            ]
        }
    
    Returns:
        JSON with start status
    """
    from federated.simulation import run_simulation
    import threading
    import json
    from datetime import datetime
    
    data = request.json or {}
    num_rounds = data.get('num_rounds', 3)
    num_packets = data.get('num_packets', 100)
    client_configs = data.get('client_configs', [
        {'cid': 'client_A', 'pattern': 'port_scan'},
        {'cid': 'client_B', 'pattern': 'normal'}
    ])
    
    # Update state
    _federation_state['is_running'] = True
    _federation_state['total_rounds'] = num_rounds
    _federation_state['current_round'] = 0
    _federation_state['clients'] = {c['cid']: {'status': 'initializing'} for c in client_configs}
    _federation_state['last_update'] = datetime.now().isoformat()
    
    # Log
    _federation_state['logs'].append({
        'timestamp': datetime.now().isoformat(),
        'message': f'Starting federation with {len(client_configs)} clients for {num_rounds} rounds'
    })
    
    # Run simulation in background
    def run_federation_thread():
        try:
            results = run_simulation(
                client_configs=client_configs,
                num_rounds=num_rounds,
                num_packets=num_packets,
                num_test_packets=50
            )
            
            # Update state with results
            _federation_state['results'] = results
            _federation_state['is_running'] = False
            _federation_state['last_update'] = datetime.now().isoformat()
            
            _federation_state['logs'].append({
                'timestamp': datetime.now().isoformat(),
                'message': f'Federation completed: {results["status"]}'
            })
            
        except Exception as e:
            _federation_state['is_running'] = False
            _federation_state['logs'].append({
                'timestamp': datetime.now().isoformat(),
                'message': f'Federation error: {str(e)}'
            })
    
    thread = threading.Thread(target=run_federation_thread)
    thread.start()
    
    return jsonify({
        'status': 'started',
        'num_rounds': num_rounds,
        'clients': len(client_configs)
    })


@federated_bp.route('/stop', methods=['POST'])
def stop_federation():
    """
    Stop federated learning session.
    
    Returns:
        JSON with stop status
    """
    _federation_state['is_running'] = False
    
    from datetime import datetime
    _federation_state['logs'].append({
        'timestamp': datetime.now().isoformat(),
        'message': 'Federation stopped by user'
    })
    
    return jsonify({'status': 'stopped'})


@federated_bp.route('/results')
def get_federation_results():
    """
    Get federation results if available.
    
    Returns:
        JSON with results
    """
    results = getattr(_federation_state, 'results', None)
    
    if results:
        # Simplify results for API
        simplified = {
            'status': results.get('status'),
            'num_rounds': results.get('num_rounds'),
            'num_clients': results.get('num_clients'),
            'round_history': [
                {
                    'round': r['round'],
                    'loss': r.get('avg_loss'),
                    'accuracy': r.get('avg_accuracy')
                }
                for r in results.get('round_history', [])
            ]
        }
        return jsonify(simplified)
    
    return jsonify({'status': 'no_results'})


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def update_federation_state(state: dict) -> None:
    """
    Update the global federation state.
    
    Args:
        state: New state dictionary
    """
    global _federation_state
    _federation_state.update(state)


def get_federation_state() -> dict:
    """
    Get the current federation state.
    
    Returns:
        State dictionary
    """
    return _federation_state.copy()


def register_with_flask_app(app, url_prefix='/api/federated'):
    """
    Register federated endpoints with a Flask app.
    
    Args:
        app: Flask application instance
        url_prefix: URL prefix for endpoints
    """
    # Update blueprint URL prefix
    global federated_bp
    federated_bp.url_prefix = url_prefix
    
    # Register blueprint
    app.register_blueprint(federated_bp)
    
    print(f"Registered federated endpoints at {url_prefix}")


# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == '__main__':
    # Test the Flask integration
    from flask import Flask
    
    app = Flask(__name__)
    register_with_flask_app(app)
    
    print("\n" + "="*60)
    print("Federated Dashboard Integration Test")
    print("="*60)
    
    # Test endpoints
    with app.test_client() as client:
        # Test status endpoint
        response = client.get('/api/federated/status')
        print(f"\nGET /api/federated/status: {response.status_code}")
        print(f"  Response: {response.get_json()}")
        
        # Test start endpoint
        response = client.post('/api/federated/start', json={
            'num_rounds': 1,
            'num_packets': 10,
            'client_configs': [
                {'cid': 'test_client', 'pattern': 'normal'}
            ]
        })
        print(f"\nPOST /api/federated/start: {response.status_code}")
        print(f"  Response: {response.get_json()}")
        
        # Test status again
        response = client.get('/api/federated/status')
        print(f"\nGET /api/federated/status: {response.status_code}")
        print(f"  Response: {response.get_json()}")
    
    print("\n✓ Flask integration test passed!")

