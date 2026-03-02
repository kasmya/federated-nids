#!/usr/bin/env python3
"""
Simple Federated Server with FedAvg Aggregation
"""

import numpy as np
from typing import List, Dict
from .consensus import RuleConsensusEngine


def fedavg_aggregate(params_list: List[List[np.ndarray]]) -> List[np.ndarray]:
    """Federated Averaging - combine client parameters"""
    if not params_list:
        return []
    if len(params_list) == 1:
        return params_list[0]
    
    n = len(params_list)
    result = []
    
    for i in range(len(params_list[0])):
        arrays = [p[i].astype(np.float32) for p in params_list]
        result.append(np.mean(arrays, axis=0))
    
    return result


class FederatedServer:
    """Simple federated server"""
    
    def __init__(self, num_rounds: int = 3):
        self.num_rounds = num_rounds
        self.current_round = 0
        self.consensus = RuleConsensusEngine(min_consensus=2)
        self.global_params = None
        
        print(f"[Server] Initialized for {num_rounds} rounds")
    
    def run_round(self, clients: List) -> Dict:
        """Run one federated round"""
        self.current_round += 1
        
        print(f"\n{'='*50}")
        print(f"FEDERATION ROUND {self.current_round}/{self.num_rounds}")
        print(f"{'='*50}")
        
        # Collect parameters from clients
        client_params = []
        client_results = []
        
        for client in clients:
            new_params, n_samples, metrics = client.fit(
                client.get_parameters() if self.current_round == 1 else self.global_params,
                {'round_number': self.current_round}
            )
            client_params.append(new_params)
            client_results.append({
                'cid': client.cid,
                'samples': n_samples,
                'metrics': metrics
            })
            
            # Submit rules to consensus
            for rule in client.get_local_rules():
                result = self.consensus.submit_rule(rule, client.cid)
                if result.get('consensus'):
                    print(f"★ CONSENSUS: {rule['rule_string'][:50]}...")
        
        # Aggregate parameters
        self.global_params = fedavg_aggregate(client_params)
        
        # Return round results
        return {
            'round': self.current_round,
            'clients': client_results,
            'global_rules': self.consensus.get_global_rules(),
            'consensus_stats': self.consensus.get_statistics()
        }
    
    def run_simulation(self, clients: List) -> Dict:
        """Run complete simulation"""
        all_results = []
        
        for _ in range(self.num_rounds):
            result = self.run_round(clients)
            all_results.append(result)
        
        return {
            'total_rounds': self.num_rounds,
            'rounds': all_results,
            'final_global_rules': self.consensus.get_global_rules()
        }
