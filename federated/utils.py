#!/usr/bin/env python3
"""
Federated NIDS - Utility Functions
Parameter serialization and FedAvg aggregation helpers
"""

import numpy as np
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)


# ============================================================================
# PARAMETER SERIALIZATION
# ============================================================================

def serialize_parameters(params: Dict[str, Any]) -> List[np.ndarray]:
    """
    Serialize NIDS parameters to NumPy arrays for Flower.
    
    Extracts key parameters from the NIDS:
    - Detection threshold
    - Baseline means and stds for: packet_rate, port_diversity, connection_rate
    
    Args:
        params: Dictionary with NIDS parameters
        
    Returns:
        List of NumPy arrays ready for federation
    """
    arrays = []
    
    # 1. Detection threshold (scalar as 1D array)
    threshold = params.get('detection_threshold', 0.5)
    arrays.append(np.array([threshold], dtype=np.float32))
    
    # 2. Baseline means for key features
    baseline_stats = params.get('baseline_stats', {})
    
    # Packet rate baseline
    pr_mean = baseline_stats.get('packet_rate', {}).get('value', 5.0)
    pr_std = baseline_stats.get('packet_rate', {}).get('std', 3.0)
    arrays.append(np.array([pr_mean, pr_std], dtype=np.float32))
    
    # Port diversity baseline
    pd_mean = baseline_stats.get('port_diversity', {}).get('value', 3.0)
    pd_std = baseline_stats.get('port_diversity', {}).get('std', 2.0)
    arrays.append(np.array([pd_mean, pd_std], dtype=np.float32))
    
    # Connection rate baseline
    cr_mean = baseline_stats.get('connection_rate', {}).get('value', 2.0)
    cr_std = baseline_stats.get('connection_rate', {}).get('std', 2.0)
    arrays.append(np.array([cr_mean, cr_std], dtype=np.float32))
    
    # Bytes per second baseline
    bps_mean = baseline_stats.get('bytes_per_second', {}).get('value', 1000.0)
    bps_std = baseline_stats.get('bytes_per_second', {}).get('std', 500.0)
    arrays.append(np.array([bps_mean, bps_std], dtype=np.float32))
    
    # DNS query rate baseline
    dns_mean = baseline_stats.get('dns_query_rate', {}).get('value', 0.5)
    dns_std = baseline_stats.get('dns_query_rate', {}).get('std', 0.5)
    arrays.append(np.array([dns_mean, dns_std], dtype=np.float32))
    
    # ICMP count baseline
    icmp_mean = baseline_stats.get('icmp_count', {}).get('value', 1.0)
    icmp_std = baseline_stats.get('icmp_count', {}).get('std', 1.0)
    arrays.append(np.array([icmp_mean, icmp_std], dtype=np.float32))
    
    # 3. Adaptation rate
    adaptation_rate = params.get('adaptation_rate', 0.1)
    arrays.append(np.array([adaptation_rate], dtype=np.float32))
    
    logger.debug(f"Serialized {len(arrays)} parameter arrays")
    return arrays


def deserialize_parameters(arrays: List[np.ndarray]) -> Dict[str, Any]:
    """
    Deserialize NumPy arrays back to NIDS parameters.
    
    Args:
        arrays: List of NumPy arrays from federation
        
    Returns:
        Dictionary with NIDS parameters
    """
    if len(arrays) < 8:
        raise ValueError(f"Expected at least 8 arrays, got {len(arrays)}")
    
    params = {
        # Detection threshold
        'detection_threshold': float(arrays[0][0]),
        
        # Baseline statistics
        'baseline_stats': {
            'packet_rate': {'value': float(arrays[1][0]), 'std': float(arrays[1][1])},
            'port_diversity': {'value': float(arrays[2][0]), 'std': float(arrays[2][1])},
            'connection_rate': {'value': float(arrays[3][0]), 'std': float(arrays[3][1])},
            'bytes_per_second': {'value': float(arrays[4][0]), 'std': float(arrays[4][1])},
            'dns_query_rate': {'value': float(arrays[5][0]), 'std': float(arrays[5][1])},
            'icmp_count': {'value': float(arrays[6][0]), 'std': float(arrays[6][1])},
        },
        
        # Adaptation rate
        'adaptation_rate': float(arrays[7][0]),
    }
    
    logger.debug(f"Deserialized parameters from {len(arrays)} arrays")
    return params


def get_parameters_as_ndarrays(client) -> List[np.ndarray]:
    """
    Get parameters from a FederatedClient as NumPy arrays.
    
    Args:
        client: Federated client instance
        
    Returns:
        List of NumPy arrays
    """
    return client.get_parameters()


def set_parameters_from_ndarrays(client, parameters: List[np.ndarray]) -> None:
    """
    Set parameters on a FederatedClient from NumPy arrays.
    
    Args:
        client: Federated client instance
        parameters: List of NumPy arrays
    """
    client.set_parameters(parameters)


# ============================================================================
# FEDAVG AGGREGATION
# ============================================================================

def aggregate_parameters_fedavg(
    parameters: List[List[np.ndarray]], 
    weights: List[float] = None
) -> List[np.ndarray]:
    """
    Aggregate parameters using Federated Averaging (FedAvg).
    
    Args:
        parameters: List of parameter lists from clients
        weights: Optional weights for each client's parameters (default: equal weights)
        
    Returns:
        Aggregated parameters as list of NumPy arrays
    """
    if not parameters:
        raise ValueError("No parameters to aggregate")
    
    # Handle single client case
    if len(parameters) == 1:
        logger.info("Single client - no aggregation needed")
        return parameters[0]
    
    # Default: equal weights
    if weights is None:
        weights = [1.0 / len(parameters)] * len(parameters)
    
    # Normalize weights
    total_weight = sum(weights)
    weights = [w / total_weight for w in weights]
    
    logger.info(f"Aggregating {len(parameters)} clients with weights: {[f'{w:.3f}' for w in weights]}")
    
    # Aggregate each parameter array
    aggregated = []
    num_params = len(parameters[0])
    
    for param_idx in range(num_params):
        # Get this parameter from all clients
        param_arrays = [params[param_idx] for params in parameters]
        
        # Weighted average
        agg_array = np.zeros_like(param_arrays[0], dtype=np.float32)
        for param_array, weight in zip(param_arrays, weights):
            agg_array += weight * param_array.astype(np.float32)
        
        aggregated.append(agg_array)
        
        logger.debug(f"  Parameter {param_idx}: shape={agg_array.shape}, "
                    f"mean={agg_array.mean():.4f}, std={agg_array.std():.4f}")
    
    logger.info("FedAvg aggregation complete")
    return aggregated


def compute_parameter_diff(
    original: List[np.ndarray], 
    updated: List[np.ndarray]
) -> List[np.ndarray]:
    """
    Compute difference between two parameter sets.
    
    Args:
        original: Original parameters
        updated: Updated parameters
        
    Returns:
        List of difference arrays
    """
    diffs = []
    for orig, upd in zip(original, updated):
        diffs.append(upd - orig)
    return diffs


def compute_parameter_norm(parameters: List[np.ndarray]) -> float:
    """
    Compute L2 norm of all parameters.
    
    Args:
        parameters: List of parameter arrays
        
    Returns:
        L2 norm value
    """
    total_norm = 0.0
    for arr in parameters:
        total_norm += np.sum(arr ** 2)
    return np.sqrt(total_norm)


# ============================================================================
# RULE SERIALIZATION (for sharing rules between clients)
# ============================================================================

def serialize_rules(rules: List[Dict]) -> bytes:
    """
    Serialize rules for transmission.
    
    Args:
        rules: List of rule dictionaries
        
    Returns:
        Serialized bytes
    """
    import json
    return json.dumps(rules).encode('utf-8')


def deserialize_rules(data: bytes) -> List[Dict]:
    """
    Deserialize rules from bytes.
    
    Args:
        data: Serialized rules
        
    Returns:
        List of rule dictionaries
    """
    import json
    return json.loads(data.decode('utf-8'))


# ============================================================================
# STATUS AND LOGGING HELPERS
# ============================================================================

def log_parameters(prefix: str, parameters: List[np.ndarray]) -> None:
    """
    Log parameter statistics for debugging.
    
    Args:
        prefix: Log prefix
        parameters: List of parameter arrays
    """
    logger.info(f"{prefix} - {len(parameters)} parameter arrays:")
    for i, arr in enumerate(parameters):
        logger.info(f"  Array {i}: shape={arr.shape}, "
                   f"dtype={arr.dtype}, min={arr.min():.4f}, "
                   f"max={arr.max():.4f}, mean={arr.mean():.4f}")


def get_client_status(client) -> Dict[str, Any]:
    """
    Get status information from a federated client.
    
    Args:
        client: Federated client instance
        
    Returns:
        Status dictionary
    """
    status = {
        'cid': getattr(client, 'cid', 'unknown'),
        'has_nids': client.nids is not None,
    }
    
    if client.nids:
        try:
            status['nids_status'] = client.nids.get_status()
        except:
            status['nids_status'] = 'error'
    
    return status

