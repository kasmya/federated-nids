#!/usr/bin/env python3
"""
Federated NIDS Package - Day 1: Foundation & Flower Setup
Federated Learning extension for Network Intrusion Detection System

This package provides:
- FederatedClient: Wrapper for NIDS to participate in federated learning
- FederatedServer: Server with FedAvg aggregation
- Simulation tools for testing federated NIDS
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import main components
from .client import MinimalFederatedClient, FederatedNIDSClient
from .server import FederatedServer, create_federated_server
from .simulation import PacketSimulator, ClientSimulator, run_simulation
from .utils import (
    serialize_parameters,
    deserialize_parameters,
    get_parameters_as_ndarrays,
    set_parameters_from_ndarrays,
   aggregate_parameters_fedavg
)

__version__ = "1.0.0"
__all__ = [
    # Client
    'MinimalFederatedClient',
    'FederatedNIDSClient',
    
    # Server
    'FederatedServer',
    'create_federated_server',
    
    # Simulation
    'PacketSimulator',
    'ClientSimulator',
    'run_simulation',
    
    # Utils
    'serialize_parameters',
    'deserialize_parameters',
    'get_parameters_as_ndarrays',
    'set_parameters_from_ndarrays',
    'aggregate_parameters_fedavg',
]

