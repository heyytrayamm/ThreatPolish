"""
Simulated Decoy Sensors for ThreatPolish.

Modules:
  • SSHDecoySimulator: In-process simulated SSH login interaction.
  • RESTDecoySimulator: In-process simulated HTTP /admin, /.env trap endpoints.
  • DatabaseDecoySimulator: In-process simulated PostgreSQL / database interactions.
"""

from app.decoys.base import BaseDecoySimulator, DecoyInteractionResult
from app.decoys.database import DatabaseDecoySimulator
from app.decoys.rest import RESTDecoySimulator
from app.decoys.ssh import SSHDecoySimulator

__all__ = [
    "BaseDecoySimulator",
    "DatabaseDecoySimulator",
    "DecoyInteractionResult",
    "RESTDecoySimulator",
    "SSHDecoySimulator",
]
