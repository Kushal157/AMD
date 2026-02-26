"""
Aegis-Prime Core Architecture
Sovereign Intelligence Mesh for Digital Autonomy and Post-Quantum Security

This module defines the abstract interfaces and base classes for all four core pillars:
- Lumina Auth (Identity via ZK-SNARKs)
- Synapse Kernel (Execution via WASM Sandbox)
- Cypher Shield (Security via PQC)
- Zenith Mesh (Ledger via Substrate)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import Enum


# ============================================================================
# LUMINA AUTH - Zero-Knowledge Proof Identity Layer
# ============================================================================

@dataclass
class ZKProof:
    """Represents a zero-knowledge proof"""
    proof: bytes
    public_inputs: List[int]
    circuit_hash: str
    timestamp: int


@dataclass
class ZKCircuit:
    """Represents a compiled ZK circuit"""
    circuit_id: str
    circuit_bytes: bytes
    proving_key: bytes
    verification_key: bytes


class LuminaAuthInterface(ABC):
    """
    Abstract interface for Zero-Knowledge Proof based identity.
    Implements ZK-SNARKs via pyzokrates.
    """

    @abstractmethod
    async def setup_circuit(self, circuit_path: str) -> ZKCircuit:
        """
        Setup and compile a ZK circuit from source.

        Args:
            circuit_path: Path to ZK circuit file (.zok)

        Returns:
            Compiled ZKCircuit with keys
        """
        pass

    @abstractmethod
    async def generate_proof(
        self,
        circuit: ZKCircuit,
        witness: Dict[str, int],
        private_inputs: Optional[List[int]] = None
    ) -> ZKProof:
        """
        Generate a zero-knowledge proof.

        Args:
            circuit: Compiled ZK circuit
            witness: Witness mapping (public + private)
            private_inputs: Optional private knowledge

        Returns:
            ZK proof with public inputs
        """
        pass

    @abstractmethod
    async def verify_proof(self, proof: ZKProof) -> bool:
        """
        Verify a zero-knowledge proof.

        Args:
            proof: ZK proof to verify

        Returns:
            True if proof is valid
        """
        pass

    @abstractmethod
    async def commit(self, value: bytes) -> str:
        """
        Create a cryptographic commitment to a value.

        Args:
            value: Data to commit

        Returns:
            Commitment digest (hex string)
        """
        pass

    @abstractmethod
    async def open_commitment(self, value: bytes, commitment: str) -> bool:
        """
        Verify opening of a commitment.

        Args:
            value: Original value
            commitment: Commitment digest

        Returns:
            True if commitment matches
        """
        pass


# ============================================================================
# SYNAPSE KERNEL - WebAssembly Sandbox Execution
# ============================================================================

class ExecutionError(Exception):
    """Raised when WASM execution fails"""
    pass


class ResourceExceeded(ExecutionError):
    """Raised when resource limits are exceeded"""
    pass


@dataclass
class WasmModule:
    """WASM module metadata and binary"""
    module_id: str
    wasm_binary: bytes
    exports: Dict[str, str]
    memory_pages: int


@dataclass
class ExecutionResult:
    """Result of WASM function execution"""
    return_value: Optional[Any]
    memory_state: bytes
    execution_time_ms: float
    gas_consumed: int


@dataclass
class SandboxConfig:
    """Sandbox resource constraints"""
    max_memory_mb: int = 512
    max_cpu_time_ms: int = 5000
    max_call_depth: int = 1024
    gas_limit: int = 1_000_000


class SynapseKernelInterface(ABC):
    """
    Abstract interface for WebAssembly sandbox execution.
    Implements WASM isolation via wasmtime-py.
    """

    @abstractmethod
    async def load_module(self, wasm_binary: bytes) -> WasmModule:
        """
        Load and validate a WASM module.

        Args:
            wasm_binary: Raw WASM binary data

        Returns:
            WasmModule with introspection metadata

        Raises:
            ExecutionError: If WASM is invalid
        """
        pass

    @abstractmethod
    async def create_sandbox(
        self,
        module: WasmModule,
        config: Optional[SandboxConfig] = None
    ) -> str:
        """
        Create an isolated sandbox instance for a module.

        Args:
            module: WASM module to sandbox
            config: Execution constraints

        Returns:
            Sandbox ID (opaque handle)
        """
        pass

    @abstractmethod
    async def execute(
        self,
        sandbox_id: str,
        function: str,
        args: List[Union[int, float, str]] = None
    ) -> ExecutionResult:
        """
        Execute a function in sandboxed WASM.

        Args:
            sandbox_id: Sandbox identifier
            function: Function name to call
            args: Function arguments

        Returns:
            ExecutionResult with return value and metrics

        Raises:
            ExecutionError: On execution failure
            ResourceExceeded: If limits exceeded
        """
        pass

    @abstractmethod
    async def memory_read(self, sandbox_id: str, offset: int, length: int) -> bytes:
        """
        Read sandbox linear memory.

        Args:
            sandbox_id: Sandbox identifier
            offset: Memory offset
            length: Bytes to read

        Returns:
            Memory bytes
        """
        pass

    @abstractmethod
    async def cleanup_sandbox(self, sandbox_id: str) -> None:
        """
        Destroy sandbox and free resources.

        Args:
            sandbox_id: Sandbox to cleanup
        """
        pass


# ============================================================================
# CYPHER SHIELD - Post-Quantum Cryptography
# ============================================================================

class PQCAlgorithm(Enum):
    """Supported post-quantum cryptographic algorithms"""
    KYBER_512 = "kyber512"
    KYBER_768 = "kyber768"
    KYBER_1024 = "kyber1024"


@dataclass
class PQCKeyPair:
    """Post-quantum cryptography key pair"""
    public_key: bytes
    secret_key: bytes
    algorithm: PQCAlgorithm


@dataclass
class PQCCiphertext:
    """Encrypted data using PQC"""
    ciphertext: bytes
    algorithm: PQCAlgorithm
    key_id: Optional[str] = None


class CypherShieldInterface(ABC):
    """
    Abstract interface for Post-Quantum Cryptography.
    Implements PQC via liboqs-python (Kyber-512 default).
    """

    @abstractmethod
    async def generate_keypair(
        self,
        algorithm: PQCAlgorithm = PQCAlgorithm.KYBER_512
    ) -> PQCKeyPair:
        """
        Generate a post-quantum cryptography key pair.

        Args:
            algorithm: PQC algorithm to use

        Returns:
            PQCKeyPair with public and secret keys
        """
        pass

    @abstractmethod
    async def encrypt(
        self,
        plaintext: bytes,
        public_key: bytes
    ) -> PQCCiphertext:
        """
        Encrypt data using PQC public key.

        Args:
            plaintext: Data to encrypt
            public_key: Recipient's public key

        Returns:
            PQCCiphertext
        """
        pass

    @abstractmethod
    async def decrypt(
        self,
        ciphertext_obj: PQCCiphertext,
        secret_key: bytes
    ) -> bytes:
        """
        Decrypt PQC-encrypted data.

        Args:
            ciphertext_obj: Encrypted data object
            secret_key: Recipient's secret key

        Returns:
            Decrypted plaintext
        """
        pass

    @abstractmethod
    async def aggregate_keys(
        self,
        public_keys: List[bytes]
    ) -> bytes:
        """
        Aggregate multiple PQC public keys.

        Args:
            public_keys: List of public keys

        Returns:
            Aggregated key
        """
        pass

    @abstractmethod
    async def get_algorithm(self) -> PQCAlgorithm:
        """
        Get the active PQC algorithm.

        Returns:
            Current PQCAlgorithm
        """
        pass


# ============================================================================
# ZENITH MESH - Substrate Blockchain Ledger
# ============================================================================

@dataclass
class Transaction:
    """Blockchain transaction"""
    sender: str
    receiver: str
    amount: int
    nonce: int
    signature: bytes
    timestamp: int
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class Block:
    """Blockchain block"""
    block_hash: str
    parent_hash: str
    block_number: int
    transactions: List[Transaction]
    state_root: str
    timestamp: int


@dataclass
class ChainState:
    """Current blockchain state"""
    latest_block: Block
    chain_height: int
    total_accounts: int
    latest_finalized_block: str


class ZenithMeshInterface(ABC):
    """
    Abstract interface for Substrate blockchain ledger integration.
    Implements blockchain via pysubstrate-interface.
    """

    @abstractmethod
    async def connect(self, endpoint: str) -> bool:
        """
        Connect to a Substrate node.

        Args:
            endpoint: WebSocket endpoint (ws://localhost:9944)

        Returns:
            True if connection successful
        """
        pass

    @abstractmethod
    async def submit_transaction(self, transaction: Transaction) -> str:
        """
        Submit a transaction to the blockchain.

        Args:
            transaction: Transaction to submit

        Returns:
            Transaction hash (hex string)
        """
        pass

    @abstractmethod
    async def query_transaction(self, tx_hash: str) -> Optional[Transaction]:
        """
        Query transaction details by hash.

        Args:
            tx_hash: Transaction hash

        Returns:
            Transaction object or None if not found
        """
        pass

    @abstractmethod
    async def query_account(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Query account state on the blockchain.

        Args:
            address: Account address

        Returns:
            Account state dict or None
        """
        pass

    @abstractmethod
    async def get_chain_state(self) -> ChainState:
        """
        Get current blockchain state.

        Returns:
            ChainState with finalization info
        """
        pass

    @abstractmethod
    async def validate_chain(self) -> bool:
        """
        Validate blockchain integrity.

        Returns:
            True if chain is valid
        """
        pass

    @abstractmethod
    async def listen_blocks(self) -> None:
        """
        Listen for new blocks (streaming).
        Yields new Block objects as they arrive.
        """
        pass


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Lumina Auth
    "LuminaAuthInterface",
    "ZKProof",
    "ZKCircuit",
    # Synapse Kernel
    "SynapseKernelInterface",
    "WasmModule",
    "ExecutionResult",
    "SandboxConfig",
    "ExecutionError",
    "ResourceExceeded",
    # Cypher Shield
    "CypherShieldInterface",
    "PQCKeyPair",
    "PQCCiphertext",
    "PQCAlgorithm",
    # Zenith Mesh
    "ZenithMeshInterface",
    "Transaction",
    "Block",
    "ChainState",
    # Zenith Mesh Data Classes (exported from zenith_mesh.py)
    "SealedIntent",
    "DeferredAction",
    "SyncStatus",
]

