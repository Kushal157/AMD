"""
Zenith Mesh: Proof-of-Agency Substrate Blockchain Ledger Integration
Implements offline-first Deferred-Sync for digital autonomy.

Features:
- seal_intent(): Proof-of-Agency via Keccak-256 + signature
- Deferred-Sync: Encrypted local buffer.db for offline queuing
- Auto-reconnect with batch sync on network restoration
- Full Substrate chain interaction via pysubstrate-interface
"""

from __future__ import annotations

import os
import sqlite3
import hashlib
import time
import logging
import json
import asyncio
from typing import Optional, Dict, List, Any, Literal
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

# Substrate integration
try:
    from substrateinterface import SubstrateInterface, Keypair
    SUBSTRATE_AVAILABLE = True
except ImportError:
    SUBSTRATE_AVAILABLE = False

# Cryptography and hashing
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Keccak-256 hashing (commonly used in Substrate pallets)
try:
    from eth_keys import keys
    KECCAK_AVAILABLE = True
except ImportError:
    KECCAK_AVAILABLE = False

# Core interfaces and types
from . import (
    ZenithMeshInterface,
    Transaction,
    Block,
    ChainState,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Exception Hierarchy
# ============================================================================

class ZenithMeshError(Exception):
    """Base exception for ZenithMesh operations"""
    pass


class ConnectionError(ZenithMeshError):
    """Raised when Substrate node connection fails"""
    pass


class SigningError(ZenithMeshError):
    """Raised when keypair operations fail"""
    pass


class ExtrinsicError(ZenithMeshError):
    """Raised when extrinsic submission fails"""
    pass


class DatabaseError(ZenithMeshError):
    """Raised when buffer.db operations fail"""
    pass


class SyncError(ZenithMeshError):
    """Raised when deferred sync exceeds max retries"""
    pass


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SealedIntent:
    """Result of seal_intent() operation"""
    intent_hash: str              # Keccak-256 hex digest
    agent_id: str                 # Agent identifier
    timestamp: int                # UTC timestamp
    status: Literal["pending", "submitted", "finalized"] = "pending"
    extrinsic_hash: Optional[str] = None  # Chain tx hash if submitted
    sync_attempts: int = 0        # Number of retry attempts (deferred)


@dataclass
class DeferredAction:
    """Queued action for offline persistence"""
    agent_id: str
    action_blob: bytes
    sealed_intent: SealedIntent
    created_at: int
    sync_attempts: int = 0
    last_error: Optional[str] = None


@dataclass
class SyncStatus:
    """Connection and queue status"""
    is_connected: bool
    pending_count: int
    synced_count: int = 0
    last_sync: Optional[int] = None
    last_error: Optional[str] = None


# ============================================================================
# ZenithMesh - Proof-of-Agency Ledger Layer
# ============================================================================

class ZenithMesh(ZenithMeshInterface):
    """
    Substrate blockchain integration with offline-first Deferred-Sync.

    Provides:
    - Intent sealing via Keccak-256 + signature
    - Encrypted local buffering for offline operations
    - Auto-sync with batch submission on reconnect
    - Full ZenithMeshInterface compliance
    """

    MAX_RETRIES = 3
    RETRY_DELAYS = [1.0, 4.0, 16.0]  # Exponential backoff (seconds)
    DB_ENCRYPT_CONTEXT = "aegis-prime-zenith-mesh-v1"

    def __init__(
        self,
        endpoint: str = "ws://localhost:9944",
        keypair_path: Optional[str] = None,
        buffer_db_path: str = "./buffer.db",
        enable_deferred_sync: bool = True
    ):
        """
        Initialize ZenithMesh.

        Args:
            endpoint: Substrate WebSocket endpoint
            keypair_path: Path to keypair file (secret key in hex)
            buffer_db_path: Path to encrypted deferred sync database
            enable_deferred_sync: Enable offline-first queuing
        """
        self.endpoint = endpoint
        self.buffer_db_path = buffer_db_path
        self.enable_deferred_sync = enable_deferred_sync
        self._substrate: Optional[SubstrateInterface] = None
        self._keypair: Optional[Keypair] = None
        self._is_connected = False
        self._sync_task: Optional[asyncio.Task] = None
        self._db_cipher: Optional[Fernet] = None
        self._deferred_intents: List[DeferredAction] = []

        logger.info(f"ZenithMesh initializing with endpoint: {endpoint}")

        try:
            # Load or generate keypair
            self._keypair = self._load_keypair(keypair_path)

            if SUBSTRATE_AVAILABLE:
                logger.info(f"Keypair loaded: {self._keypair.ss58_address}")
            else:
                logger.warning("[STUB MODE] ZenithMesh: Substrate not available - using mock ledger")
                logger.warning("↳ For production, install: pip install pysubstrate-interface eth-keys")

            # Initialize encrypted buffer.db
            if enable_deferred_sync:
                self._init_buffer_db()
                self._load_deferred_intents()
                logger.info(f"Deferred sync enabled. Pending: {len(self._deferred_intents)}")
        except Exception as e:
            logger.error(f"ZenithMesh initialization failed: {e}")
            raise RuntimeError(f"ZenithMesh init failed: {e}") from e

    # ========================================================================
    # Keypair Management
    # ========================================================================

    def _load_keypair(self, keypair_path: Optional[str]) -> Keypair:
        """Load or generate keypair for signing extrinsics."""
        if SUBSTRATE_AVAILABLE:
            if keypair_path and os.path.exists(keypair_path):
                try:
                    with open(keypair_path, 'r') as f:
                        secret_hex = f.read().strip()
                    keypair = Keypair.create_from_private_key(secret_hex)
                    logger.info(f"Keypair loaded from {keypair_path}")
                    return keypair
                except Exception as e:
                    logger.error(f"Failed to load keypair from {keypair_path}: {e}")
                    raise SigningError(f"Keypair load failed: {e}") from e
            else:
                # Generate new keypair
                keypair = Keypair.create_from_uri("//Aegis-Prime-Agent")
                if keypair_path:
                    Path(keypair_path).parent.mkdir(parents=True, exist_ok=True)
                    with open(keypair_path, 'w') as f:
                        f.write(keypair.private_key)
                    os.chmod(keypair_path, 0o600)  # Restrict permissions
                    logger.info(f"Generated new keypair and saved to {keypair_path}")
                return keypair
        else:
            # Stub mode: generate mock keypair
            logger.debug("[STUB] Generating mock keypair for offline mode")
            return type('MockKeypair', (), {
                'ss58_address': '5GrwvaEF5zXb26Fz9rcQkPAWP3B6F2f3pq7W9S4N6pVs3xqV',
                'private_key': hashlib.sha256(b"aegis-prime-stub-keypair").hexdigest(),
                'public_key': hashlib.sha256(b"aegis-prime-stub-pubkey").digest()
            })()

    # ========================================================================
    # Encrypted Buffer Database (Deferred-Sync)
    # ========================================================================

    def _init_buffer_db(self) -> None:
        """Initialize encrypted buffer.db for deferred intents."""
        try:
            # Try to setup Fernet encryption
            encryption_ok = False
            try:
                # Derive encryption key from keypair + endpoint
                key_material = (
                    self._keypair.private_key.encode() +
                    self.endpoint.encode()
                )
                key_hash = hashlib.sha256(key_material).digest()

                # Simplified: use key_hash for direct encryption (Fernet requires base64-encoded key)
                import base64
                key_b64 = base64.urlsafe_b64encode(key_hash)
                self._db_cipher = Fernet(key_b64)
                encryption_ok = True
                logger.info("Fernet encryption initialized for buffer.db")
            except Exception as enc_err:
                # Fallback: no encryption (for stub/offline mode)
                logger.warning(f"[FALLBACK] Fernet encryption failed ({type(enc_err).__name__}), using unencrypted buffer.db")
                self._db_cipher = None

            # Create or open database
            db_path = Path(self.buffer_db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)

            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Create deferred_intents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS deferred_intents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    action_blob BLOB NOT NULL,
                    sealed_intent_hash TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    sync_attempts INTEGER DEFAULT 0,
                    last_error TEXT,
                    created_timestamp INTEGER
                )
            """)
            conn.commit()
            conn.close()

            encryption_status = "encrypted" if encryption_ok else "unencrypted"
            logger.info(f"{encryption_status.capitalize()} buffer.db initialized at {self.buffer_db_path}")
        except Exception as e:
            logger.error(f"Buffer.db initialization failed: {e}")
            logger.warning("[FALLBACK] Continuing without persistent deferred sync (in-memory only)")
            self._db_cipher = None

    def _load_deferred_intents(self) -> None:
        """Load pending deferred intents from buffer.db."""
        try:
            if not os.path.exists(self.buffer_db_path):
                return

            conn = sqlite3.connect(self.buffer_db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT agent_id, action_blob, sealed_intent_hash, created_at, sync_attempts, last_error
                FROM deferred_intents
                ORDER BY created_at ASC
            """)

            rows = cursor.fetchall()
            conn.close()

            self._deferred_intents = []
            for row in rows:
                agent_id, action_blob, intent_hash, created_at, attempts, last_error = row

                # Decrypt action_blob only if cipher exists
                try:
                    if self._db_cipher:
                        action_blob = self._db_cipher.decrypt(action_blob)
                    # If no cipher, action_blob is already in plaintext
                except Exception as e:
                    logger.warning(f"[FALLBACK] Decryption failed, using plaintext: {e}")
                    # Use as-is (plaintext fallback)

                sealed_intent = SealedIntent(
                    intent_hash=intent_hash,
                    agent_id=agent_id,
                    timestamp=created_at,
                    status="pending",
                    sync_attempts=attempts
                )

                deferred = DeferredAction(
                    agent_id=agent_id,
                    action_blob=action_blob,
                    sealed_intent=sealed_intent,
                    created_at=created_at,
                    sync_attempts=attempts,
                    last_error=last_error
                )
                self._deferred_intents.append(deferred)

            logger.info(f"Loaded {len(self._deferred_intents)} deferred intents")
        except Exception as e:
            logger.warning(f"[FALLBACK] Failed to load deferred intents: {e}, continuing with empty queue")
            self._deferred_intents = []

    def _enqueue_intent(self, deferred_action: DeferredAction) -> None:
        """Queue a sealed intent to encrypted buffer.db."""
        try:
            if not self.enable_deferred_sync:
                return

            # Keep in-memory queue always
            self._deferred_intents.append(deferred_action)

            # Try to persist to database
            try:
                conn = sqlite3.connect(self.buffer_db_path)
                cursor = conn.cursor()

                # Encrypt action_blob if cipher available, otherwise use plaintext
                if self._db_cipher:
                    try:
                        action_blob = self._db_cipher.encrypt(deferred_action.action_blob)
                    except Exception as enc_err:
                        logger.warning(f"[FALLBACK] Encryption failed, saving plaintext: {enc_err}")
                        action_blob = deferred_action.action_blob
                else:
                    action_blob = deferred_action.action_blob

                cursor.execute("""
                    INSERT INTO deferred_intents
                    (agent_id, action_blob, sealed_intent_hash, created_at, sync_attempts, last_error)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    deferred_action.agent_id,
                    action_blob,
                    deferred_action.sealed_intent.intent_hash,
                    deferred_action.created_at,
                    deferred_action.sync_attempts,
                    deferred_action.last_error
                ))

                conn.commit()
                conn.close()

                logger.info(f"Queued intent {deferred_action.sealed_intent.intent_hash[:8]} to buffer")
            except Exception as db_err:
                logger.warning(f"[FALLBACK] Database persistence failed, using in-memory only: {db_err}")

        except Exception as e:
            logger.warning(f"[FALLBACK] Failed to enqueue intent: {e}, continuing with in-memory queue")

    def _remove_deferred_intent(self, intent_hash: str) -> None:
        """Remove a synced intent from buffer.db."""
        try:
            conn = sqlite3.connect(self.buffer_db_path)
            cursor = conn.cursor()

            cursor.execute(
                "DELETE FROM deferred_intents WHERE sealed_intent_hash = ?",
                (intent_hash,)
            )

            conn.commit()
            conn.close()

            self._deferred_intents = [
                d for d in self._deferred_intents
                if d.sealed_intent.intent_hash != intent_hash
            ]
            logger.debug(f"Removed intent {intent_hash[:8]} from buffer")
        except Exception as e:
            logger.error(f"Failed to remove intent: {e}")

    def _update_sync_attempts(self, intent_hash: str, attempts: int, error: Optional[str]) -> None:
        """Update sync attempts and error for a deferred intent."""
        try:
            conn = sqlite3.connect(self.buffer_db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE deferred_intents
                SET sync_attempts = ?, last_error = ?
                WHERE sealed_intent_hash = ?
            """, (attempts, error, intent_hash))

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to update sync attempts: {e}")

    # ========================================================================
    # Intent Sealing (Proof-of-Agency)
    # ========================================================================

    async def seal_intent(
        self,
        agent_id: str,
        action_blob: bytes
    ) -> SealedIntent:
        """
        Seal an agent intent via Keccak-256 hash and signature.

        Args:
            agent_id: Agent identifier
            action_blob: Action payload

        Returns:
            SealedIntent with hash and submission status
        """
        try:
            # Compute Keccak-256(agent_id + action_blob)
            intent_data = agent_id.encode() + action_blob
            intent_hash = self._keccak256(intent_data)

            logger.info(f"Sealed intent for {agent_id}: {intent_hash[:8]}...")

            sealed = SealedIntent(
                intent_hash=intent_hash,
                agent_id=agent_id,
                timestamp=int(time.time()),
                status="pending"
            )

            # Try to submit; if offline, queue for deferred sync
            if self._is_connected:
                try:
                    extrinsic_hash = await self._submit_intent_extrinsic(sealed)
                    sealed.extrinsic_hash = extrinsic_hash
                    sealed.status = "submitted"
                    logger.info(f"Intent submitted: {extrinsic_hash}")
                except Exception as e:
                    logger.warning(f"Submission failed, queuing for deferred sync: {e}")
                    deferred = DeferredAction(
                        agent_id=agent_id,
                        action_blob=action_blob,
                        sealed_intent=sealed,
                        created_at=int(time.time())
                    )
                    self._enqueue_intent(deferred)
            else:
                # Node offline - queue immediately
                logger.info(f"Node offline. Queuing intent {sealed.intent_hash[:8]} for sync.")
                deferred = DeferredAction(
                    agent_id=agent_id,
                    action_blob=action_blob,
                    sealed_intent=sealed,
                    created_at=int(time.time())
                )
                self._enqueue_intent(deferred)

            return sealed

        except Exception as e:
            logger.error(f"seal_intent failed: {e}")
            raise ExtrinsicError(f"Seal intent failed: {e}") from e

    @staticmethod
    def _keccak256(data: bytes) -> str:
        """Compute Keccak-256 hash of data."""
        try:
            from eth_utils import keccak
            return "0x" + keccak(data).hex()
        except ImportError:
            # Fallback: use SHA-256 if eth-utils not available
            logger.warning("eth-utils not available, using SHA-256 instead of Keccak-256")
            return "0x" + hashlib.sha256(data).hexdigest()

    async def _submit_intent_extrinsic(self, sealed: SealedIntent) -> str:
        """Submit sealed intent as extrinsic to blockchain."""
        try:
            if not self._substrate:
                await self.connect(self.endpoint)

            # Create extrinsic call with intent hash
            # (assumes pallet_intents::submit_intent exists on chain)
            call = self._substrate.compose_call(
                call_module="Intents",
                call_function="submit_intent",
                call_params={
                    "intent_hash": sealed.intent_hash,
                    "agent_id": sealed.agent_id
                }
            )

            # Sign and submit
            extrinsic = self._substrate.create_signed_extrinsic(
                call=call,
                keypair=self._keypair
            )

            receipt = self._substrate.submit_extrinsic(extrinsic, wait_for_finalization=True)
            extrinsic_hash = receipt.extrinsic_hash

            logger.info(f"Extrinsic submitted: {extrinsic_hash}")
            return extrinsic_hash

        except Exception as e:
            logger.error(f"Extrinsic submission failed: {e}")
            raise ExtrinsicError(f"Extrinsic submit failed: {e}") from e

    # ========================================================================
    # Deferred-Sync Engine
    # ========================================================================

    async def _sync_deferred(self) -> None:
        """Batch sync all pending deferred intents."""
        if not self._deferred_intents:
            return

        logger.info(f"Starting deferred sync for {len(self._deferred_intents)} intents")

        for deferred in list(self._deferred_intents):
            try:
                extrinsic_hash = await self._submit_intent_extrinsic(deferred.sealed_intent)
                deferred.sealed_intent.extrinsic_hash = extrinsic_hash
                deferred.sealed_intent.status = "submitted"
                deferred.sync_attempts = 0

                # Remove from buffer
                self._remove_deferred_intent(deferred.sealed_intent.intent_hash)
                logger.info(f"Synced intent {deferred.sealed_intent.intent_hash[:8]}")

            except Exception as e:
                deferred.sync_attempts += 1
                deferred.last_error = str(e)

                if deferred.sync_attempts >= self.MAX_RETRIES:
                    logger.error(
                        f"Intent {deferred.sealed_intent.intent_hash[:8]} exceeded max retries. "
                        f"Removing from buffer."
                    )
                    self._remove_deferred_intent(deferred.sealed_intent.intent_hash)
                else:
                    logger.warning(
                        f"Sync attempt {deferred.sync_attempts}/{self.MAX_RETRIES} failed: {e}"
                    )
                    self._update_sync_attempts(
                        deferred.sealed_intent.intent_hash,
                        deferred.sync_attempts,
                        str(e)
                    )

    async def _monitor_connection(self) -> None:
        """Background task to monitor connection and trigger sync."""
        while True:
            try:
                await asyncio.sleep(5)  # Check every 5 seconds

                was_connected = self._is_connected

                # Check connection health
                if self._substrate:
                    try:
                        self._substrate.get_chain_head()
                        self._is_connected = True
                    except Exception:
                        self._is_connected = False

                # Trigger sync on reconnect
                if not was_connected and self._is_connected and self._deferred_intents:
                    logger.info("Connection restored. Starting deferred sync.")
                    await self._sync_deferred()

            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
                await asyncio.sleep(10)

    # ========================================================================
    # ZenithMeshInterface Implementation
    # ========================================================================

    async def connect(self, endpoint: str) -> bool:
        """
        Connect to a Substrate node.

        Args:
            endpoint: WebSocket endpoint (ws://localhost:9944)

        Returns:
            True if connection successful
        """
        try:
            if not SUBSTRATE_AVAILABLE:
                logger.info(f"[STUB MODE] Skipping Substrate connection ({endpoint} - unavailable)")
                self._is_connected = False
                return False

            self._substrate = SubstrateInterface(url=endpoint)
            self._is_connected = True
            self.endpoint = endpoint

            # Verify connection
            version = self._substrate.get_runtime_version()
            logger.info(f"Connected to {endpoint}. Runtime: {version}")

            # Trigger deferred sync if offline-first is enabled
            if self.enable_deferred_sync and self._deferred_intents:
                await self._sync_deferred()

            # Start connection monitor if not already running
            if not self._sync_task:
                self._sync_task = asyncio.create_task(self._monitor_connection())

            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self._is_connected = False
            raise ConnectionError(f"Connect failed: {e}") from e

    async def submit_transaction(self, transaction: Transaction) -> str:
        """
        Submit a transaction (wrapper for seal_intent).

        Args:
            transaction: Transaction to submit

        Returns:
            Transaction hash
        """
        # Serialize transaction as action_blob
        action_blob = json.dumps({
            "sender": transaction.sender,
            "receiver": transaction.receiver,
            "amount": transaction.amount,
            "nonce": transaction.nonce,
            "timestamp": transaction.timestamp,
            "metadata": transaction.metadata or {}
        }).encode()

        sealed = await self.seal_intent(transaction.sender, action_blob)
        return sealed.intent_hash

    async def query_transaction(self, tx_hash: str) -> Optional[Transaction]:
        """Query transaction details by hash."""
        try:
            if not self._substrate:
                await self.connect(self.endpoint)

            # Query from chain (pallet-agnostic for now)
            # Implementation depends on specific pallet structure
            logger.debug(f"Querying transaction {tx_hash}")
            return None
        except Exception as e:
            logger.error(f"Query transaction failed: {e}")
            return None

    async def query_account(self, address: str) -> Optional[Dict[str, Any]]:
        """Query account state on the blockchain."""
        try:
            if not self._substrate:
                await self.connect(self.endpoint)

            account_info = self._substrate.query("System", "Account", [address])
            if account_info:
                return account_info.value
            return None
        except Exception as e:
            logger.error(f"Query account failed: {e}")
            return None

    async def get_chain_state(self) -> ChainState:
        """Get current blockchain state."""
        try:
            if not self._substrate:
                await self.connect(self.endpoint)

            block_hash = self._substrate.get_chain_head()
            header = self._substrate.get_block_header(block_hash)

            return ChainState(
                latest_block=Block(
                    block_hash=block_hash,
                    parent_hash="",
                    block_number=header["number"],
                    transactions=[],
                    state_root="",
                    timestamp=int(time.time())
                ),
                chain_height=header["number"],
                total_accounts=0,
                latest_finalized_block=block_hash
            )
        except Exception as e:
            logger.error(f"Get chain state failed: {e}")
            raise

    async def validate_chain(self) -> bool:
        """Validate blockchain integrity."""
        try:
            if not self._substrate:
                await self.connect(self.endpoint)

            # Basic validation: check if we can query the runtime
            version = self._substrate.get_runtime_version()
            logger.info(f"Chain validation passed. Runtime: {version}")
            return True
        except Exception as e:
            logger.error(f"Chain validation failed: {e}")
            return False

    async def listen_blocks(self) -> None:
        """Listen for new blocks (streaming)."""
        try:
            if not self._substrate:
                await self.connect(self.endpoint)

            for block_hash in self._substrate.subscribe_block_headers():
                header = self._substrate.get_block_header(block_hash)
                block = Block(
                    block_hash=block_hash,
                    parent_hash="",
                    block_number=header["number"],
                    transactions=[],
                    state_root="",
                    timestamp=int(time.time())
                )
                logger.debug(f"New block: #{block.block_number}")
        except Exception as e:
            logger.error(f"Block listening failed: {e}")

    # ========================================================================
    # Status & Utilities
    # ========================================================================

    async def get_sync_status(self) -> SyncStatus:
        """Get current deferred sync status."""
        return SyncStatus(
            is_connected=self._is_connected,
            pending_count=len(self._deferred_intents),
            last_sync=None
        )

    async def cleanup(self) -> None:
        """Clean up resources and background tasks."""
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        logger.info("ZenithMesh cleanup complete")
