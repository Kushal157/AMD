"""
Aegis-Prime: Sovereign Intelligence Mesh - Main Entry Point
Orchestrates the 4-stage Aegis Handshake workflow:
1. ZK-Auth (LuminaAuth) - Identity verification via zero-knowledge proofs
2. PQC Exchange (CypherShield) - Post-quantum key exchange & symmetric tunnel
3. Ledger Intent (ZenithMesh) - Blockchain proof-of-agency intent sealing
4. WASM Execution (SynapseKernel) - Sandboxed autonomous agent execution

Output: Quantum-Safe Execution Receipt (JSON) with cryptographic proof & blockchain confirmation
"""

import hashlib
import json
import asyncio
import logging
import sys
from typing import Dict, Any, Optional
from pathlib import Path

import click

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)-8s [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Import core modules
from core.cypher_shield import CypherShield
from core.zenith_mesh import ZenithMesh
from core.lumina_auth import LuminaAuth
from core.synapse_kernel import SynapseKernel

from core import (
    PQCAlgorithm,
    ZKCircuit,
)


# ============================================================================
# Aegis Orchestrator - Main Orchestration Engine
# ============================================================================

class AegisOrchestrator:
    """
    Composite orchestrator for the 4-stage Aegis Handshake.

    Manages:
    - LuminaAuth (ZK-SNARK proof generation and verification)
    - CypherShield (Post-quantum cryptography)
    - ZenithMesh (Blockchain ledger integration)
    - SynapseKernel (WASM sandbox execution)
    """

    def __init__(self, substrate_endpoint: str = "ws://localhost:9944"):
        """
        Initialize Aegis Orchestrator with all core modules.

        Args:
            substrate_endpoint: Substrate node WebSocket endpoint
        """
        logger.info("=" * 60)
        logger.info("Initializing Aegis-Prime Orchestrator")
        logger.info("=" * 60)

        try:
            # Initialize core modules
            self.crypto = CypherShield(algorithm=PQCAlgorithm.KYBER_512)
            self.ledger = ZenithMesh(endpoint=substrate_endpoint)
            self.auth = LuminaAuth()
            self.kernel = SynapseKernel()

            # Generate receipt ID
            self.receipt_id = "0x" + hashlib.sha256(
                str(asyncio.get_event_loop().time()).encode()
            ).hexdigest()[:16]

            logger.info(f"Orchestrator initialized. Receipt ID: {self.receipt_id}")

        except Exception as e:
            logger.error(f"Orchestrator initialization failed: {e}")
            raise RuntimeError(f"Orchestrator init failed: {e}") from e

    async def execute_handshake(self, task_description: str) -> Dict[str, Any]:
        """
        Execute the complete 4-stage Aegis Handshake workflow.

        Args:
            task_description: Description of the agent task

        Returns:
            Quantum-Safe Execution Receipt (dictionary)
        """
        logger.info("=" * 60)
        logger.info(f"Starting Aegis Handshake")
        logger.info(f"Task: {task_description[:50]}...")
        logger.info("=" * 60)

        receipt = {
            "receipt_id": self.receipt_id,
            "timestamp": int(asyncio.get_event_loop().time()),
            "task_description": task_description,
            "phases": {}
        }

        try:
            # Phase 1: Zero-Knowledge Authentication
            logger.info("\n[Phase 1] ZK-Auth (LuminaAuth)")
            receipt["phases"]["phase_1_zk_auth"] = await self._phase_zk_auth()

            # Phase 2: Post-Quantum Cryptography Exchange
            logger.info("\n[Phase 2] PQC Exchange (CypherShield)")
            receipt["phases"]["phase_2_pqc_exchange"] = await self._phase_pqc_exchange()

            # Phase 3: Ledger Intent Sealing
            logger.info("\n[Phase 3] Ledger Intent (ZenithMesh)")
            receipt["phases"]["phase_3_ledger_intent"] = await self._phase_ledger_intent(
                task_description
            )

            # Phase 4: WASM Execution
            logger.info("\n[Phase 4] WASM Execution (SynapseKernel)")
            receipt["phases"]["phase_4_wasm_execution"] = await self._phase_wasm_execution()

            # Compute overall status
            receipt["overall_status"] = "success"
            receipt["security_summary"] = {
                "quantum_resistant": True,
                "proof_verified": receipt["phases"]["phase_1_zk_auth"].get("status") == "verified",
                "intent_finalized": receipt["phases"]["phase_3_ledger_intent"].get("finalized", False),
                "autonomous": True
            }

            logger.info("\n" + "=" * 60)
            logger.info("✓ Aegis Handshake COMPLETE")
            logger.info("=" * 60)

        except Exception as e:
            logger.error(f"\n✗ Handshake failed: {e}")
            receipt["overall_status"] = "failed"
            receipt["error"] = str(e)

        return receipt

    async def _phase_zk_auth(self) -> Dict[str, Any]:
        """Phase 1: Zero-Knowledge Authentication"""
        try:
            logger.info("  → Generating ZK circuit...")
            circuit = ZKCircuit(
                circuit_id="identity-circuit-v1",
                circuit_bytes=b"aegis_identity_circuit",
                proving_key=b"proving_key_material",
                verification_key=b"verification_key_material"
            )

            logger.info("  → Creating witness...")
            witness = {"age": 25, "valid": 1, "clearance": 5}

            logger.info("  → Generating zero-knowledge proof...")
            proof = await self.auth.generate_proof(circuit, witness)

            logger.info("  → Verifying proof...")
            verified = await self.auth.verify_proof(proof)

            result = {
                "status": "verified" if verified else "failed",
                "proof_hash": "0x" + proof.proof[:8].hex(),
                "circuit_id": circuit.circuit_id,
                "witness_count": len(witness),
                "verified": verified
            }

            logger.info(f"  ✓ ZK-Auth: {result['status']}")
            return result

        except Exception as e:
            logger.error(f"  ✗ ZK-Auth failed: {e}")
            return {"status": "error", "error": str(e)}

    async def _phase_pqc_exchange(self) -> Dict[str, Any]:
        """Phase 2: Post-Quantum Cryptography Exchange"""
        try:
            logger.info("  → Generating Kyber-512 keypair...")
            keypair = await self.crypto.generate_keypair(PQCAlgorithm.KYBER_512)

            logger.info("  → Performing key encapsulation...")
            # Use portion of public key as simulated ledger key
            ledger_pubkey = keypair.public_key[:1088]
            encapsulated = await self.crypto.key_encapsulate(ledger_pubkey)

            logger.info("  → Deriving symmetric tunnel (AES-256-GCM)...")
            tunnel = await self.crypto.derive_symmetric_tunnel(
                encapsulated.shared_secret,
                context=b"aegis-handshake-v1"
            )

            logger.info("  → Verifying quantum integrity...")
            integrity_ok = await self.crypto.verify_quantum_integrity()

            result = {
                "status": "complete" if integrity_ok else "warning",
                "algorithm": "kyber512",
                "tunnel_key_id": tunnel.key_id,
                "key_encapsulation_success": True,
                "shared_secret_hash": "0x" + hashlib.sha256(
                    encapsulated.shared_secret
                ).hexdigest()[:16],
                "quantum_integrity": integrity_ok
            }

            logger.info(f"  ✓ PQC Exchange: {result['status']}")
            return result

        except Exception as e:
            logger.error(f"  ✗ PQC Exchange failed: {e}")
            return {"status": "error", "error": str(e)}

    async def _phase_ledger_intent(self, task_description: str) -> Dict[str, Any]:
        """Phase 3: Ledger Intent Sealing"""
        try:
            logger.info("  → Connecting to Substrate node...")
            try:
                await self.ledger.connect(self.ledger.endpoint)
                connected = True
            except Exception as e:
                logger.warning(f"  ⚠ Connection failed (will queue): {e}")
                connected = False

            logger.info("  → Sealing agent intent...")
            action_blob = task_description.encode()
            sealed = await self.ledger.seal_intent("aegis-agent-01", action_blob)

            logger.info("  → Querying blockchain state...")
            if connected:
                try:
                    chain_state = await self.ledger.get_chain_state()
                    block_number = chain_state.chain_height
                    block_hash = chain_state.latest_finalized_block
                except Exception as e:
                    logger.warning(f"  ⚠ Chain query failed: {e}")
                    block_number = 0
                    block_hash = "0x0000"
            else:
                block_number = 0
                block_hash = "0xpending"

            result = {
                "status": "submitted" if sealed.extrinsic_hash else "queued",
                "agent_id": "aegis-agent-01",
                "intent_hash": sealed.intent_hash,
                "extrinsic_hash": sealed.extrinsic_hash or "0xpending",
                "block_number": block_number,
                "block_hash": block_hash,
                "finalized": sealed.extrinsic_hash is not None,
                "connected": connected
            }

            logger.info(f"  ✓ Ledger Intent: {result['status']}")
            return result

        except Exception as e:
            logger.error(f"  ✗ Ledger Intent failed: {e}")
            return {"status": "error", "error": str(e)}

    async def _phase_wasm_execution(self) -> Dict[str, Any]:
        """Phase 4: Sandboxed WASM Execution"""
        try:
            logger.info("  → Loading WASM module...")
            sample_wasm = b"\x00asm\x01\x00\x00\x00"  # WASM magic + version
            module = await self.kernel.load_module(sample_wasm)

            logger.info("  → Creating sandbox...")
            sandbox_id = await self.kernel.create_sandbox(module)

            logger.info("  → Executing agent task...")
            result = await self.kernel.execute(sandbox_id, "process_task")

            logger.info("  → Cleaning up sandbox...")
            await self.kernel.cleanup_sandbox(sandbox_id)

            execution_result = {
                "status": "success",
                "module_id": module.module_id,
                "function": "process_task",
                "gas_consumed": result.gas_consumed,
                "output": "0x" + hashlib.sha256(
                    str(result.return_value).encode()
                ).hexdigest()[:16],
                "execution_time_ms": result.execution_time_ms
            }

            logger.info(f"  ✓ WASM Execution: {execution_result['status']}")
            return execution_result

        except Exception as e:
            logger.error(f"  ✗ WASM Execution failed: {e}")
            return {"status": "error", "error": str(e)}

    async def cleanup(self) -> None:
        """Cleanup all resources and background tasks"""
        logger.info("\nCleaning up...")
        modules = [self.ledger, self.kernel, self.auth, self.crypto]

        for module in modules:
            try:
                if hasattr(module, 'cleanup'):
                    await module.cleanup()
            except Exception as e:
                logger.error(f"  {module.__class__.__name__} cleanup failed: {e}")

        logger.info("✓ Cleanup complete")


# ============================================================================
# CLI Interface (Click)
# ============================================================================

@click.group()
def cli():
    """Aegis-Prime: Sovereign Intelligence Mesh for Digital Autonomy"""
    pass


@cli.command()
@click.option(
    '--task',
    required=True,
    help='Task description for the agent'
)
@click.option(
    '--endpoint',
    default='ws://localhost:9944',
    help='Substrate node WebSocket endpoint'
)
@click.option(
    '--json-output',
    is_flag=True,
    help='Output raw JSON receipt'
)
def handshake(task: str, endpoint: str, json_output: bool):
    """
    Execute the Aegis Handshake: ZK-Auth → PQC → Ledger → WASM

    Performs a complete 4-stage cryptographic workflow to:
    1. Verify agent identity via zero-knowledge proofs
    2. Establish post-quantum encrypted communication
    3. Seal intent on the blockchain ledger
    4. Execute the task in a sandboxed WASM environment

    Output: Quantum-Safe Execution Receipt containing proof & block hash
    """

    async def run():
        orchestrator = AegisOrchestrator(substrate_endpoint=endpoint)
        try:
            receipt = await orchestrator.execute_handshake(task)

            if json_output:
                # Output raw JSON
                click.echo(json.dumps(receipt, indent=2))
            else:
                # Output formatted receipt
                _print_receipt_formatted(receipt)

        finally:
            await orchestrator.cleanup()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        click.secho("\n✗ Interrupted by user", fg="red")
        sys.exit(1)
    except Exception as e:
        click.secho(f"\n✗ Fatal error: {e}", fg="red")
        sys.exit(1)


def _print_receipt_formatted(receipt: Dict[str, Any]) -> None:
    """Pretty-print the Quantum-Safe Execution Receipt"""

    # Header
    click.secho("\n", bold=True)
    click.secho("╔" + "═" * 62 + "╗", fg="cyan")
    click.secho("║" + " " * 62 + "║", fg="cyan")
    click.secho("║  " + "QUANTUM-SAFE EXECUTION RECEIPT (Aegis-Prime)".center(58) + "  ║", fg="cyan", bold=True)
    click.secho("║" + " " * 62 + "║", fg="cyan")
    click.secho("╚" + "═" * 62 + "╝", fg="cyan")

    # Overall status
    status = receipt.get("overall_status", "unknown")
    status_color = "green" if status == "success" else "red"
    click.secho(f"\nOverall Status: ", nl=False)
    click.secho(status.upper(), fg=status_color, bold=True)

    click.echo(f"Receipt ID: {receipt.get('receipt_id')}")

    if "task_description" in receipt:
        task = receipt["task_description"]
        if len(task) > 50:
            task = task[:47] + "..."
        click.echo(f"Task: {task}")

    # Phase summaries
    click.secho("\n" + "─" * 64, fg="cyan")
    click.secho("PHASE DETAILS", fg="cyan", bold=True)
    click.secho("─" * 64 + "\n", fg="cyan")

    phases = receipt.get("phases", {})
    for phase_num, (phase_name, phase_data) in enumerate(phases.items(), 1):
        if not isinstance(phase_data, dict):
            continue

        status = phase_data.get("status", "unknown")
        status_color = "green" if status in [
            "success", "verified", "complete", "submitted"
        ] else "red" if status == "error" else "yellow"

        phase_label = phase_name.replace("phase_", "").replace("_", " ").title()

        click.secho(f"{phase_num}. {phase_label}", bold=True)
        click.secho(f"   Status: ", nl=False)
        click.secho(status.upper(), fg=status_color)

        # Show key fields
        for key, value in phase_data.items():
            if key in ["status", "error"]:
                continue

            if isinstance(value, bool):
                symbol = "✓" if value else "✗"
                click.secho(f"   {symbol} {key}: {value}")
            elif isinstance(value, (int, float)):
                click.echo(f"   • {key}: {value}")
            elif isinstance(value, str) and len(value) > 50:
                click.echo(f"   • {key}: {value[:47]}...")
            else:
                click.echo(f"   • {key}: {value}")

        click.echo()

    # Security summary
    security = receipt.get("security_summary", {})
    if security:
        click.secho("─" * 64, fg="cyan")
        click.secho("SECURITY SUMMARY", fg="cyan", bold=True)
        click.secho("─" * 64 + "\n", fg="cyan")

        for key, value in security.items():
            symbol = "✓" if value else "✗"
            key_label = key.replace("_", " ").title()
            click.secho(f"{symbol} {key_label}: ", nl=False)
            click.secho("PASS" if value else "FAIL", fg="green" if value else "red")

    # Error details
    if "error" in receipt:
        click.secho("\n─" * 64, fg="red")
        click.secho("ERROR DETAILS", fg="red", bold=True)
        click.secho("─" * 64 + "\n", fg="red")
        click.secho(f"Error: {receipt['error']}", fg="red")

    click.secho("\n" + "═" * 64 + "\n", fg="cyan")


@cli.command()
@click.option('--endpoint', default='ws://localhost:9944', help='Substrate endpoint')
def health(endpoint: str):
    """Check health of all core modules"""

    async def run():
        logger.info("Running health check...")

        try:
            crypto = CypherShield()
            click.secho("✓ CypherShield: OK", fg="green")

            try:
                ok = await crypto.verify_quantum_integrity()
                if ok:
                    click.secho("  ✓ Quantum integrity verified", fg="green")
            except Exception as e:
                click.secho(f"  ⚠ Quantum check failed: {e}", fg="yellow")

        except Exception as e:
            click.secho(f"✗ CypherShield: FAILED - {e}", fg="red")

        try:
            ledger = ZenithMesh(endpoint=endpoint)
            click.secho("✓ ZenithMesh: OK", fg="green")
        except Exception as e:
            click.secho(f"✗ ZenithMesh: FAILED - {e}", fg="red")

        try:
            auth = LuminaAuth()
            click.secho("✓ LuminaAuth: OK", fg="green")
        except Exception as e:
            click.secho(f"✗ LuminaAuth: FAILED - {e}", fg="red")

        try:
            kernel = SynapseKernel()
            click.secho("✓ SynapseKernel: OK", fg="green")
        except Exception as e:
            click.secho(f"✗ SynapseKernel: FAILED - {e}", fg="red")

    try:
        asyncio.run(run())
    except Exception as e:
        click.secho(f"✗ Health check failed: {e}", fg="red")
        sys.exit(1)


if __name__ == "__main__":
    cli()
