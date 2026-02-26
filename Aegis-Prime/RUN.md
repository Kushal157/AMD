# 🚀 How to Run Aegis-Prime

## Quick Start

### Prerequisites
Make sure you're in the correct directory:
```bash
cd "e:\AMD\Aegis-Prime"
```

---

## Option 1: Web Dashboard (Recommended)

**Best for:** Visual interface, seeing all 4 phases in real-time

```bash
python web_dashboard.py
```

Then open your browser and visit:
```
http://localhost:5000
```

You'll see:
- Input field for task description
- Execute button
- Real-time phase visualization
- Security summary
- Health status

---

## Option 2: Command Line Interface

**Best for:** Quick command-line execution, scripting, automation

### Basic Usage
```bash
python main.py handshake --task "Your task description here"
```

### Example Tasks
```bash
# Authenticate a user
python main.py handshake --task "Authenticate user identity"

# Transfer funds
python main.py handshake --task "Transfer 500 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"

# Deploy smart contract
python main.py handshake --task "Deploy ERC-20 token with 1000000 supply and 18 decimals"

# Custom Substrate endpoint
python main.py handshake --task "Your task" --endpoint "ws://your-node:9944"

# Output as JSON
python main.py handshake --task "Your task" --json-output
```

---

## Option 3: Health Check

**Best for:** Verifying all modules are working

```bash
python main.py health
```

Output will show status of all 4 core modules:
- ✓ CypherShield (Post-Quantum Cryptography)
- ✓ ZenithMesh (Blockchain Integration)
- ✓ LuminaAuth (Zero-Knowledge Proofs)
- ✓ SynapseKernel (WASM Sandbox)

---

## What Happens When You Run

The system executes a **4-stage cryptographic workflow**:

1. **Phase 1: ZK-Auth** (LuminaAuth)
   - Generates zero-knowledge proofs
   - Verifies identity cryptographically
   - Status: VERIFIED ✓

2. **Phase 2: PQC Exchange** (CypherShield)
   - Kyber-512 post-quantum key exchange
   - Derives AES-256-GCM symmetric tunnel
   - Status: COMPLETE ✓

3. **Phase 3: Ledger Intent** (ZenithMesh)
   - Seals intent to blockchain (if available)
   - Keccak-256 hashing
   - Status: SUBMITTED/QUEUED

4. **Phase 4: WASM Execution** (SynapseKernel)
   - Loads WASM module
   - Creates sandbox environment
   - Executes task
   - Status: SUCCESS ✓

**Output:** Quantum-Safe Execution Receipt with all phase details and security summary

---

## Example Output (CLI)

```
============================================================
AEGIS-PRIME WEB DASHBOARD
============================================================

Starting Aegis Handshake
Task: Authenticate user identity
...

================================================================
QUANTUM-SAFE EXECUTION RECEIPT (Aegis-Prime)
================================================================

Overall Status: SUCCESS ✓

Receipt ID: 0xbf8189aab0dc6942
Task: Authenticate user identity

----------------------------------------------------------------
PHASE DETAILS
----------------------------------------------------------------

1. Phase 1 Zk Auth
   Status: VERIFIED
   • proof_hash: 0xabcd1234...
   • circuit_id: identity-circuit-v1
   • witness_count: 3

2. Phase 2 Pqc Exchange
   Status: COMPLETE
   • algorithm: kyber512
   • tunnel_key_id: 0x5678efgh...
   • key_encapsulation_success: True

3. Phase 3 Ledger Intent
   Status: QUEUED
   • agent_id: aegis-agent-01
   • intent_hash: 0xijkl9012...
   • block_number: 0

4. Phase 4 Wasm Execution
   Status: SUCCESS
   • module_id: abc123def456
   • function: process_task
   • gas_consumed: 1234
   • execution_time_ms: 45.23

----------------------------------------------------------------
SECURITY SUMMARY
----------------------------------------------------------------

[+] Quantum Resistant: PASS
[+] Proof Verified: PASS
[+] Intent Finalized: PASS
[+] Autonomous: PASS

================================================================
```

---

## Troubleshooting

### Port Already in Use
If port 5000 is busy:
```bash
python -c "from web_dashboard import app; app.run(port=5001)"
```

### Missing Dependencies
Install Flask:
```bash
pip install flask
```

Install all requirements:
```bash
pip install -r requirements.txt
```

### Module Import Errors
Make sure you're in the correct directory:
```bash
cd "e:\AMD\Aegis-Prime"
python main.py health
```

### Substrate Connection Issues
The system automatically switches to offline mode:
- Intents are queued in buffer.db
- Will auto-sync when node becomes available
- No errors - just graceful degradation

---

## File Structure

```
e:\AMD\Aegis-Prime\
├── main.py                 ← CLI entry point
├── web_dashboard.py        ← Web server
├── RUN.md                  ← This file
├── WEB_DASHBOARD_GUIDE.md  ← Web interface guide
├── requirements.txt        ← Dependencies
├── buffer.db              ← Encrypted intent queue (auto-created)
├── core/
│   ├── __init__.py        ← Type definitions & interfaces
│   ├── cypher_shield.py   ← Post-Quantum Cryptography
│   ├── zenith_mesh.py     ← Blockchain Integration
│   ├── lumina_auth.py     ← Zero-Knowledge Proofs
│   └── synapse_kernel.py  ← WASM Sandbox
└── templates/
    └── dashboard.html     ← Web UI (auto-served)
```

---

## What to Try

### Try This First (CLI)
```bash
python main.py handshake --task "Execute critical agent mission: Verify identity and transfer assets"
```

### Try This (Web)
```bash
python web_dashboard.py
# Visit http://localhost:5000
# Enter: "Deploy Uniswap V3 liquidity pool"
# Click "Execute Handshake"
```

### Try This (JSON Output)
```bash
python main.py handshake --task "Test task" --json-output
```

### Try This (Health Check)
```bash
python main.py health
```

---

## Features

✅ **4-Stage Cryptographic Orchestration**
✅ **Post-Quantum Cryptography** (Kyber-512, AES-256-GCM)
✅ **Zero-Knowledge Proofs** (Identity verification)
✅ **Blockchain Integration** (Substrate ledger)
✅ **WASM Sandbox Execution** (Task execution)
✅ **Offline-First Architecture** (Works without node)
✅ **Graceful Error Handling** (Fallback implementations)
✅ **Web Dashboard** (Real-time visualization)
✅ **REST API** (Programmatic access)
✅ **CLI Interface** (Command-line automation)

---

## Need Help?

- Check WEB_DASHBOARD_GUIDE.md for web interface details
- Run `python main.py handshake --help` for CLI options
- Run `python main.py health` to verify system status

**Aegis-Prime is ready to go! 🚀**
