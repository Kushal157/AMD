# Aegis-Prime Web Dashboard - Complete Guide

## 🚀 Quick Start

### Option 1: Start the Web Dashboard (Recommended)
```bash
cd "e:\AMD\Aegis-Prime"
python web_dashboard.py
```

Then open your browser and visit: **http://localhost:5000**

### Option 2: Run from Command Line
```bash
# Execute Aegis Handshake
python main.py handshake --task "Your task description"

# Health check
python main.py health

# JSON output
python main.py handshake --task "Your task" --json-output
```

---

## 🌐 Web Dashboard Features

### 1. **Intuitive Control Panel**
- Task description input
- Custom Substrate endpoint configuration
- One-click handshake execution
- Health check button

### 2. **Real-time Execution Visualization**
- Loading spinner during execution
- Phase-by-phase progress display
- Live receipt generation

### 3. **Comprehensive Execution Receipt**
Shows:
- Receipt ID (unique transaction identifier)
- Execution status
- Timestamp with full date/time
- Task description

### 4. **4-Phase Pipeline Cards**
Each phase displays:

#### Phase 1️⃣ - ZK-Auth (LuminaAuth)
- Status: VERIFIED/FAILED
- Proof hash
- Circuit ID
- Witness count

#### Phase 2️⃣ - PQC Exchange (CypherShield)
- Status: COMPLETE/WARNING
- Algorithm: Kyber-512
- Tunnel key ID
- Shared secret hash
- Quantum integrity verification

#### Phase 3️⃣ - Ledger Intent (ZenithMesh)
- Status: SUBMITTED/QUEUED
- Agent ID
- Intent hash
- Extrinsic hash
- Block number & hash
- Finalization status

#### Phase 4️⃣ - WASM Execution (SynapseKernel)
- Status: SUCCESS/FAILED
- Module ID
- Function name
- Gas consumed
- Execution output
- Execution time (ms)

### 5. **Security Summary Dashboard**
Visual indicators for:
- ✓ Quantum Resistant
- ✓ Proof Verified
- ✓ Intent Finalized
- ✓ Autonomous Execution

### 6. **Health Check**
Monitor all 4 modules in real-time:
- CypherShield: PQC implementation
- ZenithMesh: Blockchain integration
- LuminaAuth: Zero-knowledge proofs
- SynapseKernel: WASM sandbox

---

## 📊 API Endpoints

### Execute Handshake
```bash
POST /api/handshake
Content-Type: application/json

{
  "task": "Execute critical agent mission",
  "endpoint": "ws://localhost:9944"
}
```

**Response:**
```json
{
  "receipt_id": "0x...",
  "overall_status": "success",
  "phases": {
    "phase_1_zk_auth": {...},
    "phase_2_pqc_exchange": {...},
    "phase_3_ledger_intent": {...},
    "phase_4_wasm_execution": {...}
  },
  "security_summary": {...}
}
```

### Get Latest Receipt
```bash
GET /api/latest
```

### Health Check
```bash
GET /api/health
```

---

## 🎨 Dashboard Features

### Color Scheme
- **Cyan (#00d4ff)**: Primary highlights
- **Purple (#7f39fb)**: Secondary accents
- **Green (#00ff88)**: Success/Pass states
- **Red (#ff0057)**: Error/Fail states
- **Yellow (#ffc100)**: Pending/Warning states

### Interactive Elements
- Hover effects on phase cards
- Smooth animations
- Responsive design (desktop & mobile)
- Real-time status updates

### Status Indicators

| Status | Color | Indicator |
|--------|-------|-----------|
| VERIFIED | Green | ✓ |
| COMPLETE | Green | ✓ |
| SUCCESS | Green | ✓ |
| SUBMITTED | Green | ✓ |
| QUEUED | Yellow | ⚠ |
| FAILED | Red | ✗ |
| ERROR | Red | ✗ |

---

## 📝 Example Tasks

```bash
# Identity verification
"Verify user identity with biometric authentication"

# Token transfer
"Transfer 1000 USDC to account 0x1234..."

# Smart contract deployment
"Deploy Uniswap V3 liquidity pool smart contract"

# Oracle update
"Update price feed for BTC/USDC pair"

# Cross-chain bridge
"Bridge 50 ETH from Ethereum to Arbitrum"

# Governance vote
"Submit DAO governance vote for proposal #42"
```

---

## 🔐 Security Features

### Built-in Protections
1. **Post-Quantum Cryptography**
   - Kyber-512 key exchange
   - AES-256-GCM symmetric encryption
   - Quantum-resistant guarantees

2. **Zero-Knowledge Proofs**
   - Identity verification without exposure
   - Deterministic proof generation
   - Cryptographic commitment

3. **Blockchain Integration**
   - Keccak-256 intent hashing
   - Extrinsic submission
   - Proof-of-Agency logging

4. **Sandboxed Execution**
   - WASM bytecode validation
   - Memory protection
   - Gas accounting & limits

### Fallback Capabilities
- ✅ Graceful degradation on missing dependencies
- ✅ Offline-first deferred sync
- ✅ Encrypted persistent buffering
- ✅ In-memory queue fallback

---

## 🚨 Troubleshooting

### Port Already in Use
```bash
# Use a different port
python -c "from web_dashboard import app; app.run(port=5001)"
```

### Module Import Errors
```bash
# Ensure you're in the correct directory
cd "e:\AMD\Aegis-Prime"
```

### Missing Dependencies
```bash
# Install Flask
pip install flask

# Install all Aegis dependencies
pip install -r requirements.txt
```

### Cannot Connect to Substrate
- The system automatically switches to offline mode
- Intents are queued with Deferred-Sync
- Re-run when node is available for sync

---

## 📁 File Structure

```
e:\AMD\Aegis-Prime\
├── web_dashboard.py           ← Start here for web interface
├── main.py                    ← CLI entry point
├── templates/
│   └── dashboard.html         ← Web UI (opens automatically)
├── core/
│   ├── __init__.py
│   ├── cypher_shield.py
│   ├── zenith_mesh.py
│   ├── lumina_auth.py
│   └── synapse_kernel.py
└── buffer.db                  ← Encrypted intent buffer
```

---

## 🎯 Next Steps

1. **Start Web Server:**
   ```bash
   python web_dashboard.py
   ```

2. **Open Browser:**
   Visit `http://localhost:5000`

3. **Enter Task:**
   Describe what you want the agent to do

4. **Execute:**
   Click "🚀 Execute Handshake"

5. **View Results:**
   Real-time visualization of all 4 phases

---

## 📊 Output Examples

### Success Response
```
Receipt ID: 0xbf8189aab0dc6942
Status: SUCCESS ✓

Phase 1: ZK-Auth [VERIFIED]
Phase 2: PQC Exchange [COMPLETE]
Phase 3: Ledger Intent [QUEUED]
Phase 4: WASM Execution [SUCCESS]

Security: All checks PASSED ✓
```

### With Offline Mode
```
Phase 3: Ledger Intent [QUEUED]
(Substrate node unavailable - intent buffered)
(Will auto-sync when connection restored)
```

---

## 💡 Tips

- **For Production:** Use a proper WSGI server (Gunicorn, uWSGI)
- **For Load Testing:** Run multiple instances on different ports
- **For Debugging:** Enable verbose logging with `--debug` flag
- **For Integration:** Use the `/api/` endpoints for automation

---

**Your Aegis-Prime Web Dashboard is now ready! 🚀**

Visit: **http://localhost:5000**
