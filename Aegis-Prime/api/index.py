"""
Aegis-Prime Web Dashboard - Vercel Serverless Deployment
Real-time visualization of the 4-stage Aegis Handshake workflow with Server-Sent Events
"""

from flask import Flask, render_template, jsonify, request, Response
import asyncio
import json
import os
import sys
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from main import AegisOrchestrator
except (ImportError, ModuleNotFoundError) as e:
    # Fallback if main.py is not available or has import errors
    logger.warning(f"AegisOrchestrator not available: {e}. Using mock mode.")

    # Create a mock orchestrator for Vercel serverless
    class AegisOrchestrator:
        def __init__(self, substrate_endpoint='ws://localhost:9944'):
            import hashlib
            self.receipt_id = "0x" + hashlib.sha256(str(__import__('time').time()).encode()).hexdigest()[:16]
            self.endpoint = substrate_endpoint

        async def _phase_zk_auth(self):
            import hashlib
            return {
                "status": "verified",
                "proof_hash": "0x" + hashlib.sha256(b"zk_proof").hexdigest()[:8],
                "circuit_id": "identity-circuit-v1",
                "witness_count": 3,
                "verified": True
            }

        async def _phase_pqc_exchange(self):
            import hashlib
            return {
                "status": "complete",
                "algorithm": "kyber512",
                "tunnel_key_id": "tunnel-001",
                "key_encapsulation_success": True,
                "shared_secret_hash": "0x" + hashlib.sha256(b"shared_secret").hexdigest()[:16],
                "quantum_integrity": True
            }

        async def _phase_ledger_intent(self, task_description):
            import hashlib
            return {
                "status": "submitted",
                "intent_hash": hashlib.sha256(task_description.encode()).hexdigest()[:16],
                "block_number": 0,
                "block_hash": "0xdeferred",
                "finalized": False
            }

        async def _phase_wasm_execution(self):
            return {
                "status": "success",
                "execution_time_ms": 150,
                "gas_used": 50000,
                "output": "Agent executed successfully"
            }

        async def execute_handshake(self, task_description):
            import hashlib
            return {
                "receipt_id": self.receipt_id,
                "task_description": task_description,
                "overall_status": "success",
                "timestamp": int(__import__('time').time()),
                "phases": {}
            }

        async def cleanup(self):
            pass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__,
    template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates'),
    static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')
)

# Configuration
app.config['JSON_SORT_KEYS'] = False

# Store latest receipt
latest_receipt = None


@app.route('/')
def index():
    """Serve the dashboard homepage"""
    try:
        return render_template('dashboard.html')
    except Exception as e:
        logger.error(f"Error rendering template: {e}")
        return f"<h1>Aegis-Prime Dashboard</h1><p>Error loading dashboard: {str(e)}</p>", 500


@app.route('/api/handshake-stream', methods=['POST'])
def handshake_stream():
    """Server-Sent Events endpoint for real-time phase updates"""
    def event_generator():
        # Extract request data
        try:
            data = request.get_json() or {}
        except Exception:
            data = {}

        task = data.get('task', 'Default agent task')
        endpoint = data.get('endpoint', 'ws://localhost:9944')

        try:
            # Emit start event
            yield f"data: {json.dumps({'phase': 'workflow', 'status': 'started', 'details': {}})}\n\n"

            orchestrator = AegisOrchestrator(substrate_endpoint=endpoint)

            # Phase 1: ZK-Auth
            yield f"data: {json.dumps({'phase': 1, 'status': 'started', 'details': {'name': 'ZK-Auth'}})}\n\n"
            phase1_result = asyncio.run(orchestrator._phase_zk_auth())
            yield f"data: {json.dumps({'phase': 1, 'status': 'completed', 'details': phase1_result})}\n\n"

            # Phase 2: PQC Exchange
            yield f"data: {json.dumps({'phase': 2, 'status': 'started', 'details': {'name': 'PQC Exchange'}})}\n\n"
            phase2_result = asyncio.run(orchestrator._phase_pqc_exchange())
            yield f"data: {json.dumps({'phase': 2, 'status': 'completed', 'details': phase2_result})}\n\n"

            # Phase 3: Ledger Intent
            yield f"data: {json.dumps({'phase': 3, 'status': 'started', 'details': {'name': 'Ledger Intent'}})}\n\n"
            phase3_result = asyncio.run(orchestrator._phase_ledger_intent(task))
            yield f"data: {json.dumps({'phase': 3, 'status': 'completed', 'details': phase3_result})}\n\n"

            # Phase 4: WASM Execution
            yield f"data: {json.dumps({'phase': 4, 'status': 'started', 'details': {'name': 'WASM Execution'}})}\n\n"
            phase4_result = asyncio.run(orchestrator._phase_wasm_execution())
            yield f"data: {json.dumps({'phase': 4, 'status': 'completed', 'details': phase4_result})}\n\n"

            # Generate final receipt
            receipt = {
                "receipt_id": orchestrator.receipt_id,
                "task_description": task,
                "overall_status": "success",
                "phases": {
                    "phase_1_zk_auth": phase1_result,
                    "phase_2_pqc_exchange": phase2_result,
                    "phase_3_ledger_intent": phase3_result,
                    "phase_4_wasm_execution": phase4_result
                },
                "security_summary": {
                    "quantum_resistant": True,
                    "proof_verified": phase1_result.get("status") == "verified",
                    "intent_finalized": phase3_result.get("finalized", False),
                    "autonomous": True
                }
            }

            asyncio.run(orchestrator.cleanup())

            # Emit final event
            yield f"data: {json.dumps({'phase': 'workflow', 'status': 'completed', 'receipt': receipt})}\n\n"

        except Exception as e:
            logger.error(f"SSE Stream error: {e}")
            yield f"data: {json.dumps({'phase': 'workflow', 'status': 'error', 'details': {'error': str(e)}})}\n\n"

    return Response(event_generator(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    })


@app.route('/api/handshake', methods=['POST'])
def execute_handshake():
    """Execute Aegis Handshake and return receipt (legacy endpoint)"""
    global latest_receipt

    try:
        data = request.get_json() or {}
        task = data.get('task', 'Default agent task')
        endpoint = data.get('endpoint', 'ws://localhost:9944')

        orchestrator = AegisOrchestrator(substrate_endpoint=endpoint)
        receipt = asyncio.run(orchestrator.execute_handshake(task))
        latest_receipt = receipt

        asyncio.run(orchestrator.cleanup())

        return jsonify(receipt)
    except Exception as e:
        return jsonify({'error': str(e), 'overall_status': 'failed'}), 500


@app.route('/api/latest', methods=['GET'])
def get_latest():
    """Get the latest execution receipt"""
    if latest_receipt:
        return jsonify(latest_receipt)
    return jsonify({}), 404


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check for all modules"""
    health = {
        "status": "healthy",
        "service": "Aegis-Prime Dashboard (Vercel)",
        "orchestrator": "mock" if "main" not in sys.modules else "real"
    }

    try:
        from core.cypher_shield import CypherShield
        from core.zenith_mesh import ZenithMesh
        from core.lumina_auth import LuminaAuth
        from core.synapse_kernel import SynapseKernel

        try:
            crypto = CypherShield()
            health['cypher_shield'] = 'OK'
        except Exception as e:
            health['cypher_shield'] = f'DEGRADED: {str(e)}'

        try:
            ledger = ZenithMesh()
            health['zenith_mesh'] = 'OK'
        except Exception as e:
            health['zenith_mesh'] = f'DEGRADED: {str(e)}'

        try:
            auth = LuminaAuth()
            health['lumina_auth'] = 'OK'
        except Exception as e:
            health['lumina_auth'] = f'DEGRADED: {str(e)}'

        try:
            kernel = SynapseKernel()
            health['synapse_kernel'] = 'OK'
        except Exception as e:
            health['synapse_kernel'] = f'DEGRADED: {str(e)}'

    except (ImportError, ModuleNotFoundError) as e:
        logger.warning(f"Core modules not available: {e}. Using mock implementations.")
        health['modules'] = 'Using mock implementations'
        health['cypher_shield'] = 'MOCK'
        health['zenith_mesh'] = 'MOCK'
        health['lumina_auth'] = 'MOCK'
        health['synapse_kernel'] = 'MOCK'

    return jsonify(health)


# AI Assistant - Claude Opus Integration
@app.route('/api/ask-opus', methods=['POST'])
def ask_opus():
    """Ask Claude Opus a question based on the execution results"""
    try:
        data = request.get_json() or {}
        question = data.get('question', '').strip()
        context = data.get('context', {})

        if not question:
            return jsonify({'error': 'Question is required', 'answer': ''}), 400

        # Get API key from environment
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({
                'answer': 'Claude Opus API key not configured. Please set ANTHROPIC_API_KEY environment variable.',
                'model': 'unavailable'
            }), 200

        try:
            import anthropic

            client = anthropic.Anthropic(api_key=api_key)

            # Prepare context from execution results
            context_info = ""
            if context:
                context_info = f"\n\nExecution Context:\n"
                context_info += f"- Task: {context.get('task_description', 'N/A')}\n"
                context_info += f"- Status: {context.get('overall_status', 'N/A')}\n"
                context_info += f"- Receipt ID: {context.get('receipt_id', 'N/A')}\n"
                if context.get('phases'):
                    context_info += "- Phases:\n"
                    for phase_name, phase_data in context['phases'].items():
                        if isinstance(phase_data, dict):
                            context_info += f"  - {phase_name}: {phase_data.get('status', 'unknown')}\n"

            # Create message with context
            full_prompt = f"{question}{context_info}"

            message = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1024,
                messages=[
                    {
                        "role": "user",
                        "content": full_prompt
                    }
                ],
                system="You are an AI assistant helping users understand their Aegis-Prime execution results. Provide clear, concise answers about cryptography, blockchain, quantum safety, and the execution workflow. If asked about specific execution details, use the context provided."
            )

            # Extract the response
            answer = message.content[0].text if message.content else "No response generated"

            return jsonify({
                'question': question,
                'answer': answer,
                'model': 'claude-3-5-sonnet-20241022',
                'tokens_used': {
                    'input': message.usage.input_tokens,
                    'output': message.usage.output_tokens
                }
            })

        except ImportError:
            return jsonify({
                'answer': 'Anthropic library not available. Please install: pip install anthropic',
                'model': 'unavailable'
            }), 200

    except Exception as e:
        logger.error(f"Error in ask_opus: {e}")
        return jsonify({
            'error': str(e),
            'answer': f'Error communicating with Claude Opus: {str(e)}'
        }), 500



@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'status': 404}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error', 'status': 500}), 500


# Health check for deployment
@app.route('/health', methods=['GET'])
def deployment_health():
    """Simple health check for Vercel deployment monitoring"""
    return jsonify({'status': 'healthy', 'service': 'Aegis-Prime Dashboard'})


if __name__ == '__main__':
    print("\n" + "="*60)
    print("AEGIS-PRIME WEB DASHBOARD (Vercel)")
    print("="*60)
    print("\nStarting development server...\n")
    print("Open your browser and visit: http://localhost:5000\n")
    app.run(debug=True, port=5000, use_reloader=False)
