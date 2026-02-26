"""
Aegis-Prime Web Dashboard
Real-time visualization of the 4-stage Aegis Handshake workflow with Server-Sent Events
"""

from flask import Flask, render_template, jsonify, request, Response
import asyncio
import json
from main import AegisOrchestrator
import logging
from queue import Queue
from threading import Lock

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Store latest receipt
latest_receipt = None

# Event queue for real-time SSE streaming
event_queue = Queue()
event_lock = Lock()


@app.route('/')
def index():
    """Serve the dashboard homepage"""
    return render_template('dashboard.html')


@app.route('/api/handshake-stream', methods=['POST'])
def handshake_stream():
    """Server-Sent Events endpoint for real-time phase updates"""
    def event_generator():
        # Create orchestrator with callback
        data = request.get_json()
        task = data.get('task', 'Default agent task')
        endpoint = data.get('endpoint', 'ws://localhost:9944')

        def emit_event(phase, status, details=None):
            """Emit an event to the event stream"""
            event = {
                'phase': phase,
                'status': status,
                'details': details or {}
            }
            yield f"data: {json.dumps(event)}\n\n"

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

    data = request.get_json()
    task = data.get('task', 'Default agent task')
    endpoint = data.get('endpoint', 'ws://localhost:9944')

    try:
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
    from core.cypher_shield import CypherShield
    from core.zenith_mesh import ZenithMesh
    from core.lumina_auth import LuminaAuth
    from core.synapse_kernel import SynapseKernel

    health = {}

    try:
        crypto = CypherShield()
        health['cypher_shield'] = 'OK'
    except Exception as e:
        health['cypher_shield'] = f'FAILED: {str(e)}'

    try:
        ledger = ZenithMesh()
        health['zenith_mesh'] = 'OK'
    except Exception as e:
        health['zenith_mesh'] = f'FAILED: {str(e)}'

    try:
        auth = LuminaAuth()
        health['lumina_auth'] = 'OK'
    except Exception as e:
        health['lumina_auth'] = f'FAILED: {str(e)}'

    try:
        kernel = SynapseKernel()
        health['synapse_kernel'] = 'OK'
    except Exception as e:
        health['synapse_kernel'] = f'FAILED: {str(e)}'

    return jsonify(health)


if __name__ == '__main__':
    print("\n" + "="*60)
    print("AEGIS-PRIME WEB DASHBOARD")
    print("="*60)
    print("\nStarting web server...\n")
    print("Open your browser and visit: http://localhost:5000\n")
    app.run(debug=True, port=5000, use_reloader=False)
