"""
Aegis-Prime Web Dashboard
Real-time visualization of the 4-stage Aegis Handshake workflow
"""

from flask import Flask, render_template, jsonify, request
import asyncio
import json
from main import AegisOrchestrator
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Store latest receipt
latest_receipt = None


@app.route('/')
def index():
    """Serve the dashboard homepage"""
    return render_template('dashboard.html')


@app.route('/api/handshake', methods=['POST'])
def execute_handshake():
    """Execute Aegis Handshake and return receipt"""
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
