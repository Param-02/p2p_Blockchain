# app.py
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, Response, g 
import requests
import threading
from blockchain import Blockchain, Transaction, User, Block
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import time
import json
from decimal import Decimal, InvalidOperation
import logging
import sys
import socket
import queue

app = Flask(__name__)
app.secret_key = 'sugar_lime'  # Replace with a secure secret key
app.config['DEBUG'] = True

# Configure logging
logging.basicConfig(level=logging.DEBUG,  # Set to DEBUG for detailed logs
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

# Initialize a queue for SSE
sse_queue = queue.Queue()

# Get the port number from command-line arguments
if len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    port = 5000
app.config['SESSION_COOKIE_NAME'] = f'session_{port}'

# Get the actual IP address of the machine
def get_ip_address():
    try:
        # Create a socket to an external host to get the network interface used
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))  # Use a public DNS server
            ip_address = s.getsockname()[0]
        return ip_address
    except Exception as e:
        logger.error(f"Error getting IP address: {e}")
        return '127.0.0.1'

node_host = get_ip_address()
node_port = port  # Port number from command-line arguments
node_identifier = f'{node_host}:{node_port}'

logger.info(f"Node identifier: {node_identifier}")

# Instantiate the Blockchain
blockchain = Blockchain(node_identifier)
blockchain.add_node(node_identifier)

# Known nodes to connect to on startup
known_nodes = ['172.16.83.23:5000', '172.16.83.23:5001', '172.16.83.23:5002']

def sync_with_known_nodes():
    for node in known_nodes:
        if node != node_identifier:
            blockchain.add_node(node)
            logger.info(f"Added node {node}")
            try:
                # Synchronize users
                response = requests.get(f'http://{node}/users', timeout=5)
                if response.status_code == 200:
                    users_data = response.json()['users']
                    with blockchain.lock:
                        for user_data in users_data:
                            user = User.from_dict(user_data)
                            normalized_username = user.username.strip().lower()
                            if normalized_username not in blockchain.users:
                                blockchain.users[normalized_username] = user
                                logger.info(f"Synchronized user '{user.username}' from node {node}")
                else:
                    logger.error(f"Failed to fetch users from {node}: HTTP {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to sync users from {node}: {e}")
            # Request the list of nodes from the known node
            try:
                response = requests.get(f'http://{node}/nodes/list', timeout=5)
                if response.status_code == 200:
                    nodes_list = response.json()['nodes']
                    for n in nodes_list:
                        normalized_n = n.strip().lower()
                        if normalized_n != node_identifier and normalized_n != node:
                            blockchain.add_node(normalized_n)
                            logger.info(f"Discovered node {normalized_n} through {node}")
                else:
                    logger.error(f"Failed to get nodes from {node}: HTTP {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to get nodes from {node}: {e}")
                continue
            # Request chain
            try:
                response = requests.get(f'http://{node}/chain', timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    length = data['length']
                    chain_data = data['chain']
                    chain = blockchain.reconstruct_chain_from_data(chain_data)
                    # Ensure users for the chain are present
                    blockchain.ensure_users_for_chain(chain)
                    with blockchain.lock:
                        if length > len(blockchain.chain) and blockchain.is_chain_valid(chain):
                            blockchain.chain = chain
                            blockchain.update_balances_from_chain()
                            logger.info(f"Synchronized chain from node {node}")
                else:
                    logger.error(f"Failed to fetch chain from {node}: HTTP {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to sync chain from {node}: {e}")
            # Request pending transactions
            try:
                response = requests.get(f'http://{node}/transactions/pending', timeout=5)
                if response.status_code == 200:
                    transactions_data = response.json()['transactions']
                    with blockchain.lock:
                        for tx_data in transactions_data:
                            transaction = Transaction(
                                sender=tx_data['sender'].strip().lower(),
                                receiver=tx_data['receiver'].strip().lower(),
                                amount=Decimal(tx_data['amount']),
                                fee=Decimal(tx_data.get('fee', '0')),  # Include fee
                                signature=bytes.fromhex(tx_data['signature']) if tx_data.get('signature') else None,
                                timestamp=tx_data['timestamp']
                            )
                            transaction.transaction_id = tx_data.get('transaction_id')
                            if transaction.transaction_id not in blockchain.pending_transaction_ids:
                                blockchain.add_transaction(transaction, broadcast=False)
                                logger.info(f"Synchronized pending transaction {transaction.transaction_id} from node {node}")
                else:
                    logger.error(f"Failed to fetch pending transactions from {node}: HTTP {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to sync transactions from {node}: {e}")

# Run the sync in a separate thread
threading.Thread(target=sync_with_known_nodes, daemon=True).start()

@app.route('/')  
def index():
    username = session.get('username')
    return render_template('index.html', username=username)

@app.route('/transactions/pending', methods=['GET']) 
def get_pending_transactions():
    transactions = [tx.to_dict() for tx in blockchain.pending_transactions]
    return jsonify({'transactions': transactions}), 200

@app.route('/stream')
def stream():
    def event_stream():
        while True:
            try:
                data = sse_queue.get()
                yield f'data: {json.dumps(data)}\n\n'
            except GeneratorExit:
                break

    return Response(event_stream(), mimetype="text/event-stream")

def notify_pending_transactions():
    """
    Periodically sends the latest pending transactions to the SSE stream.
    """
    while True:
        time.sleep(1)  # Adjust the frequency as needed
        transactions = [tx.to_dict() for tx in blockchain.pending_transactions]
        sse_queue.put({'transactions': transactions})
    
# Start the SSE notifier in a separate thread
threading.Thread(target=notify_pending_transactions, daemon=True).start()


@app.route('/transactions/remove', methods=['POST'])
def remove_transactions():
    if blockchain.mining_lock.locked():
        logger.info("Mining is in progress. Skipping removal of transactions.")
        return 'Mining in progress', 200

    data = request.get_json()
    transaction_ids = data.get('transaction_ids', [])

    if not transaction_ids:
        logger.warning("No transaction IDs provided for removal.")
        return 'No transaction IDs provided.', 400

    with blockchain.lock:
        initial_count = len(blockchain.pending_transactions)
        blockchain.pending_transactions = [
            tx for tx in blockchain.pending_transactions if tx.transaction_id not in transaction_ids
        ]
        removed_count = initial_count - len(blockchain.pending_transactions)
        blockchain.pending_transaction_ids -= set(transaction_ids)

    logger.info(f"Removed {removed_count} transactions from pending list.")
    return 'Transactions removed', 200

# app.py (Modified Sections Only)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        try:
            balance = Decimal(request.form['balance'])
            if balance < 0:
                return 'Balance cannot be negative', 400
        except InvalidOperation:
            return 'Invalid balance format', 400

        if username in blockchain.users:
            return 'Username already exists', 400

        # Check if public key and encrypted private key are provided
        public_key_pem = request.form.get('public_key_pem')
        encrypted_private_key_pem = request.form.get('encrypted_private_key_pem')

        if public_key_pem and encrypted_private_key_pem:
            # Use provided keys
            try:
                public_key_pem = public_key_pem.encode('utf-8')
                encrypted_private_key_pem = encrypted_private_key_pem.encode('utf-8')
            except Exception as e:
                logger.error(f"Error encoding provided keys: {e}")
                return 'Invalid key format.', 400
        else:
            # Generate key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
            public_key = private_key.public_key()

            # Serialize public key
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Encrypt private key with the user's password
            password_bytes = password.encode('utf-8')
            encrypted_private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
            )

        # Create and register the user
        user = User(username, public_key_pem, encrypted_private_key_pem, balance)
        user.set_password(password)
        blockchain.register_user(user)

        session['username'] = username
        # Do not store private key in session

        return render_template('registration_success.html')
    else:
        return render_template('register.html')
    
# Existing /register_with_keys endpoint (modified to accept password)
@app.route('/register_with_keys', methods=['POST'])
def register_with_keys():
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password')  # New field for password
    balance = data.get('balance', '0')
    public_key_pem = data.get('public_key_pem')
    encrypted_private_key_pem = data.get('encrypted_private_key_pem')

    if not username or not password or not public_key_pem or not encrypted_private_key_pem:
        return jsonify({'error': 'Missing required fields (username, password, public_key_pem, encrypted_private_key_pem).'}), 400

    try:
        balance = Decimal(balance)
        if balance < 0:
            return jsonify({'error': 'Balance cannot be negative.'}), 400
    except InvalidOperation:
        return jsonify({'error': 'Invalid balance format.'}), 400

    if username in blockchain.users:
        return jsonify({'error': 'Username already exists.'}), 400

    try:
        public_key_pem = public_key_pem.encode('utf-8')
        encrypted_private_key_pem = encrypted_private_key_pem.encode('utf-8')
    except Exception as e:
        logger.error(f"Error encoding provided keys: {e}")
        return jsonify({'error': 'Invalid key format.'}), 400

    # Create and register the user
    user = User(username, public_key_pem, encrypted_private_key_pem, balance)
    user.set_password(password)  # Method to set and hash the password
    blockchain.register_user(user)

    # Optionally, log the user in immediately
    session['username'] = username

    logger.info(f"User '{username}' registered successfully via /register_with_keys.")
    return jsonify({'message': f"User '{username}' registered successfully."}), 200

@app.route('/nodes/list', methods=['GET'])
def list_nodes():
    nodes = list(blockchain.nodes)
    return jsonify({'nodes': nodes}), 200

# app.py (Add this route)
@app.route('/balance', methods=['GET'])
def balance():
    if 'username' not in session:
        logger.warning("Unauthorized access attempt to view balance.")
        return redirect(url_for('login'))
    
    username = session['username']
    user = blockchain.users.get(username)
    if user:
        balance = user.balance
        return render_template('balance.html', username=username, balance=balance)
    else:
        logger.error(f"User '{username}' not found.")
        return 'User not found', 404


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']

        if username not in blockchain.users:
            logger.warning(f"Login failed: User '{username}' not found.")
            return 'User not found', 400

        user = blockchain.users[username]

        # Verify the password
        if not user.check_password(password):
            logger.warning(f"Login failed: Invalid password attempt for user '{username}'.")
            return 'Invalid password', 400

        # Decrypt the private key using the provided password
        encrypted_private_key_pem = user.encrypted_private_key_pem
        password_bytes = password.encode('utf-8')
        try:
            private_key = serialization.load_pem_private_key(
                encrypted_private_key_pem,
                password=password_bytes,
                backend=None
            )
        except Exception as e:
            logger.error(f"Failed to decrypt private key for user '{username}': {e}")
            return 'Failed to decrypt private key.', 400

        # Store the decrypted private key in the session
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        session['username'] = username
        session['private_key_pem'] = private_key_pem.decode('utf-8')

        logger.info(f"User '{username}' logged in successfully.")
        return redirect(url_for('index'))
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    username = session.get('username')
    session.pop('username', None)
    session.pop('private_key_pem', None)
    logger.info(f"User '{username}' logged out.")
    return redirect(url_for('index'))

@app.route('/transactions/new', methods=['GET', 'POST'])
def new_transaction():
    if 'username' not in session:
        logger.warning("Unauthorized access attempt to create a transaction.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        sender = session['username']
        receiver = request.form['receiver'].strip().lower()
        amount = request.form['amount']
        fee = request.form.get('fee', '0')  # Retrieve fee, default to '0' if not provided

        if receiver not in blockchain.users:
            logger.warning(f"Transaction creation failed: Receiver '{receiver}' not found.")
            return 'Receiver not found', 400

        private_key_pem = session.get('private_key_pem')
        if not private_key_pem:
            logger.error("Private key not found in session during transaction creation.")
            return 'Private key not found. Please log in again.', 400

        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'), password=None, backend=None
            )
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            return 'Private key is corrupted. Please log in again.', 400

        # Validate that the amount and fee are valid decimals
        try:
            amount_decimal = Decimal(amount)
            fee_decimal = Decimal(fee)
            if amount_decimal <= 0 or fee_decimal < 0:
                logger.warning(f"Transaction creation failed: Invalid amount {amount_decimal} or fee {fee_decimal}.")
                return 'Amount must be positive and fee cannot be negative.', 400
        except InvalidOperation:
            logger.warning(f"Transaction creation failed: Invalid amount or fee format.")
            return 'Invalid amount or fee format.', 400

        transaction = Transaction(sender, receiver, amount_decimal, fee_decimal)
        transaction.sign_transaction(private_key)

        if blockchain.add_transaction(transaction):
            logger.info(f"Transaction '{transaction.transaction_id}' created by '{sender}'.")
            return redirect(url_for('pending_transactions_page'))
        else:
            logger.error(f"Transaction '{transaction.transaction_id}' failed to be added.")
            return 'Transaction failed', 400
    else:
        return render_template('transactions.html', username=session.get('username'))

@app.route('/pending')
def pending_transactions_page():
    if 'username' not in session:
        logger.warning("Unauthorized access attempt to view pending transactions.")
        return redirect(url_for('login'))
    return render_template('pending_live.html')  # New template for live updates

@app.route('/mine', methods=['GET'])
def mine():
    if 'username' not in session:
        logger.warning("Unauthorized access attempt to mine.")
        return redirect(url_for('login'))

    miner_address = session['username']
    try:
        if blockchain.mining_lock.locked():
            logger.info("Mining is already in progress. Exiting.")
            return jsonify({'message': 'Mining is already in progress.'}), 400

        def mining_thread():
            new_block = blockchain.mine_pending_transactions(miner_address)
            if new_block:
                logger.info(f"Mining complete. Mined block {new_block.index} with hash {new_block.hash}")
            else:
                logger.info("Mining complete. No transactions were mined.")

        threading.Thread(target=mining_thread, daemon=True).start()
        logger.info(f"Mining started by '{miner_address}'.")
        return jsonify({'message': 'Mining started in the background.'}), 200
    except Exception as e:
        logger.error(f"Error during mining: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/chain', methods=['GET'])
def full_chain():
    chain_data = [block.to_dict() for block in blockchain.chain]
    return jsonify({'chain': chain_data, 'length': len(chain_data)}), 200

@app.route('/users', methods=['GET'])
def get_users_route():
    users_data = [user.to_dict() for user in blockchain.users.values()]
    return jsonify({'users': users_data}), 200

@app.route('/users/<username>', methods=['GET'])
def get_user_route(username):
    normalized_username = username.strip().lower()
    user = blockchain.users.get(normalized_username)
    if user:
        user_data = user.to_dict()
        return jsonify({'user': user_data}), 200
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/transactions/receive', methods=['POST'])
def receive_transaction():
    if blockchain.mining_lock.locked():
        logger.info("Mining is in progress. Skipping processing received transaction.")
        return 'Mining in progress', 200

    transaction_data = request.get_json()
    logger.debug(f"Received transaction data: {transaction_data}")  # New log

    try:
        transaction = Transaction(
            sender=transaction_data['sender'].strip().lower(),
            receiver=transaction_data['receiver'].strip().lower(),
            amount=Decimal(transaction_data['amount']),
            fee=Decimal(transaction_data.get('fee', '0')),  # Handle fee
            signature=bytes.fromhex(transaction_data['signature']) if transaction_data.get('signature') else None,
            timestamp=transaction_data['timestamp']
        )
        transaction.transaction_id = transaction_data.get('transaction_id')
        logger.debug(f"Constructed transaction object: {transaction.to_dict()}")
    except (KeyError, InvalidOperation, TypeError) as e:
        logger.error(f"Invalid transaction data received: {e}")
        return 'Invalid transaction data.', 400

    # Ensure users are registered
    with blockchain.lock:
        if transaction.sender != "system" and transaction.sender not in blockchain.users:
            blockchain.fetch_user(transaction.sender)
        if transaction.receiver not in blockchain.users:
            blockchain.fetch_user(transaction.receiver)

    # Trigger conflict resolution to ensure chain is up-to-date
    blockchain.resolve_conflicts()

    added = blockchain.add_transaction(transaction, broadcast=False)
    if added:
        logger.info(f"Received and added transaction '{transaction.transaction_id}'")
    else:
        logger.warning(f"Failed to add transaction '{transaction.transaction_id}'")
    return 'Transaction received', 200

# Add the /nodes/receive endpoint
@app.route('/nodes/receive', methods=['POST'])
def receive_node():
    node = request.get_json().get('node')

    if node:
        blockchain.add_node(node)
        logger.info(f"Received and added new node '{node}' from another node.")
        return 'Node added', 200
    else:
        logger.warning("No node data received in /nodes/receive.")
        return 'No node data provided.', 400

@app.route('/users/receive', methods=['POST'])
def receive_user():
    user_data = request.get_json()
    try:
        user = User.from_dict(user_data)
    except (KeyError, InvalidOperation, TypeError) as e:
        logger.error(f"Invalid user data received: {e}")
        return 'Invalid user data.', 400

    with blockchain.lock:
        normalized_username = user.username.strip().lower()
        if normalized_username not in blockchain.users:
            blockchain.users[normalized_username] = user
            logger.info(f"Received and added user '{user.username}'")
        else:
            logger.info(f"User '{user.username}' already exists. Skipping.")
    return 'User received', 200

@app.route('/nodes', methods=['GET', 'POST'])
def nodes_route():
    if request.method == 'POST':
        node = request.form['node'].strip().lower()
        blockchain.add_node(node)
        logger.info(f"Node '{node}' added via /nodes endpoint.")

        # Broadcast the new node to all existing nodes
        for existing_node in blockchain.nodes.copy():
            if existing_node != node and existing_node != blockchain.node_identifier:
                url = f'http://{existing_node}/nodes/receive'
                try:
                    response = requests.post(url, json={'node': node}, timeout=5)
                    if response.status_code == 200:
                        logger.info(f"Broadcasted new node '{node}' to '{existing_node}', response: {response.status_code}")
                    else:
                        logger.error(f"Failed to broadcast new node '{node}' to '{existing_node}', response: {response.status_code}")
                except requests.exceptions.RequestException as e:
                    logger.error(f"Failed to broadcast new node '{node}' to '{existing_node}': {e}")
                    continue

        return redirect(url_for('nodes_route'))
    else:
        nodes = list(blockchain.nodes)
        return render_template('nodes.html', nodes=nodes)

@app.route('/blocks/receive', methods=['POST'])
def receive_block():
    if blockchain.mining_lock.locked():
        logger.info("Mining is in progress. Skipping processing received block.")
        return 'Mining in progress', 200

    block_data = request.get_json()
    logger.debug(f"Received block data: {block_data}")  # New log

    try:
        block = blockchain.reconstruct_block_from_data(block_data)
        logger.debug(f"Reconstructed block object: {block.to_dict() if block else 'None'}")
    except (KeyError, InvalidOperation, TypeError) as e:
        logger.error(f"Invalid block data received: {e}")
        return f'Invalid block data: {e}', 400

    if not block:
        logger.error("Block reconstruction failed.")
        return 'Block reconstruction failed.', 400

    # Ensure users involved in the block are registered
    blockchain.ensure_users_for_block(block)

    # Validate the received block
    with blockchain.lock:
        if blockchain.get_latest_block().hash != block.previous_hash:
            logger.warning(f"Received block {block.index} has invalid previous hash.")
            return 'Invalid block: Previous hash does not match.', 400

        temp_chain = blockchain.chain + [block]
        if not blockchain.is_chain_valid(temp_chain):
            logger.warning(f"Received block {block.index} is invalid.")
            # Attempt to resolve conflicts
            replaced = blockchain.resolve_conflicts()
            if replaced:
                logger.info("Chain replaced after receiving invalid block.")
                return 'Chain replaced', 200
            else:
                logger.error("Could not resolve conflicts after receiving invalid block.")
                return 'Invalid block: Chain validation failed.', 400

        # Add the block to the chain
        blockchain.chain.append(block)
        blockchain.update_balances_from_chain()
        # Remove mined transactions from pending lists
        mined_transaction_ids = {tx.transaction_id for tx in block.transactions}
        blockchain.pending_transactions = [
            tx for tx in blockchain.pending_transactions if tx.transaction_id not in mined_transaction_ids
        ]
        blockchain.pending_transaction_ids -= mined_transaction_ids
        logger.info(f"Added received block {block.index} with hash {block.hash} to the chain.")
    return 'Block received and added', 200

@app.context_processor
def inject_balance():
    balance = 0
    if 'username' in session:
        user = blockchain.users.get(session['username'])
        if user:
            balance = user.balance
    return dict(balance=balance)

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    try:
        replaced = blockchain.resolve_conflicts()
        if replaced:
            message = 'Our chain was replaced'
            logger.info("Consensus: Our chain was replaced.")
        else:
            message = 'Our chain is authoritative'
            logger.info("Consensus: Our chain is authoritative.")
        return render_template('consensus.html', message=message, chain=blockchain.chain)
    except Exception as e:
        logger.error(f"Error during consensus: {e}")
        return 'An error occurred during consensus.', 500

def periodic_resolve_conflicts():
    while True:
        time.sleep(30)  # Adjust interval as needed
        if blockchain.mining_lock.locked():
            logger.info("Mining is in progress. Delaying periodic conflict resolution.")
            continue

        with app.app_context():
            logger.info("Running periodic conflict resolution")
            try:
                replaced = blockchain.resolve_conflicts()
                if replaced:
                    logger.info("Chain was replaced during periodic conflict resolution.")
            except Exception as e:
                logger.error(f"Error during periodic conflict resolution: {e}")

# Start the periodic conflict resolution in a separate thread
if __name__ == '__main__':
    threading.Thread(target=periodic_resolve_conflicts, daemon=True).start()
    app.run(host='0.0.0.0', port=port)
