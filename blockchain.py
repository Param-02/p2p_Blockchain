# blockchain.py
import hashlib
import time
import json
import threading
from collections import OrderedDict
import requests
from decimal import Decimal, InvalidOperation
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from queue import Queue

# Configure logging
logging.basicConfig(level=logging.DEBUG,  # Set to DEBUG for detailed logs debug, ingo, warning, error
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

def time_function(func):
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        logger.info(f"Started '{func.__name__}'")
        result = func(*args, **kwargs)
        end_time = time.perf_counter() #End time after the function executes
        duration = end_time - start_time
        logger.info(f"Completed '{func.__name__}' in {duration:.6f} seconds")
        return result
    return wrapper


class Transaction:
    def __init__(self, sender, receiver, amount, fee=Decimal('0'), signature=None, timestamp=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = Decimal(str(amount))
        self.fee = Decimal(str(fee))  # New fee attribute
        self.signature = signature
        self.timestamp = str(timestamp) if timestamp is not None else str(time.time())
        self.transaction_id = None

    def calculate_hash(self):
        # Include fee in the hash calculation
        transaction_data = json.dumps(
            {
                'sender': self.sender,
                'receiver': self.receiver,
                'amount': str(self.amount),
                'fee': str(self.fee),  # Include fee
                'timestamp': self.timestamp
            },
            sort_keys=True
        ).encode()
        return hashlib.sha256(transaction_data).hexdigest()

    def to_dict(self, include_transaction_id=True):
        data = OrderedDict({
            'sender': self.sender,
            'receiver': self.receiver,
            'amount': str(self.amount),
            'fee': str(self.fee),  # Include fee
            'timestamp': self.timestamp,
            'signature': self.signature.hex() if self.signature else None
        })
        if include_transaction_id and self.transaction_id:
            data['transaction_id'] = self.transaction_id
        return data

    def sign_transaction(self, private_key):
        transaction_data = json.dumps(
            {
                'sender': self.sender,
                'receiver': self.receiver,
                'amount': str(self.amount),
                'fee': str(self.fee),  # Include fee in signing
                'timestamp': self.timestamp
            },
            sort_keys=True
        ).encode()
        logger.debug(f"Signing transaction data: {transaction_data}")
        self.signature = private_key.sign(
            transaction_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.transaction_id = self.calculate_hash()

    def verify_signature(self, public_key):
        transaction_data = json.dumps(
            {
                'sender': self.sender,
                'receiver': self.receiver,
                'amount': str(self.amount),
                'fee': str(self.fee),  # Include fee in verification
                'timestamp': self.timestamp
            },
            sort_keys=True
        ).encode()
        logger.debug(f"Verifying transaction data: {transaction_data}")
        try:
            public_key.verify(
                self.signature,
                transaction_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failedddd for transaction '{self.transaction_id}': {e}")
            return False

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions  # List of Transaction objects
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = json.dumps(self.to_dict(include_hash=False), sort_keys=True).encode()
        return hashlib.sha256(block_data).hexdigest()

    def to_dict(self, include_hash=True):
        data = OrderedDict({
            'index': self.index,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        })
        if include_hash:
            data['hash'] = self.hash
        return data

# blockchain.py

from werkzeug.security import generate_password_hash, check_password_hash

class User:
    def __init__(self, username, public_key_pem, encrypted_private_key_pem, balance=Decimal('0')):
        self.username = username
        self.public_key_pem = public_key_pem
        self.encrypted_private_key_pem = encrypted_private_key_pem
        self.initial_balance = Decimal(balance)  # Store initial balance
        self.balance = Decimal(balance)  # Current balance
        self.password_hash = None  # Initialize password hash

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)
        logger.debug(f"Password set for user '{self.username}'.")

    def check_password(self, password):
        """Verifies the provided password against the stored hash."""
        if not self.password_hash:
            logger.warning(f"Password hash not set for user '{self.username}'.")
            return False
        is_valid = check_password_hash(self.password_hash, password)
        if is_valid:
            logger.debug(f"Password verification succeeded for user '{self.username}'.")
        else:
            logger.warning(f"Password verification failed for user '{self.username}'.")
        return is_valid

    def get_public_key(self):
        return serialization.load_pem_public_key(self.public_key_pem)

    def to_dict(self):
        """Serializes the user data, including the password hash."""
        return {
            'username': self.username,
            'public_key_pem': self.public_key_pem.decode('utf-8'),
            'encrypted_private_key_pem': self.encrypted_private_key_pem.decode('utf-8'),
            'initial_balance': str(self.initial_balance),  # Include initial balance
            'password_hash': self.password_hash  # Include password hash
        }

    @staticmethod
    def from_dict(data):
        """Deserializes user data, including the password hash."""
        user = User(
            username=data['username'].strip().lower(),
            public_key_pem=data['public_key_pem'].encode('utf-8'),
            encrypted_private_key_pem=data['encrypted_private_key_pem'].encode('utf-8'),
            balance=Decimal(data.get('initial_balance', '0'))
        )
        user.password_hash = data.get('password_hash')
        return user

class Blockchain:
    def __init__(self, node_identifier):
        self.chain = []
        self.pending_transactions = []
        self.pending_transaction_ids = set()
        self.nodes = set()
        self.users = {}
        self.difficulty = 4
        self.node_identifier = node_identifier.strip().lower()
        self.lock = threading.Lock()
        self.mining_lock = threading.Lock()
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], '1732325000.0000000', "0")
        genesis_block.hash = '0000ae235555b3b53dfd4fed5a53d3736f766cb3bf502f869b036fb735900c56'  # Precomputed hash
        self.chain.append(genesis_block)
        # logger.info("Genesis block created with precomputed hash.")


    def get_latest_block(self):
        return self.chain[-1]

    def has_block(self, block_hash):
        return any(block.hash == block_hash for block in self.chain)

    def mine_pending_transactions(self, miner_address, max_transactions=5):
        if not self.mining_lock.acquire(blocking=False):
            logger.info("Mining is already in progress or consensus is running. Exiting mining.")
            return False

        try:
            with self.lock:
                total_transactions = len(self.pending_transactions)
                if total_transactions == 0:
                    logger.info("Transaction queue is empty. Exiting mining.")
                    return False

                logger.info(f"Starting to mine up to {min(max_transactions, total_transactions)} transactions.")

                # Sort transactions by fee descending
                sorted_transactions = sorted(self.pending_transactions, key=lambda tx: tx.fee, reverse=True)
                # Select top N transactions
                batch_transactions = sorted_transactions[:max_transactions]
                transaction_ids_to_mine = [tx.transaction_id for tx in batch_transactions]
                total_fees = sum(tx.fee for tx in batch_transactions)

                logger.info(f"Selected {len(batch_transactions)} transactions for mining with total fees {total_fees}.")

                # Remove selected transactions from pending lists
                self.pending_transactions = [tx for tx in self.pending_transactions if tx.transaction_id not in transaction_ids_to_mine]
                self.pending_transaction_ids -= set(transaction_ids_to_mine)

                # Add mining reward transaction
                block_reward = Decimal("50")
                total_reward = block_reward + total_fees
                reward_tx = Transaction("system", miner_address, total_reward)
                reward_tx.transaction_id = reward_tx.calculate_hash()
                batch_transactions.append(reward_tx)

                # Create new block
                new_block = Block(
                    index=len(self.chain),
                    transactions=batch_transactions,
                    timestamp=str(time.time()),
                    previous_hash=self.get_latest_block().hash
                )
                logger.info(f"Proof of work started for block {new_block.index}.")
                self.proof_of_work(new_block)
                logger.info(f"Proof of work complete for block {new_block.index}, nonce {new_block.nonce}, hash {new_block.hash}")

                # Append the new block to the chain
                self.chain.append(new_block)
                logger.info(f"Mined new block {new_block.index} with hash: {new_block.hash}")

                # Reward the miner
                logger.info(f"Miner '{miner_address}' rewarded with {total_reward} coins.")

                # Update user balances
                self.update_balances_from_chain()

                # Broadcast the new block
                self.broadcast_block(new_block)

        except Exception as e:
            logger.error(f"An error occurred during mining: {e}")
            return False

        finally:
            self.mining_lock.release()
            logger.info("Mining lock released. Mining process complete.")

        return new_block



    def broadcast_transaction_removal(self, transaction_ids):
        """
        Broadcasts a request to all nodes to remove specified transaction IDs from their pending lists.
        """
        removal_data = {'transaction_ids': list(transaction_ids)}
        for node in self.nodes.copy():
            if node != self.node_identifier:
                url = f'http://{node}/transactions/remove'
                try:
                    start_time = time.time()
                    response = requests.post(url, json=removal_data, timeout=5)
                    end_time = time.time()
                    network_latency = (end_time - start_time) * 1000  # in milliseconds
                    if response.status_code == 200:
                        logger.debug(f"Successfully requested removal of transactions {transaction_ids} from '{node}', latency: {network_latency:.2f} ms")
                    else:
                        logger.error(f"Failed to request removal of transactions {transaction_ids} from '{node}', status code: {response.status_code}, latency: {network_latency:.2f} ms")
                except requests.exceptions.RequestException as e:
                    logger.error(f"Exception occurred while requesting transaction removal from '{node}': {e}")
                    continue

    def add_transaction(self, transaction, broadcast=True):
        with self.lock:
            logger.debug(f"Attempting to add transaction '{transaction.transaction_id}'")
            if self.validate_transaction(transaction):
                if transaction.transaction_id not in self.pending_transaction_ids:
                    self.pending_transactions.append(transaction)
                    self.pending_transaction_ids.add(transaction.transaction_id)
                    logger.debug(f"Transaction '{transaction.transaction_id}' queued for mining.")
                    if broadcast:
                        self.broadcast_transaction(transaction)
                    logger.info(f"Transaction '{transaction.transaction_id}' added to pending transactions.")
                else:
                    logger.info(f"Transaction '{transaction.transaction_id}' is already pending.")
                return True
            else:
                logger.info(f"Transaction '{transaction.transaction_id}' failed validation and was not added.")
                return False

    def validate_transaction(self, transaction, user_balances=None):
        # Check if sender and receiver are registered users
        if transaction.sender != "system" and (transaction.sender not in self.users or transaction.receiver not in self.users):
            logger.warning(f"Validation failed: Sender or receiver not registered for transaction '{transaction.transaction_id}'")
            return False
        # Verify the signature
        if transaction.sender == "system":
            return True  # Reward transactions are considered valid without signature
        sender_user = self.users.get(transaction.sender)
        receiver_user = self.users.get(transaction.receiver)
        if not sender_user or not receiver_user:
            logger.warning(f"Validation failed: Sender or receiver user objects not found for transaction '{transaction.transaction_id}'")
            return False
        public_key = sender_user.get_public_key()
        if not transaction.signature:
            logger.warning(f"Validation failed: No signature for transaction '{transaction.transaction_id}'")
            return False
        if not transaction.verify_signature(public_key):
            logger.warning(f"Validation failed: Signature verification failed for transaction '{transaction.transaction_id}', {public_key}")
            return False
        # Check if sender has sufficient balance (amount + fee)
        total_amount = transaction.amount + transaction.fee
        if user_balances is not None:
            sender_balance = user_balances.get(transaction.sender, Decimal('0'))
            if sender_balance < total_amount:
                logger.warning(f"Validation failed: Insufficient balance for transaction '{transaction.transaction_id}', {sender_balance}")
                return False
        else:
            if sender_user.balance < total_amount:
                logger.warning(f"Validation failed: Insufficient balance for transaction '{transaction.transaction_id}', {sender_balance}")
                return False
        return True

    @time_function
    def proof_of_work(self, block):
        target = '0' * self.difficulty
        logger.info(f"Starting proof of work for block {block.index} with target '{target}'")
        while not block.hash.startswith(target):
            block.nonce += 1
            block.hash = block.calculate_hash()
            if block.nonce % 100000 == 0:
                logger.info(f"Still mining block {block.index}, nonce {block.nonce}, hash {block.hash}")
        logger.info(f"Proof of work complete for block {block.index}, nonce {block.nonce}, hash {block.hash}")

    @time_function
    def is_chain_valid(self, chain=None):
        if chain is None:
            chain = self.chain

        # Create a copy of user balances to use for validation
        user_balances = {username: user.initial_balance for username, user in self.users.items()}

        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                logger.error(f"Block {current_block.index} has invalid hash.")
                return False
            if current_block.previous_hash != previous_block.hash:
                logger.error(f"Block {current_block.index} has invalid previous hash.")
                return False
            if not current_block.hash.startswith('0' * self.difficulty):
                logger.error(f"Block {current_block.index} does not meet difficulty requirements.")
                return False
            # Validate transactions in the block
            for tx in current_block.transactions:
                if not tx.transaction_id:
                    logger.error(f"Transaction in block {current_block.index} lacks a transaction ID.")
                    return False
                # Ensure users are registered
                if tx.sender != "system" and tx.sender not in self.users:
                    self.fetch_user(tx.sender)
                if tx.receiver not in self.users:
                    self.fetch_user(tx.receiver)
                if not self.validate_transaction(tx, user_balances=user_balances):
                    logger.error(f"Invalid transaction '{tx.transaction_id}' in block {current_block.index}.")
                    return False
                # Update balances for validation
                if tx.sender != "system":
                    sender_balance = user_balances.get(tx.sender)
                    receiver_balance = user_balances.get(tx.receiver)
                    if sender_balance is not None and receiver_balance is not None:
                        try:
                            amount = tx.amount
                            fee = tx.fee
                            sender_balance -= (amount + fee)
                            if sender_balance < 0:
                                logger.error(f"User '{tx.sender}' has negative balance after transaction '{tx.transaction_id}'")
                                return False
                            user_balances[tx.sender] = sender_balance
                            receiver_balance += amount
                            user_balances[tx.receiver] = receiver_balance
                        except Exception as e:
                            logger.error(f"Error updating balances for transaction '{tx.transaction_id}': {e}")
                            return False
                    else:
                        logger.error(f"User not found during balance update for transaction '{tx.transaction_id}'")
                        return False
                else:
                    # Mining reward includes fees
                    receiver_balance = user_balances.get(tx.receiver)
                    if receiver_balance is not None:
                        amount = tx.amount
                        receiver_balance += amount
                        user_balances[tx.receiver] = receiver_balance
                    else:
                        logger.error(f"User '{tx.receiver}' not found during mining reward distribution")
                        return False
        return True

    def add_node(self, address):
        # Normalize address by removing protocol prefixes and converting to lowercase
        address = address.strip().lower()
        if address.startswith('http://'):
            address = address[len('http://'):]
        elif address.startswith('https://'):
            address = address[len('https://'):]
        self.nodes.add(address)
        logger.info(f"Node '{address}' added to nodes list.")

    def broadcast_transaction(self, transaction):
        transaction_data = transaction.to_dict()
        for node in self.nodes.copy():
            if node != self.node_identifier: # skips transaction to self
                url = f'http://{node}/transactions/receive'
                try:
                    start_time = time.time()
                    response = requests.post(url, json=transaction_data, timeout=5)
                    end_time = time.time()
                    network_latency = (end_time - start_time) * 1000  # in milliseconds
                    if response.status_code == 200:
                        logger.debug(f"Successfully broadcasted transaction '{transaction.transaction_id}' to '{node}', latency: {network_latency:.2f} ms")
                    else:
                        logger.error(f"Failed to broadcast transaction '{transaction.transaction_id}' to '{node}', status code: {response.status_code}, latency: {network_latency:.2f} ms")
                except requests.exceptions.RequestException as e:
                    logger.error(f"Exception occurred while broadcasting transaction '{transaction.transaction_id}' to '{node}': {e}")
                    continue


    def broadcast_block(self, block):
        block_data = block.to_dict()
        for node in self.nodes.copy():
            if node != self.node_identifier:
                url = f'http://{node}/blocks/receive'
                try:
                    start_time = time.time()
                    response = requests.post(url, json=block_data, timeout=5)
                    end_time = time.time()
                    network_latency = (end_time - start_time) * 1000  # in milliseconds
                    if response.status_code == 200:
                        logger.debug(f"Successfully broadcasted block {block.index} to '{node}', latency: {network_latency:.2f} ms")
                    else:
                        logger.error(f"Failed to broadcast block {block.index} to '{node}', status code: {response.status_code}, latency: {network_latency:.2f} ms")
                except requests.exceptions.RequestException as e:
                    logger.error(f"Exception occurred while broadcasting block {block.index} to '{node}': {e}")
                    continue
            else:
                logger.debug(f"Skipping broadcasting block {block.index} to self.")

    def register_user(self, user):
        with self.lock:
            normalized_username = user.username.strip().lower()
            self.users[normalized_username] = user
            logger.info(f"User '{user.username}' registered.")
        success = self.broadcast_user(user)
        if not success:
            logger.warning(f"User '{user.username}' was registered locally but failed to broadcast to some nodes.")

    def broadcast_user(self, user):
        user_data = user.to_dict()
        all_success = True
        for node in self.nodes.copy():
            if node != self.node_identifier:
                url = f'http://{node}/users/receive'
                try:
                    response = requests.post(url, json=user_data, timeout=5)
                    if response.status_code == 200:
                        logger.debug(f"Successfully broadcasted user '{user.username}' to '{node}', response: {response.status_code}")
                    else:
                        logger.error(f"Failed to broadcast user '{user.username}' to '{node}', response: {response.status_code}")
                        all_success = False
                except requests.exceptions.RequestException as e:
                    logger.error(f"Failed to send user data to '{node}': {e}")
                    all_success = False
                    continue
        return all_success

    def fetch_user(self, username):
        # Fetch user data from peer nodes
        normalized_username = username.strip().lower()
        logger.info(f"Attempting to fetch user '{normalized_username}' from peer nodes.")
        for node in self.nodes.copy():
            if node != self.node_identifier:
                try:
                    response = requests.get(f'http://{node}/users/{normalized_username}', timeout=5)
                    if response.status_code == 200:
                        user_data = response.json()['user']
                        user = User.from_dict(user_data)
                        with self.lock:
                            self.users[user.username] = user
                        logger.info(f"Fetched and registered user '{user.username}' from node '{node}'")
                        return
                    else:
                        logger.error(f"Failed to fetch user '{normalized_username}' from node '{node}': HTTP {response.status_code}")
                except requests.exceptions.RequestException as e:
                    logger.error(f"Failed to fetch user '{normalized_username}' from node '{node}': {e}")
        logger.error(f"User '{normalized_username}' could not be found in the network.")

    def resolve_conflicts(self):
        if not self.mining_lock.acquire(blocking=False):
            logger.info("Mining is in progress. Delaying consensus resolution.")
            return False

        try:
            neighbours = self.nodes.copy()
            new_chain = None
            max_length = len(self.chain)

            for node in neighbours:
                if node == self.node_identifier:
                    continue
                try:
                    response = requests.get(f'http://{node}/chain', timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        length = data['length']
                        chain_data = data['chain']
                        chain = self.reconstruct_chain_from_data(chain_data)

                        # Ensure the fetched chain is valid
                        if length > max_length and self.is_chain_valid(chain):
                            max_length = length
                            new_chain = chain
                except requests.exceptions.RequestException as e:
                    logger.error(f"Failed to resolve conflicts with node '{node}': {e}")
                    continue

            if new_chain:
                with self.lock:
                    self.chain = new_chain
                    self.update_balances_from_chain()
                    logger.info("Replaced chain with a longer valid chain from the network.")
                return True

            logger.info("Our chain is authoritative. No conflicts resolved.")
            return False

        finally:
            self.mining_lock.release()
            logger.info("Releasing mining lock after consensus.")

    def ensure_users_for_chain(self, chain):
        usernames_in_chain = set()
        for block in chain:
            for tx in block.transactions:
                usernames_in_chain.add(tx.sender)
                usernames_in_chain.add(tx.receiver)
        usernames_in_chain.discard("system")  # 'system' user does not need to be registered
        missing_usernames = usernames_in_chain - set(self.users.keys())
        if missing_usernames:
            for username in missing_usernames:
                self.fetch_user(username)

    def ensure_users_for_block(self, block):
        usernames_in_block = set()
        for tx in block.transactions:
            usernames_in_block.add(tx.sender)
            usernames_in_block.add(tx.receiver)
        usernames_in_block.discard("system")  # 'system' user does not need to be registered
        missing_usernames = usernames_in_block - set(self.users.keys())
        if missing_usernames:
            for username in missing_usernames:
                self.fetch_user(username)

    def reconstruct_chain_from_data(self, chain_data):
        chain = []
        for block_data in chain_data:
            transactions = []
            for tx_data in block_data['transactions']:
                try:
                    transaction = Transaction(
                        sender=tx_data['sender'].strip().lower(),
                        receiver=tx_data['receiver'].strip().lower(),
                        amount=Decimal(tx_data['amount']),
                        fee=Decimal(tx_data.get('fee', '0')),  # Include fee
                        signature=bytes.fromhex(tx_data['signature']) if tx_data.get('signature') else None,
                        timestamp=tx_data['timestamp']
                    )
                    transaction.transaction_id = tx_data.get('transaction_id')
                    transactions.append(transaction)
                except (KeyError, InvalidOperation, TypeError) as e:
                    logger.error(f"Invalid transaction data in block {block_data.get('index', 'Unknown')}: {e}")
                    continue

            try:
                block = Block(
                    index=block_data['index'],
                    transactions=transactions,
                    timestamp=block_data['timestamp'],
                    previous_hash=block_data['previous_hash'],
                    nonce=block_data['nonce']
                )
                block.hash = block_data['hash']
                chain.append(block)
            except (KeyError, InvalidOperation, TypeError) as e:
                logger.error(f"Invalid block data: {e}")
                continue
        return chain

    def reconstruct_block_from_data(self, block_data):
        transactions = []
        for tx_data in block_data['transactions']:
            try:
                transaction = Transaction(
                    sender=tx_data['sender'].strip().lower(),
                    receiver=tx_data['receiver'].strip().lower(),
                    amount=Decimal(tx_data['amount']),
                    fee=Decimal(tx_data.get('fee', '0')),  # Include fee
                    signature=bytes.fromhex(tx_data['signature']) if tx_data.get('signature') else None,
                    timestamp=tx_data['timestamp']
                )
                transaction.transaction_id = tx_data.get('transaction_id')
                transactions.append(transaction)
            except (KeyError, InvalidOperation, TypeError) as e:
                logger.error(f"Invalid transaction data in block {block_data.get('index', 'Unknown')}: {e}")
                continue
        try:
            block = Block(
                index=block_data['index'],
                transactions=transactions,
                timestamp=block_data['timestamp'],
                previous_hash=block_data['previous_hash'],
                nonce=block_data['nonce']
            )
            block.hash = block_data['hash']
            return block
        except (KeyError, InvalidOperation, TypeError) as e:
            logger.error(f"Invalid block data: {e}")
            return None

    def update_balances_from_chain(self):
        # Reset balances to their initial states
        for user in self.users.values():
            user.balance = user.initial_balance

        # Keep a set of processed transaction IDs to avoid reprocessing
        processed_transaction_ids = set()

        # Recalculate balances based on the chain
        for block in self.chain[1:]:  # Skip genesis block
            for tx in block.transactions:
                if tx.transaction_id in processed_transaction_ids:
                    logger.debug(f"Skipping already processed transaction '{tx.transaction_id}'.")
                    continue

                try:
                    if tx.sender != "system":
                        sender_user = self.users.get(tx.sender)
                        receiver_user = self.users.get(tx.receiver)

                        if not sender_user or not receiver_user:
                            logger.warning(f"User(s) not found for transaction '{tx.transaction_id}'. Skipping.")
                            continue

                        if tx.sender != tx.receiver:
                            amount = tx.amount
                            fee = tx.fee

                            if sender_user.balance < (amount + fee):
                                logger.error(f"Insufficient balance for transaction '{tx.transaction_id}'. Skipping.")
                                continue

                            # Update balances
                            sender_user.balance -= (amount + fee)
                            receiver_user.balance += amount

                    else:
                        receiver_user = self.users.get(tx.receiver)
                        if receiver_user:
                            receiver_user.balance += tx.amount

                    # Mark transaction as processed
                    processed_transaction_ids.add(tx.transaction_id)

                except Exception as e:
                    logger.error(f"Error updating balances for transaction '{tx.transaction_id}': {e}")