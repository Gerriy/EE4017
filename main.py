import hashlib
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import binascii
import json
import requests
from flask import Flask, jsonify, request
from urllib.parse import urlparse
import datetime;
import textwrap

app = Flask(__name__)

# New stuffs blablabla.....

class Transaction:
    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value

    def to_dict(self):
        return ({'sender': self.sender, 'recipient': self.recipient, 'value': self.value})

    def add_signature(self, signature_):
        self.signature = signature_

    def verify_transaction_signature(self):
        if hasattr(self, 'signature'):
            public_key = RSA.importKey(binascii.unhexlify(self.sender))
            verifier = PKCS1_v1_5.new(public_key)
            h = SHA256.new(str(self.to_dict()).encode('utf8'))
            return verifier.verify(h, binascii.unhexlify(self.signature))
        else:
            return False

    def to_json(self):
        return json.dumps(self.__dict__, sort_keys=False)


class Wallet:
    def __init__(self):
        random = Crypto.Random.new().read
        self.private_key = RSA.generate(1024, random)
        self.public_key = self.private_key.publickey()

    def sign_transaction(self, transaction: Transaction):
        signer = PKCS1_v1_5.new(self.private_key)
        h = SHA256.new(str(transaction.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    @property
    def identity(self):
        pubkey = binascii.hexlify(self.public_key.exportKey(format='DER'))
        return pubkey.decode('ascii')

    @property
    def private(self):
        privatekey = binascii.hexlify(self.private_key.exportKey(format='DER'))
        return privatekey.decode('ascii')


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = None
        self.nonce = 0

    def to_dict(self):
        return ({
            'index': self.index,
            'transactinos': self.transactions,
            'timestamp': self.previous_hash,
            'nonce': self.nonce
        })

    def to_json(self):
        return json.dumps(self.__dict__)

    def compute_hash(self):
        return hashlib.sha256(str(self.to_dict()).encode()).hexdigest()


class Blockchain:
    difficulty = 2
    nodes = set()

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"), "0")

        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block.to_json())

    def add_new_transaction(self, transaction: Transaction):
        if transaction.verify_transaction_signature():
            self.unconfirmed_transactions.append(transaction.to_json())
            return True
        else:
            return False

    def add_block(self, block, proof):

        previous_hash = self.last_block['hash']

        if previous_hash != block.previous_hash:
            return False

        if not self.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block.to_json())
        return True

    def is_valid_proof(self, block, block_hash):

        return (block_hash.startswith('0' * Blockchain.difficulty) and block_hash == block.compute_hash())

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def mine(self, myWallet):
        block_reward = Transaction("Block_Reward", myWallet.identity, "5.0").to_json()
        self.unconfirmed_transactions.insert(0, block_reward)
        if not self.unconfirmed_transactions:
            return False

        new_block = Block(index=self.last_block['index'] + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                          previous_hash=self.last_block['hash'])

        proof = self.proof_of_work(new_block)
        if self.add_block(new_block, proof):
            self.unconfirmed_transactions = []
            return new_block

        else:
            return False

    def register_node(self, node_url):

        # Checking node_url has valid format
        parsed_url = urlparse(node_url)

        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)

        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)

        else:
            raise ValueError('Invalid URL')

    def consensus(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get('http://' + node + '/fullchain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = json.loads(new_chain)
            return True
        return False

    def valid_chain(self, chain):

        current_index = 0
        chain = json.loads(chain)
        while current_index < len(chain):
            block = json.loads(chain[current_index])
            current_block = Block(block['index'],
                                  block['transactions'],
                                  block['timestamp'],
                                  block['previous_hash'])
            current_block.hash = block['hash']
            current_block.nonce = block['nonce']

            if current_index + 1 < len(chain):
                if current_block.compute_hash() != json.loads(chain[current_index + 1])['previous_hash']:
                    return False
            if isinstance(current_block.transactions, list):
                for transaction in current_block.transactions:
                    transaction = json.loads(transaction)

                    if transaction['sender'] == 'Block_Reward':
                        continue
                    current_transaction = Transaction(transaction['sender'],
                                                      transaction['recipient'],
                                                      transaction['value'])
                    current_transaction.signature = transaction['signature']

                    if not current_transaction.verify_transaction_signature():
                        return False
                    if not self.is_valid_proof(current_block, block['hash']):
                        return False
            current_index += 1
        return True

    @property
    def last_block(self):
        return json.loads(self.chain[-1])


@app.route('/new_transaction', methods=["POST"])
def new_transaction():
    value = request.form
    required = ['recipient_address', 'amount']
    if not all(k in value for k in required):
        return 'Missing value', 400

    transaction = Transaction(myWallet.identity, value['recipient_address'], value['amount'])
    transaction.add_signature(myWallet.sign_transaction(transaction))
    transaction_result = blockchain.add_new_transaction(transaction)

    if transaction_result:
        response = {'message': 'Transaction will be added to block '}
        return jsonify(response), 201
    else:
        response = {'message': 'Invalid Transaction '}
        return jsonify(response), 406


@app.route('/get_transactions', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.unconfirmed_transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def part_chain():
    response = {
        'chain': blockchain.chain[-10:],
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/fullchain', methods=['GET'])
def full_chain():
    response = {
        'chain': json.dumps(blockchain.chain),
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/get_nodes', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/register_node', methods=['POST'])
def register_node():
    values = request.form
    node = values.get('node')
    com_port = values.get('com_port')

    if com_port is not None:
        blockchain.register_node(request.remote_addr + ":" + com_port)
        return "ok", 200

    if node is None and com_port is None:
        return "Error: Please supply a valid nodes", 400

    blockchain.register_node(node)

    node_list = requests.get('http://' + node + '/get_nodes')

    if node_list.status_code == 200:
        node_list = node_list.json()['nodes']
        for node in node_list:
            blockchain.register_node(node)
    for new_nodes in blockchain.nodes:
        requests.post('http://' + new_nodes + '/register_node', data={'com_port': str(port)})

    replaced = blockchain.consensus()
    if replaced:
        response = {
            'message': 'Longer authoritative chain found from peers, replacing ours',
            'total_nodes': [node for node in blockchain.nodes]
        }
    else:
        response = {
            'message': 'New nodes have been added, but our chain is authoritative',
            'total_nodes': [node for node in blockchain.nodes]
        }
    return jsonify(response), 201


@app.route('/consensus', methods=['GET'])
def consensus():
    replaced = blockchain.consensus()
    if replaced:
        response = {
            'message': 'Our chain was replaced',
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
        }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    newblock = blockchain.mine(myWallet)
    for node in blockchain.nodes:
        requests.get('http://' + node + '/consensus')
    response = {
        'index': newblock.index,
        'transactions': newblock.transactions,
        'timestamp': newblock.timestamp,
        'nonce': newblock.nonce,
        'hash': newblock.hash,
        'previous_hash': newblock.previous_hash
    }
    return jsonify(response), 200


if __name__ == "__main__":
    myWallet = Wallet()
    print(myWallet.identity)
    blockchain = Blockchain()
    port = 5000
    app.run(host='127.0.0.1', port=port)
