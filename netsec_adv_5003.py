# Create a Cryptocurrency

# Importing the libraries
import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
from ecdsa import SigningKey, VerifyingKey, NIST384p

# Building a Blockchain

class Blockchain:

    def __init__(self):
        self.chain = []
        self.private_key = SigningKey.generate()
        self.public_key = (self.private_key).verifying_key.to_string().hex()
        self.public_addr = hashlib.sha256(str(self.public_key).encode()).hexdigest() #public addr
        self.transactions = []
        nonce, cur_hash = self.proof_of_work(1,"", 0)
        self.create_block(1, nonce, "", '0',cur_hash)
        self.nodes = set()  #maintains nodes in network
        print(f'public addr:{self.public_addr}')

    def proof_of_work(self, index, data, prev_hash):
        data = str(index) + data + str(prev_hash)
        nonce = 1
        check_proof = False
        cur_hash = ''
        while check_proof is False:
            hash_operation = hashlib.sha256((data + str(nonce)).encode()).hexdigest()
            #hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
                cur_hash = hash_operation
            else:
                nonce += 1
        return nonce, cur_hash
    
    def create_block(self, index, nonce, data, prev_hash, cur_hash):
        """
        # fetch transactions from mempool
        data = []
        if(len(self.transactions) >= 5):
            data = self.transactions[:5]
        else:
            data = self.transactions
        """    
        block = {'index': index,
                 'timestamp': str(datetime.datetime.now()),
                 'nonce': nonce,
                 'transactions': data,
                 'previous_hash': prev_hash,
                 'current_hash': cur_hash}
        # remove added transactions
        #del self.transactions[:5]
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]    
    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != previous_block['current_hash']:  #self.hash(previous_block):
                return False
            #previous_proof = previous_block['proof']
            #proof = block['proof']
            """
            data = str(block['index']) + str(block['transactions']) + str(block['previous_hash'])
            hash_operation = hashlib.sha256((data + str(block['nonce'])).encode()).hexdigest()
            if hash_operation != block['current_hash']:
                return False
            """
            previous_block = block
            block_index += 1
        return True
    
    def add_transaction(self, sender, receiver, amount, public_key, timestamp, signature):                                       
        self.transactions.append({'sender': sender,
                                  'receiver': receiver,
                                  'amount': amount,
                                  'timestamp': timestamp,
                                  'public_key': public_key,
                                  'signature': signature})
        #previous_block = self.get_previous_block()
        #return previous_block['index'] + 1
    
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            print(response.json())
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False
    
    def broadcast(self, post_data):
        # returns no. of nodes to which trans wasn't broadcasted
        not_sent = 0
        network = self.nodes
        for node in network:
            response = requests.post(f'http://{node}/add_broadcast_trans', 
                                     json = post_data)
            print(f'http://{node}/add_broadcast_trans - {response.status_code}')
            if(response.status_code != 201):
                if(response.status_code == 500):
                    # invalid transation and remove its entry
                    for index in reversed(range(len(self.transactions))):
                        if(self.transactions[index]['signature'] == post_data['signature']):
                            del self.transactions[index]
                        
                    return -1 
                not_sent += 1               
        return not_sent

# Mining our Blockchain

# Creating a Web App
app = Flask(__name__)

# Creating an address for the node on Port 5000
# this node rewards the miner
node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()

# Mining a new block
@app.route('/mine_block', methods = ['GET'])
def mine_block():
    if len(blockchain.transactions) == 0:
        response = {'message':"Block should contain atleast 1 transaction"}
        return jsonify(response), 500
    
    previous_block = blockchain.get_previous_block()
    prev_hash = previous_block['current_hash']
    prev_index = previous_block['index']
    data = []
    if(len(blockchain.transactions) >= 5):
        data = blockchain.transactions[:5]
    else:
        data = blockchain.transactions[:]
    nonce, cur_hash = blockchain.proof_of_work((prev_index + 1), str(data), prev_hash)
    #previous_hash = blockchain.hash(previous_block)
    #blockchain.add_transaction(sender = node_address, receiver = 'Hadelin', amount = 1)
    block = blockchain.create_block((prev_index + 1), nonce, data, prev_hash, cur_hash)
    # Once trans are added to block they have to be removed from mempool
    if(len(blockchain.transactions) >= 5):
        del blockchain.transactions[:5]
    else:
        blockchain.transactions.clear()
        
    response = {'message': 'Congratulations, you just mined a block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'nonce': block['nonce'],
                'transactions': block['transactions'],
                'previous_hash': block['previous_hash'],
                'current_hash': block['current_hash']}
    return jsonify(response), 200

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

# Checking if the Blockchain is valid
@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'The Blockchain is valid.'}
    else:
        response = {'message': 'The Blockchain is not valid.'}
    return jsonify(response), 200

# Adding a new transaction to the Blockchain
@app.route('/add_transaction', methods = ['POST'])
def add_transaction():
    
    # rcvd_json stores POST data
    rcvd_json = request.get_json()
    #print("***********************")
    #print(rcvd_json)
    # check if transaction contains reqd fields 
    transaction_keys = ['receiver', 'amount']
    if not all(key in rcvd_json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400
    
    # add extra fields: sender, sender's public key and transaction signature
    rcvd_json['sender'] = blockchain.public_addr
    rcvd_json['timestamp'] = str(datetime.datetime.now())
    rcvd_json['public_key'] = blockchain.public_key
    
    # find transaction signature and include it in transaction
    encoded_trans = json.dumps(rcvd_json, sort_keys = True).encode()
    signature = blockchain.private_key.sign(encoded_trans)
    rcvd_json['signature'] = signature.hex()
    blockchain.add_transaction(rcvd_json['sender'], rcvd_json['receiver'], 
                                       rcvd_json['amount'], rcvd_json['public_key'],
                                       rcvd_json['timestamp'], rcvd_json['signature'])
    response = {'message': 'Transaction added to blockchain',
                'transaction': rcvd_json}
    
    # broadcast transaction to other nodes
    status = blockchain.broadcast(rcvd_json)
    if status < 0:
        return jsonify({'message':'Invalid transaction'}), 500
    elif(status == 0):
        return jsonify(response), 201
    elif(status == len(blockchain.nodes)):
        return jsonify({'message' : 'Unable to broadcast transaction to any adj nodes'}), 500
    else:
        return jsonify({'message' : f'Unable to broadcast transaction to {status} adj nodes'}), 201


# Adding a new broadcasted transaction 
@app.route('/add_broadcast_trans', methods = ['POST'])
def add_broadcast_trans():
    """
    Accepts broadcasted transaction.
    
    Before adding transaction in mempool we check if transaction is valid and if
    its already added. For this we compare each transaction in mempool with particular signature. If we found the 
    transaction with matching signature then we don't add the transaction.
    """
    # check if transaction is valid 
    rcvd_json = request.get_json()
    """
    rcvd_trans = rcvd_json
    del rcvd_trans['signature']
    encoded_br_trans = json.dumps(rcvd_trans, sort_keys = True).encode()
    try:
        rcvd_json['public_key'].verify(rcvd_json['signature'], encoded_br_trans)
    except:
        # signature didn't match
        response = {'message':'Invalid transaction.'}
        return jsonify(response), 500
    """
        # verify if its legit transaction
    sender_public_key = VerifyingKey.from_string(bytes.fromhex(rcvd_json['public_key'])
                                                 )#curve=ecdsa.SECP256k1
    rcvd_trans = {}
    rcvd_trans['sender'] = rcvd_json['sender']
    rcvd_trans['receiver'] = rcvd_json['receiver'] 
    rcvd_trans['amount'] = rcvd_json['amount']
    rcvd_trans['public_key'] = rcvd_json['public_key']
    rcvd_trans['timestamp'] = rcvd_json['timestamp']
    
    #del rcvd_trans['signature']
    encoded_br_trans = json.dumps(rcvd_trans, sort_keys = True).encode()

    try:
        sender_public_key.verify(bytes.fromhex(rcvd_json['signature']), encoded_br_trans)
        print("*******valid transaction******")
    except:
        # signature didn't match
        print("*******invalid transaction******")
        response = {'message':'Invalid transaction.'}
        return jsonify(response), 500
    # if trans originated from this node then don't add the trans.
    if rcvd_json['sender'] == blockchain.public_addr:
        response = {'message': 'transaction already added in mempool'}
        return jsonify(response), 201
    
    mempool = blockchain.transactions
    for trans in mempool:
        if trans['signature'] == rcvd_json['signature']:
            response = {'message': 'transaction already added in mempool'}
            return jsonify(response), 201
   
    # no matching transaction found, so add the transaction
    blockchain.add_transaction(rcvd_json['sender'], rcvd_json['receiver'], 
                                       rcvd_json['amount'], rcvd_json['public_key'],
                                       rcvd_json['timestamp'], rcvd_json['signature'])

    # broadcast the transaction to adjacent nodes
    status = blockchain.broadcast(rcvd_json)
    if(status == 0):
        response = {'message' : 'Successfully broadcasted the transaction.'}        
    else:
        response = {'message' : 'Unable to broadcast transaction to all adj nodes'}
    
    return jsonify(response), 201

# Decentralizing our Blockchain

# Connecting new nodes
@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected. The Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

# Replacing the chain by the longest chain if needed
@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200

# Running the app
app.run(host = '0.0.0.0', port = 5003)
