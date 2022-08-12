import logging
from typing import Any
import os

import requests
from eth_typing import URI
from web3._utils.request import _get_session
from web3.providers.rpc import HTTPProvider
from web3.types import Middleware, RPCEndpoint, RPCResponse
from requests_auth_aws_sigv4 import AWSSigV4

from web3 import Web3
from web3.middleware import geth_poa_middleware

import boto3

import matplotlib.pyplot as plt
from datetime import datetime, time
import time
import json
from requests import get
import random as rand

"""
Note: Everytime you open this environment, make sure you set these environment variables:

export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_REGION=us-east-1
export AMB_HTTPS_ENDPOINT=https://nd-hcjkzvwiajamffnornl647yxze.ethereum.managedblockchain.us-east-1.amazonaws.com/
export SENDER_WALLET_ADDRESS=
export RECEIVER_WALLET_ADDRESS=

"""

# -------- Signature and HTTP Endpoint Setup -------- #

aws_auth = AWSSigV4(
    'managedblockchain',
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
    region=os.environ.get('AWS_REGION') # us-east-1
)


def make_post_request(
        endpoint_uri: URI, data: bytes, *args: Any, **kwargs: Any) -> bytes:
    kwargs.setdefault('timeout', 10)
    session = _get_session(endpoint_uri)
    # https://github.com/python/mypy/issues/2582
    response = session.post(endpoint_uri, data=data,
                            *args, **kwargs, auth=aws_auth)  # type: ignore
    response.raise_for_status()

    return response.content


class AMBHTTPProvider(HTTPProvider):
    def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        self.logger.debug("Making request HTTP. URI: %s, Method: %s",
                          self.endpoint_uri, method)

        # .decode() since the AWS sig library expects a string.
        request_data = self.encode_rpc_request(method, params).decode()
        raw_response = make_post_request(
            self.endpoint_uri,
            request_data,
            **self.get_request_kwargs()
        )
        response = self.decode_rpc_response(raw_response)
        self.logger.debug("Getting response HTTP. URI: %s, "
                          "Method: %s, Response: %s",
                          self.endpoint_uri, method, response)
        return response
        
# -------- Check if we are connected to the node / network -------- #
async_provider = AMBHTTPProvider(endpoint_uri=os.environ.get('AMB_HTTPS_ENDPOINT'))
async_w3 = Web3(async_provider)

# inject the poa compatibility middleware to the innermost layer (needed for Rinkeby Network)
async_w3.middleware_onion.inject(geth_poa_middleware, layer=0)

# confirm that the connection is successful
print("Are we connected?:\n", async_w3.isConnected())
print("client version:\n", async_w3.clientVersion)


# ---------------- Secrets Manager Code ---------------------- #

def get_wallet_private_key():
    secrets_manager_client = boto3.client(
        'secretsmanager'
    )
    
    iam = boto3.resource('iam')
    current_user = iam.CurrentUser().user_name
    
    if (current_user == 'elizabeth-dev'):
        response = secrets_manager_client.get_secret_value(
            SecretId='ElizabethWalletPrivateKeyTest'
        )
        secret_string = response["SecretString"]
        secret_dict = json.loads(secret_string)
        return secret_dict['ElizabethWalletPrivateKey']
        
    elif (current_user == 'mrwong1'):
        response = secrets_manager_client.get_secret_value(
            SecretId='mrwong1testprivkey'
        )
        secret_string = response["SecretString"]
        secret_dict = json.loads(secret_string)
        return secret_dict['mrwong1testwalletprivkey']
    else:
        print("You do not have access to any of these secrets.")

def get_etherscan_api_key():
    secrets_manager_client = boto3.client(
        'secretsmanager'
    )
    response = secrets_manager_client.get_secret_value(
        SecretId='BlockchainProjectSecrets'
    )
    secret_string = response["SecretString"]
    secret_dict = json.loads(secret_string)
    return secret_dict['EtherscanAPIKey']
    
def get_test_account_info():
    "returns as a list"
    secrets_manager_client = boto3.client(
        'secretsmanager'
    )
    response = secrets_manager_client.get_secret_value(
        SecretId='BlockchainProjectSecrets'
    )
    secret_string = response["SecretString"]
    secret_dict = json.loads(secret_string)
    
    public_private_key_pair = []
    for key in secret_dict:
        if (key.startswith("TestAccount")):
            public_private_key_pair.append(secret_dict[key])
    
    return public_private_key_pair
    
    
# -------- Testing out Web3.eth API Calls (Methods) -------- #
sender_wallet_address = os.environ.get('SENDER_WALLET_ADDRESS')
receiver_wallet_address = os.environ.get('RECEIVER_WALLET_ADDRESS')
sender_wallet_private_key = get_wallet_private_key()
def make_transaction(wei_to_send):
    signed_txn = async_w3.eth.account.sign_transaction(dict(
        nonce=async_w3.eth.get_transaction_count(sender_wallet_address),
        maxFeePerGas=3000000000,
        maxPriorityFeePerGas=2000000000,
        gas= 100000 ,
        to=receiver_wallet_address,
        value= wei_to_send,
        data=b'',
        type=2,  # (optional) the type is now implicitly set based on appropriate transaction params
        chainId= async_w3.eth.chainId,
      ),
      sender_wallet_private_key,
    )
    
    transaction_hash = async_w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    
def make_several_transactions(wei_to_send_list):
    loop_nonce = async_w3.eth.get_transaction_count(sender_wallet_address)
    for list_value in wei_to_send_list:
        signed_txn = async_w3.eth.account.sign_transaction(dict(
            nonce= loop_nonce,
            maxFeePerGas=3000000000,
            maxPriorityFeePerGas=2000000000,
            gas= 100000 ,
            to=receiver_wallet_address,
            value= list_value,
            data=b'',
            type=2,  # (optional) the type is now implicitly set based on appropriate transaction params
            chainId= async_w3.eth.chainId,
          ),
          sender_wallet_private_key,
        )
        
        transaction_hash = async_w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        loop_nonce = loop_nonce+1
        
def make_transaction_with_defined_account(wei_to_send, sender_account_public_address, sender_account_private_key, reciever_account_public_address, transaction_nonce=None):
    if (transaction_nonce == None):
        transaction_nonce = async_w3.eth.get_transaction_count(sender_account_public_address)
    signed_txn = async_w3.eth.account.sign_transaction(dict(
        nonce= transaction_nonce,
        maxFeePerGas=3000000000,
        maxPriorityFeePerGas=2000000000,
        gas= 100000 ,
        to=reciever_account_public_address,
        value= wei_to_send,
        data=b'',
        type=2,  # (optional) the type is now implicitly set based on appropriate transaction params
        chainId= async_w3.eth.chainId,
      ),
      sender_account_private_key,
    )
    
    transaction_hash = async_w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    
def make_several_random_transactions(account_list, num_transactions):
    prev_index = -1
    num_transactions_for_accounts = []
    for i in account_list:
        num_transactions_for_accounts.append(0)
    for i in range(0,num_transactions):
        rand_index_1 = rand.randint(0,len(account_list)-1)
        while(rand_index_1 == prev_index):
            rand_index_1 = rand.randint(0,len(account_list)-1)
        rand_index_2 = rand.randint(0,len(account_list)-1)
        while(rand_index_1 == rand_index_2):
            rand_index_2 = rand.randint(0,len(account_list)-1)
        sender_info = account_list[rand_index_1].split(",")
        reciever_info = account_list[rand_index_2].split(",")
        wei_to_send = rand.randint(1000000000000000, 20000000000000000)
        sender_nonce = async_w3.eth.get_transaction_count(sender_info[0]) + num_transactions_for_accounts[rand_index_1]
        make_transaction_with_defined_account(wei_to_send, sender_info[0], sender_info[1], reciever_info[0], transaction_nonce = sender_nonce)
        num_transactions_for_accounts[rand_index_1] += 1
        prev_index = rand_index_1
    
def get_latest_transaction_from_wallet(wallet_address):
    current_block = async_w3.eth.get_block('latest')
    current_block = current_block['number']
    block_transaction_list = async_w3.eth.get_block(current_block)
    block_transaction_list = block_transaction_list['transactions']
    account_transaction_hash = ''
    transactions_found = 0
    
    print('current block number:', current_block)
    while (transactions_found < 1):
        print('starting on block:', current_block)
        print("number of transaction in list:", len(block_transaction_list))
        for transaction in block_transaction_list:
            transaction_data = async_w3.eth.get_transaction(Web3.toHex(transaction))
            if ((transaction_data['to'] == wallet_address) or (transaction_data['from'] == wallet_address)):
                transactions_found += 1
                account_transaction_hash_list = Web3.toHex(transaction)
                print('Found latest transaction')
        print('Done with block:', current_block)            
        current_block = current_block - 1
        block_transaction_list = async_w3.eth.get_block(current_block)
        block_transaction_list = block_transaction_list['transactions']
    
    return account_transaction_hash
    
def get_wallet_history(wallet_address):
    account_transaction_count = 4 #async_w3.eth.get_transaction_count(wallet_address)
    current_block = async_w3.eth.get_block('latest')
    current_block = current_block['number']
    block_transaction_list = async_w3.eth.get_block(current_block)
    block_transaction_list = block_transaction_list['transactions']
    account_transaction_hash_list = []
    transactions_found = 0
    
    print('current block number:', current_block)
    while (transactions_found < account_transaction_count):
        print('starting on block:', current_block)
        print("number of transaction in list:", len(block_transaction_list))
        for transaction in block_transaction_list:
            transaction_data = async_w3.eth.get_transaction(Web3.toHex(transaction))
            if ((transaction_data['to'] == wallet_address) or (transaction_data['from'] == wallet_address)):
                transactions_found += 1
                account_transaction_hash_list.append(Web3.toHex(transaction))
                print('Found transaction number', transactions_found, 'of', account_transaction_count)
        print('Done with block:', current_block)            
        current_block = current_block - 1
        block_transaction_list = async_w3.eth.get_block(current_block)
        block_transaction_list = block_transaction_list['transactions']
    
    return account_transaction_hash_list
    
def update_transactions_file():
    transaction_list = get_wallet_history(sender_wallet_address)   
    file = open('transaction_list.txt', 'w')

    for item in transaction_list:
        file.write(str(item) + "\n")
    
    file.close()
    
def pretty_print_transaction_info(transaction_hash):
    transaction = async_w3.eth.get_transaction(transaction_hash)
    print("Transaction:", transaction_hash)
    print("From:", transaction['from'] )
    print("To:", transaction['to'])
    print("Value:", transaction['value'])
    print("Block Number:", transaction['blockNumber'])

def check_if_sender_reciever_valid(sender = sender_wallet_address, receiver = receiver_wallet_address):
    print("Is Sender Address Valid?:", async_w3.isAddress(sender))
    print("Is Receiver Address Valid?:",async_w3.isAddress(receiver))

def pretty_print_transaction_reciept(transaction_hash):
    receipt = async_w3.eth.get_transaction_receipt(transaction_hash)
    print(receipt)
    
def get_list_of_transaction_hashes_from_file():
    file = 'transaction_list.txt'
    
    hash_list = []
    with open(file) as f:
        hash_list = f.read().splitlines()
    
    return hash_list
    
def get_list_of_values_from_t_hash_list(hash_list):
    values = []
    for hash in hash_list:
        values.append(async_w3.eth.get_transaction(hash)['value'])
    return values
    
def get_list_of_dates_from_transaction_hash_list(hash_list):
    dates = []
    for hash in hash_list:
        block_number = async_w3.eth.get_transaction(hash)['blockNumber']
        date_time = datetime.fromtimestamp(async_w3.eth.get_block(block_number)['timestamp'])
        dates.append(date_time.minute)
    return dates
    

def make_graph(x_list,y_list):
    plt.plot(x_list, y_list, color = 'g', linestyle = 'dashed',
         marker = 'o',label = "Number of Transactions")
  
    plt.xticks(rotation = 25)
    plt.xlabel('Minute')
    plt.ylabel('Value')
    plt.title('Value of Transactions in one Hour', fontsize = 20)
    plt.grid()
    plt.show()
    plt.savefig('graph.png')
    
# ---------------- Creating Several Transactions on the Network and Storing Them ----------------------- #

TEST_ACCOUNTS = get_test_account_info()



    
# ---------------- Tracking Ethereum Account Balances Using Etherscan API ----------------------- #

API_KEY = get_etherscan_api_key()
MAINNET_BASE_URL = "https://api.etherscan.io/api"
ETHER_VALUE = 10 ** 18
MAINNET_ADDRESS = "0x3D5202A0564De9B05eCd07C955BcCA964585ea03" #address of desired wallet

def mainnet_make_api_url(module, action, mainnet_address, **kwargs):
	url = MAINNET_BASE_URL + f"?module={module}&action={action}&address={mainnet_address}&apikey={API_KEY}"

	for key, value in kwargs.items():
		url += f"&{key}={value}"

	return url

def mainnet_get_account_balance(mainnet_address):
	balance_url = mainnet_make_api_url("account", "balance", mainnet_address, tag="latest")
	response = get(balance_url)
	data = response.json()

	value = int(data["result"]) / ETHER_VALUE
	return value


def mainnet_get_transactions(mainnet_address):
	transactions_url = mainnet_make_api_url("account", "txlist", mainnet_address, startblock=0, endblock=15046210, page=1, offset=10000, sort="asc")
	response = get(transactions_url)
	data = response.json()["result"]

	internal_tx_url = mainnet_make_api_url("account", "txlistinternal", mainnet_address, startblock=0, endblock=15046210, page=1, offset=10000, sort="asc")
	response2 = get(internal_tx_url)
	data2 = response2.json()["result"]

	data.extend(data2)
	data.sort(key=lambda x: int(x['timeStamp']))

	current_balance = 0
	balances = []
	times = []
	
	for tx in data:
		to = tx["to"]
		from_addr = tx["from"]
		value = int(tx["value"]) / ETHER_VALUE

		if "gasPrice" in tx:
			gas = int(tx["gasUsed"]) * int(tx["gasPrice"]) / ETHER_VALUE
		else:
			gas = int(tx["gasUsed"]) / ETHER_VALUE

		time = datetime.fromtimestamp(int(tx['timeStamp']))
		money_in = to.lower() == mainnet_address.lower()

		if money_in:
			current_balance += value
		else:
			current_balance -= value + gas

		balances.append(current_balance)
		times.append(time)

	plt.plot(times, balances)
	plt.savefig('graph.png')
	

mainnet_eth=mainnet_get_account_balance(MAINNET_ADDRESS)
print(mainnet_eth)
mainnet_get_transactions(MAINNET_ADDRESS)


  
# ---------------- Tracking Ethereum Account Balances Using Rinkeby Testnet Etherscan API ----------------------- #

API_KEY = get_etherscan_api_key()
RINKEBY_BASE_URL = "https://api-rinkeby.etherscan.io/api"
ETHER_VALUE = 10 ** 18
RINKEBY_ADDRESS = "0x483914Cbc70046e34002bA8e495Bd4B427470902" #address of desired wallet

def rinkeby_make_api_url(module, action, rinkeby_address, **kwargs):
	url = RINKEBY_BASE_URL + f"?module={module}&action={action}&address={rinkeby_address}&apikey={API_KEY}"

	for key, value in kwargs.items():
		url += f"&{key}={value}"

	return url

def rinkeby_get_account_balance(rinkeby_address):
	rinkeby_balance_url = rinkeby_make_api_url("account", "balance", rinkeby_address, tag="latest")
	rinkeby_response = get(rinkeby_balance_url)
	rinkeby_data = rinkeby_response.json()

	rinkeby_value = int(rinkeby_data["result"]) / ETHER_VALUE
	print("I'm in rinkeby_get_account_balance()")
	return rinkeby_value
    

def rinkeby_get_transactions(rinkeby_address):
	rinkeby_transactions_url = rinkeby_make_api_url("account", "txlist", rinkeby_address, startblock=10805381, endblock=10937380, page=1, offset=10000, sort="asc")
	rinkeby_response = get(rinkeby_transactions_url)
	rinkeby_data = rinkeby_response.json()["result"]

#     For now, this is unnecessary since we havent made and contracts or transfered ether through contracts
# 	internal_tx_url = make_api_url("account", "txlistinternal", rinkeby_address, startblock=0, endblock=1093713, page=1, offset=10000, sort="asc")
# 	response2 = get(internal_tx_url)
# 	data2 = response2.json()["result"]

# 	data.extend(data2)
# 	data.sort(key=lambda x: int(x['timeStamp']))
	

	current_balance = 0
	balances = []
	times = []
	
	for tx in rinkeby_data:
		to = tx["to"]
		from_addr = tx["from"]
		value = int(tx["value"]) / ETHER_VALUE

		if "gasPrice" in tx:
			gas = int(tx["gasUsed"]) * int(tx["gasPrice"]) / ETHER_VALUE
		else:
			gas = int(tx["gasUsed"]) / ETHER_VALUE

		time = datetime.fromtimestamp(int(tx['timeStamp']))
		money_in = to.lower() == rinkeby_address.lower()

		if money_in:
			current_balance += value
		else:
			current_balance -= value + gas
			
		balances.append(current_balance)
		times.append(time)

	plt.plot(times, balances)
	plt.savefig('rinkebygraph.png')

rinkeby_eth=rinkeby_get_account_balance(RINKEBY_ADDRESS)
print(rinkeby_eth)
rinkeby_get_transactions(RINKEBY_ADDRESS)

# ---------------- Main Demo Method Calls ----------------------- #

print("-------- Begin Demo ------------")

print("Here's what we have done so far....\n")

print("We can query the node for data. Here are a few examples:\n")

print("We can get balances:")
print("Elizabeth's Wallet Balance:", async_w3.eth.get_balance('0x483914Cbc70046e34002bA8e495Bd4B427470902'))
print("Michael's Wallet Balance:", async_w3.eth.get_balance('0x5FD6e2054A3d7c1Fd025c7D4a38D020a065C986d'),"\n")

print("We can get get info from a transaction hash:")
pretty_print_transaction_info('0x0fd363068722006388bfa938ee8be9e54af90f29ba90b0ab5dfde55c1f583e05')
print("This is the latest transaction grabbed from Etherscan,\n but we can also find the latest transaction ourselves by iterating through the data in the blockchain.")

user_input = input("Would you like to see it go? Type 'y' for yes or 'n' for no: ")

if (user_input == 'y'):
    print("Here is the latest transaction hash from sender wallet:")
    print(get_latest_transaction_from_wallet(sender_wallet_address))
    
print()
    
print("We can also programatically send Ether to each other")
print("The sender will now make and sign a transaction.")

user_input = input("Would you like to send 1 ether? Type 'y' for yes and 'n for no: ")
if (user_input == 'y'):
    make_transaction(10000000000000000)

print("Now check that the transaction was made on rinkeby.etherscan.io")

print("We have also found slow way of getting transactions for a particular wallet from the blockchain. \n We stored our results in a file called transaction_list.txt")
print("We use this text file to store recent transaction hashes from a certain account. This example of from Elizabeth's account.")

hash_list = get_list_of_transaction_hashes_from_file()
print(hash_list)

print("")

print("We can find different info from the transaction hashes, and create visualations from that data.")

print("One visualization we made is on graph.png")

#make_graph(get_list_of_dates_from_transaction_hash_list(hash_list), get_list_of_values_from_t_hash_list(hash_list))

user_input = input("Would you like to make several transactions at once? Type 'y' for yes or 'n' for no: ")
if (user_input == 'y'):
    user_input = input("Enter your values in wei. Separate with commas: ")
    values = user_input.split(",")
    values = list(map(int, values))
    make_several_transactions(values)
    
user_input = input("Would You like to send 8 test accounts ether? Type 'y' for yes or 'n' for no: ")
if (user_input == 'y'):
    user_input = int(input("Put however much you want to send in wei: "))
    loop_nonce = async_w3.eth.get_transaction_count(sender_wallet_address)
    for i in TEST_ACCOUNTS:
        reciever = i.split(",")
        signed_txn = async_w3.eth.account.sign_transaction(dict(
            nonce= loop_nonce,
            maxFeePerGas=3000000000,
            maxPriorityFeePerGas=2000000000,
            gas= 100000 ,
            to=reciever[0],
            value= user_input,
            data=b'',
            type=2,  # (optional) the type is now implicitly set based on appropriate transaction params
            chainId= async_w3.eth.chainId,
          ),
          sender_wallet_private_key,
        )
        
        transaction_hash = async_w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        loop_nonce = loop_nonce+1
        

print("Make the test accounts send random transactions to each other!")
user_input = int(input("How many transactions do you want?: "))
make_several_random_transactions(TEST_ACCOUNTS, user_input)