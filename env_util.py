from web3 import Web3
import requests
import json
from time import sleep
from web3.middleware import geth_poa_middleware
import sys
import datetime
import logging
import time
import msvcrt
from functools import lru_cache
import ast
import os

api_dict = ast.literal_eval(os.getenv('api_dict'))
rpc_dict = ast.literal_eval(os.getenv('rpc_dict'))
# https://docs.alchemy.com/docs/how-to-add-alchemy-rpc-endpoints-to-metamask#4.-fill-in-the-required-information
GAS_LIMIT = 30  # gw
GAS_FLUCTUATION = 1.16
chain = "optimism"
gas_dict = {
    'mainnet': 99000,
    'optimism': 888888,
    'arbitrum': 2888888,
    'goerli': 10000000,
    'zk-goerli': 10000001,
}
#' Failed to submit transaction: invalid sender. can't start a transaction from a non-account' means no-gas specified zksync

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)


def safe_gas_price():
    return round(w3.eth.gasPrice * GAS_FLUCTUATION)


def chain_gas(chain: str):
    default_gas = gas_dict.get(chain)
    if default_gas:
        return default_gas
    else:
        print('CANT get gas')
        sys.exit()
        return 0


def init_w3():
    # adding web socket
    logging.info(f'{chain}, connect to {rpc_dict[chain]}')
    global w3
    if 'wss:' in rpc_dict[chain]:
        w3 = Web3(Web3.WebsocketProvider(rpc_dict[chain]))
    else:
        w3 = Web3(Web3.HTTPProvider(rpc_dict[chain]))
    # add the geth_poa_middleware to handle the PoA consensus like Polygon, BSC, Fantom
    # w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    # Print if web3 is successfully connected
    logging.info(f'Connection {w3.isConnected()}, last black {w3.eth.block_number}')


def save_gas(construct_txn, limit: int = GAS_LIMIT, time_pause=30, eth_limit=0.004, mandate=True):
    # msvcrt is Windows only
    global chain
    if chain in ['arbitrum', 'optimism']:
        total_burn = w3.eth.gasPrice * w3.eth.estimateGas(construct_txn) / 1e18
        logging.info(
            f'{w3.eth.gasPrice > GAS_LIMIT * 1e9} {w3.eth.gasPrice} price > {GAS_LIMIT * 1e9}. TOTAL {total_burn} WILL BE BURNT',
        )
    else:
        logging.info(
            f'skip for mainnet as estimating aavi deposit will fail, okay for arbi {str(construct_txn)}'
        )
    while w3.eth.gasPrice > GAS_LIMIT * 1e9:  # or total_burn > eth_limit:
        t0 = time.time()
        if mandate:
            print("press enter to stop waiting for lower network fee, g for Go")
            while time.time() - t0 < 30:
                if msvcrt.kbhit():
                    if msvcrt.getch() == '\r':  # not '\n'
                        sys.exit()
                    elif msvcrt.getch() == 'g':
                        return
                    # time.sleep(1)
            continue

        else:
            choice = input(f"gas is {w3.eth.gasPrice/1e9}, input: stop, pause, go")
            if choice == 'stop':
                sys.exit()
            if choice == 'pause':
                sleep(time_pause)
                return
            if choice == 'go':
                return
    logging.info('gas price check passed, okay to proceed')
    return


def get_from_blockchain(contract, func_name, *args):
    return contract.functions[func_name](*args).call()


# Write data to blockchain, not working
def write_to_blockchain(
    construct_txn: dict,
    private_key,
    contract=None,
    func_name=None,
    **kwargs,  # I modify to **kwargs form *args
) -> bool:

    gas = w3.eth.estimateGas(construct_txn)
    print(f'estimated gas:{gas}')
    construct_txn.update({'gas': gas})
    # Sign the transaction using the private key
    signed_tx = w3.eth.account.sign_transaction(construct_txn, private_key)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt['status'] == 1


# https://stackoverflow.com/questions/70583907/how-to-get-an-unsigned-transaction-data-from-web3-py-using-contract-interaction
'''
contract.functions.transfer(paymentrequest.wallet, tokenamount * pow(10, paymentrequest.token.decimals)).call({"to": tokenaddress, "from": "0xbunchoflettersandnumbers"}, )
not good as
txn = contract.encodeABI(fn_name="transfer", args=[paymentrequest.wallet, tokenamount * pow(10, paymentrequest.token.decimals)])
can use either CALL or TRANSACT
diff: A call is a local invocation of a contract function that does not broadcast or publish anything on the blockchain. use it before transact
'''


def write_to_blockchain_ori(contract, func_name, *args) -> bool:
    tx_hash = contract.functions[func_name](*args).transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

    tx_data = w3.eth.getTransaction(tx_receipt['transactionHash'])
    func_obj, func_params = contract.decode_function_input(tx_data.input)
    print(f"func_obj: {func_obj}, func_params: {func_params}")
    return tx_receipt['status'] == 1


def create_tx(
    contract, func_name, *args, unverified_contract: str = None, add_from_addr: str = None
):
    # create for contract trans
    # unverified_contract: When using `ContractFunction.build_transaction` from a contract factory you must provide a `to` address with the transaction
    # then Failed to submit transaction: invalid sender. can't start a transaction from a non-account
    # Cannot set 'to' field in contract call build transaction, so only append TO after buildTransaction

    # gas estimation fine for zk-goerli, but base-goerli fails'execution reverted'
    global chain

    tx_json = {
        'gas': chain_gas(chain),
        'gasPrice': safe_gas_price(),
        #'from': w3.toChecksumAddress(sign_wallet["address"]),
        #'nonce': w3.eth.getTransactionCount(w3.toChecksumAddress(sign_wallet["address"])),
        'chainId': w3.eth.chain_id,
    }
    if add_from_addr:
        tx_json["from"] = add_from_addr  # w3.eth.defaultAccount
        # tx_json["chainId"] = 5  # use goerli=5 as chain (logging), own zk-goerli chain=280
    # https://stackoverflow.com/questions/57580702/how-to-call-a-smart-contract-function-using-python-and-web3-py
    logging.info(f'args are{args}, UNVERIFIED CONTRACT FROM {unverified_contract}')
    construct_txn = contract.functions[func_name](*args).buildTransaction(tx_json)
    # construct_txn['gas'] = w3.eth.estimateGas(construct_txn)
    if unverified_contract:
        tx_json["to"] = w3.toChecksumAddress(unverified_contract)
    logging.info(f'to sign{construct_txn}')
    return construct_txn


# WORKING, can't catch
def write_(sign_wallet, construct_txn, eth_value=0):
    '''
    ?arbitrum or rpw was wrong so will fail on estimateGas: web3.exceptions.ContractLogicError: execution reverted: 26
    '''
    print(f'start transacting with ETH transfer{eth_value}')

    if eth_value > 0:
        construct_txn.update({'value': eth_value})
    print(f'TX to sign: {str(construct_txn)}')
    '''gas = w3.eth.estimateGas(construct_txn)
    logging.debug(f'estimated gas:{gas} worth {gas * safe_gas_price() /1e18 }')
    construct_txn.update({'gas': gas})'''
    save_gas(construct_txn)
    logging.info(f'pk length{len(sign_wallet["privateKey"])}')
    signed_txn = w3.eth.account.signTransaction(construct_txn, sign_wallet["privateKey"])
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    logging.debug(tx_receipt)
    return tx_receipt['status'] == 1


@lru_cache(maxsize=30)
# Dynamically fetch the ABI of the Smart Contract from Etherscan API
def fetch_abi(address):
    global chain

    print('request', ('%s%s' % (api_dict[chain], address)))
    response = requests.get('%s%s' % (api_dict[chain], address))
    sleep(0.5)
    response_json = response.json()
    abi_json = json.loads(response_json['result'])
    result = json.dumps(abi_json)

    '''
    # for uniswap.vote triggers TypeError: 'list' object is not callable
    if "implementation" in result:
        logging.debug(abi_json)
        imp_contract_addr = abi_json(
            "implementation"
        )  # seems old logic, doesn't know using the EIP-897 DelegateProxy concept. like ABI for the implementation contract at 0x47ebab13b806773ec2a2d16873e2df770d130b50,
        result = fetch_abi(imp_contract_addr)'''

    return result


@lru_cache(maxsize=20)
def init_contract(contract_address: str, proxy_contract: str):
    '''
    if proxy is different, then get abi from it, but call origin contract

    if no api then use https://calldata-decoder.apoorv.xyz/
    '''

    address = w3.toChecksumAddress(contract_address)
    proxy_address = w3.toChecksumAddress(proxy_contract)
    abi = fetch_abi(proxy_address)
    logging.debug(f'fetched ABI from rpc: {abi}')
    return w3.eth.contract(address=address, abi=abi)

    '''
    contract_address = '0xae7ab96520de3a18e5e111b5eaab095312d7fe84'  #'' # Lido sTEH, proxyed to 0x47ebab13b806773ec2a2d16873e2df770d130b50 
    proxy_contract = '0x47ebab13b806773ec2a2d16873e2df770d130b50'
    # proxy_abi = w3.eth.contract(address=w3.toChecksumAddress(proxy_contract)).abi
    address = w3.toChecksumAddress(contract_address)
    proxy_address = w3.toChecksumAddress(proxy_contract)
    abi = fetch_abi(proxy_address)
    return w3.eth.contract(address=address, abi=abi)
    '''


def stake_lido(sign_wallet, amount, pct_to_stake=0.94):
    '''
    adjust amount minus gas
    '''

    # Lido sTEH
    construct_txn = (
        init_contract(
            '0xae7ab96520de3a18e5e111b5eaab095312d7fe84',
            '0x47ebab13b806773ec2a2d16873e2df770d130b50',
        )
        .functions.submit("0x0000000000000000000000000000000000000000")
        .buildTransaction(
            {
                "chainId": w3.eth.chain_id,
                "from": w3.toChecksumAddress(sign_wallet["address"]),
                "nonce": w3.eth.getTransactionCount(w3.toChecksumAddress(sign_wallet["address"])),
                "gas": chain_gas(),  # 30000,
                "gasPrice": safe_gas_price(),  # 26656078076, w3.toWei('50', 'gwei')
                "value": int(amount * pct_to_stake * 1e18),
            }
        )
    )
    print(
        'gas gwei',
        safe_gas_price(),
        'cost,',
        30000 * safe_gas_price() / 1e18,
        'estimates:',
        construct_txn,
    )
    gas = w3.eth.estimateGas(construct_txn)
    print(f'estimated gas:{gas} worth {gas * safe_gas_price() /1e18 }')
    construct_txn.update({'gas': gas})
    # construct_txn.update({'value': w3.toWei(amount * pct_to_stake, 'ether')})  # - 4 * gas
    save_gas()
    print('Updated tx adjusted gas', construct_txn)

    signed_tx = w3.eth.account.sign_transaction(construct_txn, sign_wallet['privateKey'])
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(tx_receipt)


def try_swap():
    # not finished
    # https://www.publish0x.com/web3dev/web3py-walkthrough-to-swap-tokens-on-uniswap-pancakeswap-ape-xqmpllz
    input_quantity_wei = 1000000000000000000
    swap_path = [input_token_address, output_token_address]
    swap_contract.functions.getAmountsOut(input_quantity_wei, swap_path).call()

    account_address = '0xffffffffffffffffffffffffffffff'
    input_quantity_wei = 1000000000000000000
    minimum_input_quantity_wei = 997000000000000000
    deadline = int(time.time() + 60)
    fun = contract.functions.swapExactTokensForTokens(
        input_quantity_wei, minimum_input_quantity_wei, swap_path, account_address, deadline
    )
    tx = fun.buildTransaction(
        {
            'from': account_address,
            'nonce': w3.eth.getTransactionCount(account_address),
            'gasPrice': Web3.toWei('30', 'gwei'),
        }
    )
    signed_tx = w3.eth.account.signTransaction(tx, my_account.key)
    emitted = w3.eth.sendRawTransaction(signed_tx.rawTransaction)


def auth_usdc(ori_contract, proxy_contract, sign_wallet, amount):
    '''
    adjust amount minus gas
    '''

    contract = env_util.init_contract(ori_contract, proxy_contract)
    chksum_addr = env_util.w3.toChecksumAddress(sign_wallet.address)
    construct_txn = (
        init_contract(
            ori_contract,
            proxy_contract,
        )
        .functions.approve(chksum_addr, 2000000)
        .buildTransaction(
            {
                "chainId": w3.eth.chain_id,
                "from": w3.toChecksumAddress(sign_wallet["address"]),
                "nonce": w3.eth.getTransactionCount(w3.toChecksumAddress(sign_wallet["address"])),
                "gas": chain_gas(),  # 30000,
                "gasPrice": round(safe_gas_price()),  # 26656078076, w3.toWei('50', 'gwei')
                "value": int(amount * 0.2 * 1e18),  # str(int(0.0001*1e18)) #to payable function
            }
        )
    )
    print(
        'gas gwei',
        safe_gas_price(),
        'cost,',
        30000 * safe_gas_price() / 1e18,
        'estimates:',
        construct_txn,
    )
    gas = w3.eth.estimateGas(construct_txn)
    print(f'estimated gas:{gas} worth {gas * safe_gas_price() /1e18 }')
    construct_txn.update({'gas': gas})
    construct_txn.update({'value': w3.toWei(amount * 0.5, 'ether')})  # - 4 * gas
    save_gas()
    print('Updated tx adjusted gas', construct_txn)

    signed_tx = w3.eth.account.sign_transaction(construct_txn, sign_wallet['privateKey'])
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(tx_receipt)


def add_epoch(start=datetime.datetime.now(), gap=365 * 3):
    return round((start + datetime.timedelta(days=gap)).timestamp())
