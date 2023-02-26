from web3 import Web3
import requests
import json

api_dict = {
    'mainnet': 'https://api.etherscan.io/api?module=contract&action=getabi&address=',
    'optimism': 'https://api-optimistic.etherscan.io/api?module=contract&action=getabi&address=',
}
rpc_dict = {
    'mainnet': "https://eth-mainnet.g.alchemy.com/v2/IYdD0zrcPU7gT1k911f243mQrpuNe16T",
    'optimism': "https://opt-mainnet.g.alchemy.com/v2/IYdD0zrcPU7gT1k911f243mQrpuNe16T",
}
GAS_LIMIT = 25  # gw
chain = "optimism"


def init_w3():
    print(f'{chain}, connect to {rpc_dict[chain]}')
    global w3
    w3 = Web3(Web3.HTTPProvider(rpc_dict[chain]))
    # Print if web3 is successfully connected
    print(f': {w3.isConnected()}, last black {w3.eth.block_number}')


def save_gas(limit: int = GAS_LIMIT, time_pause=30):
    while w3.eth.gasPrice > GAS_LIMIT * 1e9:
        choice = input(f"gas is {w3.eth.gasPrice/1e9}, input: stop, pause, go")
        if choice == 'stop':
            sys.exit()
        if choice == 'pause':
            sleep(time_pause)
            return
        if choice == 'go':
            return
    return


def get_from_blockchain(func_name, *args):
    return contract.functions[func_name](*args).call()


def write_to_blockchain(func_name, *args) -> bool:
    tx_hash = contract.functions[func_name](*args).transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

    tx_data = w3.eth.getTransaction(tx_receipt['transactionHash'])
    func_obj, func_params = contract.decode_function_input(tx_data.input)
    print(f"func_obj: {func_obj}, func_params: {func_params}")
    return tx_receipt['status'] == 1


# Dynamically fetch the ABI of the Smart Contract from Etherscan API
def fetch_abi(address, ABI_ENDPOINT: str = api_dict[chain]):
    response = requests.get('%s%s' % (ABI_ENDPOINT, address))
    response_json = response.json()
    abi_json = json.loads(response_json['result'])
    result = json.dumps(abi_json)

    if "implementation" in result:
        print(abi_json)
        imp_contract_addr = abi_json(
            "implementation"
        )  # seems old logic, doesn't know using the EIP-897 DelegateProxy concept. like ABI for the implementation contract at 0x47ebab13b806773ec2a2d16873e2df770d130b50,
        result = fetch_abi(imp_contract_addr)

    return result


def transfer_eth(recipient: str, amount_w: int, nonce: int, private_key: str):
    construct_txn = {
        "chainId": w3.eth.chain_id,
        "to": recipient,
        "nonce": nonce,
        "gas": 0,
        "gasPrice": round(w3.eth.gasPrice * 1.1),  # w3.toWei('50', 'gwei')
        "value": amount_w,
    }
    gas = w3.eth.estimateGas(construct_txn)
    print(f'estimated gas:{gas}', "output", amount_w / 1e18)
    construct_txn.update({'gas': gas})
    save_gas()
    signed_tx = w3.eth.account.sign_transaction(construct_txn, private_key)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt
