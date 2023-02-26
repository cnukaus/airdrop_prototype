import os
from time import sleep
import ast
import logging
import env_util
import random

env_util.chain = "mainnet"
env_util.init_w3()
amount_list = [int(1 * 1e15), int(1 * 1e15), int(1 * 1e15), int(1.02 * 1e16)]

# Get the balance of an account $env:VAR1=
sec = ast.literal_eval(os.getenv('ETH_KEY'))
first_balance = env_util.w3.eth.get_balance(env_util.w3.toChecksumAddress(sec[0]["address"])) / 1e18
print(first_balance)

signer_add = env_util.w3.toChecksumAddress(sec[0]["address"])
for account_from in sec[5:]:
    wei_range = amount_list[random.randrange(1, 4)] + random.randrange(50000, 6000000, 30007)
    chksum_add = env_util.w3.toChecksumAddress(account_from["address"])
    nonce = env_util.w3.eth.getTransactionCount(signer_add)
    env_util.transfer_eth(chksum_add, wei_range, nonce, sec[0]['privateKey'])
    sleep(random.randrange(5, 20))


for account_from in sec:

    balance = w3.eth.get_balance(account_from["address"]) / 1e18
    print(
        f'{account_from["address"]} has ETH {balance}',
        f'contract balance',
        get_from_blockchain('balanceOf', account_from["address"]) / 1e18,
    )
