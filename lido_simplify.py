import os
from time import sleep
import ast
import logging
import env_util
import random
from web3 import Account
from web3.middleware import geth_poa_middleware
import logging
import asyncio
import sys
import json

logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)


env_util.init_w3()
# Get the balance of an account $env:VAR1=
# sec = ast.literal_eval(os.getenv('ETH_KEY'))
# check_wallet = sec[0]
# amount_list = [int(1 * 1e15), int(1 * 1e15), int(1 * 1e15), int(1.02 * 1e16)]
# amount_list[random.randrange(1, 4)]
# user https://jumper.exchange/ or layerswap to distribute xchainxtoken
# myContract = web3.eth.contract(contractAddress, abi=contractAbi)
# encodedData = myContract.encodeABI(fn_name='myFunctionName', args=['foo','bar'])

barebone_tx = {
    "chainId": env_util.w3.eth.chain_id,
    "gas": env_util.chain_gas(env_util.chain),
    "gasPrice": env_util.safe_gas_price(),  # w3.toWei('50', 'gwei')
}
token_list = {
    'mainnet.uniswap': '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984',
    'mainnet.gtc': '0xde30da39c46104798bb5aa3fe8b9e0e1f348163f',
}

contract_col = {
    'aave_deposit.depositETH': {
        'arbitrum': {
            'contract': '0xb5ee21786d28c5ba61661550879475976b707099',  # obtain aETH 0xe50fa9b3c56ffb159cb0fca61f5c9d750e8128c8
            'proxy': '0xb5ee21786d28c5ba61661550879475976b707099',
            '1': '0x794a61358D6845594F94dc1DB02A252b5b4814aD',  # 2 onBehalfOf, 3 referralCode0
        },
        'optimism': {
            'contract': '0x76D3030728e52DEB8848d5613aBaDE88441cbc59',  # obtain aETH
            'proxy': '0x76D3030728e52DEB8848d5613aBaDE88441cbc59',
            '1': '0x794a61358D6845594F94dc1DB02A252b5b4814aD',
        },
        'mainnet': {
            'contract': '0xD322A49006FC828F9B5B37Ab215F99B4E5caB19C',
            'proxy': '0xD322A49006FC828F9B5B37Ab215F99B4E5caB19C',
            '1': '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2',
        },
    },
    # need approval stepbefor borrow,
    'aave_borrow.approveDelegation': {
        'arbitrum': {
            'contract': '0x0c84331e39d6658Cd6e6b9ba04736cC4c4734351',
            'proxy': '0x81387c40eb75acb02757c1ae55d5936e78c9ded3',
            '1': '0xB5Ee21786D28c5Ba61661550879475976B707099',  # delegatee (fixed) , amount is unlimited , contract
            '2': 115792089237316195423570985008687907853269984665640564039457584007913129639935,  # unlimited amount fff
        },
    },
    'aave_borrow.borrowETH': {
        'arbitrum': {
            'contract': '0xb5ee21786d28c5ba61661550879475976b707099',
            'proxy': '0xb5ee21786d28c5ba61661550879475976b707099',  # will obtain token 0x0c84331e39d6658cd6e6b9ba04736cc4c4734351
            '1': '0x794a61358D6845594F94dc1DB02A252b5b4814aD',  # 2 is amount borrow,3=2 interest mode, 4=0
            '2': 'amount borrow',
            '3': 2,  # interest mode
            '4': 0,
        },
    },
    'NFT1.mintDigitalRightsCharterTokens': {
        'mainnet': {
            'contract': '0xac6f08b923a0631a4f436bf3afd29c38349093cc',
            'proxy': '0xac6f08b923a0631a4f436bf3afd29c38349093cc',  # will obtain token 0x0c84331e39d6658cd6e6b9ba04736cc4c4734351
            '1': 1,  # number of tokens needed
            'note': "https://www.digitalrightscharter.org/mintGDRC1",
        },
    },
    'univote.castVote': {
        'mainnet': {
            'contract': '0x408ed6354d4973f66138c91495f2f2fcbd8724c3',
            'proxy': '0x53a328f4086d7c0f1fa19e594c9b842125263026',  #
            '1': 33,  # proposal id
            '2': 1,  # choice 1
        },
    },
    'gitcoin.castVote': {
        'mainnet': {
            'contract': '0xdbd27635a534a3d3169ef0498beb56fb9c937489',
            'proxy': '0xdbd27635a534a3d3169ef0498beb56fb9c937489',  #
            '1': 49,  # proposal id
            '2': True,  # choice 1
        },
    },
    'zksync_bridgetoL2.requestL2Transaction': {
        'goerli': {
            'contract': '0x1908e2bf4a88f91e4ef0dc72f02b8ea36bea2319',  # goerli
            'proxy': '0xd80ef7acbec07dbf10eb84452b40d0a8882adfb5',  #
            '1': '',  # mywallet,
            '2': 170000000000000000,  # l2value in wei
            '3': ''.encode('utf-8'),  # blank call data
            '4': 10000000,  # l2 gaslim
            '5': 800,  # l2gasperpub. 6 bytes BLANK, 7 mywallet
        },
    },
    'zksync_bridgetoL1.withdraw': {
        'zk-goerli': {
            'contract': '0x000000000000000000000000000000000000800A',  # goerli
            'proxy': '0x000000000000000000000000000000000000800A',  #
            '1': '',  # own address for withdraw,
        },
    },
}


"""
# alias_of_contract.methodName:

with open('erc20_abi.json') as f:
    erc20_abi = json.load(f)

# Instantiate the contract object for the ERC20 token
erc20_contract = w3.eth.contract(address=token_address, abi=erc20_abi)

# Get the number of ERC20 tokens held by the address
token_balance = erc20_contract.functions.balanceOf(address).call()

# Loop through each ERC20 token and send it
for i in range(token_balance):
    token_amount = erc20_contract.functions.balanceOf(address).call()
    if token_amount > 0:
        # Send the ERC20 token to a specified recipient
        recipient = '0x0987654321098765432109876543210987654321'
        erc20_contract.functions.transfer(recipient, token_amount).transact({'from': address})
"""
'''first_balance = (
    env_util.w3.eth.get_balance(env_util.w3.toChecksumAddress(check_wallet["address"])) / 1e18
)
print(
    first_balance,
    ' eth ',
    check_wallet["address"],
    'nonce',
    env_util.w3.eth.getTransactionCount(env_util.w3.toChecksumAddress(check_wallet["address"])),
)'''


def balance_api(addr, token='4757a0e8-be6f-4617-957f-a0a714a24a4c', chain='ethereum'):
    url = f'https://api.n.xyz/api/v1/address/{addr}/balances/fungibles?apikey={token}&?chainid={chain}&?filterDust=True&?filterSpam=true'
    return requests.get(url).json()


def get_token_amount(ori_contract, proxy_contract, wallet_addr: str):
    return env_util.get_from_blockchain(
        env_util.init_contract(ori_contract, proxy_contract),
        'balanceOf',
        env_util.w3.toChecksumAddress(wallet_addr),
    )


def get_netaave(wallet_addr):
    aETH = '0xe50fa9b3c56ffb159cb0fca61f5c9d750e8128c8'
    aeth_proxy = '0xa5ba6e5ec19a1bf23c857991c857db62b2aa187b'
    debt = '0x0c84331e39d6658cd6e6b9ba04736cc4c4734351'
    deb_proxy = '0x81387c40eb75acb02757c1ae55d5936e78c9ded3'
    collateral = get_token_amount(aETH, aeth_proxy, wallet_addr)
    debt_bal = get_token_amount(debt, deb_proxy, wallet_addr)
    print(f'*****************{collateral} minut {debt_bal}')
    return collateral - debt_bal


def pooltogether_test(
    private_key, ori_contract, proxy_contract, func_name, *args
):  # *args accept a list
    # nonce WRONG, became mainnet 2
    # Create the transaction dictionary
    account = Account.from_key(private_key)
    contract = env_util.init_contract(ori_contract, proxy_contract)

    # add the geth_poa_middleware to handle the PoA consensus like Polygon, BSC, Fantom
    # env_util.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    chksum_addr = env_util.w3.toChecksumAddress(account.address)
    print(
        f'from {account.address}, nonce{env_util.w3.eth.getTransactionCount(chksum_addr)} calling {env_util.w3.toChecksumAddress(ori_contract)}'
    )
    construct_txn = {
        'nonce': env_util.w3.eth.getTransactionCount(chksum_addr),
        'gasPrice': safe_gas_price(),
        'gas': 220000,
        'to': env_util.w3.toChecksumAddress(ori_contract),
        'value': 0,
        'data': contract.encodeABI(
            fn_name=func_name, args=list(args)
        ),  # args=args # this works same as contract.funct().buildtransactions
        'chainId': env_util.w3.eth.chain_id,
    }
    print(construct_txn, 'web.py ABI')  # MAYBE use dict
    gas = env_util.w3.eth.estimateGas(construct_txn)
    print(f'estimated gas:{gas}')
    construct_txn.update({'gas': gas})
    print('cost', gas * safe_gas_price() / 1e18, construct_txn)
    env_util.write_to_blockchain(
        construct_txn, private_key, contract, func_name, **kwargs  # *args
    )  # approve(address spender, uint256 amount)


def sleep_short(start=30, end=70, gap=32):
    tm = random.randrange(start, end, gap)
    logging.info(f'sleep for {tm} sec..')
    sleep(tm)
    return True


def loop_transfer(sign_wallet, recipient_list, amount, poor_threshold=0):
    for account_from in recipient_list:  # sec[1:2]
        chksum_add = env_util.w3.toChecksumAddress(account_from["address"])
        tx_count = env_util.w3.eth.getTransactionCount(sign_wallet["address"])
        print(f' {account_from["address"]} has {env_util.w3.eth.get_balance(chksum_add)} wei')
        if env_util.w3.eth.get_balance(chksum_add) / 1e18 <= poor_threshold:
            print(f' transfering {amount}')
            if transfer_in(
                sign_wallet, to=chksum_add, value=amount, nonce=tx_count
            ):  # int(3.03 * 1e16)
                print('good, sleeping')
                sleep_short(20, 63, 21)


async def transfer_in(sign_wallet, save=False, wait=True, **kwargs):
    mapping = {'from_param': 'from'}  # escape reserved keyword

    # Map the parameter names to the keys in the kwargs dictionary
    for key, value in mapping.items():
        if key in kwargs:
            kwargs[value] = kwargs.pop(key)
    # MOVE eth, and others, now defined in **kwargs
    if save:
        env_util.save_gas()
    construct_txn = barebone_tx  # transfer ETH, no data
    construct_txn.update(kwargs)
    logging.info(construct_txn)

    res = env_util.write_(sign_wallet, construct_txn)
    if wait:
        sleep_short()
    return res


def staking(min_eth=0.1, already_lido=0.1):
    for account_from in [sec[2], sec[3]]:

        balance = (
            env_util.w3.eth.get_balance(env_util.w3.toChecksumAddress(account_from["address"]))
            / 1e18
        )
        print(f'{account_from["address"]} has ETH {balance}')
        if balance > min_eth:
            # env_util.stake_lido(account_from, balance)
            try:
                if (
                    env_util.get_from_blockchain(
                        env_util.init_contract(
                            '0xae7ab96520de3a18e5e111b5eaab095312d7fe84',
                            '0x47ebab13b806773ec2a2d16873e2df770d130b50',  # lido
                        ),
                        'balanceOf',
                        env_util.w3.toChecksumAddress(account_from["address"]),
                    )
                    / 1e18
                    > already_lido
                ):
                    continue
                else:
                    print('staking', balance)
                    env_util.stake_lido(account_from, balance)
                    sleep_short()
            except Exception as e:
                print('error in staking', e)


# use pooltogether as CRV create_lock


def transfer_ens():
    ens_contr = env_util.w3.toChecksumAddress('0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85')
    # Set the sender and recipient addresses
    sender_address = env_util.w3.toChecksumAddress('0x8')
    sender = ast.literal_eval(os.getenv('meta1'))
    recipient_address = env_util.w3.toChecksumAddress('0x6')
    nft_id = 000
    tx_count = env_util.w3.eth.getTransactionCount(sender_address)
    contract = env_util.init_contract(ens_contr, ens_contr)
    call_data = contract.encodeABI(
        fn_name='transferFrom',
        args=[
            sender_address,
            recipient_address,
            nft_id,
        ],  # {'from': sender_address, 'to': recipient_address, 'tokenId': nft_id}
    )

    '''ens.encodeFunctionCall(
        'transferFrom',
        {
            'from': sender_address,
            'to': recipient_address,
            'tokenId': nft_id,
        },
    )'''
    transfer_in(
        sender,
        to=ens_contr,
        from_param=sender_address,
        value=0,
        nonce=tx_count,
        data=call_data,
    )


async def invoke_action(
    network: str,
    action: str,
    signer,
    *args,
    wait: bool = True,
    eth_amt: int = 0,
    abi_source: str = 'api_url',
    unknown_contract: str = None,
    unknow_proxy: str = '',
    from_addr: str = None,
):
    '''
    Any action now
    args:
    assuming signwallet is global variable and config is done
    abi_source, either from api, or specify directly here
    '''
    logging.info(f"VALUE PASS{args}")

    if abi_source == 'api_url':
        entrance = contract_col[action][network]['contract']
        proxy = contract_col[action][network]['proxy']
        contract_spec = env_util.init_contract(
            entrance,
            proxy,
        )

    else:
        contract_spec = env_util.w3.eth.contract(address=unknown_contract, abi=abi_source)
    tx = env_util.create_tx(
        contract_spec,
        action.split('.')[1],  # get method from action.method
        *args,
        unverified_contract=unknown_contract,
        add_from_addr=from_addr,
    )

    nonce = env_util.w3.eth.getTransactionCount(env_util.w3.toChecksumAddress(signer["address"]))
    tx.update(
        {
            "nonce": nonce,
        }
    )
    logging.info(
        signer["address"], f'value{int(eth_amt * 1e18)}, USE NONCE{nonce} {json.dumps(tx)}'
    )
    env_util.write_(
        signer,
        tx,
        eth_value=int(eth_amt * 1e18),
    )
    if wait:
        sleep_short()  # can't await expression boolean return type


def cheap_mint(signer, gas=18, action='NFT1.mintDigitalRightsCharterTokens'):
    while True:
        if env_util.w3.eth.gasPrice <= gas:
            asyncio.run(
                invoke_action(
                    env_util.chain,
                    action,
                    signer,
                    contract_col[action][env_util.chain]['1'],
                )
            )
            print('done')
            break
        print(sleep(5), 'sleep')


if __name__ == "__main__":

    efficiety_in_out = 0.95
    sec = ast.literal_eval(os.getenv('ETH_KEY'))

    # print(https://api.n.xyz/api/v1/address/0xdc56EAbDB4213c8ce1c86a4806e94D286D2cA4e6/balances/fungibles?apikey=4757a0e8-be6f-4617-957f-a0a714a24a4c)

    signwallet = sec[0]
    for i, loopwallet in enumerate(sec[1:10]):

        bal = (
            env_util.w3.eth.get_balance(env_util.w3.toChecksumAddress(loopwallet["address"])) / 1e18
        )
        zk_eth = random.randrange(101, 121, 7) / 10000  # 0.01ETH
        print(f'eth bal:{bal}, we will manipulate {zk_eth}')
        env_util.chain = "goerli"

        if bal == 0:
            # distrubet goerli eth to each wallet
            asyncio.run(
                transfer_in(
                    signwallet,
                    value=int(random.randrange(90, 100, 3) / 10000 * 1e18),  # 90, 131, 19
                    nonce=env_util.w3.eth.getTransactionCount(
                        env_util.w3.toChecksumAddress(signwallet["address"])
                    ),
                    to=env_util.w3.toChecksumAddress(sec[i + 1]["address"]),
                )
            )
        else:
            action = 'zksync_bridgetoL2.requestL2Transaction'
            dest_addr = env_util.w3.toChecksumAddress(loopwallet['address'])

            asyncio.run(
                # this bridge to zkL2 request eth_amt also be set
                invoke_action(
                    env_util.chain,
                    action,
                    loopwallet,
                    dest_addr,
                    int(zk_eth * 1e18),
                    contract_col[action][env_util.chain]['3'],
                    contract_col[action][env_util.chain]['4'],
                    contract_col[action][env_util.chain]['5'],
                    [],  # env_util.w3.toBytes(hexstr=''),  # bytearray(),
                    # https://ethereum.stackexchange.com/questions/59185/how-to-send-a-python-bytearray-into-solidity-function-by-web3-py
                    # https://ethereum.stackexchange.com/questions/110790/web3-py-encoding-zero-length-byte-array
                    dest_addr,
                    eth_amt=zk_eth,
                )
            )

        env_util.chain = "zk-goerli"
        action = 'zksync_bridgetoL1.withdraw'
        dest_addr = env_util.w3.toChecksumAddress(loopwallet['address'])

        # move back from loopwallet zk-goerli that has no API_service, so specify abi manuly
        asyncio.run(
            invoke_action(
                env_util.chain,
                action,
                loopwallet,
                env_util.w3.toChecksumAddress(loopwallet['address']),
                abi_source="""[
                    {
                        "constant": false,
                        "inputs": [
                        {
                            "name": "address",
                            "type": "address"
                        }
                        ],
                        "name": "withdraw",
                        "outputs": [],
                        "type": "function"
                    }
                    ]""",
                unknown_contract=contract_col[action][env_util.chain]["contract"],
                from_addr=env_util.w3.toChecksumAddress(loopwallet['address']),
                eth_amt=zk_eth * efficiety_in_out,
            )
        )

        ''''''
    sys.exit()

    for signwallet in sec[0:1]:

        print('**start', len(sec))
        # cheap_mint(signwallet)

        amount_eth = random.randrange(89, 101, 9) / 1000000  # 0.0001ETH
        actual = amount_eth  # min(amount_eth, bal * efficiety_in_out)
        bal = (
            env_util.w3.eth.get_balance(env_util.w3.toChecksumAddress(signwallet["address"])) / 1e18
        )
        print(bal, f'balance to borrow {actual} ', signwallet["address"])

        max_collateral = get_netaave(signwallet['address'])
        if max_collateral > 0:

            action = 'aave_deposit.depositETH'
            asyncio.run(
                invoke_action(
                    env_util.chain,
                    action,
                    signwallet,
                    env_util.w3.toChecksumAddress(contract_col[action][env_util.chain]['1']),
                    env_util.w3.toChecksumAddress(signwallet["address"]),
                    0,
                )
            )
            continue

            action = 'aave_borrow.approveDelegation'  # can only approve once, otherwise tx reverts
            asyncio.run(
                invoke_action(
                    env_util.chain,
                    action,
                    signwallet,
                    env_util.w3.toChecksumAddress(contract_col[action][env_util.chain]['1']),
                    contract_col[action][env_util.chain]['2'],
                )
            )

            sleep(5)
            action = 'aave_borrow.borrowETH'
            asyncio.run(
                invoke_action(
                    env_util.chain,
                    action,
                    signwallet,
                    env_util.w3.toChecksumAddress(contract_col[action][env_util.chain]['1']),
                    int(max_collateral * 1e18 * 0.6),
                    2,
                    0
                    # 2 is amount borrow,3=2 interest mode, 4=0
                )
            )
    #            sleep_short()

    sys.exit()

    for signwallet in sec:
        voting = token_list["mainnet.gtc"]
        if get_token_amount(voting, voting, signwallet["address"]) > 0:
            action = 'gitcoin.castVote'  # can only approve once, otherwise tx reverts
            asyncio.run(invoke_action(env_util.chain, action, signwallet, 49, True, wait=False))
            sleep_short(400, 800, 37)
            logging.info(f'voted {action} {signwallet["address"]}')
    sys.exit()

    for i, signwallet in enumerate(sec[3:11]):
        bal = (
            env_util.w3.eth.get_balance(env_util.w3.toChecksumAddress(signwallet["address"])) / 1e18
        )
        print(bal, f', {i} ', signwallet["address"])
        if (
            bal < 0.01
            and env_util.w3.eth.get_balance(env_util.w3.toChecksumAddress(sec[0]["address"])) / 1e18
            > 0.1
        ):
            # if True:
            asyncio.run(
                transfer_in(
                    sec[0],
                    value=int(random.randrange(90, 131, 19) / 10000 * 1e18),
                    nonce=env_util.w3.eth.getTransactionCount(
                        env_util.w3.toChecksumAddress(sec[0]["address"])
                    ),
                    to=env_util.w3.toChecksumAddress(signwallet["address"]),
                )
            )
            sleep_short()
    # sys.exit()

    # to do loop_transfer(sec[2:10], int(1.03 * 1e16))
    # loop_transfer(sec[0], sec[1:11], int(random.randrange(680, 712, 19) / 100000 * 1e18))
    # transfer_in(sec[0], amount=int(1.03 * 1e16)
    # staking()

    # working, Arbitrum deposit aave eth, don't estimate gas
    '''
    
    for signwallet in sec[0:1]:
        amount_eth = random.randrange(81, 131, 19) / 10000  # 0.01ETH
        bal = (
            env_util.w3.eth.get_balance(env_util.w3.toChecksumAddress(signwallet["address"])) / 1e18
        )
        actual = min(amount_eth, bal * efficiety_in_out)
        logging.info(f'processing {signwallet["address"]}')
        invoke_aave()
'''

    '''# move CRV
    for recipient in sec[1:9]:
        logging.info(f'processing {recipient["address"]}')
        env_util.write_(
            env_util.init_contract(
                '0xd533a949740bb3306d119cc777fa900ba034cd52',
                '0xd533a949740bb3306d119cc777fa900ba034cd52',
            ),  # curve contract 0xd533
            sec[0],
            'transfer',
            env_util.w3.toChecksumAddress(recipient["address"]),  # vecrv can spend
            round(random.randrange(5, 55, 6) / 100 * 1e18),
        )
        sleep_short()

    '''

    # working, approve 20 USDC for vecrv
    '''token_amount = get_token_amount(
        '0xd533a949740bb3306d119cc777fa900ba034cd52',
        '0xd533a949740bb3306d119cc777fa900ba034cd52',
        check_wallet["address"],
    )
    print(token_amount / 1e18)
    sleep(10)
    env_util.write_(
        env_util.init_contract(
            '0xd533a949740bb3306d119cc777fa900ba034cd52',
            '0xd533a949740bb3306d119cc777fa900ba034cd52',
        ),  # curve contract 0xd533
        sec[3],
        'approve',
        env_util.w3.toChecksumAddress(
            '0x5F3B5DFEB7B28CDBD7FABA78963EE202A494E2A2'
        ),  # vecrv can spend
        round(token_amount * 1e18),
    )
    

    # working crv lock, just need approval tx first
    # need exact 24 hours gap -UNKNOWN value, needs calc
    sleep(66)
    env_util.write_(
        env_util.init_contract(
            '0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2',
            '0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2',  # veCRV 0x5f3
        ),
        sec[3],
        'create_lock',
        round(token_amount * efficiency_in_out * 1e18),
        1798880449,
    )
    '''
