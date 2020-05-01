import web3
import requests
import json

def get_trace(hash):
    payload = {"jsonrpc":"2.0","id":8,"method":"debug_traceTransaction", "params":
               [ hash, {"disableStorage":True,"disableMemory":True,"disableStack":False,"fullStorage":False}
               ]
    }
    response = requests.post('http://node.web3api.com:8545/', json = payload, timeout = 100, stream = True)
    assert response.status_code == 200, response
    response_json = json.loads(response.text)
    return response_json


def get_starting_contract(hash):
    payload = {"jsonrpc":"2.0","id":8,"method":"eth_getTransactionByHash", "params": [ hash ] }
    response = requests.post('http://node.web3api.com:8545/', json = payload, timeout = 100, stream = True)
    assert response.status_code == 200, response
    response_json = json.loads(response.text)
    assert response_json['result']['to'] != None
    return response_json['result']['to']