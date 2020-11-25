import web3
import requests
import json
#TODO Add security authentication options
def get_trace(hash, rpc_endpoint):
    payload = {"jsonrpc":"2.0","id":1,"method":"debug_traceTransaction", "params":
               [ hash, {"disableStorage":False,"disableMemory":False,"disableStack":False,"fullStorage":True}
               ]
    }
    response = requests.post(rpc_endpoint, json = payload, timeout = 100, stream = True)
    assert response.status_code == 200, response
    response_json = json.loads(response.text)
    return response_json


def get_transactionData(hash, rpc_endpoint):
    payload = {"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash", "params": [ hash ] }
    response = requests.post(rpc_endpoint, json = payload, timeout = 100, stream = True)
    assert response.status_code == 200, response
    response_json = json.loads(response.text)
    return response_json