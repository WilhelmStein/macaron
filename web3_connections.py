import web3
import requests
import json
from macaron_utils import print_err


def get_trace(hash, rpc_endpoint):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "debug_traceTransaction",
        "params": [
            hash,
            {
                "disableStorage": False,
                "disableMemory": False,
                "disableStack": False,
                "fullStorage": True,
            },
        ],
    }
    response = requests.post(rpc_endpoint, timeout=None, json=payload, stream=True)
    assert response.status_code == 200, response
    response_json = json.loads(response.text)
    if "error" in response_json:
        print_err(response_json["error"])
        exit(1)
    return response_json


def get_transactionData(hash, rpc_endpoint):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionByHash",
        "params": [hash],
    }
    response = requests.post(rpc_endpoint, json=payload, timeout=None, stream=True)
    assert response.status_code == 200, response
    response_json = json.loads(response.text)
    return response_json