import requests
import config
import json
from collections import defaultdict, namedtuple
from dataclasses import dataclass
import tokens
import time
from datetime import datetime

memory_writes = {
    'CALLDATACOPY': (-1, -3), 'CODECOPY': (-1, -3), 'EXTCODECOPY': (-2, -4),
    'MSTORE': (-1, 32), 'MSTORE8': (-1, 1), 'CALL': (-6, -7),
    'CALLCODE': (-6, -7), 'DELEGATECALL': (-5, -6)
}

memory_reads = {
    'SHA3': (-1, -2), 'MLOAD': (-1, 32), 'CREATE': (-2, -3), 'CREATE2': (-2, -3),
    'CALL': (-4, -5), 'STATICCALL': (-3, -4), 'CALLCODE': (-4, -5),
    'RETURN': (-1, -2), 'DELEGATECALL': (-3, -4), 'LOG1': (-1, -2),
    'LOG2': (-1, -2), 'LOG3': (-1, -2), 'LOG4': (-1, -2)
}

def get_mem_args(op, stack, **kwargs):
    '''Returns start and end'''
    if op in memory_writes:
        start_index, length_index = memory_writes[op]
    if op in memory_reads:
        start_index, length_index = memory_reads[op]
    if start_index < 0:
        start_index = int(stack[start_index], 16)
    if length_index < 0:
        length_index = int(stack[length_index], 16)        
    return start_index, length_index

value_arg = {'CALL': -3, 'CALLCODE': -3, 'CREATE': -1, 'CREATE2': -1}

calls = {'CALL', 'CALLCODE', 'STATICCALL', 'DELEGATECALL', 'CREATE', 'CREATE2'}


def get_trace(hash):
    start = time.time()
    payload = {"jsonrpc":"2.0","id":8,"method":"debug_traceTransaction", "params":
               [ hash, {"disableStorage":True,"disableMemory":False,"disableStack":False,"fullStorage":False}
               ]
    }
    response = requests.post(f'http://127.0.0.1:{config.GANACHE_CLI_PORT}/', json = payload, timeout = 100, stream = True)
    assert response.status_code == 200, response
    response_json = json.loads(response.text)
    end = time.time()
    print(f'Elapsed Time: {end - start}s')
    return response_json['result']['structLogs']


known_addresses = {}

def add_contract(address, alias):
    assert(len(address) == 42)
    known_addresses[address.lower().replace('0x', '')] = alias

for t in tokens.all_tokens:
    add_contract(t.address, t.symbol)

EVMStorageLocation = namedtuple('EVMStorageLocation', ['contract', 'store'])

ZERO = '00'*32

class TraceParser:
    def __init__(self, main_address):
        main_address = main_address.lower().replace('0x', '')
        assert len(main_address) == 40
        self.main_address = main_address
        self.action_tally = 0
        self.evm = EVMExecuctionStack()
        self.loaded = [set()]
        self.stored = [set()]
        self.ignore_addresses_storage = {t.normalized_address for t in tokens.all_tokens}
        self.ignore_addresses_storage.add(main_address)

        
    def parse_trace(self, trace):

        self.evm.entry(self.main_address)
    
        prev_t = {'depth': 0, 'op': None}
        for i, t in enumerate(trace):
            op = t['op'] ; stack = t['stack'] ; depth = t['depth']
            if depth < prev_t['depth']:
                self.evm.ret(prev_t)
            current_stack_entry = self.evm.head()
            if op == 'MSTORE':
                self.evm.mstore(stack[-1], stack[-2])
            if op == 'MSTORE8':
                self.evm.mstore8(stack[-1], stack[-2])
            if op == 'CALLDATACOPY':
                self.evm.calldatacopy(stack[-1], stack[-2], stack[-3])
            if op == 'CODECOPY':
                self.evm.codecopy(stack[-1], stack[-2], stack[-3])
            if op in calls:
                # take next address from the stack, cast to 160-bits
                call_address = stack[-2][-40:]
                self.evm.call(call_address, t)
            self.track_storage(t)
            prev_t = t
        return self.evm

    def track_storage(self, t):
        last_stack = self.evm.stack[-1]
        op = t['op']
        if last_stack.address == self.main_address and op == 'LOG1':
            t['stack'][-1]
            start, length = get_mem_args(**t)
            value = int(self.evm.memory[-1][start:start+length].hex(), 16)
            print("Amount Gotten: %.3g"%value)
            
            # reentry
            self.action_tally += 1
            self.loaded.append(set())
            self.stored.append(set())
        if op == 'SLOAD':
            tally = self.loaded[-1]
        elif op == 'SSTORE':
            tally = self.stored[-1]
        else:
            tally = None
        if tally is not None:
            store = t['stack'][-1]
            if last_stack.address not in self.ignore_addresses_storage:
                tally.add(
                    EVMStorageLocation(last_stack.address, store)
                )
            

def format_address(a):
    a = a.lower()
    if a.startswith('0x'):
        a = a[2:]
    if a in known_addresses:
        ret = known_addresses[a]
        if ' ' in ret:
            # braketize for readability
            return '<' + ret + '>'
        else:
            return ret
    else:
        return config.api.toChecksumAddress(a)

# 64kb may seem excessive, but isn't
MAX_MEMORY = 0x10000

class EVMExecuctionStack:

    @dataclass(init = True, repr = True)
    class TraceEntry:
        address: str
        reason: str
        detail: str = ''
        depth: int = 0
    
    public_functions_db = json.load(open(config.PUBLIC_FUNCTION_SIGNATURES_JSON))
    
    def __init__(self):
        self.stack = []
        self.trace = []
        self.memory = []
        self.calldatas = []
        self.code = {}


    def entry(self, address):
        self.stack.append(self.TraceEntry(address, 'ENTRY'))
        self.memory.append(bytearray(b'\0'*MAX_MEMORY))
        self.do_trace('ENTRY')
        self.calldatas.append(bytearray())
        
    def do_trace(self, reason, detail = ''):
        last_stack = self.stack[-1]
        self.trace.append(
            self.TraceEntry(
                last_stack.address, reason, detail, depth = len(self.stack)
            )
        )

    def mstore(self, index, entry):
        index = int(index, 16)
        self.memory[-1][index:index+32] = bytearray.fromhex(entry)

    def mstore8(self, index, entry):
        index = int(index, 16)        
        self.memory[-1][index:index+1] = bytearray.fromhex(entry[-2:])

    def calldatacopy(self, memstart, cdstart, length):
        memstart, cdstart, length = int(memstart, 16), int(cdstart, 16), int(length, 16)
        self.memory[-1][memstart:memstart+length] = self.calldatas[-1][cdstart:length+cdstart]
        
    def get_calldata_and_value(self, t):
        op = t['op']
        stack = t['stack']
        start, length = memory_reads[op]
        start, length = int(stack[start], 16), int(stack[length], 16)
        calldata = self.memory[-1][start:start+length]
        if op in value_arg:
            value = int(t['stack'][value_arg[op]], 16)
        else:
            value = 0
        return calldata, value
        
    def call(self, address, t):
        calldata, value = self.get_calldata_and_value(t)
        self.calldatas.append(calldata)
        self.memory.append(bytearray(b'\0'*MAX_MEMORY))
        call_formatted = self.format_calldata(calldata, value)
        if t['op'] in ['CREATE', 'CREATE2']:
            call_formatted = "New Contract Creation"
        self.stack.append(self.TraceEntry(address, t['op'], call_formatted))
        self.do_trace(reason = t['op'], detail = call_formatted)

    def codecopy(self, memstart, codestart, length):
        memstart, codestart, length = int(memstart, 16), int(codestart, 16), int(length, 16)        
        current_address = self.stack[-1].address
        if current_address not in self.code:
            # get code
            self.code[current_address] = (
                bytes(config.api.eth.getCode(config.api.toChecksumAddress(current_address)))
            )
        copied = self.code[current_address][codestart:length+codestart]
        copied += b'\0' * (length - len(copied)) # pad with 0 chars
        self.memory[-1][memstart:memstart+length] = copied
        
    def ret(self, t):
        last_mem = self.memory[-1]
        detail = self.stack[-1].detail
        self.stack.pop()
        self.memory.pop()
        if t['op'] == 'REVERT':
            # get revert reason
            start, length = int(t['stack'][-1], 16), int(t['stack'][-2], 16)
            revert_reason = last_mem[start+4:start+length].decode('cp437')
            self.do_trace(reason = f'{hex(t["pc"])}:revert("{revert_reason}")', detail = detail)
        else:
            self.do_trace(reason = f'{hex(t["pc"])}:{t["op"]}', detail = detail)




    def head(self):
        return self.trace[-1]
        

    def format_calldata(self, calldata, value):
        value_formatted = '%4f ETH'%((value * 1.0) / 10**18)
        if value == 0:
            value_formatted = '0 ETH'
        if len(calldata) == 0:
            return f'transfer({value_formatted})'
        if value > 0:
            value_part = f'.value({value_formatted})'
        else:
            value_part = ''
        selector = calldata[:4].hex()
        if selector not in self.public_functions_db:
            return '#' + selector
        function_data = self.public_functions_db[selector]
        signature_split = function_data['signature'].split('(')
        function_name, rest = signature_split
        arg_types = rest[:-1]
        arg_types = [a for a in arg_types.split(',') if a]
        lost = False
        arg_format = []
        pointer = 4
        for i, t in enumerate(arg_types):
            if t.endswith(']'):
                # is an array
                t, multiple_str = t[:-1].split('[')
                if multiple_str == '':
                    multiple = -1
                else:
                    multiple = int(multiple_str)
            else:
                multiple = 0
            if t == 'address':
                format = lambda a: format_address(a[-40:])
            elif t.startswith('uint'):
                unix_timestamp = time.time()
                def format(a):
                    a = int(a, 16)
                    if abs(a - unix_timestamp) < unix_timestamp/10:
                        # within 10%, treat as timestamp
                        return datetime.utcfromtimestamp(a).strftime('%Y-%m-%d %H:%M:%S UTC')
                    return "%.3g"%a

            elif t == 'bool':
                format = lambda a: 'false' if int(a, 16) == 0 else 'true'
            elif t.startswith('bytes'):
                length_str = t[5:]
                if length_str:
                    length = int(length_str)
                else:
                    length = 32
                format = lambda a: a[:length*2+1]
            else:
                lost = True
            if lost:
                value = f'<{t}>'
            else:
                if multiple == 0:
                    # convert arg
                    calldata_arg_hex = calldata[pointer:pointer+32].hex()
                    value = format(calldata_arg_hex)
                    pointer += 32
                elif multiple == -1:
                    # dynamically-sized arrays
                    values = []
                    data_pointer = 4 + int(calldata[pointer:pointer+32].hex(), 16)
                    multiple = int(calldata[data_pointer:data_pointer+32].hex(), 16)
                    data_pointer += 32
                    for i in range(multiple):
                        calldata_arg_hex = calldata[data_pointer:data_pointer+32].hex()
                        values.append(format(calldata_arg_hex))                        
                        data_pointer += 32
                    value = '[' + ', '.join(values) + ']'                        
                    pointer += 32
                else:
                    # statically-sized arrays
                    values = []
                    for i in range(multiple):
                        calldata_arg_hex = calldata[pointer:pointer+32].hex()
                        values.append(format(calldata_arg_hex))
                        pointer+=32
                    value = '[' + ', '.join(values) + ']'
            if len(function_data['param_names']) > i:
                variable = function_data['param_names'][i] + ' = '
            else:
                variable = ''
            arg_format.append(variable + value)
        args = ', '.join(arg_format) 
        return f'{function_name}{value_part}({args})'
    

add_contract("0x148426fdc4c8a51b96b4bed827907b5fa6491ad0", "bZx Exploiter 1, bZx Exploit")
add_contract("0x4f4e0f2cb72e718fc0433222768c57e823162152", "Contract, bZx Exploit")
add_contract("0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e", "SoloMargin, dYdX, Main dYdX contract, Solo Margin, DeFi")
add_contract("0x56e7d4520abfecf10b38368b00723d9bd3c21ee1", "Operation Impl, OperationImpl, dYdX, SoloMargin library containing operation functions")
add_contract("0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e", "SoloMargin, dYdX, Main dYdX contract, Solo Margin, DeFi")
add_contract("0xf61ae328463cd997c7b58e7045cdc613e1cfdb69", "Weth Price Oracle, WethPriceOracle, dYdX, Price oracle for WETH")
add_contract("0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e", "SoloMargin, dYdX, Main dYdX contract, Solo Margin, DeFi")
add_contract("0x729d19f657bd0614b4985cf1d82531c67569197b", "Medianizer, Medianizer 2, Maker")
add_contract("0xf61ae328463cd997c7b58e7045cdc613e1cfdb69", "Weth Price Oracle, WethPriceOracle, dYdX, Price oracle for WETH")
add_contract("0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e", "SoloMargin, dYdX, Main dYdX contract, Solo Margin, DeFi")



add_contract("0x05a9cbe762b36632b3594da4f082340e0e5343e8", "TokenState")
add_contract("0x2157a7894439191e520825fe9399ab8655e0f708", "Vyper_contract, Uniswap Exchange Template, Uniswap")
add_contract("0x31e085afd48a1d6e51cc193153d625e8f0514c7f", "Reserve Uniswap, Kyber")
add_contract("0x360f85f0b74326cddff33a812b05353bc537747b", "Contract, bZx Exploit")
add_contract("0x4cb01bd05e4652cbb9f312ae604f4549d2bf2c99", "Reserve sUSD, Kyber")
add_contract("0x57ab1e02fee23774580c119740129eac7081e9d3", "NominUSD, Havven, https://havven.io/, https://www.synthetix.io/, Synth_sUSD , Synthetix, Token Contract, Stablecoin, Proxy, Synth sUSD (sUSD), Synth sUSD")
add_contract("0x65bf64ff5f51272f729bdcd7acfb00677ced86cd", "Contract 2, Kyber, Contract")
add_contract("0x8007aa43792a392b221dc091bdb2191e5ff626d1", "Fee Burner, Kyber")
add_contract("0x818e6fecd516ecc3849daf6845e3ec868087b755", "Proxy, Kyber, KyberNetworkProxy")