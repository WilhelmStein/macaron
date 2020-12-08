#!/usr/bin/env python3
from collections import namedtuple, defaultdict
from web3_connections import *
from dataclasses import dataclass
import config
import json
from macaron_utils import print_err
# import tokens
import os.path
import pickle
import sys


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

MAX_MEMORY = 0x10000
class EVMExecuctionStack:
    InstructionEntry = namedtuple('InstructionEntry', ['pc', 'data'])
    DataEntry = namedtuple('DataEntry', ['stack', 'storage', 'memory'])

    @dataclass(init = True, repr = True, frozen=True)
    class TraceEntry:
        address: str
        reason: str
        detail: str = ''
        value: int = 0
        depth: int = 0
    

    def __init__(self):
        self.stack = []
        self.trace = []
        self.memory = []
        self.calldatas = []
        self.code = {}
        self.instructions = defaultdict(list)
        self.function_db = {}


    def entry(self, transaction_data):
        address, starting_calldata, value = transaction_data['to'][2:], bytes.fromhex(transaction_data['input'][2:]), int(transaction_data['value'], 16)

        self.calldatas.append(starting_calldata)
        self.stack.append(self.TraceEntry(address, 'ENTRY', starting_calldata, value))
        self.memory.append(bytearray(b'\0'*MAX_MEMORY))
        self.do_trace('ENTRY', starting_calldata, value)
        

    def do_trace(self, reason, detail = '', value = 0):
        last_stack = self.stack[-1]
        self.trace.append(
            self.TraceEntry(
                last_stack.address, reason, detail, value, depth = len(self.stack)
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
        calldata = bytes(self.memory[-1][start:start+length])
        if op in value_arg:
            value = int(t['stack'][value_arg[op]], 16)
        else:
            value = 0
        return calldata, value


    def call(self, address, t):
        calldata, value = self.get_calldata_and_value(t)
        self.calldatas.append(calldata)
        self.memory.append(bytearray(b'\0'*MAX_MEMORY))
        if t['op'] in ['CREATE', 'CREATE2']:
            calldata = "New Contract Creation"
        self.stack.append(self.TraceEntry(address, t['op'], calldata, value))
        self.do_trace(reason = t['op'], detail = calldata, value = value)


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
        detail, value = self.stack[-1].detail, self.stack[-1].value
        self.stack.pop()
        self.memory.pop()
        if t['op'] == 'REVERT':
            # get revert reason
            start, length = int(t['stack'][-1], 16), int(t['stack'][-2], 16)
            revert_reason = last_mem[start+4:start+length].decode('cp437')
            self.do_trace(reason = f'{hex(t["pc"])}:revert("{revert_reason}")', detail = detail, value = value)
        else:
            self.do_trace(reason = f'{hex(t["pc"])}:{t["op"]}', detail = detail, value = value)


    def head(self):
        return self.trace[-1]
        
    # TODO Decide what to do with this
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


    def import_transaction(self, transaction, rpc_endpoint):
        
        # Trace cache 
        if not os.path.exists('traces'):
            os.makedirs('traces')

        transaction_path = f"traces/{transaction}.pkl"
        transaction_trace = None

        try:
            if os.path.isfile(transaction_path):
                with open(transaction_path,"rb") as f:
                    transaction_trace = pickle.load(f)
            else:
                transaction_trace = get_trace(transaction, rpc_endpoint)['result']['structLogs']

                with open(transaction_path,"wb") as f:
                    pickle.dump(transaction_trace,f)
        except Exception as e:
            print(e)
            exit(1)

        try:
            transaction_data = get_transactionData(transaction, rpc_endpoint)
             # TODO this assertion makes it so that contract creation trasnactions cannot be examined with this tool, fix this
            assert transaction_data['result']['to'] != None
        except Exception:
            print_err(f"Could not achieve a connection to rpc_endpoint \'{rpc_endpoint}\'")
            exit()

        # Begin replaying the trace
        self.entry(transaction_data['result'])
    
        prev_t = {'depth': 0, 'op': None}
        for i, t in enumerate(transaction_trace):
            op = t['op'] ; stack = t['stack'] ; depth = t['depth']
            if depth < prev_t['depth']:
                self.ret(prev_t)
            current_stack_entry = self.head()
            pc = t['pc']
            self.instructions[current_stack_entry].append(self.InstructionEntry(pc, self.DataEntry( t['stack'], t['storage'], t['memory'] )))

            if op == 'MSTORE':
                self.mstore(stack[-1], stack[-2])
            if op == 'MSTORE8':
                self.mstore8(stack[-1], stack[-2])
            if op == 'CALLDATACOPY':
                self.calldatacopy(stack[-1], stack[-2], stack[-3])
            if op == 'CODECOPY':
                self.codecopy(stack[-1], stack[-2], stack[-3])
            if op in calls and transaction_trace[i + 1]['depth'] != prev_t['depth']:
                # take next address from the stack, cast to 160-bits
                call_address = stack[-2][-40:]
                self.call(call_address, t)
            # self.track_storage(t)
            prev_t = t