#!/usr/bin/env python
from collections import namedtuple, defaultdict
from web3_connections import *
import os.path
import pickle

class EVMExecuctionStack:
    calls = {'CALL', 'CALLCODE', 'STATICCALL', 'DELEGATECALL', 'CREATE', 'CREATE2'}
    StackEntry = namedtuple('StackEntry', ['address', 'reason', 'vmstate'])
    PersistantDataEntry = namedtuple('PersistantDataEntry', ['stack', 'storage', 'memory'])
    
    def __init__(self):
        self.stack = []
        self.trace = []
        self.instructions = defaultdict(set)
        self.instructions_order = defaultdict(lambda : defaultdict(lambda : 0xFFFF))
        self.data_at_instruction = defaultdict(lambda : defaultdict(self.PersistantDataEntry))
        self.order = 0

    def entry(self, address):
        self.stack.append([address, 'ENTRY'])
        self.state = 0
        self.order = 0
        self.do_trace()
        
    def do_trace(self):
        self.trace.append(self.StackEntry(*(self.stack[-1] + [self.state])))


    def call(self, address, opcode):
        self.stack.append([address, opcode])
        self.state += 1
        self.order = 0
        self.do_trace()

    def ret(self):
        self.stack.pop()
        self.stack[-1][1] = 'RETURN from previous contract'
        self.state += 1
        self.order = 0
        self.do_trace()

    def head(self):
        return self.trace[-1]
    
    def import_transaction(self, transaction, rpc_endpoint):

        self.entry(get_starting_contract(transaction, rpc_endpoint)[2:])

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


        prev_depth = 0

        for idx, t in enumerate(transaction_trace):
            if t['depth'] < prev_depth:
                self.ret()

            current_stack_entry = self.head()
            pc = t['pc']

            self.instructions[current_stack_entry].add(pc)
            self.instructions_order[current_stack_entry][pc] = min(self.instructions_order[current_stack_entry][pc], self.order)
            self.data_at_instruction[current_stack_entry][pc] = self.PersistantDataEntry( t['stack'], t['storage'], t['memory'] )
            self.order += 1

            if t['op'] in self.calls and transaction_trace[idx + 1]['depth'] != prev_depth:
                # take next address from the stack, cast to 160-bits
                self.call(t['stack'][-2][-40:], t['op'])
                
            prev_depth = t['depth']

        