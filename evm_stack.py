#!/usr/bin/env python
from collections import namedtuple, defaultdict
from web3_connections import *
import os.path
import pickle

class EVMExecuctionStack:
    calls = {'CALL', 'CALLCODE', 'STATICCALL', 'DELEGATECALL', 'CREATE', 'CREATE2'}
    StackEntry = namedtuple('StackEntry', ['address', 'reason', 'vmstate'])
    InstructionEntry = namedtuple('InstructionEntry', ['pc', 'data'])
    DataEntry = namedtuple('DataEntry', ['stack', 'storage', 'memory'])
    

    def __init__(self):
        self.stack = []
        self.trace = []
        self.instructions = defaultdict(list)
        self.instructions_order = defaultdict(lambda : defaultdict(lambda : 0xFFFF))
        self.data_at_instruction = defaultdict(lambda : defaultdict(self.DataEntry))


    def entry(self, address):
        self.stack.append([address, 'ENTRY'])
        self.state = 0
        self.do_trace()
        

    def do_trace(self):
        self.trace.append(self.StackEntry(*(self.stack[-1] + [self.state])))


    def call(self, address, opcode):
        self.stack.append([address, opcode])
        self.state += 1
        self.do_trace()


    def ret(self):
        self.stack.pop()
        self.stack[-1][1] = 'RETURN from previous contract'
        self.state += 1
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

            self.instructions[current_stack_entry].append(self.InstructionEntry(pc, self.DataEntry( t['stack'], t['storage'], t['memory'] )))

            if t['op'] in self.calls and transaction_trace[idx + 1]['depth'] != prev_depth:
                # take next address from the stack, cast to 160-bits
                self.call(t['stack'][-2][-40:], t['op'])
                
            prev_depth = t['depth']

        