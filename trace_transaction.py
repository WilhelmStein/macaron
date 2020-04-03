#!/usr/bin/env python
# connect to db, make sure there is an ssh tunnel:
#ssh contract-library.com -L 3307:127.0.0.1:3306 -N
import pymysql
import pandas as pd
import requests
import json
import dill
import solcx
import solcx.install
import pickle
from collections import defaultdict, namedtuple
from itertools import chain

# transaction = '0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838' # Flash Loan Attack
transaction = '0x7155e10930c1b1e5afae6781cc09bbd4150f6dda' # test1

def get_trace(hash):
    payload = {"jsonrpc":"2.0","id":8,"method":"debug_traceTransaction", "params":
               [ hash, {"disableStorage":True,"disableMemory":True,"disableStack":False,"fullStorage":False}
               ]
    }
    response = requests.post('http://node.web3api.com:8545/', json = payload, timeout = 100, stream = True)
    assert response.status_code == 200, response
    response_json = json.loads(response.text)
    return response_json

calls = {'CALL', 'CALLCODE', 'STATICCALL', 'DELEGATECALL', 'CREATE', 'CREATE2'}

trace = get_trace(transaction)['result']['structLogs']

with open("file.pkl","wb") as f:
   pickle.dump(trace,f)
with open("./transaction_debugger/file.pkl","rb") as f:
    trace = pickle.load(f)


class EVMExecuctionStack:

    StackEntry = namedtuple('StackEntry', ['address', 'reason', 'vmstate'])
    
    def __init__(self):
        self.stack = []
        self.trace = []
        order = 0

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
        
evm_stack = EVMExecuctionStack()
evm_stack.entry('0' * 40)
instructions = defaultdict(set)
instructions_order = defaultdict(lambda : defaultdict(lambda : 0xFFFF))

prev_depth = 0
for t in trace:
    if t['depth'] < prev_depth:
        evm_stack.ret()
    current_stack_entry = evm_stack.head()
    pc = t['pc']
    instructions[current_stack_entry].add(pc)
    instructions_order[current_stack_entry][pc] = min(instructions_order[current_stack_entry][pc], evm_stack.order)
    evm_stack.order += 1
    if t['op'] in calls:
        # take next address from the stack, cast to 160-bits
        evm_stack.call(t['stack'][-2][-40:], t['op'])
    prev_depth = t['depth']


query_decompiled = """
  select d.source_level, d.debug
  from address a
  join decompiled_code d on a.md5_bytecode = d.md5_bytecode
  where a.address = '%s'
  and a.network = 'Ethereum'
"""

query_source = """
  select b.hex_bytecode, d.*
  from address a
  join source_code d on a.md5_bytecode = d.md5_bytecode and d.`code` is not null
  join bytecode b on b.md5_bytecode = a.md5_bytecode
  where a.address = '%s'
  and a.network = 'Ethereum'
"""

def make_compiler_json(filename, optimization_enabled = False, optimization_runs = 0, evmVersion = None):
    settings = {
        'optimizer': {
          'enabled': optimization_enabled,
          'runs': optimization_runs
         },
        'evmVersion': evmVersion, 
        'outputSelection': {
            "*": {
                "*": [ 'evm.deployedBytecode.sourceMap', 'evm.deployedBytecode.object' ]
            }
        }
      }
    if evmVersion is None:
        del settings['evmVersion']
    return {
      'language': "Solidity",
      'sources': {
        filename: {
            'urls': [filename]
        },
      },
      'settings': settings
    }

LINE_SPLIT_DELIMETER = '\n'

def char_to_line(source):
    line = 0
    res = {}
    for i, s in enumerate(source):
        res[i] = line
        if s == LINE_SPLIT_DELIMETER:
            line +=1
    return res
        

conn = pymysql.connect(
    host="127.0.0.1",
    port=int(3307),
    user="tracer",
    passwd="a=$G5)Z]vqY6]}w{",
    db="gigahorse",
    charset='utf8mb4')

def process_compiler_version(compiler):
    print(compiler)
    compiler_processed = compiler[:7]
    if compiler_processed[-1] == '+':
        compiler_processed = compiler_processed[:-1]
    if float(compiler_processed[1:4] + compiler_processed[6:]) < 0.411:
        return 'v0.4.11'
    return compiler_processed

def compile_solidity(code, compiler, optimization, other_settings, **kwargs):
    assert isinstance(code, str)
    with open('/tmp/temp.sol', 'w') as f:
        f.write(code)
    compiler_processed = process_compiler_version(compiler)
    # process optimization flag
    optimization_enabled, _, optimization_runs, _ = optimization.split(' ')
    optimization_enabled = optimization_enabled.lower() == 'yes'
    optimization_runs = int(optimization_runs)
    evmVersion = other_settings.split(' ')[0]
    if evmVersion == 'default':
        evmVersion = None
    try:
        solcx.install_solc(compiler_processed)
        solcx.set_solc_version(compiler_processed)
        output_js = solcx.compile_standard(make_compiler_json('/tmp/temp.sol', optimization_enabled, optimization_runs, evmVersion), allow_paths='/tmp')
    except solcx.exceptions.SolcError as e:
        print("SOLC Compiler error")
        print(e)
        return None
    return list(output_js['contracts'].values())[0]

colors = [f'\033[38;5;{15 if c<244 else 0}m\033[48;5;{c}m' for c in range(255, 233, -1)]
color_unused = '\033[38;5;0m\033[48;5;232m'
color_entrypoint = '\033[38;5;45m\033[48;5;15m'
color_important = '\033[38;5;9m\033[48;5;15m'

def explain_legend():
    color_line = 'The background color is the order in which the statement is executed............'
    n = len(color_line) // len(colors) + 1
    
    print(color_important + 'Legend:')
    print(' '+ (''.join(chain.from_iterable(zip(colors, [color_line[i:i+n] for i in range(0, len(color_line), n)])))))
    print(color_entrypoint + '  Entry Point')
    print(color_unused + "  Unexecuted")

def get_contract_from_db(a):
    res = pd.read_sql_query(query_source%a, conn)
    if len(res) == 0:
        return None
    for i, row in res.iterrows():
        if sum(v is None for v in row.values) > 1:
            return None
        return row

def main_render():
    explain_legend()
    for stack_entry in evm_stack.trace:
        print(color_important + '#'*80)
        print(f'EVM is running code at {stack_entry.address}. Reason: {stack_entry.reason}')
        res = get_contract_from_db(stack_entry.address)
        if res is None:
            print("Source not found in db, skipping...")
            continue
        code = res['code']
        contract_name = res['contract_name']
        bytecode = res['hex_bytecode']
        source_map = res['source_map']
        if source_map is None:
            solidity_file = compile_solidity(**res)
            if solidity_file is None:
                continue
            contract = solidity_file[contract_name]
            source_map = contract['evm']['deployedBytecode']['sourceMap']
            object = contract['evm']['deployedBytecode']['object']
        else:
            object = bytecode

        inst_to_source_line = defaultdict(set)
        source_char_to_line = char_to_line(code)
        
        if object == bytecode:
            print('Compiled bytecode matches perfectly')
        elif len(object) == len(bytecode):
            print('Compiled bytecode does not match perfectly, but is the same size')
        else:
            print(f'Warning: Deployed bytecode is length {len(bytecode)}, but compiled bytecode is length {len(object)}')
        pc = 0
        for s in source_map.split(';'):
            if s:
                s_split = s.split(':')
                if s_split[0]:
                    fro = int(s_split[0])
                if len(s_split) > 1 and s_split[1]:
                    length = int(s_split[1])
            inst_to_source_line[pc].update(
                source_char_to_line[c] for c in range(fro, fro+length) 
            )
            opcode = int(object[pc * 2] + object[pc * 2 + 1], 16)
            if 0x60 <= opcode < 0x80:
                # it's a push instruction, increment by extra size of instruction
                pc += (opcode - 0x5f)
            pc += 1
        contributing = defaultdict(float)
        source_lines = set()
        source_lines_order = defaultdict(lambda : 0xFFFF)
        most_contributing_instruction_for_source_line = defaultdict(lambda : [0, 0])

        for i in instructions[stack_entry]:
            inst_contributing_per_line = 1.0 / len(inst_to_source_line[i])
            for l in inst_to_source_line[i]:
                source_lines.add(l)
                contributing[l] += inst_contributing_per_line
                i_m, c_m = most_contributing_instruction_for_source_line[l]
                if inst_contributing_per_line > c_m:
                    most_contributing_instruction_for_source_line[l] = i, inst_contributing_per_line

        for l, (i, _) in most_contributing_instruction_for_source_line.items():
            source_lines_order[l] = instructions_order[stack_entry][i]

        source_lines_color = {}

        sorted_source_lines_order = sorted(source_lines_order.items(), key = lambda a: a[1] * 0xFFFF + a[0])
        for i, (s, _) in enumerate(sorted_source_lines_order):
            source_lines_color[s] = colors[int((float(i) / len(source_lines)) * len(colors))]
        output = []
        elipses = False
        for l, c in enumerate(code.split(LINE_SPLIT_DELIMETER)):
            if l in source_lines and contributing[l] >= 2:
                output.append(source_lines_color[l] + c)
            else:
                output.append(color_unused + c)
        # postprocess
        output2 = []
        for i, o in enumerate(output):
            if o.startswith(color_unused):
                if all(output[j].startswith(color_unused) for j in range(max(i-2, 0), min(i+2, len(output)-1))):
                    continue
            output2.append(o)
        print(LINE_SPLIT_DELIMETER.join(output2).replace('\r', ''))

if __name__ == '__main__':
    try:
        main_render()
    except Exception:
        import pdb
        import traceback
        import sys

        extype, value, tb = sys.exc_info()
        traceback.print_exc()

        pdb.post_mortem(tb)
        
