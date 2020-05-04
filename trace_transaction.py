#!/usr/bin/env python
# connect to db, make sure there is an ssh tunnel:
#ssh contract-library.com -L 3307:127.0.0.1:3306 -N
import pymysql
import pandas as pd
import dill
import solcx
import solcx.install
from collections import defaultdict
from itertools import chain
import evm_stack

# entry = pd.read_sql_query(f'select * from ', conn)


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
                "*": [ 'evm.deployedBytecode.sourceMap', 'evm.deployedBytecode.object' ],
                "": ["ast"]
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
    
    return (list(output_js['sources'].values())[0]['ast'], list(output_js['contracts'].values())[0]) # TODO Clean Up 


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


def get_contract_from_db(a, conn):
    res = pd.read_sql_query(query_source%a, conn)
    if len(res) == 0:
        return None
    for i, row in res.iterrows():
        if sum(v is None for v in row.values) > 1:
            return None
        return row


validAstTypes = ['ParameterList', 'ExpressionStatement', 'FunctionCall']
invalidAstTypes = ['PragmaDirective','VariableDeclaration']

def search_ast(ast, fro, length):

    # if 'src' not in ast:
    #     return None

    node_s, node_r, node_m = ast['src'].split(':')

    if fro == int(node_s) and length == int(node_r):
        return ast
    # TODO Add source searching


    nodes = []
    nodes += ast['body']['statements'] if 'body' in ast else []
    nodes += [ast['expression']] if 'expression' in ast else []
    nodes += [ast['leftHandSide']]  if 'leftHandSide' in ast else []
    nodes += [ast['rightHandSide']] if 'rightHandSide' in ast else []
    nodes += [ast['expression']] if 'expression' in ast else []
    nodes += ast['nodes'] if 'nodes' in ast else []
    
    
    for node in nodes:
        returned_node = search_ast(node, fro, length)

        if returned_node is None:
            continue
        else:
            return returned_node

    return None


def remove_consecutives(input_list):
    prevElem = None
    for elem in input_list:
        if prevElem == elem:
            continue
        else:
            prevElem = elem
            yield elem 


def main_render(stack, conn):
    explain_legend()
    for stack_entry in stack.trace:
        print(color_important + '#'*80)
        print(f'EVM is running code at {stack_entry.address}. Reason: {stack_entry.reason}')
        res = get_contract_from_db(stack_entry.address, conn)

        if res is None:
            print("Source not found in db, skipping...")
            continue

        code = res['code']
        contract_name = res['contract_name']
        bytecode = res['hex_bytecode']
        source_map = res['source_map']
        ast, solidity_file = compile_solidity(**res)

        if source_map is None:
            if solidity_file is None or ast is None:
                continue

            contract = solidity_file[contract_name]
            source_map = contract['evm']['deployedBytecode']['sourceMap']
            object = contract['evm']['deployedBytecode']['object']
        else:
            object = bytecode

        
        if object == bytecode:
            print('Compiled bytecode matches perfectly')
        elif len(object) == len(bytecode):
            print('Compiled bytecode does not match perfectly, but is the same size')
        else:
            print(f'Warning: Deployed bytecode is length {len(bytecode)}, but compiled bytecode is length {len(object)}')

        pc = 0
        ast_list = []
        for s in source_map.split(';'):

            # Filter out all instructions that were not part of the trace
            if pc in stack.instructions[stack_entry]:
                if s:
                    s_split = s.split(':')
                    if s_split[0]:
                        fro = int(s_split[0])

                    if len(s_split) > 1 and s_split[1]:
                        length = int(s_split[1])

                    
                ast_node = search_ast(ast, fro, length)

                if ast_node and ast_node['nodeType'] in validAstTypes: 
                    ast_list.append(ast_node)

            opcode = int(object[pc * 2] + object[pc * 2 + 1], 16)

            if 0x60 <= opcode < 0x80:
                # it's a push instruction, increment by extra size of instruction
                pc += (opcode - 0x5f)
            pc += 1

        line_index = char_to_line(code)

        print('Displaying trace:')
        for ast_node in remove_consecutives(ast_list):
            node_f, node_r, node_l = ast_node['src'].split(':')
            print("line " + str(line_index[int(node_f)] + 1) + ": " + code[int(node_f) : int(node_f) + int(node_r)])
        print('\n')


if __name__ == '__main__':
    try:
        # transaction = '0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b'    # DAO Attack
        # transaction = '0x863df6bfa4469f3ead0be8f9f2aae51c91a907b4'                            # Parity Attack
        # transaction = '0xd6c24da4e17aa18db03f9df46f74f119fa5c2314cb1149cd3f88881ddc475c5a'    # DAOSTACK Attack - Self Destructed :(
        # transaction = '0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838'    # Flash Loan Attack

        # transaction = '0xa2f866c2b391c9d35d8f18edb006c9a872c0014b992e4b586cc2f11dc2b24ebd' # test1
        # transaction = '0xc1f534b03e5d4840c091c54224c3381b892b8f1a2869045f49913f3cfaf95ba7' # Million Money
        # transaction = '0xa537c0ae6172fc43ddadd0f94d2821ae278fae4ba8147ea7fa882fa9b0a6a51a' # Greed Pit
        transaction = '0x51f37d7b41e6864d1190d8f596e956501d9f4e0f8c598dbcbbc058c10b25aa3b' # Dust
        # transaction = '0x3f0a309ebbc5642ec18047fb902c383b33e951193bda6402618652e9234c9abb' # Tokens

        conn = pymysql.connect(
            host="127.0.0.1",
            port=int(3307),
            user="tracer",
            passwd="a=$G5)Z]vqY6]}w{",
            db="gigahorse",
            charset='utf8mb4')

        stack = evm_stack.EVMExecuctionStack()
        stack.import_transaction(transaction)

        main_render(stack, conn)
    except Exception:
        import pdb
        import traceback
        import sys

        extype, value, tb = sys.exc_info()
        traceback.print_exc()

        pdb.post_mortem(tb)
        
