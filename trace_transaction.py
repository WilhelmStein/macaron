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
import collections

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

    ast = None
    contract = list(output_js['contracts'].values())[0]
    source = list(output_js['sources'].values())[0]


    if 'ast' in source:
        ast = source['ast']
        

    return (ast, contract) # TODO Clean Up 


colors = [f'\033[38;5;{15 if c<244 else 0}m\033[48;5;{c}m' for c in range(255, 233, -1)]
color_unused = '\033[38;5;0m\033[48;5;232m'
color_entrypoint = '\033[38;5;45m\033[48;5;15m'
color_important = '\033[38;5;9m\033[48;5;15m'


def get_contract_from_db(a, conn):
    res = pd.read_sql_query(query_source%a, conn)
    if len(res) == 0:
        return None
    for i, row in res.iterrows():
        if sum(v is None for v in row.values) > 1:
            return None
        return row


validAstTypes = ['ParameterList', 'ExpressionStatement', 'FunctionCall', 'VariableDeclarationStatement', 'DoWhileStatement', 'WhileStatement', 'ForStatement', 'IfStatement',
                  'Return']

invalidAstTypes = ['PragmaDirective', 'ContractDefinition', 'EventDefinition', 'VariableDeclaration', 'Identifier', 'BinaryOperation',
                   'FunctionDefinition', 'Literal', 'MemberAccess', 'IndexAccess']


def search_ast(ast, fro, length, source_index):

    curr_node_s, curr_node_r, curr_node_m = map(int , ast['src'].split(':'))

    if fro == curr_node_s and length == curr_node_r and curr_node_m == source_index:
        return ast

    # TODO Performance optimizations

    ambiguous_size_element_types = {'parameters'}
    list_element_types = {'statements', 'nodes', 'arguments', 'declarations'}
    single_element_types = { 'body', 'expression', 'leftHandSide', 'rightHandSide', 'leftExpression', 'rightExpression',
                             'initializationExpression', 'initialValue', 'expression', 'trueBody', 'falseBody', 'condition', 
                             'baseExpression', 'indexExpression', 'loopExpression', 'returnParameters', 'subExpression'}

    nodes = []

    for element_type in single_element_types:
        if element_type in ast and ast[element_type]:
            nodes.append(ast[element_type])

    for element_type in list_element_types:
        nodes += ast[element_type] if element_type in ast and ast[element_type] else []

    for element_type in ambiguous_size_element_types:
        if element_type in ast:
            if isinstance(ast[element_type], collections.Mapping):
                nodes.append(ast[element_type])
            else:
                nodes += ast[element_type]
            

    
    for node in nodes:
        # node_s, node_r, node_m = map(int, node['src'].split(':'))

        # # A small optimization, as to avoid a full dfs of the ast
        # if node_s < fro or node_s >= fro + length:
        #     continue

        returned_node = search_ast(node, fro, length, source_index)

        if returned_node is None:
            continue

        return returned_node

    return None

def remove_consecutives(node_list):
    prevNode = None
    output_list = []

    for node in node_list:
        if prevNode == node:
            continue
        prevNode = node
        output_list.append(node)
    
    return output_list


def group_instructions(instruction_node_list):
    
    explored_nodes = set() #defaultdict(int)
    grouped_node_list = []

    jumpOpcodes = {0x56, 0x57}

    for (opcode, node) in instruction_node_list:

        
        if opcode in jumpOpcodes:
            explored_nodes = set()
        elif node['id'] in explored_nodes:
            continue
        else:
            explored_nodes.add(node['id'])
            grouped_node_list.append(node)

    return remove_consecutives(grouped_node_list)



def main_render(stack, conn):
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

        if ast is None:
            print('AST is empty or using legacyAST, which is not supported.')
            continue

        if True:# if source_map is None:
            if solidity_file is None or ast is None:
                continue

            contract = solidity_file[contract_name]
            source_map = contract['evm']['deployedBytecode']['sourceMap']
            object = contract['evm']['deployedBytecode']['object']
        else:
            object = bytecode

        
        # if object == bytecode:
        #     print('Compiled bytecode matches perfectly')
        # elif len(object) == len(bytecode):
        #     print('Compiled bytecode does not match perfectly, but is the same size')
        # else:
        #     print(f'Warning: Deployed bytecode is length {len(bytecode)}, but compiled bytecode is length {len(object)}')

        pc = 0
        instruction_node_list = []
        for s in source_map.split(';'):

            # Filter out all instructions that were not part of the trace

            opcode = int(object[pc * 2] + object[pc * 2 + 1], 16)

            if pc in stack.instructions[stack_entry]:
                if s:
                    s_split = s.split(':')
                    if s_split[0]:
                        fro = int(s_split[0])

                    if len(s_split) > 1 and s_split[1]:
                        length = int(s_split[1])
                    
                    if len(s_split) > 2 and s_split[2]:
                        source_index = int(s_split[2])
                    
                
                if source_index != -1:
                    ast_node = search_ast(ast, fro, length, source_index)

                    if ast_node is None:
                        raise Exception(f"Could not find ast node from source mapping: {fro} : {length} : {source_index}")

                    instruction_node_list.append((opcode, ast_node))
                        

            if 0x60 <= opcode < 0x80:
                # it's a push instruction, increment by extra size of instruction
                pc += (opcode - 0x5f)
            pc += 1

        line_index = char_to_line(code)

        print('Displaying trace:')
        for node in group_instructions(instruction_node_list):#remove_consecutives(instruction_node_list):
            if node['nodeType'] in validAstTypes:
                node_f, node_r, node_l = map(int, node['src'].split(':'))
                print(f"line {line_index[node_f] + 1}: {code[node_f - 1 : node_f + node_r].lstrip()} : node_id {node['id']} : {node['nodeType']}")
            elif node['nodeType'] in invalidAstTypes:
                continue
            else:
                print(f"Warning: Unknown AST Node type: {node['nodeType']} encountered during AST search.")


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
        # transaction = '0x51f37d7b41e6864d1190d8f596e956501d9f4e0f8c598dbcbbc058c10b25aa3b' # Dust
        # transaction = '0x3f0a309ebbc5642ec18047fb902c383b33e951193bda6402618652e9234c9abb' # Tokens
        transaction = '0x6aec28ad65052132bf04c0ed621e24c007b2476fe6810389232d3ac4222c0ccc' # Doubleway
        # transaction = '0xa228e903a5d751e4268a602bd6b938392272e4024e2071f7cd4a479e8125c370' # Saturn Network 2

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
        
