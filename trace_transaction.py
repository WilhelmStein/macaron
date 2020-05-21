#!/usr/bin/env python
# connect to db, make sure there is an ssh tunnel:
#ssh contract-library.com -L 3307:127.0.0.1:3306 -N
import pymysql
import pandas as pd
import dill
import solcx
import solcx.install
from collections import defaultdict, OrderedDict, Mapping, namedtuple
from itertools import chain
import evm_stack
import os.path
import pickle
import functools
from trace_shell import MacaronShell


# Globals
LINE_SPLIT_DELIMETER = '\n'

color_normal = '\033[31m\033[40m'
color_highlight = '\033[30m\033[107m'


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


validAstTypes = [   'ParameterList', 'ExpressionStatement', 'VariableDeclaration', 'VariableDeclarationStatement', 'Return', 'Assignment', 'Identifier',
                    'BinaryOperation', 'Literal', 'MemberAccess', 'IndexAccess', 'FunctionCall', 'UnaryOperation']

invalidAstTypes = ['PragmaDirective', 'ContractDefinition', 'EventDefinition', 'DoWhileStatement', 'WhileStatement', 'ForStatement', 'IfStatement',
                   'FunctionDefinition', 'PlaceholderStatement']

node_children_names = { 'parameters', 'statements', 'nodes', 'arguments', 'declarations', 'body', 'expression', 'leftHandSide', 'rightHandSide', 
                        'leftExpression', 'rightExpression', 'initializationExpression', 'initialValue', 'expression', 'trueBody', 'falseBody', 
                        'condition', 'baseExpression', 'indexExpression', 'loopExpression', 'returnParameters', 'subExpression', 'eventCall', 'components' }

# Debug
# validAstTypes += invalidAstTypes
# invalidAstTypes = []

NodeWrapper = namedtuple('NodeWrapper', ['node', 'lineage'])


# Function Definitions
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


def create_source_index(source):
    line = 0
    line_index = {}
    char_index = defaultdict(list)

    for i, s in enumerate(source):
        line_index[i] = line
        char_index[line].append(i)

        if s == LINE_SPLIT_DELIMETER:
            line +=1
    return (line_index, char_index)


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
        

    return (ast, contract)


def get_contract_from_db(a, conn):
    """Connect to contract-lib.com and receive the contract's code."""

    res = pd.read_sql_query(query_source%a, conn)
    if len(res) == 0:
        return None
    for i, row in res.iterrows():
        if sum(v is None for v in row.values) > 1:
            return None
        return row


def valid_source(ast, fro, length, source_index):
    ast_fro, ast_length, ast_source_index = map(int, ast['src'].split(':'))

    return ( fro >= ast_fro and fro + length <= ast_fro + ast_length and ast_source_index == source_index )


def list_children(ast):
    """Utility function that, given an ast node, returns its children in list form."""
    nodes = []

    for name in node_children_names:
        if name in ast and ast[name]:
            if isinstance(ast[name], Mapping):
                nodes.append(ast[name])
            else:
                nodes += ast[name] # Lists can contain None Elements (for some inexplicable reason!)
    
    return nodes


def search_ast(wrapper, fro, length, source_index):
    """Recursive function that searches a given AST for a node with a specific source mapping."""
    
    ast, lineage = wrapper

    if ast is None:
        raise Exception(f"Node is None. Searching for {fro} : {length} : {source_index}")

    curr_node_s, curr_node_r, curr_node_m = map(int , ast['src'].split(':'))
    output_node = None

    if fro == curr_node_s and length == curr_node_r and curr_node_m == source_index:
        output_node = (ast, lineage)
    elif curr_node_s + curr_node_r < fro or curr_node_s > fro + length: # A small optimization, as to avoid a full dfs of the ast
        return None

    nodes = list_children(ast)
            
    
    for node in nodes:
        if node is None:
            continue

        returned_node = search_ast((node, [ast] + lineage), fro, length, source_index)

        if returned_node is None:
            continue

        output_node = returned_node

    return output_node


def remove_consecutives(node_list):
    """Remove consecutive entries from a given list."""

    prevNode = None
    output_list = []

    for node in node_list:
        if prevNode == node:
            continue
        prevNode = node
        output_list.append(node)
    
    return output_list    


def group_instructions(instruction_node_list):
    """Try to group bytecode instructions that correspond to the same solidity instruction"""
    
    output_list = []
    grouped_nodes = {}
    scope = None

    opcodes = {'JUMP': 0x56, 'JUMPI': 0x57, 'JUMPDEST': 0x5B}
    
    for idx, (opcode, node_wrapper) in enumerate(instruction_node_list):
        # TODO Optimize

        node, lineage = node_wrapper
        if node['nodeType'] in {'ModifierDefinition', 'FunctionDefinition'}:
            scope = node['src']
        else:
            for ancestor in lineage:
                if ancestor['nodeType'] in {'ModifierDefinition', 'FunctionDefinition'}:
                    scope = ancestor['src']
                    break

        if not scope:
            continue
        elif opcode == opcodes['JUMPI'] or opcode == opcodes['JUMP']:
            output_list.append((scope, grouped_nodes))
            grouped_nodes = {}
        elif opcode != opcodes['JUMPDEST']:
            grouped_nodes[node['id']] = node

    if grouped_nodes:
        output_list.append((scope, grouped_nodes))

    return output_list


def calculate_trace_display(stack, conn):
    """Renders a trace in human-readable format."""

    contract_trace = []

    for stack_entry in stack.trace:
        current_step = f"{color_normal}{'#'*80}\nEVM is running code at {stack_entry.address}. Reason: {stack_entry.reason}\n"
        # print(current_step)
        res = get_contract_from_db(stack_entry.address, conn)

        if res is None:
            current_step += "Source not found in db, skipping..."
            continue

        code = res['code']
        contract_name = res['contract_name']
        bytecode = res['hex_bytecode']
        source_map = res['source_map']

        stack_entry_folder = f"{stack.starting_transaction}/{stack_entry[0]}"
        ast = solidity_file = None
        
        # Save compiler output as to not recompile each time
        try:
            ast_path = f"{stack_entry_folder}/ast.pkl"
            solidity_file_path = f"{stack_entry_folder}/solidity_file.pkl"

            if os.path.exists(stack_entry_folder):
                with open(ast_path, "rb") as f:
                    ast = pickle.load(f)
                
                with open(solidity_file_path, "rb") as f:
                    solidity_file = pickle.load(f)
            else:
                ast, solidity_file = compile_solidity(**res)

                os.makedirs(stack_entry_folder)

                with open(ast_path,"wb") as f:
                    pickle.dump(ast,f)
                
                with open(solidity_file_path,"wb") as f:
                    pickle.dump(solidity_file,f)

        except Exception as e:
            print(e)
            exit(1)


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
                    
                
                if valid_source(ast, fro, length, source_index):
                    ast_node = search_ast((ast, []), fro, length, source_index)

                    if ast_node is None:
                        print(f"Could not find ast node from source mapping: {fro} : {length} : {source_index}")
                    else:
                        instruction_node_list.append( (stack.instructions_order[stack_entry][pc], opcode, ast_node) )
                        

            if 0x60 <= opcode < 0x80:
                # it's a push instruction, increment by extra size of instruction
                pc += (opcode - 0x5f)
            pc += 1


        # Sort the list and clip the node ordering
        instruction_node_list = list(map(lambda a: (a[1], a[2]), sorted(instruction_node_list, key = lambda a: a[0])))

        line_index, char_index = create_source_index(code)
        
        step_counter = 0
        step_trace = []
        for idx, (scope, node_set) in enumerate(group_instructions(instruction_node_list)):#remove_consecutives(instruction_node_list):

            scope_f, scope_r, scope_l = map(int, scope.split(':'))
            highlighted_nodes = set()
            highlighted_indices = set()
            node_types = []
            
            for _, node in node_set.items():
            
                if node['nodeType'] in validAstTypes:
                    node_types.append(node['nodeType'])

                    if node['id'] not in highlighted_nodes: #and highlight_node_family(node, node_set):
                        highlighted_nodes.add(node['id'])
                        node_f, node_r, node_l = map(int, node['src'].split(':'))
                        highlighted_indices.update(range(node_f, node_f + node_r + 1))

                elif node['nodeType'] not in invalidAstTypes:
                    print(f"Warning: Unknown AST Node type: {node['nodeType']} encountered during mapping to source.")
            
            source_display = ""

            curr_color = color_normal
            for i in range(scope_f, scope_f + scope_r): # TODO Check when range is incorrect
                if i in highlighted_indices:
                    if curr_color == color_normal:    
                        curr_color = color_highlight
                        source_display += curr_color
                    
                else:
                    if curr_color == color_highlight:
                        curr_color = color_normal
                        source_display += curr_color

                source_display += code[i]
                
            if node_types:
                current_step += f"step {step_counter}:\nline: {line_index[scope_f] + 1} : {source_display}{color_normal} : {node_types}\n"
                step_trace.append((current_step, node_types))
                current_step = ""
                step_counter += 1
            
        contract_trace.append(step_trace)
        
    return contract_trace

# Execution start
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
        step_trace = calculate_trace_display(stack, conn)

        navigator = MacaronShell(step_trace)
        navigator.cmdloop()
    except Exception:
        import pdb
        import traceback
        import sys

        extype, value, tb = sys.exc_info()
        traceback.print_exc()

        pdb.post_mortem(tb)
        
