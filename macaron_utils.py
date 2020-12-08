import time
from datetime import datetime
import config
from web3 import Web3

known_addresses = {}

# Opcode Defs
opcodes = {
    'STOP': 0x0,
    'ADD': 0x1,
    'MUL':0x2,
    'SUB': 0x3,
    'SHA3' : 0x20,
    'MSTORE': 0x52,
    'SLOAD': 0x54,
    'SSTORE': 0x55,
    'JUMP': 0x56,
    'JUMPI': 0x57,
    'JUMPDEST': 0x5B,
}


# AST data Defs
validAstTypes = [   'ParameterList', 'ExpressionStatement', 'VariableDeclaration', 'VariableDeclarationStatement', 'Return', 'Assignment', 'Identifier',
                    'BinaryOperation', 'Literal', 'MemberAccess', 'IndexAccess', 'FunctionCall', 'UnaryOperation', 'Continue', 'Break', 'Conditional', 'CustomInlineAssemblyChild']

invalidAstTypes = ['PragmaDirective', 'ContractDefinition', 'EventDefinition', 'DoWhileStatement', 'WhileStatement', 'ForStatement', 'IfStatement',
                   'FunctionDefinition', 'PlaceholderStatement', 'InlineAssembly']

node_children_names = { 'arguments', 'baseExpression', 'body', 'components', 'condition', 'declarations', 'expression', 'externalReferences', 'falseBody', 'falseExpression', 'modifiers', 'parameters', 'statements', 'nodes', 'leftHandSide', 'rightHandSide', 
                        'leftExpression', 'rightExpression', 'initializationExpression', 'initialValue', 'value', 'trueBody', 'trueExpression', 'indexExpression', 'loopExpression', 'returnParameters',
                        'subExpression', 'eventCall', '_codeLength', '_addr'}


# Printing Defs
LINE_SPLIT_DELIMETER = '\n'
LINE_LIMIT = 36

# color_normal = '\033[31m\033[40m'       # RED on BLACK
color_normal = '\033[0m\033[97m'               # WHITE

# color_highlight = '\033[30m\033[107m'   # BLACK on BRIGHT WHITE
color_highlight = '\033[30m\033[103m'   # BLACK on BRIGHT YELLOW

color_calldata = '\033[30m\033[105m'    # BLACK on BRIGHT MAGENTA
color_warning = '\033[30m\033[106m'     # BLACK on BRIGHT CYAN
color_note = '\033[30m\033[102m'        # BLACK on BRIGHT GREEN
color_error = '\033[30m\033[101m'       # BLACK on BRIGHT RED
color_reset = '\033[m'                  # RESET


def int_to_hex_addr(address):
    address = Web3.toHex(address)[2:]
    return address.zfill(65 - len(address))


def strip_cbor(bytecode):
    assert(len(bytecode) % 2 == 0)

    cbor_size = int(bytecode[len(bytecode) - 4 : ], 16)

    stripped_bytecode = bytecode[ : len(bytecode) - 4 - cbor_size * 2 + 1]
    cbor_object = bytecode[len(bytecode) - 4 - cbor_size * 2 : ]

    return (stripped_bytecode, cbor_object)


def format_calldata(calldata, value, function_db):

    if calldata == "New Contract Creation":
        return calldata

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
    if selector not in function_db:
        return '#' + selector
    function_data = function_db[selector]
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

def print_err(msg):
    print(f"{color_error}Error: {msg}{color_normal}.")