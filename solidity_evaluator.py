
from collections import namedtuple
from web3 import Web3

SolidityState = namedtuple('State', ['stack', 'memory', 'storage'])
OpcodeWrapper = namedtuple('OpcodeWrapper', ['value', 'transition'])


opcodes = {
    'STOP': OpcodeWrapper(0x0, lambda state: state),
    'ADD': OpcodeWrapper(0x1, lambda state: SolidityState(state.stack[0:-2] + [state.stack[-1] + state.stack[-2]], state.storage, state.memory) ),
    'MUL': OpcodeWrapper(0x2, lambda state: SolidityState(state.stack[0:-2] + [state.stack[-1] * state.stack[-2]], state.storage, state.memory) ),
    'SUB': OpcodeWrapper(0x3, lambda state: SolidityState(state.stack[0:-2] + [state.stack[-1] - state.stack[-2]], state.storage, state.memory) ),
    'SHA3' : OpcodeWrapper(0x20, lambda state : sha3(state) ),
    'MSTORE': OpcodeWrapper(0x52, None),
    'SLOAD': OpcodeWrapper(0x54, None),
    'SSTORE': OpcodeWrapper(0x55, None),
    'JUMP': OpcodeWrapper(0x56, None),
    'JUMPI': OpcodeWrapper(0x57, None),
    'JUMPDEST': OpcodeWrapper(0x5B, None)
}


def evaluate(start_state, instructions):
    
    current_state = start_state
    
    for opcode in instructions:
        current_state = opcodes[opcode].transition(current_state)

    return current_state


def sha3(state):
    # Extract arguments from stack
    *_, length, offset = state.stack
    length = int(length, base=16)
    offset = int(length, base=16)
    offset_mod = offset % 32

    state.memory[offset/32]
        


    # hash_value = Web3.solidityKeccak(,)
    return SolidityState(state.stack[0:-2] + [hash_value])