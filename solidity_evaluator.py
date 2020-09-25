
from collections import namedtuple

SolidityState = namedtuple('State', ['stack', 'memory', 'storage'])
OpcodeWrapper = namedtuple('OpcodeWrapper', ['value', 'transition'])

opcodes = {
    'STOP': OpcodeWrapper(0x0, lambda state: state),
    'ADD': OpcodeWrapper(0x1, lambda state: SolidityState(state.stack[0:-2] + [state.stack[-1] + state.stack[-2]], state.memory, state.storage) ),
    'MUL': OpcodeWrapper(0x2, lambda state: SolidityState(state.stack[0:-2] + [state.stack[-1] * state.stack[-2]], state.memory, state.storage) ),
    'SUB': OpcodeWrapper(0x3, lambda state: SolidityState(state.stack[0:-2] + [state.stack[-1] - state.stack[-2]], state.memory, state.storage) ),
    'SHA3' : OpcodeWrapper(0x20, lambda state: state ),
    'MSTORE': 0x52,
    'SLOAD': 0x54,
    'SSTORE': 0x55,
    'JUMP': 0x56,
    'JUMPI': 0x57,
    'JUMPDEST': 0x5B
}

def evaluate(self, start_state, instructions):
    
    current_state = start_state
    
    for opcode in instructions:
        current_state = opcodes[opcode].transition(current_state)

    return current_state

