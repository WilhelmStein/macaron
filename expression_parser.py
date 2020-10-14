from abc import ABC, abstractmethod
from collections import namedtuple
from enum import Enum

class StateCode(Enum):
    Identifier = 0
    IndexAccess = 1


class State(ABC):
    buffer = ''
    StateOutput = namedtuple('StateOutput', ['data', 'remaining_input', 'new_state'])
    StateData = namedtuple('StateData', ['code', 'value'])
    
    @abstractmethod
    def transition(self, input_stream):
        return NotImplemented


class ReadString(State):

    def transition(self, input_stream):
        for idx, c in enumerate(input_stream):
            if c.isalpha() or c.isnumeric() or c == '_':
                self.buffer += c
            elif c == '[':
                return self.StateOutput(self.StateData(StateCode.Identifier, self.buffer), input_stream[idx + 1:], ReadIndex())
            elif c == '.':
                return self.StateOutput(self.StateData(StateCode.Identifier, self.buffer), input_stream[idx + 1:], ReadString())
            else:
                raise Exception(f'Unknown token \'{c}\' encountered during parsing')
        
        return self.StateOutput(self.StateData(StateCode.Identifier, self.buffer), '', None)


class ReadIndex(State):
    def transition(self, input_stream):

        hex_mode = False
        for idx, c in enumerate(input_stream):
            if idx == 2 and self.buffer == '0x':
                hex_mode = True

            if (idx == 1 and c == 'x' and self.buffer == '0') or (hex_mode and c.isalpha()) or c.isnumeric():
                self.buffer += c
            elif c == ']':
                return self.StateOutput(self.StateData(StateCode.IndexAccess, self.buffer), input_stream[idx + 1:], ReadString())
            else:
                raise Exception(f'Unknown token \'{c}\' encountered during parsing')


def parse_expression(expr):
    current_state = ReadString()
    remaining_input = expr
    output_list = []

    while True:
        state_data, remaining_input, current_state = current_state.transition(remaining_input)
        if state_data.value: # TODO Better define state machine to avoid this check
            output_list.append(state_data)

        if current_state == None:
            break
    
    return output_list


if __name__ == '__main__':
    print(parse_expression(input('>: ')))