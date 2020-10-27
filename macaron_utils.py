
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
                    'BinaryOperation', 'Literal', 'MemberAccess', 'IndexAccess', 'FunctionCall', 'UnaryOperation', 'Continue', 'Break', 'Conditional', 'InlineAssembly']

invalidAstTypes = ['PragmaDirective', 'ContractDefinition', 'EventDefinition', 'DoWhileStatement', 'WhileStatement', 'ForStatement', 'IfStatement',
                   'FunctionDefinition', 'PlaceholderStatement']

node_children_names = { 'arguments', 'baseExpression', 'body', 'components', 'condition', 'declarations', 'expression', 'externalReferences', 'falseBody', 'falseExpression', 'modifiers', 'parameters', 'statements', 'nodes', 'leftHandSide', 'rightHandSide', 
                        'leftExpression', 'rightExpression', 'initializationExpression', 'initialValue', 'value', 'trueBody', 'trueExpression', 'indexExpression', 'loopExpression', 'returnParameters',
                        'subExpression', 'eventCall', '_codeLength', '_addr'}


# Printing Defs
LINE_SPLIT_DELIMETER = '\n'

color_normal = '\033[31m\033[40m'
color_highlight = '\033[30m\033[107m'
color_warning = '\033[30m\033[106m'
color_error = '\033[30m\033[101m'
