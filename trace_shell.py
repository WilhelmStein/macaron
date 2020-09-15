import cmd, sys, copy, functools
# from trace_transaction import color_normal

class MacaronShell(cmd.Cmd):

    color_normal = '\033[31m\033[40m'
    clear = '\033c\033'

    intro = f'{color_normal}Macaron Navigator V 0.1'
    prompt = '>:'
    step_index = contract_index = 0
    contract_trace = []
    help_message = 'Controls: (n)ext step - (p)revious step - next function call (nf) - previous function call (pf) - next contract (nc) - previous contract (pc) - (q)uit'

    refresh = False

    def __init__(self, contract_trace):
        cmd.Cmd.__init__(self)
        self.contract_trace = [contract_wrapper.steps for contract_wrapper in contract_trace]
        self.aliases = {
            'n' : self.do_next,
            'p' : self.do_prev,
            'nf' : self.do_next_func_call,
            'pf' : self.do_prev_func_call,
            'nc' : self.do_next_contract,
            'pc' : self.do_prev_contract,
            'q' : self.do_quit,
            'r' : self.do_refresh
        }


    # User commands
    def do_next(self, arg): #TODO Fix issue with incorrect navigation
        '''Navigate to the previous step.'''
        if self.step_index == len(self.contract_trace[self.contract_index]) - 1:
            if self.contract_index == len(self.contract_trace) - 1:
                print('Reached the end of the trace.')
            else:
                self.do_next_contract(arg)
        else:
            self.step_index += 1
            self.refresh = True
    
    
    def do_prev(self, arg):
        '''Navigate to the next step'''
        if self.step_index == 0:
            if self.contract_index == 0:
                print('Reached the start of the trace.')
            else:
                self.do_prev_contract(arg)
        else:
            self.step_index -= 1
            self.refresh = True


    def do_next_func_call(self, arg):
        '''Navigate to the previous function call.'''
        while self.contract_index <= len(self.contract_trace) - 1:
            self.do_next(arg)
            if functools.reduce(lambda a, b: a or b, [ node_type == 'FunctionCall' for node_type in self.get_current_step().debug_info ]):
                break


    def do_prev_func_call(self, arg):
        '''Navigate to the next function call.'''
        while self.contract_index >= 0:
            self.do_prev(arg)
            if functools.reduce(lambda a, b: a or b, [ node_type == 'FunctionCall' for node_type in self.get_current_step().debug_info ]):
                break

    
    def do_next_contract(self, arg):
        '''Navigate to the next contract.'''
        if self.contract_index == len(self.contract_trace) - 1:
            print('Reached the last contract.')
        else:
            self.contract_index += 1
            self.step_index = 0
            self.refresh = True

    def do_prev_contract(self, arg):
        '''Navigate to the previous contract'''
        if self.contract_index == 0:
            print('Reached the first contract.')
        else:
            self.contract_index -= 1
            self.step_index = 0
            self.refresh = True
    
    def do_print(self, arg):
        '''Print the contents of a variable in scope'''
        try:
            if arg == '':
                print('Usage: print VARIABLE_NAME')
                return

            print(f'{arg} = {self.get_current_step().persistant_data}')
        except KeyError:
            print(f'Error: Could not find variable \'{arg}\'')

    def do_quit(self, arg):
        '''Terminate the program.'''
        exit(0)


    def do_help(self, arg):
        '''List available commands.'''
        if arg in self.aliases:
            arg = self.aliases[arg].__name__[3:]
        cmd.Cmd.do_help(self, arg)

    def do_refresh(self, arg):
        '''Refresh the terminal.'''
        self.refresh = True
        

    def default(self, line):
        cmd, arg, line = self.parseline(line)
        if cmd in self.aliases:
            self.aliases[cmd](arg)
        else:
            print(f"Error: Unknown syntax: {line}")


    # Utility
    def preloop(self):
        self.print_current_step()
        print(self.help_message)
    

    def postcmd(self, stop, line):
        if self.refresh:
            self.refresh = False
            print(f'{self.clear}{self.color_normal}') # Reset Terminal
            self.print_current_step()
            print(self.help_message)
    
    def get_current_step(self):
        return self.contract_trace[self.contract_index][self.step_index]
    
    def print_current_step(self):
        current_step = self.get_current_step()
        print(f'{current_step.code}\n{current_step.persistant_data}\n{current_step.debug_info}')
        