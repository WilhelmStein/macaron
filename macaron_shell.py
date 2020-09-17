import cmd, sys, copy, csv, pickle, functools, pymysql, evm_stack
from trace_transaction import calculate_trace_display

class MacaronShell(cmd.Cmd):

    color_normal = '\033[31m\033[40m'
    clear = '\033c\033'

    intro = f'{color_normal}Macaron Navigator V 0.5'
    prompt = '>:'
    step_index = contract_index = 0
    contract_trace = []
    help_message = 'Controls: (n)ext step - (p)revious step - next function call (nf) - previous function call (pf) - next contract (nc) - previous contract (pc) - print \'storage_var\' - (q)uit'

    refresh = False

    def __init__(self, transaction_address = None, rpc_endpoint = 'http://localhost:8545'):
        cmd.Cmd.__init__(self)

        self.rpc_endpoint = rpc_endpoint
        self.contract_trace = []
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

        if transaction_address:
            self.contract_trace = [contract_wrapper.steps for contract_wrapper in self.prepare_transaction(transaction_address)]


    # Connection Commands
    def do_set_rpc_endpoint(self, arg):
        try:
            self.rpc_endpoint, self.endpoint_secret = arg.split(':')
            print(f'Rpc endpoint successfully changed to \'{self.rpc_endpoint}\'')
        except Exception:
            print('Usage: set_rpc_endpoint ENDPOINT_URL:ENDPOINT_SECRET (ENDPOINT_URL: if no secret)')

    # Navigation commands
    # TODO bounds check for when no transaction has been loaded
    def do_next(self, arg):
        '''Navigate to the next step.'''
        if self.step_index == len(self.contract_trace[self.contract_index]) - 1:
            if self.contract_index == len(self.contract_trace) - 1:
                print('Reached the end of the trace.')
            else:
                self.do_next_contract(arg)
        else:
            self.step_index += 1
            self.refresh = True
    
    
    def do_prev(self, arg):
        '''Navigate to the previous step'''
        if self.step_index == 0:
            if self.contract_index == 0:
                print('Reached the start of the trace.')
            else:
                self.contract_index -= 1
                self.step_index = len(self.contract_trace[self.contract_index]) - 1
                self.refresh = True
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

            print(f'{arg} = {self.get_current_step().persistant_data[arg]}')
        except KeyError:
            print(f'Error: Could not find variable \'{arg}\'')


    # Filesystem commands
    def do_create_alias(self, arg):
        '''Create an alias for a transaction'''
        try:
            transaction_alias, transaction_address = arg.split(' ')
        except:
            print('Usage: create_alias TRANSACTION_ALIAS TRANSACTION_ADDRESS')

        aliases = self.load_aliases()

        if transaction_alias in aliases:
            if input(f'Transaction alias \'{transaction_alias}\' already exists. Do you want to overwrite? Y/N\n{self.prompt}') == 'Y':
                aliases[transaction_alias] = transaction_address
                print('\nOverwriting alias...\n')
            else:
                print('\nWill not overwrite alias\n')
        else:
            aliases[transaction_alias] = transaction_address

        with open('transaction_aliases.pkl', 'wb+') as aliases_file:
            pickle.dump(aliases, aliases_file)


    def do_load_transaction(self, arg):
        '''Load a transaction from alias or address'''
        if arg[0:2] == "0x":
            self.contract_trace = [contract_wrapper.steps for contract_wrapper in self.prepare_transaction(arg)]
        else:
            aliases = self.load_aliases()
            
            try:
                self.contract_trace = [contract_wrapper.steps for contract_wrapper in self.prepare_transaction(aliases[arg])]
            except KeyError:
                print(f'Error: Could not find transaction alias \'{arg}\'')


    def do_list_aliases(self, arg):
        '''Display all current aliases'''
        aliases = self.load_aliases()
        for alias, value in aliases.items():
            print(f'{alias} : {value}')
            

    # Misc commands
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
    def prepare_transaction(self, transaction_address):
        '''Calculate all transaction display data'''
        stack = evm_stack.EVMExecuctionStack()
        stack.import_transaction(transaction, self.rpc_endpoint)
        self.contract_index = self.step_index = 0
        return calculate_trace_display(stack, conn)


    def load_aliases(self):
        try:
            with open('transaction_aliases.pkl', 'rb') as aliases_file:
                return pickle.load(aliases_file)
        except:
            print('Error: Could not open alias file')
            return


    def preloop(self):
        if self.contract_trace:
            self.print_current_step()
        else:
            print(f'{self.clear}{self.color_normal}') # Reset Terminal

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
        

if __name__ == '__main__':
    try:

        # if len(sys.argv) != 2:
        #     raise Exception('Usage: python3 macaron_shell.py TRANSACTION')


        conn = pymysql.connect(
            host="127.0.0.1",
            port=int(3307),
            user="tracer",
            passwd="a=$G5)Z]vqY6]}w{",
            db="gigahorse",
            charset='utf8mb4')

        # Attacks
        # transaction = '0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b'    # DAO Attack - Compilation Error
        # transaction = '0x77e93eaa08349fff1c68025e77a2d95e3e88f673d33c5501664e958d8727d4a9'    # Parity Attack - Compilation Error
        # transaction = '0xd6c24da4e17aa18db03f9df46f74f119fa5c2314cb1149cd3f88881ddc475c5a'    # DAOSTACK Attack - Self Destructed :(
        # transaction = '0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838'    # Flash Loan Attack - Compilation Error

        # Other Tests
        transaction = '0x5c932a5c59f9691ca9f334fe744c00f9aabe64991ade8fea52a6e1b22a793664'    # Fomo3D
        # transaction = '0x7e8738e2fe6e67ac07b003fe23e4961b0677d4ef345d141647cc407b915d6927'    # Sol Wallet - Compilation Error
        # transaction = '0x129da6f54480b27d49411af82db7da5c98cf8f455508bc7e87838e938d4d0ef2'    # SafeMath
        # transaction = '0x26df3b770389b8f298446a25404d05402065bc8fe00ff5f6c0af6912c2c46947'    # E2D
        # transaction = '0xa2f866c2b391c9d35d8f18edb006c9a872c0014b992e4b586cc2f11dc2b24ebd'    # test1
        # transaction = '0xc1f534b03e5d4840c091c54224c3381b892b8f1a2869045f49913f3cfaf95ba7'    # Million Money
        # transaction = '0x51f37d7b41e6864d1190d8f596e956501d9f4e0f8c598dbcbbc058c10b25aa3b'    # Dust
        # transaction = '0x3f0a309ebbc5642ec18047fb902c383b33e951193bda6402618652e9234c9abb'    # Tokens
        # transaction = '0x6aec28ad65052132bf04c0ed621e24c007b2476fe6810389232d3ac4222c0ccc'    # Doubleway
        # transaction = '0xa228e903a5d751e4268a602bd6b938392272e4024e2071f7cd4a479e8125c370'    # Saturn Network 2 - Compilation Error
        # transaction = '0xf3e1b43611423c39d2839dc95d70090ba1ae91d66a8303ddad842e4bb9ed4793'    # Chess Coin


        navigator = MacaronShell(transaction, 'https://mainnet.infura.io/v3/2cba9e1aa07741c2b91ab3a7582982fb')
        navigator.cmdloop()
    except Exception:
        import pdb
        import traceback

        extype, value, tb = sys.exc_info()
        traceback.print_exc()

        pdb.post_mortem(tb)
        