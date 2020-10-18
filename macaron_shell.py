#!/usr/bin/env python3

import cmd, sys, copy, csv, pickle, functools, pymysql, evm_stack
from trace_transaction import calculate_trace_display
from expression_parser import parse_expression, StateCode
from web3 import Web3

# import cProfile, pstats, io

class MacaronShell(cmd.Cmd):

    color_normal = '\033[31m\033[40m'
    color_reset = '\033[m'
    clear = '\033c\033'

    intro = f'{color_normal}Macaron Navigator Prototype'
    prompt = '>:'
    step_index = contract_index = 0
    contract_trace = []
    help_message = 'Navigation: (n)ext step - (p)revious step - next function call (nf) - previous function call (pf) - next contract (nc) - previous contract (pc) - help'

    refresh = False

    def __init__(self, transaction_address = None, database_connection = None, rpc_endpoint = 'http://localhost:8545'): #TODO Add instant alias loading
        cmd.Cmd.__init__(self)

        self.rpc_endpoint = rpc_endpoint
        self.database_connection = database_connection
        self.current_transaction = transaction_address
        self.contract_trace = []
        self.aliases = {
            'n' : self.do_next,
            'p' : self.do_prev,
            'so': self.do_step_out,
            'nf' : self.do_next_func_call,
            'pf' : self.do_prev_func_call,
            'nc' : self.do_next_contract,
            'pc' : self.do_prev_contract,
            'q' : self.do_quit,
            'r' : self.do_refresh
        }

        self.reload_transaction()


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
        if self.step_index == len(self.contract_trace[self.contract_index].steps) - 1:
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
                self.step_index = len(self.contract_trace[self.contract_index].steps) - 1
                self.refresh = True
        else:
            self.step_index -= 1
            self.refresh = True

        
    def do_step_out(self, arg):
        '''Step out of the function currently in'''
        current_id = self.contract_trace[self.contract_index].steps[self.step_index].function_id
        function_id = None

        # TODO As it stands, the previous function could actually be a function we returned from instead of the parent function. This is a bug.
        # Find the immediately previous function
        current_step_index = None
        for i in range(self.contract_index, -1, -1):
            found_function_id = False

            if current_step_index:
                current_step_index = len(self.contract_trace[i].steps)
            else:
                current_step_index = self.step_index


            for j in range(current_step_index, -1, -1):
                target_id = self.contract_trace[i].steps[j].function_id

                if target_id != current_id:
                    function_id = target_id
                    found_function_id = True
                    break

            if found_function_id:
                break
            
        
        if function_id is None:
            print('Cannot step out.')
            return
        
        marking_balance = 0
        current_step_index = self.step_index
        for i in range(self.contract_index, len(self.contract_trace)):
            for j in range(current_step_index, len(self.contract_trace[i].steps)):
                if function_id == self.contract_trace[i].steps[j].function_id:
                    if self.contract_trace[i].steps[j].marking == 'FUNCTION_EXIT':
                        if marking_balance != 0:
                            marking_balance -= 1
                        else:
                            self.contract_index = i
                            self.step_index = j
                            self.refresh = True
                            return
                    elif self.contract_trace[i].steps[j] == 'FUNCTION_ENTRY':
                        marking_balance += 1
            current_step_index = 0



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

            print(f'{arg} = {self.access_storage(parse_expression(arg))}')
        except Exception as e:
            print(e)


    # Filesystem commands
    def do_create_transaction_alias(self, arg):
        '''Create an alias for a transaction'''
        try:
            transaction_alias, transaction_address = arg.split(' ')
        except:
            print('Usage: create_transaction_alias TRANSACTION_ALIAS TRANSACTION_ADDRESS')
            return

        aliases = self.load_pickle('transaction_aliases.pkl', 'rb')

        if aliases and transaction_alias in aliases:
            if input(f'Transaction alias \'{transaction_alias}\' already exists. Do you want to overwrite? Y/N\n{self.prompt}') == 'Y':
                aliases[transaction_alias] = transaction_address
                print('\nOverwriting alias...\n')
            else:
                print('\nWill not overwrite alias\n')
        else:
            aliases = {}
            aliases[transaction_alias] = transaction_address

        with open('transaction_aliases.pkl', 'wb+') as aliases_file:
            pickle.dump(aliases, aliases_file)


    def do_load_transaction(self, arg):
        '''Load a transaction from alias or address'''
        if arg[0:2] == "0x":
            self.contract_trace = self.prepare_transaction(arg)
        else:
            aliases = self.load_pickle('transaction_aliases.pkl', 'rb')
            
            try:
                self.contract_trace = self.prepare_transaction(aliases[arg])
            except KeyError:
                print(f'Error: Could not find transaction alias \'{arg}\'')


    def do_list_aliases(self, arg):
        '''Display all current aliases'''
        transaction_aliases = self.load_pickle('transaction_aliases.pkl', 'rb')

        if transaction_aliases:
            print('Transaction Aliases:')
            for alias, value in transaction_aliases.items():
                print(f'\t{alias} : {value}')
        else:
            print('\tNone')
        

        endpoint_aliases = self.load_pickle('endpoint_aliases.pkl', 'rb')
        print('Endpoint Aliases:')
        if endpoint_aliases:
            for alias, value in endpoint_aliases.items():
                print(f'\t{alias} : {value}')
        else:
            print('\tNone')
    

    def do_create_endpoint_alias(self, arg):
        '''Create a new alias for an endpoint'''
        try:
            endpoint_alias, endpoint_address, endpoint_secret = arg.split(' ')
        except:
            print('Usage: create_endpoint_alias ENDPOINT_ALIAS ENDPOINT_ADDRESS ENDPOINT_SECRET')
            return

        aliases = self.load_pickle('endpoint_aliases.pkl', 'rb')

        if aliases and endpoint_alias in aliases:
            if input(f'Endpoint alias \'{endpoint_alias}\' already exists. Do you want to overwrite? Y/N\n{self.prompt}') == 'Y':
                aliases[endpoint_alias] = (endpoint_address,endpoint_secret)
                print('\nOverwriting alias...\n')
            else:
                print('\nWill not overwrite alias\n')
        else:
            aliases = {}
            aliases[endpoint_alias] = (endpoint_address,endpoint_secret)

        with open('endpoint_aliases.pkl', 'wb+') as aliases_file:
            pickle.dump(aliases, aliases_file)

    
    def do_load_endpoint(self, arg):
        '''Load an endpoint from the alias file'''
        
        aliases = self.load_pickle('endpoint_aliases.pkl', 'rb')

        try:
            self.rpc_endpoint, self.endpoint_secret = aliases[arg]
        except KeyError:
            print(f'Error: Could not find endpoint alias \'{arg}\'')


    # Misc commands
    def do_quit(self, arg):
        '''Terminate the program.'''
        print(self.color_reset) # Reset terminal colors
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
        return calculate_trace_display(stack, self.database_connection)


    def load_pickle(self, filename, open_method):
        try:
            with open(filename, open_method) as file:
                return pickle.load(file)
        except:
            return


    def reload_transaction(self):
        if self.current_transaction:
            self.contract_trace = self.prepare_transaction(self.current_transaction)
        else:
            print('No transaction currently loaded.')


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

    
    def access_storage(self, access_instructions):
        storage_layout = self.contract_trace[self.contract_index].storage_layout
        current_address = 0
        current_offset = 0
        current_encoding = None
        current_type_data = None

        primary_instruction, *other_instructions = access_instructions
        # First, find the primary variable in storage
        found = False
        for entry in storage_layout['storage']:
            if primary_instruction.value == entry['label']:
                
                current_type_data = storage_layout['types'][entry['type']]
                current_encoding = current_type_data['encoding']
                current_address += int(entry['slot'])
                current_offset = int(entry['offset'])
                found = True
                break
        
        if not found:
            raise Exception('Could not find target variable in storage')
        
        # Then, start accessing its inner parts
        for instruction in other_instructions:
            if instruction.code == StateCode.Identifier:
                if current_encoding == 'inplace':
                    pass
                elif current_encoding == 'mapping':
                    current_type_data = storage_layout['types'][current_type_data['value']]
                elif current_encoding == 'dynamic_array':
                    current_type_data = storage_layout['types'][current_type_data['base']]
                elif current_encoding == 'bytes':
                    raise Exception('BYTES IDENTIFIER NOT CONFIGURED YET')
                else:
                    raise Exception(f'Error: Unknown encoding \'{current_encoding}\' encountered during storage access')

                found = False
                if 'members' in current_type_data:
                    for member in current_type_data['members']:
                        if member['label'] == instruction.value:
                            current_address += int(member['slot'])
                            current_type_data = storage_layout['types'][member['type']]
                            current_encoding = current_type_data['encoding']
                            current_offset = int(member['offset'])
                            found = True
                            break

                if not found:
                    raise Exception(f'Could not find member {instruction.value}')

            elif instruction.code == StateCode.IndexAccess:
                
                # Decode hex representation
                if instruction.value == '0x':
                    index_value = 0
                elif len(instruction.value) >= 3 and instruction.value[0:2] == '0x':
                    index_value = int(instruction.value, 16)
                else:
                    index_value = int(instruction.value)


                if current_encoding == 'inplace':
                    current_address += index_value
                elif current_encoding == 'mapping':
                    current_address = int(Web3.solidityKeccak(['uint256', 'uint256'], [index_value, current_address]).hex(), base=16)
                elif current_encoding == 'dynamic_array':
                    array_element_type_size = int(storage_layout['types'][current_type_data['base']]['numberOfBytes'])
                    current_address = int(Web3.solidityKeccak(['uint256'], [current_address]).hex(), base=16) + int(index_value) * array_element_type_size // 32
                elif current_encoding == 'bytes':
                    raise Exception('BYTES INDEXACCESS NOT CONFIGURED YET')
                else:
                    raise Exception(f'Error: Unknown encoding \'{current_encoding}\' encountered during storage access')


        try:
            # Stringify the final address to access and add the necessary padding
            final_address = Web3.toHex(current_address)[2:]
            final_address = final_address.zfill(65 - len(final_address))


            # Use offset for tightly packed variables
            accessed_value = self.contract_trace[self.contract_index].steps[self.step_index].persistant_data[final_address][64 - (current_offset + int(current_type_data['numberOfBytes']) ) * 2 : 64 - current_offset * 2]
            

            # TODO Add different printing accoring to type
            if current_type_data['label'] == 'address' or current_type_data['label'].split(' ')[0] == 'contract':
                return_value = hex(int(accessed_value, base=16))
            else:
                return_value = int(accessed_value, base=16)

            return return_value
        except KeyError:
            print(f'Nothing to access in storage area {final_address}')
            return '?'
        
    def get_current_step(self):
        return self.contract_trace[self.contract_index].steps[self.step_index]
    

    def print_current_step(self):
        current_step = self.get_current_step()
        print(f'{current_step.code}\n{current_step.persistant_data}\n{current_step.debug_info}\n{current_step.marking} : {current_step.function_id}')
        

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
            read_timeout=int(3),
            charset='utf8mb4')

       # Mainnet Tests
        transaction = '0xa67c14e87755014e75f843aef3db09a5a2d8e54f746e6938b77ea1ccae1ccf2c' # Scheme Registrar v0.5.13
        transaction = '0x4bbea23a4cca98a5231854c48b4f31d71f7b437c681299d23957ebe63542f3fe' # RenBTC v0.5.16
        transaction = '0x4ae860eb77a12e3f9a0b0bd83228d066f4249607b5840aa30ca324c77c3073ca' # KyberNetworkProxy v0.6.6 #TODO NOT WORKING CORRECTLY
        transaction = '0x0f386cd63450bbcbe0d4a4da1354b96c7f1b4f1c6f8b2dcc12971c20aef26194' # KyberStorage v0.6.6
        transaction = '0x99d3197f0149bf1dcfebec320f67704358564a768f2fa479342e954e7ec21dfa' # Kyber: Matching Engine v0.6.6
        transaction = '0x080a77fa25c18a2cf11e305eddcca06bd47f70d0b3d683e370647aacb9ab8e54' # Bancor Finder v0.5.17 #TODO CREATION
        transaction = '0xcf0cc27bb2c9f160c2ac90d419c7c741c58ba4f6e2c4d3546f02b72723985ca8' # Loihi v0.5.15 #TODO Index out of range when stepping
        transaction = '0x3c5ae6d88316d96bc5b3632aa37dcc7bd1ffcc3217a3b83b36448f1b0f30c67c' # InitializableAdminUpgreadabilityProxy v0.5.14

        # Local Tests
        # transaction = '0x291d26ca20c289da4ea549ed95a9228b4811c06a6df7cdd848c4d27afe1b742b' # Storage Write
        # transaction = '0xde360948210245dbce9f09ae49eb097ceb80c21e3bfd2c79aa4b0af1a7c0493e' # Storage Read

        # transaction = '0x7f444e65cc26c4eae2b0fe66b7cbe9f5b83b8befa23dc7f46f9d22d516d20129' # Send ticket


        # pr = cProfile.Profile()

        # pr.enable()
        navigator = MacaronShell(transaction, conn)
        # pr.disable()

        # s = io.StringIO()
        # sortby = 'cumulative'
        # ps = pstats.Stats(pr, stream=s).strip_dirs().sort_stats(sortby)
        # ps.print_stats()
        # with open('profile.stats', 'w+') as f:
        #     f.write(s.getvalue())

        navigator.cmdloop()
    except Exception:
        import pdb
        import traceback

        print(MacaronShell.color_reset) # Reset terminal colors
        extype, value, tb = sys.exc_info()
        traceback.print_exc()

        pdb.post_mortem(tb)
        