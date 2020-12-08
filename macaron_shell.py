#!/usr/bin/env python3

import argparse, cmd, sys, copy, csv, pickle, functools, pymysql, evm_stack
from trace_transaction import calculate_trace_display
from expression_parser import parse_expression, StateCode
from macaron_utils import *
from tabulate import tabulate
from math import ceil
from web3 import Web3
# from calldata_extractor import TraceParser
# from web3_connections import get_trace

# import cProfile, pstats, io

class MacaronShell(cmd.Cmd):

    clear = '\033c\033'

    intro = f'{color_normal}Macaron Navigator Prototype'
    prompt = '>:'
    step_index = contract_index = 0
    contract_trace = []
    help_message = 'Navigation: (n)ext step - (p)revious step - change (v)iew - next function call (nf) - previous function call (pf) - next contract (nc) - previous contract (pc) - help'

    refresh = False

    def __init__(self, transaction_address = None, database_connection = None, rpc_endpoint = 'http://localhost:8545', contract_cache = './local_contract_db'): #TODO Add instant alias loading
        cmd.Cmd.__init__(self)

        self.rpc_endpoint = rpc_endpoint
        self.database_connection = database_connection
        self.contract_cache = contract_cache
        self.current_transaction = transaction_address
        self.contract_trace = []
        self.block_trace_activated = False
        self.aliases = {
            'n' : self.do_next,
            'p' : self.do_prev,
            's': self.do_step_over,
            'su': self.do_step_up,
            'nf' : self.do_next_func_call,
            'pf' : self.do_prev_func_call,
            'nc' : self.do_next_contract,
            'pc' : self.do_prev_contract,
            'v' : self.do_change_view,
            'q' : self.do_quit,
            'r' : self.do_refresh,
            'bt': self.do_blocktrace
        }

        self.reload_transaction()


    # Connection Commands
    #TODO Add authentication
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

        
    def do_step_up(self, arg):
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


    def do_step_over(self, arg):
        '''Step over (instead of into) a function call'''
        current_depth = self.contract_trace[self.contract_index].steps[self.step_index].depth

        current_step_index = self.step_index + 1
        for i in range(self.contract_index, len(self.contract_trace)):
            for j in range(current_step_index, len(self.contract_trace[i].steps)):
                if self.contract_trace[i].steps[j].depth == current_depth:
                    self.contract_index = i
                    self.step_index = j
                    self.refresh = True
                    return
            
            current_step_index = 0
        
        print('Reached the end of the trace.')


    def do_next_func_call(self, arg):
        '''Navigate to the previous function call.'''
        while self.contract_index <= len(self.contract_trace) - 1:
            self.do_next(arg)
            if functools.reduce(lambda a, b: a or b, [ node_type == 'FunctionCall' for node_type in self.get_current_step().solidity_ast_nodes ]):
                break


    def do_prev_func_call(self, arg):
        '''Navigate to the next function call.'''
        while self.contract_index >= 0:
            self.do_prev(arg)
            if functools.reduce(lambda a, b: a or b, [ node_type == 'FunctionCall' for node_type in self.get_current_step().solidity_ast_nodes ]):
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
    

    def do_change_view(self, arg):
        self.high_level_view  = not self.high_level_view
        self.refresh = True


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
            self.refresh = True
        else:
            aliases = self.load_pickle('transaction_aliases.pkl', 'rb')
            
            try:
                self.contract_trace = self.prepare_transaction(aliases[arg])
                self.refresh = True
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
        print(color_reset) # Reset terminal colors
        exit(0)


    def do_help(self, arg):
        '''List available commands.'''
        if arg in self.aliases:
            arg = self.aliases[arg].__name__[3:]
        cmd.Cmd.do_help(self, arg)


    def do_print(self, arg):
        '''Print the contents of a storage variable in scope'''
        try:
            if arg == '':
                print('Usage: print VARIABLE_NAME')
                return            

            print(f'{arg} = {self.access_storage(parse_expression(arg))}')
        except Exception as e:
            print(e)


    def do_blocktrace(self, arg):
        self.block_trace_activated = not self.block_trace_activated
        self.refresh = True


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
        stack.import_transaction(transaction_address, self.rpc_endpoint)
        self.contract_index = self.step_index = 0
        self.high_level_view = True
        return calculate_trace_display(stack, self.database_connection, self.contract_cache)


    def load_pickle(self, filename, open_method):
        try:
            with open(filename, open_method) as file:
                return pickle.load(file)
        except:
            return


    def reload_transaction(self):
        if self.current_transaction:
            # self.trace_parser = TraceParser(self.current_transaction)
            # self.trace_parser.parse_trace(get_trace()['result']['structLogs'])
            self.contract_trace = self.prepare_transaction(self.current_transaction)
            self.refresh = True
        else:
            print('No transaction currently loaded.')


    def preloop(self):
        if self.contract_trace:
            if self.high_level_view:
                self.print_high_level()
            else:
                self.print_current_step()
        else:
            print(f'{self.clear}{color_normal}') # Reset Terminal

        print(self.help_message)
    

    def postcmd(self, stop, line):
        if self.refresh:
            self.refresh = False
            print(f'{self.clear}{color_normal}') # Reset Terminal

            if self.high_level_view:
                self.print_high_level()
            else:
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
                    raise Exception(f'Bytes type has no member {instruction.value}')
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
                    # current_address = int(Web3.solidityKeccak(['uint256'], [current_address]).hex(), base=16) + int(index_value) # For > 31 bytes
                    pass 
                else:
                    raise Exception(f'Error: Unknown encoding \'{current_encoding}\' encountered during storage access')


        try:
            # Stringify the final address to access and add the necessary padding
            final_address = int_to_hex_addr(current_address)

            # Use offset for tightly packed variables
            accessed_value = self.value_at_storage_address(final_address, current_offset, current_type_data)
            

            if current_type_data['label'] == 'address' or current_type_data['label'].split(' ')[0] == 'contract':
                return_value = hex(int(accessed_value, base=16))
            elif current_encoding == 'bytes':
                bytes_over_31 = True if int(accessed_value[-1], base=16) % 2 else False

                # Load the whole byte array
                if bytes_over_31:
                    bytes_length = (int(accessed_value, base=16) - 1) // 2
                    array_address = int(Web3.solidityKeccak(['uint256'], [current_address]).hex(), base=16)
                    read_bytes = 0
                    
                    byte_array = ""
                    while read_bytes < bytes_length:
                        stringified_address = int_to_hex_addr(array_address + read_bytes // 32)
                        byte_array += self.value_at_storage_address(stringified_address, current_offset, current_type_data)  
                        read_bytes += 32
                    
                    byte_array = byte_array[: 2 * bytes_length]                    

                else:
                    bytes_length = int(accessed_value[-2:], base=16) // 2
                    byte_array = accessed_value[:2 * bytes_length]
                
                
                if current_type_data['label'] == "string":
                    byte_array = bytes.fromhex(byte_array).decode("utf-8")
                else:
                    byte_array = [ (elem1 + elem2).encode() for elem1, elem2 in zip(*[iter(byte_array)] * 2) ]
                

                # Choose which part to show
                if instruction.code == StateCode.Identifier:
                    return_value = byte_array
                elif instruction.code == StateCode.IndexAccess:
                    return_value = byte_array[index_value]
                else:
                    raise Exception(f'Error: Unknown StateCode {instruction.code} encountered.')
            else:
                return_value = int(accessed_value, base=16)

            return return_value
        except KeyError:
            print(f'Nothing to access in storage area {final_address}')
            return '?'

    
    def value_at_storage_address(self, address, offset, type_data):
        return self.contract_trace[self.contract_index].steps[self.step_index].persistant_data[address][64 - (offset + int(type_data['numberOfBytes']) ) * 2 : 64 - offset * 2]

        
    def get_current_step(self):
        return self.contract_trace[self.contract_index].steps[self.step_index]


    def get_prev_step(self):
        prev_step_index = self.step_index - 1
        prev_step_contract_index = self.contract_index

        if prev_step_index < 0:
            if self.contract_index - 1 < 0:
                return None
            prev_step_contract_index = self.contract_index - 1
            prev_step_index = len(self.contract_trace[prev_step_contract_index].steps) - 1
        
        return self.contract_trace[prev_step_contract_index].steps[prev_step_index]

    
    @staticmethod
    def buff_print(output):
        lines = output.splitlines()
        concat_lines = [ "\n".join(lines[i * LINE_LIMIT : i * LINE_LIMIT + LINE_LIMIT]) for i in range(0, int(ceil(len(lines) / LINE_LIMIT )))]
        for idx, buff in enumerate(concat_lines):
            print(buff + "\n")
            if idx == len(concat_lines) - 1 or input(f"{color_note}Press any key to resume printing or \'x\' to stop printing...{color_normal}\n") == 'x':
                break
    

    def print_current_step(self):
        current_step = self.get_current_step()

        storage_changes_str = '\n  '.join([ f'{k}: {color_note}{v[0]}{color_normal} => {color_note}{v[1]}{color_normal}' for (k,v) in current_step.storage_changes.items()])
        storage_changes_str = f'Storage changes:\n  {storage_changes_str}' if storage_changes_str != '' else ''
        block_trace_str =  f'Block Trace:\n{tabulate(current_step.block_trace, headers=["Pc", "Opcode"])}\n\n' if self.block_trace_activated else ''  

        MacaronShell.buff_print(
            f'{current_step.annotations}{current_step.code}\n\n'
            f'Solidity AST nodes:\n{current_step.solidity_ast_nodes}\n\n'
            f'Function call depth: {current_step.depth}\n'
            f'{storage_changes_str}\n\n'
            f'{block_trace_str}'
            # f'Storage Entries: {current_step.persistant_data}\n\n'
        )
        

    def print_high_level(self):
        tab_buff = ''
        output = f"{color_normal}"
        for idx, contract in enumerate(self.contract_trace):
            
            used_color = color_highlight if idx == self.contract_index else color_normal

            if contract.reason in evm_stack.calls:
                tab_buff += '    '

            output += f"{tab_buff}{used_color}{contract.reason} address {contract.address} : {contract.calldata}{color_normal}\n\n"

            if contract.reason not in evm_stack.calls:
                tab_buff = tab_buff[:-4]
        
        MacaronShell.buff_print(output)


if __name__ == '__main__':
    try:
        #TODO This is for debugging purposes. Remove it.
        transaction = None
        # Mainnet Tests
        # transaction = '0xa67c14e87755014e75f843aef3db09a5a2d8e54f746e6938b77ea1ccae1ccf2c' # Scheme Registrar v0.5.13

        transaction = '0x4bbea23a4cca98a5231854c48b4f31d71f7b437c681299d23957ebe63542f3fe' # RenBTC v0.5.16
        # transaction = '0x4ae860eb77a12e3f9a0b0bd83228d066f4249607b5840aa30ca324c77c3073ca' # KyberNetworkProxy v0.6.6
        # transaction = '0x0f386cd63450bbcbe0d4a4da1354b96c7f1b4f1c6f8b2dcc12971c20aef26194' # KyberStorage v0.6.6
        # transaction = '0x99d3197f0149bf1dcfebec320f67704358564a768f2fa479342e954e7ec21dfa' # Kyber: Matching Engine v0.6.6
        # transaction = '0x080a77fa25c18a2cf11e305eddcca06bd47f70d0b3d683e370647aacb9ab8e54' # Bancor Finder v0.5.17 #TODO CREATION
        # transaction = '0xcf0cc27bb2c9f160c2ac90d419c7c741c58ba4f6e2c4d3546f02b72723985ca8' # Loihi v0.5.15 #TODO Index out of range when stepping and File not found compiler error
        # transaction = '0x3c5ae6d88316d96bc5b3632aa37dcc7bd1ffcc3217a3b83b36448f1b0f30c67c' # InitializableAdminUpgreadabilityProxy v0.5.14

        # Debug Tests
        # transaction = '0x247357d9bdac0ddb6fd26641090aad59595c6cd6ec2e89fae16fc3cbdafeb2cb' # Storage Write
        # transaction = '' # Storage Read
        # transaction = '0x58b51b4918fbc9f31f026c9eb1494b96af8ad024bfb3603d5aa8a47efb745929' # Rename Slot
        # transaction = '0x02c9962e1f1f7509704d245af56df099e8a8ff458e94a60320ac9bac141d470f' # Rename Slot with more than 31 bytes

        # transaction = '0x7f444e65cc26c4eae2b0fe66b7cbe9f5b83b8befa23dc7f46f9d22d516d20129' # Send ticket

        # transaction = '0xe52c4aedb8f15aacd8d8e7c074c0736bbf4ebcd0fc08e87dc43f8946cbb5da30' # Clean storage write
        # transaction = '0x591b7c81bdfd0fdb2d73414df1e5376d2145426210bbc50f95812e790488d0c0' # Fib rec call
        # transaction = '0xf222aa6dfef05f2c7804a7330fa8fb17dfacdb988b7cdf973c01eed96760720a' # Fib iter call
        # transaction = '0x6b21aab5da28737ff8a645e7dabfb4c7ac19eb0b4668b1f5169ec4a7a3bb3d6b' # PrimesUntil 30
        # transaction = '0x2077d345b232480899b6dc9543c44b62f101bbe5fa8716438a1e34c22a1c51d5' # PrimesUntilWhile 30

        parser = argparse.ArgumentParser(description='A transaction trace navigation tool for solidity contracts on the ethereum blockchain.')
        parser.add_argument('tx', metavar='TX', type=str, nargs='?', default=transaction, help='the hash of the transaction to be explored')
        parser.add_argument('--db', dest = 'contract_db_data', metavar=('HOST', 'PORT', 'USER', 'PASS', 'DB_NAME'), type=str, nargs=5, default=None, help='the contract database connection data')
        parser.add_argument('--cache', dest = 'contract_cache', metavar='CACHE_DIR', type=str, nargs='?', default='./local_contract_db', help='the contract cache location that will be used')
        parser.add_argument('--node', dest = 'ethereum_node', metavar='NODE_IP', type=str, nargs='?', default='http://localhost:8545', help='the blockchain node ip which will serve the transaction trace')
        args = parser.parse_args()


        if args.contract_db_data:
            h, p, u, pwd, db = args.contract_db_data
            try:
                conn = pymysql.connect(
                    host=h,
                    port=int(p),
                    user=u,
                    passwd=pwd,
                    db=db,
                    read_timeout=int(3),
                    charset='utf8mb4')
            except Exception:
                print_err(f"Could not connect to contract_db \'{db}\' on \'{u}@{h}:{p}\'")
                exit()
        else:
            conn = None

        # TODO Remove profiler code after completion of project
        # pr = cProfile.Profile()

        # pr.enable()
        navigator = MacaronShell(args.tx, conn, args.ethereum_node, args.contract_cache)
        # pr.disable()

        # s = io.StringIO()
        # sortby = 'cumulative'
        # ps = pstats.Stats(pr, stream=s).strip_dirs().sort_stats(sortby)
        # ps.print_stats()
        # with open('profile.stats', 'w+') as f:
        #     f.write(s.getvalue())

        navigator.cmdloop()
    except Exception:
        import traceback

        print(color_error)
        extype, value, tb = sys.exc_info()
        traceback.print_exc()
        print(color_reset)
        