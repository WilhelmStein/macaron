import pandas as pd
import dill
import solcx
import solcx.install
from collections import defaultdict, OrderedDict, Mapping, namedtuple
from itertools import chain
from copy import deepcopy
from dataclasses import dataclass, field
import os.path
import pickle
import functools
import json
from macaron_utils import (
    LINE_SPLIT_DELIMETER,
    node_children_names,
    validAstTypes,
    invalidAstTypes,
    opcodes,
    int_to_hex_addr,
    format_calldata,
    color_normal,
    color_calldata,
    strip_cbor,
    color_warning,
    color_warning,
    color_error,
    color_note,
    color_highlight,
)
from web3 import Web3


query_source = """
  select b.hex_bytecode, d.*
  from address a
  join source_code d on a.md5_bytecode = d.md5_bytecode and d.`code` is not null
  join bytecode b on b.md5_bytecode = a.md5_bytecode
  where a.address = '%s'
  and a.network = 'Ethereum'
"""

query_source = """
  select d.*
  from address a
  join source_code d on a.md5_bytecode = d.md5_bytecode and d.`code` is not null
  where a.address = '%s'
  and a.network = 'Ethereum'
"""

NodeWrapper = namedtuple("NodeWrapper", ["node", "lineage"])


# Function Definitions
def __make_compiler_json(
    filename, optimization_enabled=False, optimization_runs=0, evmVersion=None
):
    settings = {
        "optimizer": {"enabled": optimization_enabled, "runs": optimization_runs},
        "evmVersion": evmVersion,
        "outputSelection": {
            "*": {
                "*": [
                    "metadata",
                    "evm.deployedBytecode.sourceMap",
                    "evm.deployedBytecode.object",
                    "storageLayout",
                ],
                "": ["ast"],
            }
        },
    }
    if evmVersion is None:
        del settings["evmVersion"]
    output = {
        "language": "Solidity",
        "sources": {
            filename: {"urls": [filename]},
        },
        "settings": settings,
    }

    # print(output)
    return output


def __create_source_index(source):
    line = 0
    line_index = {}
    char_index = defaultdict(list)

    for i, s in enumerate(source):
        line_index[i] = line
        char_index[line].append(i)

        if s == ord(LINE_SPLIT_DELIMETER):
            line += 1
    return line_index


def __process_compiler_version(compiler):
    # print(compiler)
    compiler_processed = compiler[:7]
    if compiler_processed[-1] == "+":
        compiler_processed = compiler_processed[:-1]
    if float(compiler_processed[1:4] + compiler_processed[6:]) < 0.411:
        return "v0.4.11"
    return compiler_processed


def __compile_solidity(code, compiler, optimization, other_settings, **kwargs):
    assert isinstance(code, str)
    with open("/tmp/temp.sol", "w") as f:
        f.write(code)
    compiler_processed = __process_compiler_version(compiler)
    # process optimization flag
    optimization_enabled, _, optimization_runs, _ = optimization.split(" ")
    optimization_enabled = optimization_enabled.lower() == "yes"
    optimization_runs = int(optimization_runs)
    evmVersion = other_settings.split(" ")[0]
    if evmVersion == "default":
        evmVersion = None
    try:
        solcx.install_solc(compiler_processed)
        solcx.set_solc_version(compiler_processed)

        output_js = solcx.compile_standard(
            __make_compiler_json(
                "/tmp/temp.sol", optimization_enabled, optimization_runs, evmVersion
            ),
            allow_paths="/tmp",
        )
    except solcx.exceptions.SolcError as e:
        print("SOLC Compiler error")
        print(e.message)
        return None

    ast = None
    contract = list(output_js["contracts"].values())[0]
    source = list(output_js["sources"].values())[0]

    if "ast" in source:
        ast = source["ast"]

    return (ast, contract)


def __get_contract_from_db(contract_address, conn, local_db_path="./local_contract_db"):
    """Connect to contract-lib.com and receive the contract's code. If the connection is None, then look locally."""

    # First check the cache
    if os.path.isdir(local_db_path):
        if os.path.isdir(f"{local_db_path}/{contract_address}"):
            if os.path.isfile(f"{local_db_path}/{contract_address}/contract.pkl"):
                with open(
                    f"{local_db_path}/{contract_address}/contract.pkl", "rb"
                ) as contract_file:
                    return pickle.load(contract_file)

    # If the cache does not contain the target contract, connect to the database
    if conn:
        res = pd.read_sql_query(query_source % contract_address, conn)
        if len(res) == 0:
            return None
        for _, row in res.iterrows():
            if sum(v is None for v in row.values) > 1:
                return None

            if not os.path.exists(local_db_path):
                os.makedirs(local_db_path)

            if not os.path.exists(f"{local_db_path}/{contract_address}"):
                os.makedirs(f"{local_db_path}/{contract_address}")

            with open(
                f"{local_db_path}/{contract_address}/contract.pkl", "wb"
            ) as contract_file:
                pickle.dump(row, contract_file)

            return row

    return None


def __compile_contract(stack_entry_folder, contract_wrapper):
    """Compile a contract if you have not already and save its output, or load it if it already exists. Then return it's AST and Solidity_File data."""
    try:
        ast_path = f"{stack_entry_folder}/ast.pkl"
        solidity_file_path = f"{stack_entry_folder}/solidity_file.pkl"

        if (
            os.path.exists(stack_entry_folder)
            and os.path.exists(ast_path)
            and os.path.exists(solidity_file_path)
        ):
            with open(ast_path, "rb") as f:
                ast = pickle.load(f)

            with open(solidity_file_path, "rb") as f:
                solidity_file = pickle.load(f)
        else:
            ast, solidity_file = __compile_solidity(**contract_wrapper)

            if ast is None:
                return (None, solidity_file)

            if not os.path.exists(stack_entry_folder):
                os.makedirs(stack_entry_folder)

            with open(ast_path, "wb") as f:
                pickle.dump(ast, f)

            with open(solidity_file_path, "wb") as f:
                pickle.dump(solidity_file, f)

        return (ast, solidity_file)

    except Exception as e:
        print(e)
        exit(1)


def __valid_source(ast, fro, length, source_index):
    ast_fro, ast_length, ast_source_index = map(int, ast["src"].split(":"))

    return (
        fro >= ast_fro
        and fro + length <= ast_fro + ast_length
        and ast_source_index == source_index
    )


def __list_children(ast):
    """Utility function that, given an ast node, returns its children in list form."""
    nodes = []

    for name in node_children_names:
        if name in ast and ast[name]:
            if isinstance(ast[name], Mapping):
                nodes.append(ast[name])
            else:
                nodes += ast[name]

    return nodes


def __search_ast(wrapper, fro, length, source_index):
    """Recursive function that searches a given AST for a node with a specific source mapping."""
    if not hasattr(__search_ast, "last_custom_node_id"):
        __search_ast.last_custom_node_id = 0

    ast, lineage = wrapper

    if ast is None:
        raise Exception(
            f"Node is None. Searching for {fro} : {length} : {source_index}"
        )

    output_node = None
    if "src" in ast:
        curr_node_s, curr_node_r, curr_node_m = map(int, ast["src"].split(":"))

        if fro == curr_node_s and length == curr_node_r and curr_node_m == source_index:
            output_node = (ast, lineage)
        elif (
            curr_node_s + curr_node_r < fro or curr_node_s > fro + length
        ):  # A small optimization, as to avoid a full dfs of the ast
            return None

    # Be lax with inline assembly, since the solc isn't very verbose when it comes to it
    if "nodeType" in ast and ast["nodeType"] == "InlineAssembly":
        __search_ast.last_custom_node_id += 1
        custom_node = {
            "id": __search_ast.last_custom_node_id,
            "nodeType": "CustomInlineAssemblyChild",
            "src": f"{fro}:{length}:{source_index}",
        }
        return (custom_node, [ast] + lineage)

    nodes = __list_children(ast)

    for node in nodes:
        if node is None:
            continue

        returned_node = __search_ast((node, [ast] + lineage), fro, length, source_index)

        if returned_node is None:
            continue

        output_node = returned_node

    return output_node


def __group_instructions(instruction_node_list, storage_layout):
    """Try to group bytecode instructions that correspond to the same solidity instruction"""

    output_list = []
    grouped_nodes = {}
    block_trace = []
    scope_node = None

    for pc, opcode, data, node_wrapper in instruction_node_list:

        # Ascertain current node's scope (if applicable) by taking a look at its lineage
        node, lineage = node_wrapper

        if opcode != opcodes["JUMPDEST"]:

            if node["nodeType"] == "ContractDefinition":
                scope_node = node
            elif node["nodeType"] in {"ModifierDefinition", "FunctionDefinition"}:
                scope_node = node
            else:
                for ancestor in lineage:
                    if ancestor["nodeType"] in {
                        "ModifierDefinition",
                        "FunctionDefinition",
                    }:
                        scope_node = ancestor
                        break

        # Create groups between JUMP instructions
        if opcode == opcodes["JUMPI"] or opcode == opcodes["JUMP"]:
            pass
        elif opcode == opcodes["JUMPDEST"]:
            # Do not group JUMPDEST instructions, as they only confuse the display process and their display is unnecessary

            output_list.append((scope_node, grouped_nodes, block_trace, data.storage))
            grouped_nodes = {}
            block_trace = []

        else:
            grouped_nodes[node["id"]] = node

        block_trace.append((pc, opcode))

    if grouped_nodes:
        output_list.append((scope_node, grouped_nodes, block_trace, data.storage))

    return output_list


def compute_var_addr(var, storage_layout):
    addr_to_var = {}
    var_to_starting_addr = {var["astId"]: 0}
    frontier = [var]

    for v in frontier:
        starting_addr = var_to_starting_addr[v["astId"]]
        v_type_data = storage_layout["types"][var["type"]]
        if "members" in v_type_data:
            for m in v_type_data["members"]:
                if not m["astId"] in var_to_starting_addr:
                    var_to_starting_addr[m["astId"]] = starting_addr + int(v["slot"])
                    frontier.append(m)

        addr_to_var[int_to_hex_addr(starting_addr + int(v["slot"]))] = v

    return addr_to_var


def calculate_trace_display(stack, conn=None, local_db_path="./local_contract_db"):
    """Renders a trace in human-readable format."""

    @dataclass(init=True, repr=True)
    class StepWrapper:
        function_id: int = 0
        code: str = ""
        persistant_data: dict = field(default_factory=dict)
        solidity_ast_nodes: list = field(default_factory=list)
        block_trace: list = field(default_factory=list)
        annotations: str = ""
        storage_changes: dict = field(default_factory=dict)

    ContractWrapper = namedtuple(
        "ContractWrapper", ["address", "reason", "steps", "storage_layout", "calldata"]
    )

    PcData = namedtuple("PcData", ["opcode", "source_mapping", "ast_node_mapping"])
    SourceMapping = namedtuple(
        "SourceMapping", ["source_from", "source_range", "source_index"]
    )

    # Compile all contracts encountered during the trace
    contract_db = {}
    function_db = {}

    print("Compiling contracts:")
    for stack_entry in stack.trace:
        if stack_entry.address in contract_db:
            continue

        res = __get_contract_from_db(stack_entry.address, conn, local_db_path)
        if res is None:
            contract_db[stack_entry.address] = (None, None, None, None)
            print(f"  - {stack_entry.address} => Could not find source in db")
            continue

        ast, solidity_file = __compile_contract(
            f"{local_db_path}/{stack_entry.address}", res
        )

        if solidity_file is None or ast is None:
            contract_db[stack_entry.address] = (res, None, None, None)
            print(f"  - {stack_entry.address} => Compilation error/incompatible ast")
            continue

        contract_to_storage = {}
        for contract_key, contract in solidity_file.items():

            # Populate storage_address => var_name dictionary
            addr_to_var = {}
            if "storageLayout" in contract:
                storage_layout = contract["storageLayout"]

                for var in storage_layout["storage"]:
                    addr_to_var |= compute_var_addr(var, storage_layout)

            contract_to_storage[contract_key] = addr_to_var

            # Populate function db
            if "metadata" not in contract or contract["metadata"] == "":
                continue

            metadata = json.loads(contract["metadata"])
            for entry in metadata["output"]["abi"]:
                if entry["type"] == "function":
                    function_sig = f"{entry['name']}({','.join(map(lambda i: i['type'], entry['inputs']))})"
                    function_db[Web3.keccak(text=function_sig)[:4].hex()[2:]] = {
                        "signature": function_sig,
                        "param_names": list(map(lambda i: i["name"], entry["inputs"])),
                    }

        contract_db[stack_entry.address] = (
            res,
            ast,
            solidity_file,
            contract_to_storage,
        )
        print(f"  - {stack_entry.address} => OK")

    contract_trace = []
    contract_last_storage = defaultdict(dict)

    # Each stack entry represents the call/return of/from a contract
    for stack_entry in stack.trace:
        calldata = format_calldata(stack_entry.detail, stack_entry.value, function_db, stack.api)
        current_step_code = f"{color_normal}{'#'*80}\nEVM is running code at {stack_entry.address}. Reason: {stack_entry.reason}\nCalldata: {color_calldata}{calldata}{color_normal}\n"

        res, ast, solidity_file, contract_to_storage = contract_db[stack_entry.address]

        # If no trace of the contract's source is found on the selected local cache or node, skip this stack entry
        if res is None:
            current_step_code += "Source not found in db, skipping..."
            contract_trace.append(
                ContractWrapper(
                    stack_entry.address,
                    stack_entry.reason,
                    [StepWrapper(code=current_step_code)],
                    {},
                    calldata,
                )
            )
            continue

        code = res["code"].encode()  # UTF-8 encoding
        contract_name = res["contract_name"]

        # Handle old solc versions that do not make use of the new ast
        if solidity_file is None or ast is None:
            current_step_code += (
                "AST is empty or using legacyAST, which is not supported."
            )
            contract_trace.append(
                ContractWrapper(
                    stack_entry.address,
                    stack_entry.reason,
                    [StepWrapper(code=current_step_code)],
                    {},
                    calldata,
                )
            )
            continue

        contract = solidity_file[contract_name]
        # metadata = json.loads(contract['metadata'])
        source_map = contract["evm"]["deployedBytecode"]["sourceMap"]
        bytecode_object = contract["evm"]["deployedBytecode"]["object"]
        addr_to_var = contract_to_storage[contract_name]

        # Bytecode divergence check
        if "hex_bytecode" in res:
            stripped_res_bytecode, _ = strip_cbor(res["hex_bytecode"])
            stripped_compiled_bytecode, _ = strip_cbor(bytecode_object)

            if stripped_res_bytecode == stripped_compiled_bytecode:
                current_step_code += "Bytecode matches exactly\n"
            elif len(stripped_res_bytecode) == len(stripped_compiled_bytecode):
                current_step_code += f"{color_warning}Warning: Bytecode does not match exactly, but has same length{color_normal}\n"
            else:
                current_step_code += f"{color_error}Warning: Bytecode mismatch encountered{color_normal}\n"
        else:
            current_step_code += f"{color_warning}No bytecode was found for this contract{color_normal}\n"

        if "storageLayout" in contract:
            storage_layout = contract["storageLayout"]
        else:
            current_step_code += (
                "WARNING: No storage layout could be produced for this contract.\n"
            )
            storage_layout = None

        pc = 0
        pc_to_data = {}

        # Decompress source map and create a mapping from the pc to relevant static data
        try:
            for source_mapping in source_map.split(";"):
                opcode = int(bytecode_object[pc * 2] + bytecode_object[pc * 2 + 1], 16)

                if source_mapping:
                    source_split = source_mapping.split(":")
                    if source_split[0]:
                        source_from = int(source_split[0])

                    if len(source_split) > 1 and source_split[1]:
                        source_range = int(source_split[1])

                    if len(source_split) > 2 and source_split[2]:
                        source_index = int(source_split[2])

                pc_to_data[pc] = PcData(
                    opcode, SourceMapping(source_from, source_range, source_index), None
                )

                # it's a push instruction, increment by extra size of instruction
                if 0x60 <= opcode < 0x80:
                    pc += opcode - 0x5F
                pc += 1

        except Exception as e:
            current_step_code += f"{color_error}Error: Could not decompress source map. Encountered exception: {e}{color_normal}"
            contract_trace.append(
                ContractWrapper(
                    stack_entry.address,
                    stack_entry.reason,
                    [StepWrapper(code=current_step_code)],
                    {},
                    calldata,
                )
            )
            continue

        # Search for node mappings for each step of the trace
        instruction_node_list = []
        for instruction_entry in stack.instructions[stack_entry]:
            pc_data = pc_to_data[instruction_entry.pc]

            source_from, source_length, source_index = list(pc_data.source_mapping)

            if pc_data.ast_node_mapping:
                ast_node = pc_data.ast_node_mapping
            elif __valid_source(ast, source_from, source_length, source_index):
                ast_node = __search_ast(
                    (ast, []), source_from, source_length, source_index
                )

                # Use ._replace() because namedtuples are immutable
                pc_to_data[instruction_entry.pc] = pc_to_data[
                    instruction_entry.pc
                ]._replace(ast_node_mapping=ast_node)
            elif source_index != -1:  # -1 is reserved for code the compiler adds
                current_step_code += f"{color_warning}Invalid source mapping: {source_from} : {source_length} : {source_index}{color_normal}"

            if ast_node:
                instruction_node_list.append(
                    (
                        instruction_entry.pc,
                        pc_data.opcode,
                        instruction_entry.data,
                        ast_node,
                    )
                )
                ast_node = None
            elif source_index == -1:
                pass
            else:
                current_step_code += f"{color_warning}Could not find ast node from source mapping: {source_from} : {source_length} : {source_index}{color_normal}\n"

        line_index = __create_source_index(code)

        node_groups = __group_instructions(instruction_node_list, storage_layout)

        # Highlight executed code
        step_counter = 0
        step_trace = []
        prev_storage_data = contract_last_storage[stack_entry.address]
        storage_changes = {}

        for scope_node, node_set, block_trace, storage_data in node_groups:
            annotations = ""

            # Take into account data from previous calls
            storage_data = prev_storage_data | storage_data

            # Add state access annotation and calculate storage changes between steps for pretty printing
            if prev_storage_data != storage_data:
                annotations += f"{color_note}State access detected{color_normal}\n"
                old_entry_changes = {
                    address: (prev_storage_data[address], storage_data[address])
                    for address in storage_data.keys() & prev_storage_data
                    if storage_data[address] != prev_storage_data[address]
                }
                new_entries = {
                    address: ("Uninitialized/Unknown", storage_data[address])
                    for address in storage_data.keys() - prev_storage_data
                }
                # Keep changes from previous steps which will not be shown
                storage_changes |= old_entry_changes | new_entries
                prev_storage_data = storage_data

            scope = scope_node["src"]
            scope_f, scope_r, _ = map(int, scope.split(":"))
            highlighted_nodes = set()
            highlighted_indices = set()
            node_types = []

            # Choose what to highlight
            for _, node in node_set.items():

                if node["nodeType"] in validAstTypes:
                    node_types.append(node["nodeType"])

                    if node["id"] not in highlighted_nodes:
                        highlighted_nodes.add(node["id"])
                        node_f, node_r, _ = map(int, node["src"].split(":"))
                        highlighted_indices.update(range(node_f, node_f + node_r))

                elif node["nodeType"] not in invalidAstTypes:
                    print(
                        f"Warning: Unknown AST Node type: {node['nodeType']} encountered during mapping to source."
                    )

            source_display = bytearray()

            # Apply highlighting colors
            curr_color = color_normal
            for i in range(scope_f, scope_f + scope_r):
                if i in highlighted_indices:
                    if curr_color == color_normal:
                        curr_color = color_highlight
                        source_display += curr_color.encode()

                else:
                    if curr_color == color_highlight:
                        curr_color = color_normal
                        source_display += curr_color.encode()

                source_display.append(code[i])

            # Unless there was nothing to highlight, wrap all the data in a single step for the contract trace display
            if node_types:
                current_step_code += f"step {step_counter}:\nline: {line_index[scope_f] + 1} : {source_display.decode()}{color_normal}\n"

                # Try to match storage addresses to variable names
                updated_storage_changes = {}
                for (k, v) in storage_changes.items():
                    if k in addr_to_var:
                        k_type = addr_to_var[k]["type"]
                        k_label = addr_to_var[k]["label"]
                        updated_storage_changes[f"{k}: ({k_type}) {k_label}"] = v
                    else:
                        updated_storage_changes[k] = v

                step_trace.append(
                    StepWrapper(
                        scope_node["id"],
                        current_step_code,
                        storage_data,
                        node_types,
                        block_trace,
                        annotations,
                        updated_storage_changes,
                    )
                )
                current_step_code = ""
                step_counter += 1
                storage_changes = {}

        contract_trace.append(
            ContractWrapper(
                stack_entry.address,
                stack_entry.reason,
                step_trace,
                storage_layout,
                calldata,
            )
        )
        contract_last_storage[stack_entry.address] = storage_data

    return contract_trace