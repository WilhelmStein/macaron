from collections import defaultdict

def build_index(node_list):


    built_index = defaultdict(lambda : list())
    prev_block_id = None
    for idx, node in enumerate(node_list):

        if prev_block_id:
            built_index[prev_block_id].append((node, idx))

        prev_block_id = node
    
    return built_index


built_index = build_index([1, 2, 3, 4, 5, 6, 7, 6, 8, 6, 7, 6, 8 , 9])
for key, val in built_index.items():
    print(f'{key} : {val}')
