'''
Author: Taurus052
Date: 2023-10-18 15:51:41
LastEditTime: 2024-07-08 16:40:25
'''

import re
import sys
import os

current_path = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(current_path,'..', 'qemu_output_logs')
program_name = sys.argv[1]
log_path = os.path.join(log_dir, str(program_name) + '_qemu_log.txt')

####

indirect_jump_inst = ["jr", "jalr", "ret"]
fail_addr_range = sys.argv[2]

# def exec_func(tr_log_path, in_asm_path, program_name):
def exec_func(log_path):    
    filtered_blocks, blocks_instr, blocks_linking, blocks_trace = parse_log_file(log_path)
    
    block_with_indirect_jump, indirect_jump_instrs_addr, blocks_with_pat_trace, need_pat_blocks\
        = get_indirect_jump_instrs(blocks_instr, blocks_trace)
    
    blocks_with_pat_trace = find_pat_trace(blocks_trace, need_pat_blocks, blocks_with_pat_trace)
    
    indirect_jump_target = get_indirect_jump_targets(blocks_trace, blocks_instr, block_with_indirect_jump)
    
    indirect_jump_instrs_addr_str = ','.join(indirect_jump_instrs_addr)
    # print(indirect_jump_instrs_addr_str)
    
    indirect_jump_target_str = ','.join(indirect_jump_target)
    
    indirect_data = indirect_jump_instrs_addr_str + '//' + indirect_jump_target_str
    print(indirect_data)
    # print(indirect_jump_target_str)
    # log_blocks = read_trace_log_file(log_path, fail_addr_range)
    # log_blocks_str = ' '.join(['//'.join(block) for block in log_blocks])
    # print(log_blocks_str)
    # print(trace_points_str)

    
# def in_asm_func(in_asm_path, program_name):
#     asm_blocks = read_in_asm_log(in_asm_path)
#     asm_blocks_str = '//'.join(asm_blocks)
#     print(asm_blocks_str)
def parse_log_file(log_path):
    with open(log_path, 'r') as file:
        log_content = file.read()
        lines = log_content.split('\n')

    # Define regex pattern for separator
    separator_pattern = re.compile(r'[-]+')

    # Lists to store extracted content
    blocks = []
    current_block = []
    blocks_instr = []
    blocks_trace = []
    blocks_linking = []

    # Iterate over lines and extract content
    for line in lines:
        # Check if the line matches the separator pattern
        if separator_pattern.match(line):
            # Add the current block to the list
            if current_block:
                blocks.append('\n'.join(current_block))
            # Start a new block
            current_block = []
        else:
            # Exclude empty lines and specific format lines
            if line.strip() and not line.startswith('IN: ') and not line.startswith('Priv: 3; Virt: 0'):
                current_block.append(line)

    # Add the last block to the list
    if current_block:
        blocks.append('\n'.join(current_block))
    
    fail_func_start = int(fail_addr_range.split(',')[0], 16)
    fail_func_end = int(fail_addr_range.split(',')[1], 16)


    # Remove blocks that start with an address within the fail address range
    filtered_blocks = []
    for block in blocks:
        if re.match(r'0x([0-9a-fA-F]+):', block.split('\n')[0]):
            start_addr = int(re.match(r'0x([0-9a-fA-F]+):', block.split('\n')[0]).group(1), 16)
            if start_addr <= fail_func_start or start_addr >= fail_func_end:
                filtered_blocks.append(block)
            else:
                break
        else:
            filtered_blocks.append(block)
   
    for block in filtered_blocks:
        f_lines = block.split('\n')
        current_block_instr = []
        current_block_linking = []
        current_block_trace = []
        
        for f_line in f_lines:
            if f_line.startswith('Linking'):
                current_block_linking.append(f_line)
            elif f_line.startswith('Trace'):
                current_block_trace.append(f_line)    
            else:
                current_block_instr.append(f_line)
        # Append the current block's content to the respective lists
        blocks_instr.append(current_block_instr)
        blocks_linking.append(current_block_linking)
        blocks_trace.append(current_block_trace)

    return filtered_blocks, blocks_instr, blocks_linking, blocks_trace

def get_indirect_jump_instrs(blocks_instr, blocks_trace):
    indirect_jump_instrs = []
    indirect_jump_instrs_addr = []
    block_with_indirect_jump = []
    blocks_with_pat_trace = {}
    need_pat_blocks = {}
    # block_need_pat_index = []
    # need_pat_block_head_addr = []
    
    # block_with_ret = []
    # ret_instrs = []
    # ret_instrs_addr = []
    
    block_index = 0
    for block in blocks_instr:
        instr = block[-1]
        tokens = instr.split()
        instr_addr_str = tokens[0][:-1][6:]
        instr_addr = hex(int(instr_addr_str, 16)).lstrip("0x")
        mnemonic = tokens[2]
        if mnemonic in indirect_jump_inst:
            indirect_jump_instrs.append(instr)
            indirect_jump_instrs_addr.append(instr_addr)
            block_with_indirect_jump.append(block_index)
            
            if len(blocks_trace[block_index]) > 1:
                # block_with_pat_trace.append(blocks_trace[block_index][-1])
                blocks_with_pat_trace[block_index] = blocks_trace[block_index][-1]
                block_index += 1
                need_pat_block_first_instr = blocks_instr[block_index][0]
                need_pat_block_haddr_str = need_pat_block_first_instr.split()[0][:-1][6:]
                need_pat_block_haddr = hex(int(need_pat_block_haddr_str, 16)).lstrip("0x")
                need_pat_blocks[block_index] = need_pat_block_haddr
                # need_pat_block_head_addr.append(need_pat_block_haddr)
                # block_need_pat_index.append(block_index)
            else:
                block_index += 1
            
        # elif mnemonic == 'ret':
        #     ret_instrs.append(instr)
        #     ret_instrs_addr.append(instr_addr)
        #     block_with_ret.append(block_index)
        #     block_index += 1
        
        else:
            block_index += 1
            continue

    return block_with_indirect_jump, indirect_jump_instrs_addr, blocks_with_pat_trace, need_pat_blocks

def find_pat_trace(blocks_trace, need_pat_blocks, blocks_with_pat_trace):
    pat_addr_list = []
    block_addr_pat = {}
    for block_index, block_haddr in need_pat_blocks.items():
        if block_haddr not in block_addr_pat:
            block_addr_pat[block_haddr] = []
        # last_pat_addr = []
        for id in range(len(blocks_trace)):
            for i, trace_line in enumerate(blocks_trace[id]):
                match = re.search(r'\[(?:[0-9a-fA-F]+/){1}([0-9a-fA-F]+)',trace_line)
                if match:
                    if int(match.group(1),16) == int(block_haddr,16):
                        if i > 0:
                            pat_line_1 = blocks_trace[id][i-1]
                            if id not in blocks_with_pat_trace.keys():
                                blocks_with_pat_trace[id] = pat_line_1
                            pat_addr_1 = re.search(r'\[(?:[0-9a-fA-F]+/){1}([0-9a-fA-F]+)',pat_line_1).group(1)
                            
                            if block_index -1 in blocks_with_pat_trace.keys():
                                pat_line_2 = blocks_with_pat_trace[block_index-1]
                                pat_addr_2 = re.search(r'\[(?:[0-9a-fA-F]+/){1}([0-9a-fA-F]+)',pat_line_2).group(1)
                            if pat_addr_1 not in block_addr_pat[block_haddr]:
                                block_addr_pat[block_haddr].append(pat_addr_1)
                            if pat_addr_2 not in block_addr_pat[block_haddr]:
                                block_addr_pat[block_haddr].append(pat_addr_2)
                        elif i == 0:
                            pat_line_2 = blocks_with_pat_trace[block_index-1]
                            pat_addr_2 = re.search(r'\[(?:[0-9a-fA-F]+/){1}([0-9a-fA-F]+)',pat_line_2).group(1)
                            if pat_addr_2 not in block_addr_pat[block_haddr]:
                                block_addr_pat[block_haddr].append(pat_addr_2)
                                    
                                    
    return blocks_with_pat_trace, block_addr_pat




def get_indirect_jump_targets(blocks_trace, blocks_instr, block_with_indirect_jump):
    indirect_jump_target = []
    
    for block_index in block_with_indirect_jump:
        
        tar_line = blocks_trace[block_index][0]
        tr_match = re.search(r'\[(?:[0-9a-fA-F]+/){1}([0-9a-fA-F]+)',tar_line)
        if tr_match:
            if int(tr_match.group(1),16) != int(blocks_instr[block_index][0].split()[0][:-1], 16):
                indirect_jump_target.append(tr_match.group(1)[4:].lstrip("0"))
            else:
                if len(blocks_trace[block_index]) > 1:
                # tar_line_2 = blocks_instr[block_index+1][0]
                    tar_line_2 = blocks_trace[block_index][1]
                    tl2_match = re.search(r'\[(?:[0-9a-fA-F]+/){1}([0-9a-fA-F]+)',tar_line_2)
                    target = tl2_match.group(1)
                    # target = tar_line_2.split()[0][:-1][6:]
                    indirect_jump_target.append(target)
                elif len(blocks_trace[block_index]) == 1:
                    tar_line_2 = blocks_instr[block_index+1][0]
                    target = tar_line_2.split()[0][:-1][6:].lstrip("0")
                    indirect_jump_target.append(target)
    
    return indirect_jump_target

if __name__ == "__main__":
    exec_func(log_path)
