'''
Copyright (C) <2023>  <Taurus052>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''
import os
import hashlib # standard hash library
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import threading
import subprocess
import matplotlib.pyplot as plt
import graphviz
import time
# import signal
import networkx as nx
import traceback
import math




# branch instructions
branch_inst = ["beq", "bne", "blt", "bltu", "bge", "bgeu", "beqz", "bnez", "bltz", "blez", "bgtz", "bgez", "bgt", "bgtu", "ble", "bleu"]
# jump instruction
unconditional_jump_inst = ["jal", "j"]
indirect_jump_inst = ["jr", "jalr"]

current_dir = os.path.dirname(os.path.abspath(__file__))
#Change the current working directory to the directory of the script
os.chdir(current_dir)

def main(objdump_file, Hash_algorithm, Hash_value_length, program_name):
    output_directory = os.path.join(os.path.dirname(os.getcwd()), 'output_files')
    # Check if the output directory exists, if not, create it
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    
    function_line_ranges, function_addr_ranges, function_instr, fail_addr_range =  get_func_information(objdump_file)
    
    # Analyze the QEMU log file
    trace_process = subprocess.Popen(['python', 'trace_analyze.py', program_name, fail_addr_range], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    qemu_data = trace_process.communicate()[0].strip()
    indirect_instr_addr, indirect_jump_targets = qemu_data.split('//')
    indirect_instr_addr_list = indirect_instr_addr.split(',')
    indirect_jump_targets_list = indirect_jump_targets.split(',')
    indirect_jumps = indirect_jump_func(indirect_instr_addr_list, indirect_jump_targets_list)
    ### find the function to visit 
    function_call_instr = {}
    # extra_func_name = extract_function_before_xx(objdump_file, '<__to_main>')
    to_visit_functions, visited_functions_id, visited_functions, function_call_instr  \
                            = find_to_visit_function(objdump_file, function_instr,function_addr_ranges,\
                                '<__start>',function_call_instr, indirect_jumps, visited_functions = None,visited_functions_id=None)
        
    all_instr, all_control_transfer_instr_addr, sorted_functions_with_jump_instr_addr = \
        get_all_control_transfer_instr(objdump_file, function_addr_ranges,visited_functions, indirect_jumps)

    ret_instr_addr, function_have_ret_instr =  find_ret_instruction(visited_functions, function_addr_ranges, function_instr)
    
    function_call_relationship = get_function_call_relationship(function_call_instr, function_addr_ranges, output_directory, program_name)
    
    return_target = get_return_relationship(function_call_relationship, ret_instr_addr, function_call_instr, \
                                                all_instr, function_addr_ranges) ### 2024.01.24
        
    used_function_instr = extract_used_function_instr(function_instr, visited_functions)
    
    address, machine_code, mnemonic, operands = get_func_machine_code(used_function_instr)
    
    end_addr_list, branch_or_jump_target_addr, \
        branch_taken_start_addr, all_taken_target_addr, order_start_addr_list= \
            get_the_addr_information_for_basic_block(address, mnemonic, operands, function_addr_ranges, indirect_jumps)
    
    
    basic_block = create_basic_blocks_in_order(order_start_addr_list, end_addr_list, used_function_instr, function_addr_ranges,\
                                                ret_instr_addr,return_target, indirect_jumps)
                                       
    basic_block =  create_basic_blocks_start_with_taken_target(all_taken_target_addr, basic_block, order_start_addr_list, used_function_instr)
    
    sorted_basic_blocks =  sort_basic_blocks(basic_block)
    


    #export_trace_CFG(exec_bb, output_directory, exec_bb_num, program_name)
    # #
    export_results(function_addr_ranges, program_name + '_function_addr.txt',
                all_instr, sorted_functions_with_jump_instr_addr, program_name + '_forward_transfers.txt', \
                    program_name + '_control_transfer.bin',\
                program_name + '_basic_block.txt', sorted_basic_blocks,
                program_name + '_bin_basic_block_inf.txt', program_name + '_hex_basic_block_inf.txt',
                Hash_algorithm, Hash_value_length, output_directory, program_name)
    
    # generate_CFG(exec_bb, basic_block, program_name, output_directory)
    edge_count, adjacency_blocks = generate_CFG(sorted_basic_blocks, program_name, output_directory)
    # generate_main_CFG(basic_block, program_name, output_directory, function_addr_ranges)



def get_func_machine_code(input_data):
    '''
    Extracts machine code information from the input data.

    Args:
        input_data (list): Used function instructions.

    Returns:
        tuple: A tuple containing lists of addresses, machine codes, mnemonics, and operands.

    '''
    # Initialize lists to store the machine code information
    address = []
    machine_code = []
    mnemonic = []
    operands = []

    # Iterate over the input data
    for line in input_data:
        if len(line) == 1:
            break

        # Split the line into tokens
        tokens = line.split()

        # Extract the address, machine code, mnemonic, and operands
        if len(tokens) == 3:    
            address.append(tokens[0][:-1])  
            machine_code.append(tokens[1])
            mnemonic.append(tokens[2])
            operands.append('')
        else:
            address.append(tokens[0][:-1])  
            machine_code.append(tokens[1])
            mnemonic.append(tokens[2])
            operands.append(tokens[3])

    # Return the extracted machine code information as a tuple of lists
    return address, machine_code, mnemonic, operands

def get_func_information(objdump_file):
    '''
    Extract function information from the objdump file.

    Args:
        objdump_file (str): Path to the objdump file.

    Returns:
        tuple: A tuple containing dictionaries of function line ranges, function address ranges,
               and function instructions.

    '''
    # Read the objdump file
    with open(objdump_file, 'r') as f:
        lines = f.readlines()
    # Initialize variables
    function_line_ranges = {}
    function_addr_ranges = {}
    function_instr = {}
    start_line = 0
    in_function = False
    function_name = ""
    fail_address = ""
    # Process each line in the file
    for i, line in enumerate(lines):
        # Check if the line indicates the start of a function
        if line.endswith(">:\n"): 
            in_function = True
            function_name = line.split()[-1][:-1]  # Extract the function name
            start_line = i + 1
            func_instr = [] # Initialize a list to store the function instructions
        
        # Check if the line indicates the end of a function
        elif line.startswith("\n") or "..." in line: 
            if in_function:
                in_function = False
                end_line = i - 1
                # Get the start and end addresses based on line numbers
                start_address = lines[start_line].split()[0][:-1]
                end_address = lines[end_line].split()[0][:-1]
                 # Store the function information in the dictionaries
                function_line_ranges[function_name] = (start_line, end_line)
                function_addr_ranges[function_name] = (start_address, end_address)
                function_instr[function_name] = func_instr
                    
        # Check if the line is an instruction within a function
        else:
            if in_function:
                instr = line.strip()
                func_instr.append(instr)
    
    #Get the exit address of the program
    exit_addr_range = function_addr_ranges['<__exit>']
    fail_addr_range = function_addr_ranges['<__fail>']
    fail_addr_range_str = exit_addr_range[0] + ',' + fail_addr_range[1]
       
    return function_line_ranges, function_addr_ranges, function_instr, fail_addr_range_str

def write_functions_information(function_addr_ranges, output_file, output_directory):
    func_info_path = os.path.join(output_directory, output_file)
    with open(func_info_path, 'w') as f:
        for func_name, func_range in function_addr_ranges.items():
            f.write(func_name + ':' + '\n' + '\tstart_addr:' + ' ' + str(func_range[0]) \
                +'\n' + '\tend_addr:' + ' ' + str(func_range[1]) + '\n')

def indirect_jump_func(indirect_instr_addr_list, indirect_jump_targets_list):
    indirect_jumps = {}
    for i in range(len(indirect_instr_addr_list)):
        if indirect_instr_addr_list[i] in indirect_jumps.keys():
            indirect_jumps[indirect_instr_addr_list[i]].append(indirect_jump_targets_list[i])
        else:
            indirect_jumps[indirect_instr_addr_list[i]] = [indirect_jump_targets_list[i]]
    return indirect_jumps

          
def find_to_visit_function(objdump_file, function_instr, function_addr_ranges, func_name, function_call_instr, indirect_jumps,\
                            visited_functions = None, visited_functions_id=None):
    '''
    Find functions to visit based on the function's instructions and addresses.

    Args:
        objdump_file (str): Path to the objdump file.
        function_instr (dict): Dictionary containing the instructions of each function.
        function_addr_ranges (dict): Dictionary containing the address ranges of each function.
        func_name (str): Name of the current function.
        function_call_instr (dict): Dictionary to store the call instructions for each function.
        visited_functions (set, optional): Set of visited functions. Defaults to None.
        visited_functions_id (bool, optional): Identifier for whether visited_functions has been initialized. Defaults to None.

    Returns:
        tuple: A tuple containing the set of functions to visit, the visited_functions_id flag,
                the visited functions, and the function_call_instr dictionary.

    '''
    
    # Initialize visited_functions set if not already initialized
    if visited_functions_id is None:
        visited_functions = set()
        visited_functions_id = True
    # Read objdump file
    with open(objdump_file, 'r') as file:
        lines = file.readlines()

    func_addr_range = function_addr_ranges[func_name]    
    call_instrs = []
    
    # Search for called functions in the function range
    to_visit_functions = set()
    for line in function_instr[func_name]:
        if len(function_instr[func_name]) == 1:
            if line.split()[2] == 'jal' or line.split()[2] ==  'j' :
                    operand = line.split()[3]
                    if ',' in operand:
                        jump_target = operand.split(',')[1]
                        if int(jump_target,16) > int(func_addr_range[1],16) or int(jump_target,16) < int(func_addr_range[0],16):
                            call_instrs.append(line)
                    elif ',' not in operand:
                        jump_target = operand
                        if int(jump_target,16) > int(func_addr_range[1],16) or int(jump_target,16) < int(func_addr_range[0],16):
                            call_instrs.append(line)
                    
                    for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                        if int(jump_target,16) >= int(func_addr_range[0],16) and int(jump_target,16) <= int(func_addr_range[1],16):
                            to_visit_functions.add(to_visit_func_name)
                            called_func_name = func_name
                            break
            
            # branch instr    
            elif  any(all(instr_char in line.split()[2] for instr_char in instr) for instr in branch_inst):
                operand = line.split()[3]
                jump_target = operand.split(',')[-1]
                
                if line == function_instr[func_name][-1]:# Check if the last instruction is a branch instruction
                    for b_next_func_name in function_addr_ranges.keys():
                        current_func_addr_range = function_addr_ranges[func_name]
                        next_func_addr_range = function_addr_ranges[b_next_func_name]
                        if b_next_func_name != func_name and int(next_func_addr_range[0],16) > int(current_func_addr_range[1],16):
                            to_visit_functions.add(b_next_func_name)
                            called_func_name = func_name
                            break
                for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                    if int(jump_target,16) >= int(func_addr_range[0],16) and int(jump_target,16) <= int(func_addr_range[1],16):
                        to_visit_functions.add(to_visit_func_name)
                        called_func_name = func_name
                        break
            # indirect jump instr
            if line.split()[2] in indirect_jump_inst:
                indirect_instr_tokens = line.split()
                indirect_instr_addr = indirect_instr_tokens[0][:-1]
                if not any('' in v for v in indirect_jumps.values()):
                    for indirect_instr_addr_key in indirect_jumps.keys():
                        if indirect_instr_addr == indirect_instr_addr_key:
                            indirect_instr_targets = indirect_jumps[indirect_instr_addr_key]
                            target_str = ','.join(indirect_instr_targets)
                            call_instrs.append(line + '\t' + target_str)
                
                for indirect_instr_target in indirect_instr_targets:
                    for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                        if int(indirect_instr_target,16) >= int(func_addr_range[0],16) and int(indirect_instr_target,16) <= int(func_addr_range[1],16):
                            to_visit_functions.add(to_visit_func_name)
                            called_func_name = func_name
                            break
                 
            
        else:
            if line.split()[2] == 'jal' or line.split()[2] ==  'j' :
                operand = line.split()[3]
                if ',' in operand:
                    jump_target = operand.split(',')[-1]
                    if int(jump_target,16) > int(func_addr_range[1],16) or int(jump_target,16) < int(func_addr_range[0],16):
                        call_instrs.append(line)
                elif ',' not in operand:
                    jump_target = operand
                    if int(jump_target,16) > int(func_addr_range[1],16) or int(jump_target,16) < int(func_addr_range[0],16):
                        call_instrs.append(line)

                for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                    if int(jump_target,16) >= int(func_addr_range[0],16) and int(jump_target,16) <= int(func_addr_range[1],16):
                        to_visit_functions.add(to_visit_func_name)
                        called_func_name = func_name
                        break
            # branch instr
            elif  any(all(instr_char in line.split()[2] for instr_char in instr) for instr in branch_inst):
                operand = line.split()[3]
                jump_target = operand.split(',')[-1]
                
                if line == function_instr[func_name][-1]:# # Check if the last instruction is a branch instruction
                    for b_next_func_name in function_addr_ranges.keys():
                        current_func_addr_range = function_addr_ranges[func_name]
                        next_func_addr_range = function_addr_ranges[b_next_func_name]
                        if b_next_func_name != func_name and int(next_func_addr_range[0],16) > int(current_func_addr_range[1],16):
                            to_visit_functions.add(b_next_func_name)
                            called_func_name = func_name
                            break
                for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                    if int(jump_target,16) >= int(func_addr_range[0],16) and int(jump_target,16) <= int(func_addr_range[1],16):
                        to_visit_functions.add(to_visit_func_name)
                        called_func_name = func_name
                        break
            
            # indirect jump instr
            if line.split()[2] in indirect_jump_inst:
                indirect_instr_tokens = line.split()
                indirect_instr_addr = indirect_instr_tokens[0][:-1]
                if indirect_instr_addr in indirect_jumps.keys():
                    if not any('' in v for v in indirect_jumps.values()):
                        for indirect_instr_addr_key in indirect_jumps.keys():
                            if indirect_instr_addr == indirect_instr_addr_key:
                                indirect_instr_targets = indirect_jumps[indirect_instr_addr_key]
                                target_str = ','.join(indirect_instr_targets)
                                call_instrs.append(line + '\t' + target_str)
                    
                    for indirect_instr_target in indirect_instr_targets:
                        for to_visit_func_name, func_addr_range in function_addr_ranges.items():
                            if int(indirect_instr_target,16) >= int(func_addr_range[0],16) and int(indirect_instr_target,16) <= int(func_addr_range[1],16):
                                to_visit_functions.add(to_visit_func_name)
                                called_func_name = func_name
                                break
                else:
                    continue

    function_call_instr[func_name] = call_instrs
    # If no called functions found, add the next sequential function as to visit
    if not to_visit_functions:
        found = False
        for next_func_name in function_addr_ranges.keys():
            if found:
                to_visit_functions.add(next_func_name)
                called_func_name = func_name
                break
            if next_func_name == func_name:
                found = True
    
    # Recursively search for called functions in the called functions
    for been_called_func_name in to_visit_functions:
        if been_called_func_name not in visited_functions:
            visited_functions.add(called_func_name)
            visited_functions.add(been_called_func_name)
            find_to_visit_function(objdump_file, function_instr, function_addr_ranges, been_called_func_name, \
                                    function_call_instr, indirect_jumps, visited_functions, visited_functions_id)
    

    visited_functions = sorted(visited_functions, key=lambda func_name: int(function_addr_ranges[func_name][0], 16))

    
    return to_visit_functions, visited_functions_id, visited_functions, function_call_instr    


def find_ret_instruction(visited_functions, function_addr_ranges, function_instr):
    '''
    Find return instructions within visited functions.

    Args:
        visited_functions (list): List of visited function names.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.
        function_instr (dict): Dictionary mapping function names to their instructions.

    Returns:
        tuple: A tuple containing a dictionary of return instruction addresses and a list of functions
               that have return instructions.

    '''
    
    # Initialize variables
    ret_instr_addr = {}
    function_have_ret_instr = []

    # Process each visited function
    for func_name in visited_functions:
        start_addr, end_addr = function_addr_ranges[func_name]
        instrs = function_instr[func_name]

        # Search for return instructions within the function's address range
        for line in instrs:
            tokens = line.split()
            instr_addr = tokens[0][:-1]
            mnemonic = tokens[2]

            # Check if the instruction is a return instruction
            if int(instr_addr, 16) >= int(start_addr, 16) and int(instr_addr, 16) <= int(end_addr, 16) \
                    and mnemonic == 'ret':
                # Store the return instruction address in the dictionary
                if func_name in ret_instr_addr:
                    ret_instr_addr[func_name].append(instr_addr)
                else:
                    ret_instr_addr[func_name] = [instr_addr]
                # Add the function to the list of functions with return instructions
                function_have_ret_instr.append(func_name)

    # Return the dictionary of return instruction addresses and the list of functions with return instructions
    return ret_instr_addr, function_have_ret_instr

def get_function_call_relationship(function_call_instr, function_addr_ranges, output_directory, program_name):
    '''
    Get the function call relationship between functions.

    Args:
        function_call_instr (dict): Dictionary mapping function names to their function call instructions.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.

    Returns:
        dict: Dictionary representing the function call relationships.

    '''
    
    # Initialize dictionary to store the function call relationship
    function_call_relationship = {}
    
    # Iterate over the function call instructions
    for caller_func_name, call_instrs in function_call_instr.items():
        for call_instr in call_instrs:
            tokens = call_instr.split()
            instr_addr = tokens[0][:-1]
            mnemonic = tokens[2]
            operand = tokens[3]
            indirect_instr_targets = tokens[-1]
            if ',' in operand:
                jump_target = operand.split(',')[-1]
            else:
                jump_target = operand
            
            if ',' in indirect_instr_targets:
                indirect_jump_targets = indirect_instr_targets.split(',')
            else:
                indirect_jump_targets = [indirect_instr_targets]
            
            # Iterate over the function address ranges
            for callee_func_name, address in function_addr_ranges.items():
                func_start_addr = address[0]
                func_end_addr = address[1]
                
                 # Check if the jump target matches the start address of the callee function
                if mnemonic == 'jal':
                    if jump_target in func_start_addr:
                        if caller_func_name in function_call_relationship:
                            function_call_relationship[caller_func_name].append(callee_func_name)
                        else:
                            function_call_relationship[caller_func_name] = [callee_func_name]
                        break
                elif mnemonic == 'j':
                    if jump_target in func_start_addr:
                        if caller_func_name in function_call_relationship:
                            function_call_relationship[caller_func_name].append(callee_func_name)
                        else:
                            function_call_relationship[caller_func_name] = [callee_func_name + ' *']
                        break 
                
                elif mnemonic == 'jalr':
                    for indirect_jump_target in indirect_jump_targets:
                        if indirect_jump_target in func_start_addr:
                            if caller_func_name in function_call_relationship:
                                function_call_relationship[caller_func_name].append(callee_func_name)
                            else:
                                function_call_relationship[caller_func_name] = [callee_func_name]
                            break
                
                elif mnemonic == 'jr':
                    for indirect_jump_target in indirect_jump_targets:
                        if indirect_jump_target in func_start_addr:
                            if caller_func_name in function_call_relationship:
                                function_call_relationship[caller_func_name].append(callee_func_name)
                            else:
                                function_call_relationship[caller_func_name] = [callee_func_name + ' *']
                            break

    # Remove duplicates from the function call relationship
    for caller_func_name in function_call_relationship:
        function_call_relationship[caller_func_name] = list(set(function_call_relationship[caller_func_name]))
    # Sort the function call relationship based on the start address of the caller functions
    function_call_relationship = {k: v for k, v in sorted(function_call_relationship.items(), key=lambda item: int(function_addr_ranges[item[0]][0], 16))}
    
    G = graphviz.Digraph(format='svg')

    # Add nodes and edges to the graph
    for caller_func_name, callee_func_names in function_call_relationship.items():
        G.node(caller_func_name)
        for callee_func_name in callee_func_names:
            G.node(callee_func_name)
            G.edge(caller_func_name, callee_func_name)

    # Set the output file path
    output_file = os.path.join(output_directory, f'{program_name}_function_call_relationship')

    # Render the graph and save it to a file
    G.render(filename=output_file, cleanup=True, view=False)
 
    return function_call_relationship

def get_return_relationship(function_call_relationship, ret_instr_addr, function_call_instr, all_instr,function_addr_ranges):
    '''
    Get the return relationship between functions and the corresponding return targets.

    Args:
        function_call_relationship (dict): Dictionary representing the function call relationships.
        ret_instr_addr (dict): Dictionary mapping function names to their return instruction addresses.
        function_call_instr (dict): Dictionary mapping function names to their function call instructions.
        all_instr (list): List of all instructions.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.

    Returns:
        dict: Dictionary representing the return targets for each function.

    '''
    
    # Initialize dictionaries to store the return relationship and return targets
    return_relationship = {}
    return_target = {}
    
    # Iterate over the function call relationship
    for caller_func_name, callee_func_names in function_call_relationship.items():
        for func_name in callee_func_names:
            try:
                callee_func_name = func_name.split()[0]
                 # The function where the ret instruction is located is the jump target function of the j instruction
                if len(func_name.split()) != 1 and func_name.split()[1] == '*':
                    last_func = [key for key, names in function_call_relationship.items() if caller_func_name.strip('<>').strip() in [name.strip('<>').strip() for name in names]]
                    last_func_str =  ' '.join(last_func)
                    if callee_func_name in ret_instr_addr.keys():
                        if callee_func_name in return_relationship:
                            return_relationship[callee_func_name].append(last_func_str + ' ' + caller_func_name)
                        else:
                            return_relationship[callee_func_name] = [last_func_str + ' ' + caller_func_name]
                    
                else:
                    if callee_func_name in ret_instr_addr.keys():
                        if callee_func_name in return_relationship:
                            return_relationship[callee_func_name].append(caller_func_name)
                        else:
                            return_relationship[callee_func_name] = [caller_func_name]

            except KeyError:
                print(f"KeyError: {callee_func_name} not found in ret_instr_addr")
    
    # Iterate over the return relationship to find return targets
    for ret_key, ret_funcs in return_relationship.items():
        for func in ret_funcs:
            func_n = func.split()[0]
            if func in function_call_instr.keys() and ' ' not in func:
                for jal_instr in function_call_instr[func_n]:
                    tokens = jal_instr.split()
                    instr_addr = tokens[0][:-1]
                    instr_target_func = tokens[-1]
                    if instr_target_func == ret_key:
                        for i in range(len(all_instr)):
                            if int(all_instr[i].split()[0][:-1],16) == int(instr_addr,16):
                                for func_name, addr in function_addr_ranges.items():
                                    if int(all_instr[i+1].split()[0][:-1],16) >= int(addr[0],16) and \
                                        int(all_instr[i+1].split()[0][:-1],16) <= int(addr[1],16):
                                        if ret_key in return_target:
                                            return_target[ret_key].append(func_name + ' '+all_instr[i+1].split()[0][:-1])
                                        else:
                                            return_target[ret_key] = [func_name + ' '+all_instr[i+1].split()[0][:-1]]
                                        break
                                    else:
                                        continue
                    else:
                        continue
            elif func_n in function_call_instr.keys() and ' ' in func:
                func_n2 = func.split()[-1]
                for jal_instr in function_call_instr[func_n]:
                    tokens = jal_instr.split()
                    instr_addr = tokens[0][:-1]
                    instr_target_func = tokens[-1]
                    if instr_target_func == func_n2:
                        for i in range(len(all_instr)):
                            if int(all_instr[i].split()[0][:-1],16) == int(instr_addr,16):
                                for func_name, addr in function_addr_ranges.items():
                                    if int(all_instr[i+1].split()[0][:-1],16) >= int(addr[0],16) and \
                                        int(all_instr[i+1].split()[0][:-1],16) <= int(addr[1],16):
                                        if ret_key in return_target:
                                            return_target[ret_key].append(func_name + ' '+all_instr[i+1].split()[0][:-1])
                                        else:
                                            return_target[ret_key] = [func_name + ' '+all_instr[i+1].split()[0][:-1]]
                                        break
                                    else:
                                        continue
                    else:
                        continue
    
    return return_target


def get_all_control_transfer_instr(objdump_file, function_addr_ranges,visited_functions, indirect_jumps):
    '''
    Get all control transfer instructions within the given objdump file.

    Args:
        objdump_file (str): Path to the objdump file.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.
        visited_functions (list): List of visited function names.

    Returns:
        tuple: A tuple containing the list of all instructions, a list of all control transfer instruction addresses,
               and a dictionary mapping visited function names to their control transfer instruction addresses.

    '''
    # Initialize lists and dictionaries
    all_instr = []
    address = []
    machine_code = []
    mnemonic = []
    operands = []
    all_control_transfer_instr_addr = []   
    indirect_transfer_addr = []
    
    # Read the objdump file and extract instructions
    with open(objdump_file,'r') as file:
        for line in file:
            if line.startswith(" "):
                all_instr.append(line.strip())
    
    # Process each instruction and extract relevant information            
    for i in range(len(all_instr)):
        tokens = all_instr[i].split()
        if len(tokens) == 3:    
            address.append(tokens[0][:-1])  
            machine_code.append(tokens[1])
            mnemonic.append(tokens[2])
            operands.append('')
        else:
            address.append(tokens[0][:-1])  
            machine_code.append(tokens[1])
            mnemonic.append(tokens[2])
            operands.append(tokens[3])
    
    # Find all control transfer instruction addresses (no indirect jump instructions)
    for i in range(len(mnemonic)):
        if mnemonic[i] in branch_inst:
            operand = operands[i].split(',')
            all_control_transfer_instr_addr.append(address[i] + ',' + operand[-1])
            
        elif mnemonic[i] == 'jal':
            operand = operands[i].split(',')
            all_control_transfer_instr_addr.append(address[i] + ',' + operand[-1]) 
            
        elif mnemonic[i] == 'j':
            if ',' in operands[i]:
                operand = operands[i].split(',')
                all_control_transfer_instr_addr.append(address[i] + ',' + operand[-1])
            elif ',' not in  operands[i]:
                operand = operands[i].split() 
                all_control_transfer_instr_addr.append(address[i] + ',' + operand[-1])            
        
        elif mnemonic[i] in indirect_jump_inst :
            if not any('' in v for v in indirect_jumps.values()):
                for ij_addr in indirect_jumps:
                    if int(address[i],16) == int(ij_addr, 16):
                        ij_taddr_str = '/'.join(indirect_jumps[ij_addr])
                        all_control_transfer_instr_addr.append(address[i] + ',' + ij_taddr_str)
        # elif mnemonic[i] in indirect_jump_inst:
        #     all_control_transfer_instr_addr.append(address[i] + ',' + operands[i])
        #     indirect_transfer_addr.append(address[i])
    
    # Create a dictionary to store control transfer instruction addresses for each visited function
    functions_with_jump_instr_addr = {func_name: [] for func_name in visited_functions}
    
    # Assign control transfer instruction addresses to their corresponding functions
    for i in range(len(all_control_transfer_instr_addr)):
        for func_name in visited_functions:
            func_addr_range = function_addr_ranges[func_name]
            if int(all_control_transfer_instr_addr[i].split(',')[0],16) >= int(func_addr_range[0],16) and \
                int(all_control_transfer_instr_addr[i].split(',')[0],16) <= int(func_addr_range[1],16):
                functions_with_jump_instr_addr[func_name].append(all_control_transfer_instr_addr[i])
                break
    
    # Sort the dictionary based on the starting address of each function
    sorted_functions_with_jump_instr_addr = {k: v for k, v in sorted(functions_with_jump_instr_addr.items(), \
                                                key=lambda item: int(function_addr_ranges[item[0]][0], 16))}
   
    return all_instr, all_control_transfer_instr_addr, sorted_functions_with_jump_instr_addr#, indirect_transfer_addr

def write_in_may_used_control_transfer_instr(all_instr, functions_with_jump_instr_addr, output_file1, output_file2 ,\
                                                output_directory, program_name):
    ct_path = os.path.join(output_directory, output_file1)
    bin_path = os.path.join(output_directory, output_file2)
    
    trans_count = 0
    
    with open (ct_path,'w',encoding='utf-8') as file1, open(bin_path,'wb') as file2:
        for func_name in functions_with_jump_instr_addr:
            file1.write('\n' + func_name + ':\n'+'\n')
            
            for line in functions_with_jump_instr_addr[func_name]:
                addr, taken_target = line.split(',')
                if '/' in taken_target:
                    indirect_targets = taken_target.split('/')
                    ij_tar_list = list(set(indirect_targets))
                    for ij_target in ij_tar_list:
                        target_line_num = None
                        
                        int_addr = int(addr, 16)
                        int_target = int(ij_target, 16)
                        bin_addr = bin(int_addr)[2:].zfill(16)
                        bin_target = bin(int_target)[2:].zfill(16)
                        addr_bytes = bin_addr.encode('utf-8')
                        target_bytes = bin_target.encode('utf-8')
                        file2.write(addr_bytes + target_bytes + b'\n')
                        
                        trans_count += 1

                        for line_num , instr in enumerate(all_instr):
                            if instr.startswith(ij_target):
                                target_line_num = line_num
                                break
                        
                        if target_line_num is not None:
                            jump_instr_line_num = None
                            for line_num , instr in enumerate(all_instr):
                                if instr.startswith(addr):
                                    jump_instr_line_num = line_num
                                    break      
                            if jump_instr_line_num is not None:
                                file1.write('j/b_instr: '+all_instr[jump_instr_line_num] + '\n')
                                file1.write('t_instr:   '+all_instr[target_line_num] + '\n')
                                file1.write('\n')
                
                elif '/' not in taken_target:
                    target_line_num = None
                        
                    int_addr = int(addr, 16)
                    int_target = int(taken_target, 16)
                    bin_addr = bin(int_addr)[2:].zfill(16)
                    bin_target = bin(int_target)[2:].zfill(16)
                    addr_bytes = bin_addr.encode('utf-8')
                    target_bytes = bin_target.encode('utf-8')
                    file2.write(addr_bytes + target_bytes + b'\n')
                    
                    trans_count += 1

                    for line_num , instr in enumerate(all_instr):
                        if instr.startswith(taken_target):
                            target_line_num = line_num
                            break
                    
                    if target_line_num is not None:
                        jump_instr_line_num = None
                        for line_num , instr in enumerate(all_instr):
                            if instr.startswith(addr):
                                jump_instr_line_num = line_num
                                break      
                        if jump_instr_line_num is not None:
                            file1.write('j/b_instr: '+all_instr[jump_instr_line_num] + '\n')
                            file1.write('t_instr:   '+all_instr[target_line_num] + '\n')
                            file1.write('\n')
                    
    
    with open(ct_path,'r+',encoding='utf-8') as file1, open(bin_path, 'r+', encoding='utf-8') as file2:
        content1 = file1.read()
        file1.seek(0,0)
        file1.write("trans_num: " + str(trans_count) + '\n' + content1)
        
        content2 = file2.read()
        file2.seek(0,0)
        bin_trans_count = bin(trans_count)[2:].zfill(16)
        file2.write(str(bin_trans_count) + '\n' + content2)

        
    
    instruction_count = []
    function_names = []

    for function_name, jump_instructions in functions_with_jump_instr_addr.items():
        instruction_count.append(len(jump_instructions))
        function_names.append(function_name)

    # Set the figure size and spacing
    fig, ax = plt.subplots(figsize=(12, 6))
    plt.subplots_adjust(bottom=0.3)

    # Plot the bar chart
    bars = plt.bar(function_names, instruction_count)
    plt.xlabel('Function Name')
    plt.ylabel('Transfer Instructions')
    plt.title(program_name + ' Transfers per Function (Forward)')

    # Rotate the x-axis labels to prevent overlap
    plt.xticks(rotation=90)

    # Add data labels to the bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, height, str(int(height)), ha='center', va='bottom')

    # Save the figure to a file
    plt.savefig(os.path.join(output_directory, program_name + '_forward_transfers_per_function.svg'))


def extract_used_function_instr(function_instr, visited_functions):
    used_function_instr = []
        
    for func_name, instr_list in function_instr.items():
        if func_name in visited_functions:
            used_function_instr.extend(instr_list)
            
    used_function_instr.sort(key=lambda x: int(x.split(':')[0], 16))
    # with open(output_file,'w',encoding='utf-8') as file :
    #     for instr in used_function_instr:
    #         file.write(instr + '\n') 
            
    return used_function_instr

def get_the_addr_information_for_basic_block(address, mnemonic, operands, function_addr_ranges, indirect_jumps):
    '''
    Get address information for basic block.

    Args:
        address (list): List of instruction addresses.
        mnemonic (list): List of instruction mnemonics.
        operands (list): List of instruction operands.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.

    Returns:
        tuple: A tuple containing the list of end addresses for each function, a list of branch or jump target addresses,
               a list of start addresses for branches that are taken, a list of all taken target addresses,
               and a list of start addresses in order.

    '''
    # Initialize lists and variables
    branch_or_jump_target_addr = []
    order_start_addr_list = []
    end_addr_list = []
    func_end_addr_list = []
    branch_taken_start_addr = []
    branch_i = 0
    all_taken_target_addr = [] # All taken_target address
    
    # Extract function end addresses from function address ranges
    for func, addresses in function_addr_ranges.items():
        func_end_addr = addresses[-1]
        func_end_addr_list.append(func_end_addr)
    
    # Process each instruction and extract address information
    for i in range(len(mnemonic)):
        if i == 0:
            order_start_addr_list.append(address[i])
        
        # function without transfer instruction     
        if address[i] in func_end_addr_list and i+1 <= len(mnemonic):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic):
                order_start_addr_list.append(address[i+1])
                # all_taken_target_addr.append(address[i] + ',' + address[i+1])
            elif i+1 == len(mnemonic):
                continue

        # Deal with branch instructions
        if mnemonic[i] in branch_inst and i+1 < len(mnemonic):
            branch_i += 1
            end_addr_list.append(address[i])
            order_start_addr_list.append(address[i+1])
            branch_or_jump_target_addr.append(address[i+1]+' bnt' + ' ' + str(branch_i))
            operand = operands[i].split(',')
            branch_taken_start_addr.append(operand[-1])
            branch_or_jump_target_addr.append(operand[-1]+' bt' + ' ' + str(branch_i))
            all_taken_target_addr.append(address[i] + ',' + operand[-1])

    # Deal with direct jump instructions
    for i in range(len(mnemonic)):
        if (mnemonic[i] == 'ret'):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic) and mnemonic[i+1]:
                order_start_addr_list.append(address[i+1])
            
        elif (mnemonic[i] == 'jal'):
            end_addr_list.append(address[i])
            operand = operands[i].split(',')
            branch_or_jump_target_addr.append(operand[-1]+' jal')
            all_taken_target_addr.append(address[i] + ',' + operand[-1])
            if i+1 < len(mnemonic):
                order_start_addr_list.append(address[i+1])
                
        elif (mnemonic[i] == 'j'):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic):
                order_start_addr_list.append(address[i+1])

            if ',' in operands[i]:
                operand = operands[i].split(',')
                branch_or_jump_target_addr.append(operand[0]+' j')
                all_taken_target_addr.append(address[i] + ',' + operand[-1])
                
            elif ',' not in  operands[i]:
                operand = operands[i]
                branch_or_jump_target_addr.append(operand+' j')   
                all_taken_target_addr.append(address[i] + ',' + operand)

    # Deal with indirect jump instructions
    for i in range(len(mnemonic)):
        if (mnemonic[i] == 'jalr'):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic):
                order_start_addr_list.append(address[i+1])
            for ij_addr in indirect_jumps:
                if int(ij_addr,16) == int(address[i], 16):
                    ij_taddr_str = '/'.join(indirect_jumps[ij_addr])
                    all_taken_target_addr.append(address[i] + ',' + ij_taddr_str)
                # if int(ij_addr,16) == int(address[i], 16):
                    # all_taken_target_addr.append(ij_taddr)
            # branch_or_jump_target_addr.append('ffff'+' jalr')
            
        elif (mnemonic[i] == 'jr'):
            end_addr_list.append(address[i])
            if i+1 < len(mnemonic):    
                order_start_addr_list.append(address[i+1])
            for ij_addr in indirect_jumps:
                if int(ij_addr,16) == int(address[i], 16):
                    ij_taddr_str = '/'.join(indirect_jumps[ij_addr])
                    all_taken_target_addr.append(address[i] + ',' + ij_taddr_str)
            # branch_or_jump_target_addr.append('ffff'+' jr')
    
    # Sort the lists
    all_taken_target_addr = sorted(all_taken_target_addr, key=lambda x: int(x.split(',')[0], 16))
    order_start_addr_list = sorted(list(set(order_start_addr_list)),key=lambda x: int(x, 16))
    end_addr_list = sorted(list(set(end_addr_list)),key=lambda x: int(x, 16))
    
    return end_addr_list, branch_or_jump_target_addr, branch_taken_start_addr, \
        all_taken_target_addr, order_start_addr_list

import pdb
class BasicBlock:
    def __init__(self, name, func, start, end, length, taken_target, not_taken_target, \
        start_instr, end_instr, taken_target_instr, not_taken_target_instr, instr):
        self.name = name
        self.func = func
        self.start = start
        self.end = end
        self.length = length
        self.taken_target = taken_target
        self.not_taken_target = not_taken_target
        self.start_instr = start_instr
        self.end_instr = end_instr
        self.taken_target_instr = taken_target_instr
        self.not_taken_target_instr = not_taken_target_instr
        self.instr = instr    

def calculate_block_length(start_addr, end_addr, used_function_instr):
    start_line = get_line_number(start_addr, used_function_instr)
    end_line = get_line_number(end_addr, used_function_instr)
    # if not isinstance(start_line, int) or not isinstance(end_line, int):
    #     pdb.set_trace()  # 如果条件满足，暂停执行
    if start_line is None:
        raise ValueError(f"Start address {start_addr} not found in used_function_instr.")
    if end_line is None:
        raise ValueError(f"End address {end_addr} not found in used_function_instr.")
    block_length = end_line - start_line + 1
    return block_length

def get_line_number(addr, used_function_instr):
    addr_for_get_line = str(hex(int(addr, 16)).lstrip('0x')) or '0'
    for i, instr in enumerate(used_function_instr):
        if instr.startswith(addr_for_get_line + ":"):
            return i

        
def create_basic_blocks_in_order(order_start_addr_list, end_addr_list, used_function_instr, function_addr_ranges,\
                                ret_instr_addr, return_target, indirect_jumps):
    '''
    Create basic blocks in order based on the provided address information.

    Args:
        order_start_addr_list (list): List of start addresses for basic blocks in order.
        end_addr_list (list): List of end addresses for basic blocks.
        used_function_instr (list): List of used function instructions.
        function_addr_ranges (dict): Dictionary mapping function names to their address ranges.
        ret_instr_addr (dict): Dictionary mapping function names to their return instruction addresses.
        return_target (dict): Dictionary mapping function names to their return targets.

    Returns:
        list: List of created basic blocks.

    '''
    # Initialize a list to store the basic blocks
    basic_block = []
    # Create a BasicBlock object for each start address
    for i in range(len(order_start_addr_list)):
        basic_block.append(BasicBlock(0, '', 0, 0, 0, '', '', '', '', '', '', ''))
    
    # Populate the basic block objects with information
    for i in range(len(order_start_addr_list)):
        basic_block[i].name = i
        basic_block[i].start = order_start_addr_list[i]
        basic_block[i].end = end_addr_list[i]
        basic_block[i].length = calculate_block_length(basic_block[i].start, basic_block[i].end, used_function_instr)
        
        # Get the function name for each basic block
        func_name_l = [key for key ,addr in function_addr_ranges.items() if \
                        int(basic_block[i].start,16) >= int(addr[0],16) and int(basic_block[i].start,16) <= int(addr[1],16)]
        func_name = func_name_l[0]
        basic_block[i].func = func_name
        
        # Find the start and end instructions for each basic block 
        block_instr_list = []
        for line in used_function_instr:
            if int(order_start_addr_list[i],16) == int(line[:line.index(':')],16):
                basic_block[i].start_instr = line
            if int(order_start_addr_list[i],16) <= int(line[:line.index(':')],16) <= int(end_addr_list[i],16):
                block_instr_list.append(line)
            if int(end_addr_list[i],16) == int(line[:line.index(':')],16):
                basic_block[i].end_instr = line
                break
        basic_block[i].instr = block_instr_list
        
        # Determine the taken and not-taken targets for each basic block      
        tokens = basic_block[i].end_instr.split()
        if len(tokens) == 3:    
            instr_addr = tokens[0][:-1]
            mnemonic = tokens[2]
            operands = ''
        else:
            instr_addr = tokens[0][:-1]
            mnemonic = tokens[2]
            operands = tokens[3]
        
        if mnemonic in branch_inst:
            operand = operands.split(',')
            basic_block[i].taken_target = operand[-1]
            
        elif mnemonic in unconditional_jump_inst:
            if ',' in operands:
                operand = operands.split(',')
                basic_block[i].taken_target = operand[-1]
            elif ',' not in operands:
                operand = operands.split()
                basic_block[i].taken_target = operand[-1]
       
        # Deal with indirect jump's target
        elif mnemonic in indirect_jump_inst:
            if instr_addr in indirect_jumps.keys():
                if not any('' in v for v in indirect_jumps.values()):
                    for ij_addr in indirect_jumps:
                        if int(ij_addr,16) == int(basic_block[i].end, 16):
                            ij_taddr_set = set(indirect_jumps[ij_addr])
                            ij_taddr_str = ','.join(ij_taddr_set)
            else: 
                ij_taddr_str = 'register: ' + operands

            basic_block[i].taken_target = ij_taddr_str
            # basic_block[i].taken_target = 'register: ' + operands + ": " + ij_taddr_str
            # basic_block[i].taken_target = 'FFFF'
            # basic_block[i].taken_target_instr = 'FFFFFFFF'

        
        # Deal with 'ret' target
        elif mnemonic == 'ret':
            for func, addresses in ret_instr_addr.items():
                for ret_addr in addresses:
                    if int(basic_block[i].end,16) == int(ret_addr,16):
                        if func in return_target.keys():
                            basic_block[i].taken_target = return_target[func]
                            break
                        else:
                            if ret_addr in indirect_jumps.keys():
                                basic_block[i].taken_target = indirect_jumps[ret_addr] 
                    else:
                        continue
            
        
        #branch not taken target            
        if i+1 < len(order_start_addr_list) and mnemonic in branch_inst:
            basic_block[i].not_taken_target = order_start_addr_list[i+1]
    
        # Find the taken target and not taken target instructions
        for line in used_function_instr:
            if ',' in basic_block[i].taken_target:
                bb_ij_taddrs = basic_block[i].taken_target.split(',')
                for bb_ij_taddr in bb_ij_taddrs:  
                    if bb_ij_taddr == line[:line.index(':')]:
                        basic_block[i].taken_target_instr = line
            elif "," not in basic_block[i].taken_target:
                if basic_block[i].taken_target == line[:line.index(':')]:
                    basic_block[i].taken_target_instr = line                
                    
            # if basic_block[i].taken_target == line[:line.index(':')]:
            #     basic_block[i].taken_target_instr = line
            if mnemonic in branch_inst and basic_block[i].not_taken_target == line[:line.index(':')]:
                basic_block[i].not_taken_target_instr = line    
                
    return basic_block    

def blocks_creation_with_taken_target(target_addr, basic_block, order_start_addr_list, used_function_instr):
    # Check if target address is not already in order_start_addr_list
    if target_addr not in order_start_addr_list:
        # Check if a basic block with the same start address exists
        existing_bb_with_start = next((bb for bb in basic_block if bb.start == target_addr), None)
        
        if existing_bb_with_start:
            in_bb = next((bb for bb in basic_block if int(bb.start,16) <= int(target_addr,16) <= int(bb.end,16)), None)
            # Update the existing basic block's end address
            existing_bb_with_start.end = in_bb.end
            existing_bb_with_start.length = calculate_block_length(existing_bb_with_start.start, existing_bb_with_start.end, used_function_instr)
        else:
            # Find the basic block that contains the target address
            for bb in basic_block:
                if int(bb.start,16) <= int(target_addr,16) <= int(bb.end,16):
                    # Create a new basic block with the target address as start and bb.end as end
                    new_bb_name = str(len(basic_block)) + ' start_with_taken_target'
                    new_bb_start = str(hex(int(target_addr,16)).lstrip("0x"))#target_addr
                    new_bb_end = bb.end
                    new_bb_length = calculate_block_length(new_bb_start, new_bb_end, used_function_instr)
                    new_bb_func = bb.func
                    block_instr_list = []
                    for instr in used_function_instr:
                        if int(new_bb_start,16) == int(instr[:instr.index(':')],16):
                            new_bb_start_instr = instr
                        if int(new_bb_start,16) <= int(instr[:instr.index(':')],16) <= int(new_bb_end,16):
                            block_instr_list.append(instr)
                        if int(new_bb_end,16) == int(instr[:instr.index(':')],16):
                            new_bb_end_instr = instr
                        if int(new_bb_end,16) == int(bb.end,16):
                            new_bb_taken_target = bb.taken_target
                            new_bb_not_taken_target = bb.not_taken_target
                            new_bb_taken_target_instr = bb.taken_target_instr
                            new_bb_not_taken_target_instr = bb.not_taken_target_instr

                    new_bb_instr = block_instr_list

                    new_bb = BasicBlock(new_bb_name, new_bb_func, new_bb_start, new_bb_end,\
                        new_bb_length, new_bb_taken_target, new_bb_not_taken_target, new_bb_start_instr, \
                            new_bb_end_instr, new_bb_taken_target_instr, new_bb_not_taken_target_instr, new_bb_instr)
                    basic_block.append(new_bb)
                    break
    return basic_block


def create_basic_blocks_start_with_taken_target(all_taken_target_addr, basic_block, order_start_addr_list, used_function_instr):
    '''
    The create_basic_blocks_start_with_taken_target function takes in several parameters including a list of all taken target addresses, \
        a list of existing basic blocks, a list of starting addresses, and a list of used function instructions. 
    The function creates new basic blocks that start with a taken target address and adds them to the existing list of basic blocks. 
    The function returns the updated list of basic blocks.
    '''
    
    # Iterate through all_taken_target_addr to handle new basic block creation
    for addr_pair in all_taken_target_addr:
        jump_addr, target_addr = addr_pair.split(",")
        if '/' in target_addr:
            target_addrs = list(set(target_addr.split('/')))
            
            for target_addr in target_addrs:
                basic_block = blocks_creation_with_taken_target(target_addr, basic_block, order_start_addr_list, used_function_instr)
        else:
            basic_block = blocks_creation_with_taken_target(target_addr, basic_block, order_start_addr_list, used_function_instr)
        
    return basic_block


def sort_basic_blocks(basic_block):
    sorted_basic_blocks = sorted(basic_block, key=lambda bb: int(bb.start, 16))
    print("basic blocks' num: "+str(len(sorted_basic_blocks)))
    return sorted_basic_blocks

def remove_duplicates(exec_bb):
    i = 0
    while i < len(exec_bb):
        count = 1
        j = i + 1
        while j < len(exec_bb) and exec_bb[j] == exec_bb[i]:
            count += 1
            j += 1
        if count >= 2:
            del exec_bb[i+1:j]
        else:
            i += 1
    return exec_bb


                

def write_basic_blocks_to_file(file_name, basic_block, output_directory):
    basic_block_path = os.path.join(output_directory, file_name)
    with open(basic_block_path, 'w', encoding='utf-8') as file:
        for bb in basic_block:
            file.write(f'Basic_block Name: {bb.name}\n')
            file.write(f'In Function:      {bb.func}\n')
            file.write(f'Start address:    {bb.start}\n')
            file.write(f'End address:      {bb.end}\n')
            file.write(f'Start instruction: \n\t{bb.start_instr.strip()}\n')
            file.write(f'End instruction: \n\t{bb.end_instr.strip()}\n')
            file.write(f'Length:           {bb.length}\n')
            file.write(f'Taken_Target address:       {bb.taken_target}\n')
            file.write(f'Taken_Target instruction: \n\t{bb.taken_target_instr.strip()}\n')
            file.write(f'Not_Taken_Target address:   {bb.not_taken_target}\n')
            file.write(f'Not_Taken_Target instruction: \n\t{bb.not_taken_target_instr.strip()}\n')
            file.write('Instruction: '+'\n')
            for line in bb.instr:
                file.write(f'\t{line.strip()}\n')
            file.write('\n\n')

from collections import deque

def generate_CFG(basic_block, program_name, output_directory):
    # Create a new Graphviz graph
    graph1 = graphviz.Digraph(format='svg', graph_attr={'rankdir': 'TB'})
    
    # Create a mapping of basic block names to their respective nodes
    bb_nodes = {}
    bb_start_to_name = {}
    adjacency_blocks = {}

    # Add nodes to the graph
    for bb in basic_block:
        
        label = f'Basic_block Name: {bb.name}\nIn Function: {bb.func}\nStart address: {bb.start}\nEnd address: {bb.end}\nLength: {bb.length}\nTaken_Target: {bb.taken_target}'
        if bb.not_taken_target is not None:
            label += f'\nNot_Taken_Target address: {bb.not_taken_target}'

        node_name = str(bb.name)
        graph1.node(node_name, label=label, shape='box')
        bb_nodes[bb.name] = node_name 
        bb_start_to_name[bb.start] = node_name
        adjacency_blocks[node_name] = {}
        
    # edge counter
    edge_counter = 0
    # Function to add edges to the graph
    def add_edge(source, target, edge_type, style=None, color=None):
        nonlocal edge_counter
        if source in bb_nodes and target in bb_start_to_name:
            graph1.edge(bb_nodes[source], bb_start_to_name[target], style=style, color=color)
            edge_counter += 1
            # adjacency_blocks[bb_nodes[source]].append((bb_start_to_name[target], edge_type))
            adjacency_blocks[bb_nodes[source]][bb_start_to_name[target]] = edge_type
    # Add edges to the graph
    for i, bb in enumerate(basic_block):
        if bb.taken_target != '':
            if isinstance(bb.taken_target, list):
                for target_str in bb.taken_target:
                    target = target_str.split()[-1]
                    edge_type = 'R' if 'ret' in bb.end_instr else 'T'
                    add_edge(bb.name, target, edge_type)
            else:
                edge_type = 'R' if 'ret' in bb.end_instr else 'T'
                add_edge(bb.name, bb.taken_target, edge_type)

        elif not bb.taken_target and i+1 < len(basic_block) and 'ret' not in bb.end_instr:
            next_bb = basic_block[i+1]
            add_edge(bb.name, next_bb.start, 'NT')
            edge_counter += 1

        if bb.not_taken_target != '':
            add_edge(bb.name, bb.not_taken_target, 'NT', style='dashed', color='red')
    
    # Analyze nodes' levels
    bb_levels = {node: {} for node in bb_nodes.values()}
    bb_predecessors = {node: {} for node in bb_nodes.values()}
    

    # Create a queue for BFS
    queue = deque()
    
    # Find all nodes without incoming edges and add them to the queue
    entry_nodes = [node for node in bb_nodes.values() if not any(node in adjacency_blocks[other_node] for other_node in bb_nodes.values())]
    for i, node in enumerate(entry_nodes):
        path = f'path{i}'
        bb_levels[node][path] = 0
        queue.append((node, path))
        
    path_nodes = {f'path{i}': [node] for i, node in enumerate(entry_nodes)}
    
    while queue:
        node, path = queue.popleft()
        if adjacency_blocks[node]:
            for successor in adjacency_blocks[node].keys():
                if path not in bb_levels[successor]:
                    bb_levels[successor][path] = bb_levels[node][path] + 1
                    bb_predecessors[successor][path] = node
                    queue.append((successor, path))
                    edge_type = adjacency_blocks[node][successor]
                    parent_node = bb_predecessors[successor][path] 
                    
                    # path_nodes: successor, edge_type, parent_node, level
                    # if edge_type is None:
                    #     path_nodes[path].append(successor + ',' + 'None' + ',' + parent_node + ',' + str(bb_levels[successor][path]))
                    # else:
                    path_nodes[path].append(successor + ',' + str(edge_type)+ ',' + parent_node + ',' + str(bb_levels[successor][path]))
    
    
    # # Initialize the maximum number of parents and children
    # max_parents = 0
    # max_children = 0

    # # Iterate over the adjacency_blocks dictionary
    # for node, children in adjacency_blocks.items():
    #     # Count the number of parents
    #     num_parents = sum(node in adjacency_blocks[other_node] for other_node in bb_nodes.values())
    #     # Count the number of children
    #     num_children = len(children)
    #     # Update the maximum number of parents and children
    #     max_parents = max(max_parents, num_parents)
    #     max_children = max(max_children, num_children)
    
    # # Calculate the number of basic blocks
    # num_basic_blocks = len(bb_nodes)

    # # Calculate the maximum number of parents, children, and logN
    # max_value = max(max_parents, max_children, math.log(num_basic_blocks))

    # # Calculate the number of bits for the Hamming code
    # num_bits = math.ceil(max_value) + 1
    
    def hamming_distance(x, y):
        return bin(x ^ y).count('1')
    
    def generate_hamming_distance_codes(num_bits, min_hamming_distance):
        """ Generate binary codes with given bits ensuring minimum Hamming distance. """
        max_code = 2 ** num_bits
        codes = []
        
        for i in range(max_code):
            if all(hamming_distance(i, code) >= min_hamming_distance for code in codes):
                codes.append(i)
        
        return codes
    
    # Function to assign binary codes to basic blocks based on their levels
    def level_nodes_analyze(path_nodes):
        level_nodes = {}
        max_level = 0
        max_nodes_in_same_level = 0
        
        for path, nodes in path_nodes.items():
            for node_info in nodes:
                if ',' not in node_info:
                    node = node_info
                    if 0 not in level_nodes:
                        level_nodes[0] = []
                    if node not in level_nodes[0]:
                        level_nodes[0].append(node)
                else:
                    node, edge_type, parent, level = node_info.split(',')
                    level = int(level)
                    max_level = max(max_level, level)
                    if level not in level_nodes:
                        level_nodes[level] = []
                    if node not in level_nodes[level]:
                        level_nodes[level].append(node)
        
        for level, nodes in level_nodes.items():
            max_nodes_in_same_level = max(max_nodes_in_same_level, len(nodes))        
            
        return level_nodes, max_level, max_nodes_in_same_level
    
    level_nodes, max_level, max_nodes_in_same_level = level_nodes_analyze(path_nodes)
        
        # num_bits = math.ceil(math.log2(len(path_nodes))) + 1  # Extra bit for self-loop
        # level_codes = {}
        
        #  # Assign codes to each level ensuring the Hamming distance
        # for level in range(max_level + 1):
        #     same_level_codes = generate_hamming_distance_codes(num_bits, min_same_level_distance)
        #     level_codes[level] = same_level_codes[:len(level_nodes[level])]
        #     if level > 0:
        #         previous_level_codes = level_codes[level - 1]
        #         for code in level_codes[level]:
        #             if not any(hamming_distance(code, prev_code) == min_adjacent_level_distance for prev_code in previous_level_codes):
        #             # if all(any(hamming_distance(code, prev_code) == min_adjacent_level_distance for prev_code in previous_level_codes)):
        #                 continue
        #             else:
        #                 raise ValueError("Cannot satisfy Hamming distance requirement between levels.")
        
        # node_codes = {}
        # for level, nodes in level_nodes.items():
        #     for i, node in enumerate(nodes):
        #         node_codes[node] = level_codes[level][i]
        
        # return node_codes

    
    # # Call the functions to generate binary codes
    # min_same_level_distance = 2
    # min_adjacent_level_distance = 1
    
    # node_codes = assign_binary_codes(path_nodes, min_same_level_distance, min_adjacent_level_distance)

    # # Add flag bit for self-loop if necessary
    # for node, code in node_codes.items():
    #     if node in adjacency_blocks and node in adjacency_blocks[node]:
    #         node_codes[node] = (1 << num_bits) | code
        
    
    # Set the output file path
    output_file = os.path.join(output_directory, f'{program_name}_CFG')

    # Render the graph and save it to a file
    graph1.render(filename=output_file, cleanup=True, view=False)  
    
    return edge_counter, adjacency_blocks



def convert_to_binary(basic_block, output_file_name, Hash_algorithm, value_length, output_directory):
    '''
    The convert_to_binary function takes in a list of basic blocks and an output file name. 
    The function converts the machine code instructions in each basic block to binary format and writes the binary instructions \
        and a hash value to the output file.
    '''
    binary_file_path = os.path.join(output_directory, output_file_name)
    
    with open (binary_file_path,'w',encoding='utf-8') as file:
        for i in range (len(basic_block)):
            bb_instr = basic_block[i].instr
            address, machine_code, mnemonic, operands =  get_func_machine_code(bb_instr)
        
            # Get binary_machine_code    
            binary_machine_code = []
            for j in range (len(machine_code)):
                int_machine_code = int(machine_code[j], 16)
                bin_machine_code = bin(int_machine_code)[2:].zfill(32)
                binary_machine_code.append(bin_machine_code)

            # Get binary_address
            binary_address = []
            for m in range (len(address)):
                int_address = int(address[m], 16)
                bin_address = bin(int_address)[2:].zfill(16)
                binary_address.append(bin_address)
            
            # Get hash value
            hash_value = calculate_hash_value(binary_machine_code, Hash_algorithm, value_length)

            # Write to file
            file.write(f'Basic_block: {basic_block[i].name}\n')
            file.write(f'bin_basic_block_instructions: \n')
            
            for i in range(len(binary_address)):
                file.write(f'\t{binary_address[i]}: {binary_machine_code[i]}\n')

            file.write(f'hash_value: \n\t{hash_value}\n')
            file.write('\n')

def convert_to_hex(basic_block, output_file, Hash_algorithm, value_length, output_directory):
    '''
    The convert_to_hex function takes in a list of basic blocks and an output file name. 
    The function converts the machine code instructions in each basic block to hexadecimal format and\
        writes the hexadecimal instructions and a hash value to the output file.
    '''
    hex_file_path = os.path.join(output_directory, output_file)
    
    with open(hex_file_path,'w',encoding='utf-8') as file:
        for i in range (len(basic_block)):
            bb_instr = basic_block[i].instr
            address, machine_code, mnemonic, operands =  get_func_machine_code(bb_instr)
            
            # Get binary_machine_code    
            binary_machine_code = []
            for j in range (len(machine_code)):
                int_machine_code = int(machine_code[j], 16)
                bin_machine_code = bin(int_machine_code)[2:]
                binary_machine_code.append(bin_machine_code)
        
            # Get hash value
            hash_value = calculate_hash_value(binary_machine_code, Hash_algorithm, value_length)

            # Write to file
            file.write(f'Basic_block: {basic_block[i].name}\n')
            file.write(f'bin_basic_block_instructions: \n')
            
            for i in range(len(address)):
                file.write(f'\t{address[i]}: {machine_code[i]}\n')

            file.write(f'hash_value: \n\t{hash_value}\n')
            file.write('\n')


from PHOTON80 import Photon_80_20_16
def calculate_hash_value(data, algorithm, value_length):
    binary_data = ''.join(data)
    binary_data = binary_data.encode('utf-8')

    # Create hash object based on selected algorithm
    if algorithm == 'SHA-256':
        hash_type = hashlib.sha256()
    elif algorithm == 'MD5':
        hash_type = hashlib.md5()
    elif algorithm == 'SHA-1':
        hash_type = hashlib.sha1()
    elif algorithm == 'SHA-512':
        hash_type = hashlib.sha512()
    elif algorithm == 'PHOTON80':
        hash_value = Photon_80_20_16(data, value_length)
    # Custom hash algorithm
    # elif algorithm == " ":
    #     hash_type = xxx.xxx()

    # Calculate hash value
    if algorithm != 'PHOTON80':
        hash_type.update(binary_data)

        # Get hexdigest of hash value
        hash_value = hash_type.hexdigest()
        
    # Get the hash value of the specified number of digits
    hash_value_spl = hash_value[:int(value_length)]

    return hash_value_spl

def export_results(function_addr_ranges, function_information_file,\
                    all_instr, functions_with_jump_instr_addr, control_transfer_file,bin_file,\
                        basicblock_file_name, basic_block,\
                        block_binary_file_name, hex_file_name, Hash_algorithm, value_length, output_directory, program_name):
    
    # write_functions_information(function_addr_ranges, function_information_file, output_directory)
    
    write_in_may_used_control_transfer_instr(all_instr, functions_with_jump_instr_addr, control_transfer_file, \
                                            bin_file, output_directory, program_name)
    
    write_basic_blocks_to_file(basicblock_file_name, basic_block, output_directory)
    
    convert_to_binary(basic_block, block_binary_file_name, Hash_algorithm, value_length, output_directory)
    
    convert_to_hex(basic_block, hex_file_name, Hash_algorithm, value_length, output_directory)
 
# main(objdump_file)  
 
## UI

def judge_file_type(input_file_path):
    type = None
    with open(input_file_path, 'r') as file:
        lines = file.readlines()
        for line in lines[:15]:
            if line.startswith('#'):
                type = 1
    return type

class CFIEE_UI:
    def __init__(self, master):

        self.master = master
        master.title("CFIEE_Enhanced_version")
        # master.geometry("800x600") 
        master.configure(bg="white")
        
        # Custom style for Notebook
        self.style = ttk.Style()
        self.style.configure("Custom.TNotebook", borderwidth=5,padding=[5, 2],tabmargins=[2, 5, 2, 0])
        self.style.configure("Custom.TNotebook.Tab", padding=[10, 5], background="white", font=("Arial", "12", "bold"))
                
        self.notebook = ttk.Notebook(master, style="Custom.TNotebook")
        self.notebook.pack(fill='both', expand=True)
        
        self.page1 = ttk.Frame(self.notebook)
        self.notebook.add(self.page1, text='QEMU Execution')
        self.create_qemu_content()
        
        self.page2 = ttk.Frame(self.notebook)
        self.notebook.add(self.page2, text='Control Flow Analysis')
        self.create_page2_content()

    def create_qemu_content(self):
        #Execution Frame
        execution_frame = tk.Frame(self.page1)
        # execution_frame.grid(row=1, column=1, padx=30, pady=30, sticky="nw")
        execution_frame.pack(side=tk.TOP, anchor="n", padx=30, pady=60)
        
        # Create file selection button
        elf_file_select_button = tk.Button(execution_frame, text="Select ELF File", command=self.select_elf_file_for_qemu,font=("Arial", 14, "bold"), bg="lightgray",\
                                                    padx=20, pady=20, bd=1, relief="raised")
        elf_file_select_button.pack(side=tk.TOP, padx=10, anchor="n")
        self.qemu_elf_file_path_var= tk.StringVar()
        self.qemu_elf_file_path_label = tk.Label(execution_frame, textvariable=self.qemu_elf_file_path_var, wraplength=150, anchor="n", bg="white", bd=1,\
                                            relief="groove", padx=40, font=("Arial", 12))
        self.qemu_elf_file_path_label.pack(side=tk.TOP, fill=tk.X, anchor="n", padx=10, pady=20)
        
        self.qemu_elf_select_label = tk.Label(execution_frame, wraplength=200, anchor="n", font=("Arial", 10), justify=tk.LEFT)
        self.qemu_elf_select_label.pack(side=tk.TOP, anchor="n", pady=5)
        
        # Create QEMU execution button
        self.qemu_execution_button = tk.Button(execution_frame, text="QEMU Execution", command=self.qemu_execution,font=("Arial", 14, "bold"), bg="lightgray",\
                                                    padx=20, pady=20, bd=1, relief="raised", state=tk.DISABLED)
        self.qemu_execution_button.pack(side=tk.TOP, padx=10, anchor="n")
                
    def create_page2_content(self):       
        # Column 1: Select .elf file and Disassemble
        elf_file_frame = tk.Frame(self.page2)
        elf_file_frame.grid(row=0, column=0, padx=30, pady=30, sticky="nw")
        elf_file_label = tk.Label(elf_file_frame, text="STEP1: Disassemble ELF File", font=("Arial", 10, "bold"))
        elf_file_label.pack(side=tk.TOP, anchor="n", pady=20)

        # File Selection Row
        file_select_frame = tk.Frame(elf_file_frame)
        file_select_frame.pack(side=tk.TOP, anchor="n")
        self.elf_file_select_button = tk.Button(file_select_frame, text="Select ELF file", command=self.select_elf_file_to_disassemble, padx=10, pady=5, bd=1, relief="raised")
        self.elf_file_select_button.pack(side=tk.TOP, padx=10, anchor="n")
        self.elf_file_path_var = tk.StringVar()
        self.elf_file_path_label = tk.Label(file_select_frame, textvariable=self.elf_file_path_var, wraplength=150, anchor="w", bg="white", bd=1,\
                                            relief="groove", padx=5)
        self.elf_file_path_label.pack(side=tk.TOP, fill=tk.X, anchor="n", padx=10, pady=20)


        # Disassemble Row
        disassemble_frame = tk.Frame(elf_file_frame)
        disassemble_frame.pack(side=tk.TOP, anchor="n", pady=10)
        self.disassemble_button = tk.Button(disassemble_frame, text="Disassemble", command=self.disassemble_program, font=("Arial", 10, "bold"), bg="lightgray",\
                                                    padx=10, pady=5, bd=1, relief="raised", state=tk.DISABLED)
        self.disassemble_button.pack(side=tk.TOP, anchor="n")
        self.disassemble_label = tk.Label(disassemble_frame, wraplength=200, anchor="w", font=("Arial", 10), justify=tk.LEFT)
        self.disassemble_label.pack(side=tk.TOP, padx=10, fill=tk.X, expand=True)

        # Browse file section
        browse_frame = tk.Frame(elf_file_frame)
        browse_frame.pack(side=tk.TOP, anchor="n", padx=10, pady=10)

        self.browse_section_label = tk.Label(browse_frame, text="STEP2: Select disassembly file(.txt)", font=("Arial", 10, "bold"))
        self.browse_section_label.pack(side=tk.TOP, anchor="n", pady=10)

        self.browse_button = tk.Button(browse_frame, text="Browse File", command=self.browse_file, padx=10, pady=5, bd=1, relief="raised")
        self.browse_button.pack(side=tk.TOP, anchor="n", padx=10, pady=10)

        self.file_path_var = tk.StringVar()
        self.file_path_label = tk.Label(browse_frame, textvariable=self.file_path_var, wraplength=150, anchor="w", bg="white", bd=1, relief="groove", padx=5)
        self.file_path_label.pack(side=tk.TOP, fill=tk.X, anchor="n", padx=10, pady=10)

        self.browse_label = tk.Label(browse_frame, wraplength=200, anchor="w", font=("Arial", 8), justify=tk.LEFT)
        self.browse_label.pack(side=tk.TOP, anchor="n", pady=5)

        # Column 2: Preprocess, Analyze, Hash algorithm selection, and Data length selection
        section2_frame = tk.Frame(self.page2)
        section2_frame.grid(row=0, column=2, padx=20, pady=30, sticky="nw")
        # Preprocess section
        preprocess_frame = tk.Frame(section2_frame)
        preprocess_frame.pack(side=tk.TOP, anchor="n", padx=10, pady=10)

        self.preprocess_section_label = tk.Label(preprocess_frame, text="STEP3: Data Preprocess", font=("Arial", 10, "bold"))
        self.preprocess_section_label.pack(side=tk.TOP, anchor="n", padx= 10, pady=10)

        self.preprocess_button = tk.Button(preprocess_frame, text="Preprocess", command=self.rewrite_file, state=tk.DISABLED, bg="lightgray", \
                                                    padx=10, pady=5, bd=1, relief="raised")
        self.preprocess_button.pack(side=tk.TOP, padx=10, pady=10, anchor="n")

        self.rewrite_label = tk.Label(preprocess_frame, wraplength=200, anchor="center", font=("Arial", 8), justify=tk.CENTER)
        self.rewrite_label.pack(side=tk.TOP, fill=tk.X, pady=5)

        self.rewrite_file_path_var = tk.StringVar()

        # Analyze section
        analyze_frame = tk.Frame(section2_frame)
        analyze_frame.pack(side=tk.TOP, anchor='n', padx=10, pady=10)

        self.analyze_section_label = tk.Label(analyze_frame, text="STEP4: File Analyze", font=("Arial", 10, "bold"))
        self.analyze_section_label.pack(side=tk.TOP, anchor="n", pady=10)

        self.analyze_label = tk.Label(analyze_frame, wraplength=200, anchor="center", font=("Arial", 8), justify=tk.CENTER)
        self.analyze_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

        hash_algorithm_frame = tk.Frame(analyze_frame)
        hash_algorithm_frame.pack(side=tk.TOP, anchor="w", padx=10, pady=5)
        
        hash_algorithm_label = tk.Label(hash_algorithm_frame, text="Hash:", font=("Arial", 10))
        hash_algorithm_label.pack(side=tk.LEFT, anchor="w",padx=10,pady = 5)

        self.hash_algorithm_var = tk.StringVar()
        hash_algorithm_options = ["MD5", "SHA-1", "SHA-256", "SHA-512", "PHOTON80"]
        self.hash_algorithm_menu = tk.OptionMenu(hash_algorithm_frame, self.hash_algorithm_var, *hash_algorithm_options)
        self.hash_algorithm_menu.pack(side=tk.LEFT, anchor="w", padx = 10, pady = 5)

        data_length_frame = tk.Frame(analyze_frame)
        data_length_frame.pack(side=tk.TOP, anchor="w", padx=10, pady=5)
        
        data_length_label = tk.Label(data_length_frame, text="Data Length:", font=("Arial", 10))
        data_length_label.pack(side=tk.LEFT, anchor="w", padx=10, pady=5)

        self.data_length_var = tk.StringVar()
        data_length_options = ["8", "16", "32", "Custom"]
        self.data_length_menu = tk.OptionMenu(data_length_frame, self.data_length_var, *data_length_options)
        self.data_length_menu.pack(side=tk.LEFT, anchor="w", padx=10, pady=5)
        
        custom_length_frame = tk.Frame(analyze_frame)
        custom_length_frame.pack(side=tk.TOP, anchor="w", padx=10, pady=5)
        
        custom_length_label = tk.Label(custom_length_frame, text="Custom Length:", font=("Arial", 10))
        custom_length_label.pack(side=tk.LEFT, anchor="w", padx=10, pady=5)

        self.custom_length_var = tk.StringVar()
        custom_length_entry = tk.Entry(custom_length_frame, textvariable=self.custom_length_var)
        custom_length_entry.pack(side=tk.LEFT, anchor="w", padx=10, pady=5)
        # custom_length_entry.config(state=tk.DISABLED)
        
        self.analyze_button = tk.Button(analyze_frame, text="Analyze", command=self.analyze_program, state=tk.DISABLED, bg="lightgray", \
                                            padx=10, pady=5, bd=1, relief="raised")
        self.analyze_button.pack(side=tk.TOP, padx=10, pady=20, anchor="n")
        
        # Progress bar 
        self.progress_bar = ttk.Progressbar(analyze_frame, length=270, mode='determinate', orient=tk.HORIZONTAL)
        self.progress_bar.pack(side=tk.TOP, anchor="n", padx=10, pady=20)
        # self.progress_bar.grid(row=1, column=2, padx=10, pady=20, columnspan=1, sticky="n")
        
        # Column 3: Result output
        section3_frame = tk.Frame(self.page2)
        section3_frame.grid(row=0, column=4, padx=10, pady=120, sticky="nw")

        self.output_section_label = tk.Label(section3_frame, text="STEP5: Output Files", font=("Arial", 10, "bold"))
        self.output_section_label.pack(side=tk.TOP, anchor="n", pady=20)

        left_frame = tk.Frame(section3_frame)
        left_frame.pack(side=tk.LEFT, padx=10)

        right_frame = tk.Frame(section3_frame)
        right_frame.pack(side=tk.LEFT, padx=30)
        
        button_width = 15

        basic_block_info_button = tk.Button(left_frame, text="Basic Block Info", command=self.show_basic_block_info, width=button_width)
        basic_block_info_button.pack(side=tk.TOP, pady=15)
        
        bin_bb_button = tk.Button(left_frame, text="Binary Basic Block", command=self.show_bin_bb, width=button_width)
        bin_bb_button.pack(side=tk.TOP, pady=15)

        hex_bb_button = tk.Button(left_frame, text="Hex Basic Block", command=self.show_hex_bb, width=button_width)
        hex_bb_button.pack(side=tk.TOP, pady=15)

        binary_data_button = tk.Button(left_frame, text="Binary Data", command=self.show_binary_data, width=button_width)
        binary_data_button.pack(side=tk.TOP, pady=15)

        transfers_info_button = tk.Button(right_frame, text="Transfers Info", command=self.show_transfers_info, width=button_width)
        transfers_info_button.pack(side=tk.TOP, pady=15)

        cfg_button = tk.Button(right_frame, text="CFG", command=self.show_cfg, width=button_width)
        cfg_button.pack(side=tk.TOP, pady=15)

        transfers_number_button = tk.Button(right_frame, text="Transfers Number", command=self.show_transfers_number, width=button_width)
        transfers_number_button.pack(side=tk.TOP, pady=15)

        function_call_button = tk.Button(right_frame, text="Function Call", command=self.show_function_call, width=button_width)
        function_call_button.pack(side=tk.TOP, pady=15)

        # Add padding between columns
        separator1 = ttk.Separator(self.page2, orient='vertical')
        separator1.grid(row=0, column=1, sticky="ns", padx=10, pady=30)

        separator2 = ttk.Separator(self.page2, orient='vertical')
        separator2.grid(row=0, column=3, sticky="ns", padx=10, pady=30) 

        # Help button
        self.help_button = tk.Button(elf_file_frame, text="Help", command=self.show_help, padx=10, pady=5, bd=1, relief="raised")
        self.help_button.pack(side=tk.TOP, anchor="n", padx=10, pady=10)
        #self.help_button.grid(row=1, column=0, padx=10, pady=20,columnspan=1, sticky="n")
        
        #Custom Label
        self.author_label = tk.Label(self.page2, text="Github @Taurus052", font=("Arial", 8))
        self.author_label.grid(row=1, column=2, padx=10, pady=10, sticky="n")
        
    def select_elf_file_for_qemu(self):
        current_directory = os.getcwd()
        parent_directory = os.path.dirname(current_directory)
        elf_files_directory = os.path.join(parent_directory, "elf_files")
        filetypes = [("ELF Files", "*.elf")]
        file_path = filedialog.askopenfilename(initialdir=elf_files_directory, filetypes=filetypes)
        if file_path:
            self.qemu_elf_file_path_var.set(file_path)
            self.qemu_execution_button.config(state=tk.NORMAL)
        
    def qemu_execution(self):
        qemu_elf_file = self.qemu_elf_file_path_var.get()
        if not qemu_elf_file:
            self.qemu_elf_select_label.config(text="No file selected")
            return
        try:
            output_directory = os.path.join(os.path.dirname(os.getcwd()), "qemu_output_logs")
            # exec_log_path = os.path.splitext(os.path.basename(qemu_elf_file))[0] + "_qemu_exec_log.txt"
            # in_asm_log_path = os.path.splitext(os.path.basename(qemu_elf_file))[0] + "_qemu_inasm_log.txt"
            output_file_path = os.path.splitext(os.path.basename(qemu_elf_file))[0] + "_qemu_log.txt"

            # Convert output file path to bytes with an appropriate encoding (e.g., utf-8)
            # exec_log_bytes = exec_log_path.encode('utf-8')
            # in_asm_log_bytes = in_asm_log_path.encode('utf-8')
            output_file_bytes = output_file_path.encode('utf-8')

            # Decode bytes back to string (for subprocess.run usage)
            # exec_file = os.path.join(output_directory, exec_log_bytes.decode('utf-8'))
            # in_asm_file = os.path.join(output_directory, in_asm_log_bytes.decode('utf-8'))
            output_file = os.path.join(output_directory, output_file_bytes.decode('utf-8'))
            
            if not os.path.exists(output_directory):
                os.makedirs(output_directory)
                
            # 如果log文件已存在，删除它
            if os.path.exists(output_file):
                os.remove(output_file)  
            
            command = f"qemu-system-riscv32 -nographic -machine smartl -cpu e906fdp -kernel {qemu_elf_file} -d nochain,exec,in_asm -D {output_file}"

            # process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # subprocess.Popen(['cmd.exe', '/k', f'{command}'])
            os.system(f'start cmd /K "{command}"')
            while True:
                time.sleep(1.5)
                if os.path.exists(output_file):
                    os.system('taskkill /f /im qemu-system-riscv32.exe')  # 终止 QEMU 进程
                    break
            self.qemu_elf_select_label.config(text="QEMU execution complete.")

        
        except subprocess.CalledProcessError as e:
            error_message = f"Error: {e.stderr}"
            self.show_error_message(error_message)

        
    def select_elf_file_to_disassemble(self):
        
        current_directory = os.getcwd()
        parent_directory = os.path.dirname(current_directory)
        elf_files_directory = os.path.join(parent_directory, "elf_files")

        filetypes = [("ELF Files", "*.elf")]
        file_path = filedialog.askopenfilename(initialdir=elf_files_directory, filetypes=filetypes)
        if file_path:
            self.elf_file_path_var.set(file_path)
            self.disassemble_button.config(state=tk.NORMAL)

    def disassemble_program(self):
        elf_file = self.elf_file_path_var.get()
        if not elf_file:
            self.disassemble_label.config(text="No file selected")
            return
        try:
            output_directory = os.path.join(os.path.dirname(os.getcwd()), "objdump_files")
            if not os.path.exists(output_directory):
                os.makedirs(output_directory)
            output_file = os.path.join(output_directory, os.path.splitext(os.path.basename(elf_file))[0] + "_disassembly.txt")
            process = subprocess.run(["riscv64-unknown-elf-objdump", "-d", elf_file], capture_output=True, text=True)
            with open(output_file, 'w') as file:
                file.write(process.stdout)
            self.disassemble_label.config(text="Disassembly complete.")
            
            self.file_path_var.set(output_file)
            
            self.preprocess_button.config(state=tk.NORMAL)
            self.analyze_button.config(state=tk.NORMAL)
            return output_file
        
        except subprocess.CalledProcessError as e:
            error_message = f"Error: {e.stderr}"
            self.show_error_message(error_message)

    def browse_file(self):
        
        current_directory = os.getcwd()
        parent_directory = os.path.dirname(current_directory)
        elf_files_directory = os.path.join(parent_directory, "objdump_files")

        filetypes = [("TXT Files", "*.txt")]
        objdump_file = filedialog.askopenfilename(initialdir=elf_files_directory, filetypes=filetypes)

        if not objdump_file:
            self.browse_label.config(text="No file selected")
            return

        self.file_path_var.set(objdump_file)
        self.browse_label.config(text="Objdump file selected")
        self.preprocess_button.config(state=tk.NORMAL)
        self.analyze_button.config(state=tk.NORMAL)
        
        type = judge_file_type(objdump_file)
        if type == 1:
            self.browse_label.config(
                text="\nPlease click the 'preprocess' button first")
        else:
            self.browse_label.config(
                text="\nYou can click the 'analyze' button now!")


    def rewrite_file(self):
        objdump_file = self.file_path_var.get()
        file_name = os.path.basename(objdump_file)
        file_directory = os.path.dirname(objdump_file)
        output_file = os.path.join(file_directory, os.path.splitext(file_name)[0] + '_preprocessed.txt')
        self.rewrite_file_path_var.set(output_file)
        self.master.update()
        
        self.progress_bar['value'] = 0 
        self.progress_bar.start()  # startup progress bar
        
        subprocess.run(['python', 'file_preprocess.py', objdump_file, output_file])
        
        self.master.after(100, lambda: self.rewrite_label.config(text="Objdump file has been rewrited!\n \
    File path: {0}\n".format(output_file)))
        
        self.progress_bar.stop()
        self.progress_bar['value'] = 100 
        self.master.update()


    def analyze_program(self):
        input_file = self.file_path_var.get()
        rewrite_file = self.rewrite_file_path_var.get()
        program_name = os.path.basename(input_file)

        # Extract program name
        if "_objdump" in program_name:
            program_name = program_name.split("_objdump")[0]
        elif "_disassembly" in program_name:
            program_name = program_name.split("_disassembly")[0]

        type = judge_file_type(input_file)
        if type == 1:
            self.analyze_label.config(
                text="Please click the 'preprocess' button first and rechoose the new file")
        else:
            t = threading.Thread(target=self.run_analyze_program, args=(input_file, rewrite_file, program_name))
            t.start()


    def run_analyze_program(self, input_file, rewrite_file, program_name):
        try:
            self.progress_bar['value'] = 0

            hash_algorithm = self.hash_algorithm_var.get()
            if hash_algorithm == "PHOTON80" and self.data_length_var.get() == "Custom":
                self.analyze_label.config(
                    text="Custom length is not available for PHOTON80")
                return
            
            if self.data_length_var.get() == "Custom":
                result_length = self.custom_length_var.get()
                if result_length == "":
                    self.analyze_label.config(
                        text="Please enter a custom length")
                    return
            else:
                result_length = self.data_length_var.get()

            if not hash_algorithm or not result_length:
                self.analyze_label.config(
                    text="Please select hash algorithm and result length")
                return

            file_to_analyze = rewrite_file if os.path.exists(
                rewrite_file) else input_file
            self.progress_bar.start()  # startup progress bar
            self.analyze_label.config(text="Analyzing...")

            # Execute analysis program
            main(file_to_analyze, hash_algorithm, result_length, program_name)

            self.progress_bar.stop()
            self.progress_bar['value'] = 100

            self.analyze_label.config(text="Complete!")
                    
        except Exception as e:
            error_message = f"错误: {e}\n{traceback.format_exc()}"
            self.show_error_message(error_message)
        
    def show_help(self):
        try:
            # Open .md files with the default application associated with the system
            readme_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Readme.md'))
            subprocess.Popen(['start', '', readme_path], shell=True)
        except FileNotFoundError:
            print("Unable to find a default application to open the .md file.")

    def show_basic_block_info(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        lastest_modification_time = 0
        bb_info_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("basic_block.txt"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > lastest_modification_time:
                    lastest_modification_time = file_modification_time
                    bb_info_file_path = file_path
        
        if bb_info_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:
            try:
                os.startfile(bb_info_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_binary_data(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        lastest_modification_time = 0
        bin_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith(".bin"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > lastest_modification_time:
                    lastest_modification_time = file_modification_time
                    bin_file_path = file_path
            
        if bin_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:
            try:
                subprocess.Popen(["notepad.exe", bin_file_path])
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_transfers_info(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        lastest_modification_time = 0
        transfers_info_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("transfers.txt"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > lastest_modification_time:
                    lastest_modification_time = file_modification_time
                    transfers_info_file_path = file_path
        
        if transfers_info_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
            
        else:
            try:
                os.startfile(transfers_info_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_cfg(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        cfg_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith(".svg"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    cfg_file_path = file_path
        
        if cfg_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:
            try:
                os.startfile(cfg_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
        
    def show_transfers_number(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        transfers_number_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("per_function.svg"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    transfers_number_file_path = file_path
                
            
        if transfers_number_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:    
            try:
                os.startfile(transfers_number_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
        
    def show_function_call(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        function_call_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("call_relationship.svg"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    function_call_file_path = file_path

            
        if function_call_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:    
            try:
                os.startfile(function_call_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_bin_bb(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        bin_bb_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("bin_basic_block_inf.txt"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    bin_bb_file_path = file_path
        
        if bin_bb_file_path is None:
            error_message = "Error: File not found"
            self.show_error_message(error_message)
        
        else:
            try:  
                os.startfile(bin_bb_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
    
    def show_hex_bb(self):
        output_files_dir = os.path.join(os.path.dirname(os.getcwd()), "output_files")
        latest_modification_time = 0
        hex_bb_file_path = None
        for filename in os.listdir(output_files_dir):
            if filename.endswith("hex_basic_block_inf.txt"):
                file_path = os.path.join(output_files_dir, filename)
                file_modification_time = os.path.getmtime(file_path)
                
                if file_modification_time > latest_modification_time:
                    latest_modification_time = file_modification_time
                    hex_bb_file_path = file_path
        
        if hex_bb_file_path is None:
            error_message = "Error:File not found"
            self.show_error_message(error_message)
        else:
            try:
                os.startfile(hex_bb_file_path)
            except Exception as e:
                error_message = f"Error: {e}"
                self.show_error_message(error_message)
        
    def show_error_message(self, error_message):
        error_window = tk.Toplevel(self.master)
        error_window.title("Error")
        error_window.geometry("400x300")

        scrollbar = tk.Scrollbar(error_window)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
 
        error_text = tk.Text(error_window, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        error_text.pack(fill=tk.BOTH, expand=True)

        scrollbar.config(command=error_text.yview)

        error_text.insert(tk.END, error_message)

if __name__ == "__main__":
    root = tk.Tk()
    gui = CFIEE_UI(root)
    root.mainloop()




