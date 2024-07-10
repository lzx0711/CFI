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

import re
import sys

input_file = sys.argv[1]
output_file = sys.argv[2]

function_pattern = r"\s*([\da-f]+)\s*<(.+)>:"
instruction_pattern = r'^\s*([\da-f]+):\s+([\da-f]+)\s+([^:]+)\s+(.+)'

def main(input_file):
    instructions = extract_disassembly_instructions(input_file)
    rewrite_objdump_file(output_file, instructions)
        
    
# def judge_type(input_file_path):
#     type = None
#     with open(input_file_path, 'r') as file:
#         lines = file.readlines()
#         for line in lines[:15]:
#             if line.startswith('#'):
#                 type = 1
#     return type

def extract_disassembly_instructions(input_file_path):
    instructions = []
    with open(input_file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            instr_match = re.search(instruction_pattern, line)
            func_match = re.search(function_pattern, line)
            if func_match:
                if instructions == []:
                    instructions.append(line)
                else:
                    instructions.append('\n' + line)
            elif instr_match:
                instructions.append(line)
    return instructions

def rewrite_objdump_file(output_file, instructions):
    with open(output_file, 'w') as file:
        for instruction in instructions:
            file.write(instruction)

if __name__ == '__main__':
    main(input_file)

