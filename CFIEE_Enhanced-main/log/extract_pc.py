'''
Author: Taurus052
Date: 2023-12-21 10:57:51
LastEditTime: 2023-12-21 11:14:17
'''
import os
import re

current_path = os.path.dirname(os.path.abspath(__file__))
f_path = os.path.join(current_path, 'uart_test_wwk_cpu_log.txt')

def extract_pc_in_log(f_path,current_path):
    pc_lines = []
    with open(f_path, 'r') as f1:
        for line in f1:
            line = line.strip()
            if line.startswith('pc'):
                pc_lines.append(line)
    
    with open(os.path.join(current_path, 'pc_in_log.txt'), 'w') as f2:
        for line in pc_lines:
            f2.write(line + '\n')