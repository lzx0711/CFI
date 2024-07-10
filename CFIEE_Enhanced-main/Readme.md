# CFIEE: A Critical Metadata Extraction Engine for RISC-V CFI Scheme

#### Author: @Taurus052&#x20;

### Program dependencies

- riscv64-unknown-elf toolchain (If you need to disassemble RISC-V ELF file.)

- Python version: Python 3.x (It is recommended to use python3.11 or above version.)

- Python modules:

  - os

  - re

  - sys

  - hashlib

  - tkinter

  - threading

  - subprocess

  - matplotlib

  - graphviz

### Program Function

This program is a highly efficient tool designed specifically for the purpose of extracting control flow integrity metadata.

### Program Input

Users can provide RISC-V ELF executable files, or provide ELF disassembly files in .txt format.

### Program Output

All files will be stored in **"output_files"** directory.

#### 1. 'xxx_basic_block.txt':

This file contains all Basic block information obtained by Program analysis. The number of each basic block, the start and end addresses (and instructions), the length of the Basic block, the jump target address (and instructions) of the Basic block, and the instructions in the Basic block are all reflected in the file.

#### 2. 'xxx_forward_transfers.txt':

This file contains all control transfer instructions and their target instructions within the analyzed functions.

#### 3. 'xxx_bin/hex_basic_block_inf.txt':

This file contains the PC address and instructions of binary /hexadecimal instructions in the Basic block, as well as the hash value calculated based on binary /hexadecimal instructions.

#### 4. 'xxx_function_addr.txt':

This file contains the function's start\&end addresses.

#### 5. 'xxx_control_transfer.bin':

This binary file contains all control transfer instructions' addresses and their target addresses. The first 16 bits of each line is the binary address of the control transfer instruction, and the last 16 bits are the address of the transfer target.

#### 6.'xxx_forward_transfers_per_function.svg':

This is a figure that shows the number of forward control transfer instructions (including unconditional direct jumps and branches) in different function.

#### 7. ‘xxx_function_call_relationship.svg':

This picture shows the function call relationship of the current program. If there is a label "\*" after the function name in the figure, it means that the function is not called by the "jal" instruction, but jumps from the "j" instruction at the end of the previous function.

#### 8. 'xxx_CFG.svg':

This is a control flow graph of the entire program flow in svg format.

### Program Usage

This program can be used via the command line, with the following usage:

    python CFIEE.py

In the CFIEE interface, we have provided clear usage instructions for you to follow in order to perform corresponding operations. It is important to note that the disassembly function is not mandatory and if preferred, you may complete the disassembly of your executable file beforehand and proceed directly to STEP2. CFIEE utilizes the riscv64-unknown-elf-objdump toolchain on your local computer.

### Notice

1.  All development and testing processes for this program are based on the T-Head Xuantie E906 RISC-V processor using the RV32IMAFC instruction set. The selected RISC-V toolchain is Xuantie-900-gcc-elf-newlib-x86_64-V2.6.1. Its disassembly toolchain is GNU objdump (GNU Binutils) 2.35.

2.  We **cannot** guarantee the correctness of this program when analyzing the disassembly files of other RISC-V instruction sets.
    Current program **cannot** analyze information related to indirect jumps. The target addresses of all indirect jump instructions are set to the name of their target registers.
