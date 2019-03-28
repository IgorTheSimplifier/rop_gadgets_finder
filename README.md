# rop_gadgets_finder
This script is made as an assigment for the course Software Vulnerabilities: Exploitation and Mitigation. It finds all unique rop gadges of the given length in the .text section of the given binary.

The scrip relies on the capstone and elftools libraries to parse ELF files.

usage:
python gadgets.py --length 2 /bin/ls
