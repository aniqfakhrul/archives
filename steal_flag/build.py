#!/usr/bin/env python3
import sys
import os

# Build C Progam
script_c = open("steal_flag.c").read()
fix_c = script_c.replace("127.0.0.1",sys.argv[1])
f = open("steal.c", "w")
f.write(fix_c)
f.close()
os.system("gcc steal.c -o steal")
