#!/usr/bin/env python3

import sys
import re

def load_trace(trace):
    f = open(trace, "r")
    return f.readlines()

exec_regex = re.compile(r"exec_tb_block \d+\.\d+ pid=\d+ tb=\w+ pc=\w+ size=(0x\w+) icount=(0x\w+)")
syscall_regex = re.compile(r"guest_user_syscall \d+\.\d+ pid=\d+ __cpu=\w+ num=(0x\w+)")

def parse_stdin():
    ret = []
    for l in sys.stdin:
        match = exec_regex.match(l)
        if match:
            bsize = int(match.group(1), 16)
            icount = int(match.group(2), 16)
            ret.append(["exec_tb_block", bsize, icount])
        else:
            match = syscall_regex.match(l)
            if match:
                syscall_nr = int(match.group(1), 16)
                ret.append(["syscall", syscall_nr])
            else:
                exit(1)
    return ret

def construct_limit(trace):
    ret = {}
    for t in trace:
        if t[0] == "syscall":
            if t[1] not in ret:
                ret[t[1]] = 1
            else:
                ret[t[1]] += 1
    return ret

def calculate_reduction(trace, limit):
    used = {}
    result = {}
    for t in trace:
        current_open = len(limit)
        if t[0] == 'exec_tb_block':
            if current_open not in result:
                result[current_open] = t[2]
            else:
                result[current_open] += t[2]
        elif t[0] == 'syscall':
            if t[1] not in used:
                used[t[1]] = 1
            else:
                used[t[1]] += 1
            if used[t[1]] == limit[t[1]]:
                del limit[t[1]]
    return result

if __name__ == '__main__':
    trace = parse_stdin()
    limit = construct_limit(trace)
    result = calculate_reduction(trace, limit)
    print(result)


