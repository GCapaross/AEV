malloc# Study Notes

## 1. Buffer Overflows (Stack)
* **Definition:** A condition where a program writes data past the end of an allocated buffer, overwriting adjacent memory locations[cite: 9].
* **Root Cause:**
    * Missing bounds checking (e.g., using `strcpy`, `gets`, `scanf` without width limits)[cite: 8].
    * Using C/C++ which are not memory-safe languages[cite: 128].
* **Memory Layout (Process Address Space):**
    * **Text (Code):** Read-only instructions[cite: 278].
    * **Data:** Initialized global variables[cite: 277].
    * **BSS:** Uninitialized global variables[cite: 276].
    * **Heap:** Dynamically allocated memory (`malloc`/`free`), grows upwards (lower to higher addresses)[cite: 275, 283].
    * **Stack:** Local variables, function arguments, return addresses. Grows downwards (higher to lower addresses)[cite: 273, 280].
* **Stack Overflow Mechanics:**
    * **Stack Frame:** Created for each function call. Contains Return Pointer (RIP/EIP) and Frame Pointer (RBP/EBP) [cite: 407-411, 444-447].
    * **The Attack:** By overflowing a local buffer on the stack, an attacker can overwrite the Return Pointer. When the function exits (via `ret` instruction), the CPU jumps to the address injected by the attacker instead of the original caller [cite: 1013-1020, 1054-1060].
* **Payload Types:**
    * **Shellcode:** Malicious code injected into the stack to spawn a shell [cite: 1399-1400].
    * **Return-to-Libc:** Instead of injecting code (which might be blocked by NX bits), the attacker overwrites the return address to point to a system function like `system("/bin/sh")` [cite: 1200-1225].
    * **ROP (Return Oriented Programming):** Chaining small snippets of existing code ("gadgets") that end in a `ret` instruction to perform complex logic without injecting new code [cite: 1378-1383].
* **Mitigations:**
    * **Canaries:** A random secret value placed before the return pointer. If the buffer overflows, the canary is corrupted. The system checks the canary before returning; if changed, it aborts [cite: 1264-1267].
    * **NX (No-Execute) / DEP:** Marking the stack as non-executable [cite: 1251-1255].
    * **ASLR (Address Space Layout Randomization):** Randomizing the memory locations of the stack, heap, and libraries so attackers cannot predict addresses [cite: 2284-2288].

## 2. Buffer Overflows (Heap)
* **Difference from Stack:** Heap overflows target dynamically allocated memory[cite: 55]. They do not directly overwrite return addresses because return addresses are stored on the stack, not the heap[cite: 1921].
* **Mechanism:**
    * **Overwriting Data:** Changing critical application variables (e.g., `isAdmin = true`).
    * **Overwriting Pointers:** Modifying function pointers or C++ vtables stored in heap objects to redirect control flow.
    * **Heap Metadata Corruption:** Overwriting the "chunk headers" (metadata like `prev_size`, `size`, `fd`, `bk`) used by `malloc` and `free` [cite: 1928-1930, 2001-2015]. This can trick the memory allocator into writing to arbitrary memory locations (e.g., "Fastbin attacks") [cite: 2185-2195].
* **Use-After-Free (UAF):**
    * Occurs when a program uses a pointer after the memory it points to has been freed[cite: 2249].
    * **Exploit:** An attacker forces the allocator to reuse the freed memory for a new object. The dangling pointer now points to this new attacker-controlled data, but the program thinks it's the old object [cite: 1976-1981, 2234-2236].

## 3. Over-read vs. Over-write
* **Over-write (Buffer Overflow):**
    * **Action:** Writing past the buffer boundary[cite: 9].
    * **Impact:** Corruption of data, crashes (DoS), or Code Execution (control flow hijacking) [cite: 10-12].
* **Over-read (Buffer Over-read):**
    * **Action:** Reading past the buffer boundary (e.g., Heartbleed bug) [cite: 32, 55, 922-923].
    * **Impact:** Information Disclosure (leaking secrets, passwords, memory addresses to bypass ASLR)[cite: 925, 948]. Does not typically cause code execution directly.

## 4. Concurrency & Race Conditions
* **Race Condition (CWE-362):**
    * Occurs when multiple processes/threads access a shared resource without proper synchronization, and the outcome depends on the timing of execution [cite: 2929-2931].
    * **Example:** Two threads try to withdraw money from a bank account simultaneously. Both read the balance ($100), both calculate the new balance ($90), and both write it back. Result: $10 lost [cite: 3025-3031].
* **TOCTOU (Time-Of-Check to Time-Of-Use):**
    * A specific race condition where a security check (TOC) is performed, but the system changes state before the resource is actually used (TOU) [cite: 3302-3306].
    * **Classic Exploit:** A program checks if a file is safe (`access()`), then opens it (`open()`) [cite: 3312-3315, 3356-3357]. An attacker swaps the file for a symlink to `/etc/passwd` between the check and the open [cite: 3359-3361].
* **Side Channels (Timing Attacks):**
    * Inferring secrets by measuring how long a process takes [cite: 3605-3607].
    * **Example (Question 7 from your image):** Validating a password character-by-character. If the program returns faster for a wrong first letter than a correct first letter, an attacker can guess the password one byte at a time [cite: 3620-3624].
    * **Switch Statement Vulnerability:** `switch` cases are often sequential. Case 1 returns fast; Case 100 takes longer [cite: 3416-3432]. This timing difference leaks the value of the internal variable.

## 5. Web Security (XSS & CORS)
* **XSS (Cross-Site Scripting):** Injecting malicious JavaScript into a web page viewed by other users[cite: 2376].
    * **Reflected:** Malicious script is part of the URL (e.g., in a query parameter). The server reflects it back [cite: 2564-2566]. (Impact: Moderate) [cite: 2345].
    * **Stored (Persistent):** Script is saved in the database (e.g., a comment). Every user who views the comment executes the script [cite: 2589-2590]. (Impact: Severe/Critical) [cite: 2346].
    * **DOM-based:** The vulnerability is in the client-side JavaScript code itself, not the server response[cite: 2609].
* **CORS (Cross-Origin Resource Sharing):**
    * **SOP (Same Origin Policy):** Browsers block websites from reading data from a different origin (Protocol + Domain + Port) [cite: 2716-2722].
    * **CORS Headers:** Allow servers to relax SOP[cite: 2755].
    * **Risks:**
        * `Access-Control-Allow-Origin: *`: Allows any site to read your data [cite: 2812, 2869-2870].
        * `Access-Control-Allow-Origin: null`: Often allows local files or sandboxed iframes to access data.
* **CSRF (Cross-Site Request Forgery):**
    * Forcing a user's browser to send a request to a vulnerable site where they are authenticated (e.g., forcing a bank transfer)[cite: 2631].
    * **Defense:** Synchronizer Tokens (CSRF Tokens) hidden in forms[cite: 2649].

## 6. Analysis of the C Code (Recurso21_aev.png)
* **Vulnerabilities found:**
    * **Stack Buffer Overflow (`sprintf`):** The code copies `dir` into `fname` (256 bytes) without checking length[cite: 19, 55].
    * **Stack Buffer Overflow (`recv`):** The code trusts the user-provided integer `sz` and reads that many bytes into `data` (1500 bytes). If `sz > 1500`, stack corruption occurs[cite: 55].
    * **Format String Vulnerability (`printf(data)`):** The code prints user input directly. An attacker can send `%x` or `%n` to read/write memory [cite: 1889-1893].
    * **TOCTOU Race Condition:** The code checks `strncmp(fname, "/tmp/")` (Check) but opens the file later (`fopen`). The file could be swapped in between [cite: 2962-2964, 3304-3306].
* **Fixes:**
    * **Overflows:** Check lengths (`strlen(dir) < 256` and `sz <= 1500`).
    * **Format String:** Use `printf("%s", data)`[cite: 1891].
    * **Race Condition:** Use file descriptors (`open` then `fstat` to verify ownership/location) rather than filename strings for the second step[cite: 3574].
