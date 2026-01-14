### Notes / Concepts for exam


## buffer Overflows (stacks)
*Definition:* A condition where a programw rites data past the end of an allocated buffer, overwriting adjacent memory locations.
*Root Cause*:
    - Missing bounds checking (using strcpy, gets, scanf, without width limits)
    - Using C/C++ which are not memory safe languages
*Memoery Layout* (Process Address Space)
- Text (Code): Read-only instructoins
- Data: Initialized global variables
- BSS: Unitialized global variables
- Heap: Dynamically allocated memory (malloc/free), grows upwards (lower to higher addresses)
- Stack: Local variables, function arguments, return addresses, grows downards (higher to lower addresses)
*Stack Overflow Mechanics*
