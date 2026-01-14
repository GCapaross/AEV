#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char cntvar[]="constant";
static char bssvar[4];

void foo(unsigned long argc, unsigned long long mask, unsigned long c, unsigned long m)
{
    char a[4096*0x100];
    unsigned long stack = (unsigned long) &argc;

    printf("foo [%03u]: &argc  = %016lx -> stack = %016lx\n", c, stack, stack & mask);
    if(c < m)
        foo(argc,mask,c+1, m);
}



int main(int argc, void** argv) {
        FILE* fd;
        char line[1024];
        unsigned long mask;
        unsigned long stack = (unsigned long) &argc;
        unsigned long heap  = (unsigned long) malloc(sizeof(unsigned long));
        unsigned long bss   = (unsigned long) bssvar;
        unsigned long cnst  = (unsigned long) cntvar;
        unsigned long text  = (unsigned long) &main;
        
	memset(&mask, 0xff, sizeof(mask));
        mask ^= getpagesize() -1 ;
	printf("Internal Variables (Page = %u)\n", getpagesize());
        printf("&argc  = %016lx -> stack = %016lx\n", stack, stack & mask);
        printf("malloc = %016lx -> heap  = %016lx\n", heap,  mask  & heap);
        printf("bssvar = %016lx -> bss   = %016lx\n", bss,   bss   & mask);
        printf("cntvar = %016lx -> const = %016lx\n", cnst,  cnst  & mask);
        printf("&main  = %016lx -> text  = %016lx\n", text,  text  & mask);

	foo((unsigned long) argv, 0xFFFFe000 , 0, 10);
}
