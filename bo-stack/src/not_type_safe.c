#include <stdio.h>

void main(int argc, char* argv[]){
	int aux = 42; // Integer
	int *value = &aux; // Pointer to Integer
	
	// Correct usage
	printf("%d\n", *value);
	// Reading memory after the variable
	printf("%d\n", *(value + 4));
	// Reading memory before the variable
	printf("%d\n", *(value - 4));
	// Cast to variable with different storage
	printf("%f\n", *((double*) &value));
	// Cast to variable with different size
	printf("%llu\n", *((unsigned long long*) &value));
}
