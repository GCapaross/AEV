// File : burger.c
// A simple program that simulates a burger shop from the Bon-nie-appetit challenge

#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>

// Function to read a number from stdin
int read_num() {
  char buf [16];

  do{
    memset(buf,0,16);
    read(0,buf,15);
  } while ( buf[0] < '0' || buf[0] > '9' );
  return atoi(buf);
}

// Function to find an empty order slot
int get_empty_order(char **orders, int max) {
  int i;
  
  for (i = 0; i < max; i++) {
    if (orders[i] == NULL) 
      return i;
  }

  return -1; // No empty order found
}

// Function to create a new order
char* new_order(char** data) {
  int empty_order;
  int num; 
  void *buf; 
 
  empty_order = get_empty_order(data, 20);

  if ( empty_order == -1 ) {
    printf("%s\n[-] Cannot order more!%s\n", "\x1B[1;31m", "\x1B[1;34m");
  } else {
    printf("\n[*] For how many: ");
    num = read_num();
    buf = malloc(num);

    if ( buf ) {
      printf("\n[*] What would you like to order: ");
      read(0, buf, num);
      data[empty_order] = (void*) buf;
    } else {
      printf("%s\n[-] Something went wrong!%s\n", "\x1B[1;31m", "\x1B[1;34m");
    }
  }
  return buf;
}

// Function to show an existing order
void show_order(char **data) {
  printf("\n[*] Number of order: ");
  int num = read_num();

  if ( num <= 0x13 && data[num] )
    printf("\n[+] Order[%d] => %s \n%s", num, (const char *)data[num], "\x1B[1;34m");
  else
    printf("\n%s[-] There is no such order!%s\n", "\x1B[1;31m", "\x1B[1;34m");
}

// Function to edit an existing order
void edit_order(char** data)
{
  unsigned int num; 

  printf("\n[*] Number of order: ");
  num = read_num();

  if ( num <= 0x13 && data[num] ) {
    printf("\n[*] New order: ");

    // WARNING
    // There is a read overflow here since strlen will go beyond the allocated size
    // The last byte corresponds to the size of the next chunk in the heap
    unsigned int aux = strlen(data[num]); 
    read(0, data[num], aux); // Write back to the same location, overflowing by 1 byte
  } else {
    printf("\n%s[-] There is no such order!%s\n", "\x1B[1;31m", "\x1B[1;34m");
  }
}

// Function to delete an existing order
void delete_order(char** data)
{
  printf("\n[*] Number of order: ");
  unsigned int num = read_num();
  if ( num <= 0x13 && data[num] ) {
    free((void *) data[num]);
    data[num] = 0LL;          
  } else {
    printf("\n%s[-] There is no such order!%s\n", "\x1B[1;31m", "\x1B[1;34m");
  }
}

// Setup function to configure I/O buffering
void setup(void) {
  setvbuf(stdout,0LL,2,0LL);
  setvbuf(stdin,0LL,2,0LL);
  setvbuf(stderr,0LL,2,0LL);
}

// Function to display the banner
void banner() {
  printf("%s", "\x1B[1;34m");
  printf("\n%s", "**********************************************\n");
  printf("%s", "*                                            *\n");
  printf("%s", "*           Welcome to Burger Shop          *\n");
  printf("%s", "*                                            *\n");
  printf("%s", "**********************************************\n");
}

// Function to display the menu
void menu() {
  printf("\n%s", "+=-=-=-=-=-=-=-=-=-=-=-=-=-=+\n");
  printf("%s",   "* 1. New Order              *\n");
  printf("%s",   "* 2. Show Order             *\n");
  printf("%s",   "* 3. Edit Order             *\n");
  printf("%s",   "* 4. Delete Order           *\n");
  printf("%s",   "* 5. Exit                   *\n");
  printf("%s",   "+-=-=-=-=-=-=-=-=-=-=-=-=-=+\n");
  printf("\n[*] Select an option> ");
}

// Main function
void main(void) {
  int option;
  char* data [20];
  
  memset(data,0,0xa0);
  setup();
  banner();
  do {
    menu();
    option = read_num();
    switch(option) {
    default:
      printf("\n[-] Invalid option!\n");
      break;
    case 1:
      new_order(data);
      break;
    case 2:
      show_order(data);
      break;
    case 3:
      edit_order(data);
      break;
    case 4:
      delete_order(data);
      break;
    case 5:
      printf("\n[+] Your order will be ready soon!\n");
      exit(0x45);
    }
  } while(1);
}


