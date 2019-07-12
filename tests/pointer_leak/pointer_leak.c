#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
   char buff[10];
   int var = malloc(16);
   int* addr;

   read(0, &buff, 10);

   addr = var;
   //write(1, &addr, sizeof(addr));
   write(1, &argv, 8);
   write(1, &printf, 8);
}

