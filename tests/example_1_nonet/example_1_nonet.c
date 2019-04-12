#include <stdio.h>
#include <string.h>


#define BUFFER_SIZE 64
#define FALSE 0
#define TRUE 1

char pswd[21]   = {0} ;
char secret[32] = {0} ;

int main(int argc, char *argv[]){
   
    struct request
    {
        char buffer[BUFFER_SIZE];
        int authenticated;
    } req;


   req.authenticated = FALSE;

   if(argc != 3){
     return;
   }
   
   puts("Server initialization");

   strncpy(secret, argv[1], 32);  // <----- INITIALIZING SERVER WITH SECRET 
   strncpy(pswd, argv[2], 21);    // <----- PASSWORD TO PRINT THE SECRET 
   
   puts("Input the password");

   // receiving the user guess
   read(0, req.buffer, 300); // <------------ VULNERABILITY HERE

   // Authenticate request
   if (!strncmp(req.buffer, pswd, strlen(pswd)))
     req.authenticated = TRUE;   //<------------ AUTH THE REQUEST IF PASSWORD IS CORRECT

   // Request Authenticated
   if (req.authenticated != FALSE)
   {
    printf("%s", secret);
   }

   // Request Not Authenticated
   else 
   {
    puts("ACCESS DENIED");
   }
}
   


