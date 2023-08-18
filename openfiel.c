#include<stdio.h>
int main(int argc, char **args)
{
    FILE *file = fopen("/home/wyx/workspace/bcc-codes/file","a+");
    if(file != NULL)
    {
        fclose(file);
        printf("open is OK\n");
    }
    return 0;
}