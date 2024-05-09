#include<stdio.h>
#include <string.h>
#include<stdlib.h>
void success() { puts("You Hava already controlled it."); }
void vulnerable(){
    char s[12];
    gets(s);
    puts(s);
    return;
}
int main(){
    vulnerable();
    return 0;
}



