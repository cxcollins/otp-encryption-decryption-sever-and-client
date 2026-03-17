#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: keygen keylength\n");
        return 1;
    }
    
    int keylength = atoi(argv[1]);

    if (keylength <= 0) {
        fprintf(stderr, "Error: keylength must be a positive integer\n");
        return 1;
    }
    
    // Seed random number generator
    srand(time(NULL));
    
    for (int i = 0; i < keylength; i++) {
        int random_char = rand() % 27;
        
        if (random_char == 26) {
            putchar(' ');
        } else {
            putchar('A' + random_char);
        }
    }
    
    putchar('\n');
    
    return 0;
}