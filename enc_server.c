#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/wait.h>

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void setupAddressStruct(struct sockaddr_in* address, int portNumber) {
    memset((char*) address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);
    address->sin_addr.s_addr = INADDR_ANY;
}

void encrypt_otp(const char *plaintext, const char *key, char *ciphertext, int length) {
    for (int i = 0; i < length; i++) {
        char p = plaintext[i];
        char k = key[i];
        
        int p_val, k_val;
        
        if (p == ' ') {
            p_val = 26;
        } else {
            p_val = p - 'A';
        }
        
        if (k == ' ') {
            k_val = 26;
        } else {
            k_val = k - 'A';
        }
        
        int cipher_val = (p_val + k_val) % 27;
        
        if (cipher_val == 26) {
            ciphertext[i] = ' ';
        } else {
            ciphertext[i] = 'A' + cipher_val;
        }
    }
    ciphertext[length] = '\0';
}

void handle_client(int connectionSocket) {
    int plaintext_len;
    int charsRead;
    
    // Receive client identifier for authentication
    char client_id;
    charsRead = recv(connectionSocket, &client_id, sizeof(client_id), 0);
    if (charsRead < 0) {
        fprintf(stderr, "SERVER: ERROR receiving client ID\n");
        close(connectionSocket);
        return;
    }
    
    if (client_id != 'E') {
        fprintf(stderr, "SERVER: Unauthorized client connection rejected\n");
        close(connectionSocket);
        return;
    }
    
    // Receive plaintext length
    charsRead = recv(connectionSocket, &plaintext_len, sizeof(plaintext_len), 0);
    if (charsRead < 0) {
        fprintf(stderr, "SERVER: ERROR receiving plaintext length\n");
        close(connectionSocket);
        return;
    }
    plaintext_len = ntohl(plaintext_len);
    
    // Allocate memory for plaintext and key
    char *plaintext = malloc(plaintext_len + 1);
    char *key = malloc(plaintext_len + 1);
    char *ciphertext = malloc(plaintext_len + 1);
    
    if (!plaintext || !key || !ciphertext) {
        fprintf(stderr, "SERVER: ERROR allocating memory\n");
        close(connectionSocket);
        free(plaintext);
        free(key);
        free(ciphertext);
        return;
    }
    
    // Receive plaintext
    int total_received = 0;
    while (total_received < plaintext_len) {
        charsRead = recv(connectionSocket, plaintext + total_received, 
                        plaintext_len - total_received, 0);
        if (charsRead < 0) {
            fprintf(stderr, "SERVER: ERROR receiving plaintext\n");
            close(connectionSocket);
            free(plaintext);
            free(key);
            free(ciphertext);
            return;
        }
        if (charsRead == 0) break;
        total_received += charsRead;
    }
    plaintext[plaintext_len] = '\0';
    
    // Receive key
    total_received = 0;
    while (total_received < plaintext_len) {
        charsRead = recv(connectionSocket, key + total_received, 
                        plaintext_len - total_received, 0);
        if (charsRead < 0) {
            fprintf(stderr, "SERVER: ERROR receiving key\n");
            close(connectionSocket);
            free(plaintext);
            free(key);
            free(ciphertext);
            return;
        }
        if (charsRead == 0) break;
        total_received += charsRead;
    }
    key[plaintext_len] = '\0';
    
    // Perform OTP encryption using separate function
    encrypt_otp(plaintext, key, ciphertext, plaintext_len);
    
    // Send ciphertext back to client
    int total_sent = 0;
    while (total_sent < plaintext_len) {
        charsRead = send(connectionSocket, ciphertext + total_sent, 
                        plaintext_len - total_sent, 0);
        if (charsRead < 0) {
            fprintf(stderr, "SERVER: ERROR sending ciphertext\n");
            break;
        }
        total_sent += charsRead;
    }
    
    // Clean up
    close(connectionSocket);
    free(plaintext);
    free(key);
    free(ciphertext);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }
    
    int listenSocket, connectionSocket;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);
    
    // Create the listening socket
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        error("SERVER: ERROR opening socket");
    }
    
    // Set up the address struct for the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));
    
    // Associate the socket to the port
    if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        error("SERVER: ERROR on binding");
    }
    
    // Start listening for connections
    listen(listenSocket, 5);
    
    printf("SERVER: Server open on %d\n", atoi(argv[1]));
    
    // Create pool of 5 child processes
    for (int i = 0; i < 5; i++) {
        pid_t pid = fork();
        
        if (pid < 0) {
            fprintf(stderr, "SERVER: ERROR on fork\n");
            exit(1);
        } else if (pid == 0) {
            // Child process handles connections indefinitely
            while (1) {
                // Accept a connection
                connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
                if (connectionSocket < 0) {
                    fprintf(stderr, "SERVER: ERROR on accept\n");
                    continue;
                }
                handle_client(connectionSocket);
            }
        }
    }
    
    // Parent process waits for all children to complete (they won't in this design)
    while (1) {
        waitpid(-1, NULL, WNOHANG);
        sleep(1);
    }
    
    close(listenSocket);
    return 0;
}
