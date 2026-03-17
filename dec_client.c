#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

void error(const char *msg) { 
    perror(msg); 
    exit(1); 
}

void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname) {
    memset((char*) address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);
    
    struct hostent* hostInfo = gethostbyname(hostname); 
    if (hostInfo == NULL) { 
        fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
        exit(2); 
    }
    memcpy((char*) &address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}

int validate_chars(const char *filename, char **content) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: cannot open file %s\n", filename);
        return 0;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    *content = malloc(file_size + 1);
    size_t bytes_read = fread(*content, 1, file_size, file);
    (*content)[bytes_read] = '\0';
    fclose(file);
    
    // Remove trailing newline from files
    size_t len = strlen(*content);
    if (len > 0 && (*content)[len - 1] == '\n') {
        (*content)[len - 1] = '\0';
        len--;
    }
    
    // Validate characters
    for (size_t i = 0; i < len; i++) {
        char c = (*content)[i];
        if (!((c >= 'A' && c <= 'Z') || c == ' ')) {
            fprintf(stderr, "Error: invalid character '%c' in %s\n", c, filename);
            return 0;
        }
    }
    
    return len;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s ciphertext key port\n", argv[0]);
        exit(1);
    }
    
    char *ciphertext = NULL;
    char *key = NULL;
    
    // Validate and read files
    int ciphertext_len = validate_chars(argv[1], &ciphertext);
    if (ciphertext_len == 0) {
        free(key);
        exit(1);
    }
    
    int key_len = validate_chars(argv[2], &key);
    if (key_len == 0) {
        free(ciphertext);
        exit(1);
    }
    
    // Check if key is long enough
    if (key_len < ciphertext_len) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        free(ciphertext);
        free(key);
        exit(1);
    }
    
    // Create socket
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        error("CLIENT: ERROR opening socket");
    }
    
    // Set up server address
    struct sockaddr_in serverAddress;
    setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");
    
    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        error("CLIENT: ERROR connecting");
    }
    
    // Send client identifier for authentication
    char client_id = 'D'; // 'D' for decryption client
    if (send(socketFD, &client_id, sizeof(client_id), 0) < 0) {
        error("CLIENT: ERROR sending client ID");
    }
    
    // Send data to server, starting with encoded ciphertext length
    int net_len = htonl(ciphertext_len);
    if (send(socketFD, &net_len, sizeof(net_len), 0) < 0) {
        error("CLIENT: ERROR sending ciphertext length");
    }
    
    // Send ciphertext
    if (send(socketFD, ciphertext, ciphertext_len, 0) < 0) {
        error("CLIENT: ERROR sending ciphertext");
    }
    
    // Send key
    if (send(socketFD, key, ciphertext_len, 0) < 0) {
        error("CLIENT: ERROR sending key");
    }
    
    // Receive plaintext from server
    char *plaintext = malloc(ciphertext_len + 1);
    if (!plaintext) {
        error("CLIENT: ERROR allocating memory for plaintext");
    }
    
    int total_received = 0;
    while (total_received < ciphertext_len) {
        int chars_read = recv(socketFD, plaintext + total_received, 
                             ciphertext_len - total_received, 0);
        if (chars_read < 0) {
            error("CLIENT: ERROR reading from socket");
        }
        if (chars_read == 0) {
            break;
        }
        total_received += chars_read;
    }
    
    plaintext[ciphertext_len] = '\0';
    
    // Output plaintext to stdout
    printf("%s\n", plaintext);
    
    // Clean up
    close(socketFD);
    free(ciphertext);
    free(key);
    free(plaintext);
    
    return 0;
}
