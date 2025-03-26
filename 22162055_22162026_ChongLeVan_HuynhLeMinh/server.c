#include <stdio.h>
#include <winsock2.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

EVP_PKEY* read_public_key(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error opening public key file");
        return NULL;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    return pkey;
}

int main() {
    WSADATA wsa;
    SOCKET server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    WSAStartup(MAKEWORD(2, 2), &wsa);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);

    printf("Server is listening on port %d...\n", PORT);

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
        printf("\nClient connected from %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // Gửi challenge cho client
        unsigned char challenge[32];
        RAND_bytes(challenge, sizeof(challenge));
        send(new_socket, (char*)challenge, sizeof(challenge), 0);

        // Nhận chữ ký từ client
        uint32_t sig_len_net;
        recv(new_socket, (char*)&sig_len_net, sizeof(sig_len_net), 0);
        unsigned int sig_len = ntohl(sig_len_net);

        unsigned char* sig = (unsigned char*)malloc(sig_len);
        recv(new_socket, (char*)sig, sig_len, 0);

        // Đọc khóa công khai để xác thực
        EVP_PKEY* public_key = read_public_key("authorized_keys.pem");
        if (!public_key) {
            closesocket(new_socket);
            free(sig);
            continue;
        }

        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* ctx;
        EVP_DigestVerifyInit(md_ctx, &ctx, EVP_sha256(), NULL, public_key);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

        int verify_result = EVP_DigestVerify(md_ctx, sig, sig_len, challenge, sizeof(challenge));

        free(sig);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(public_key);

        if (verify_result != 1) {
            send(new_socket, "FAIL", 4, 0);
            closesocket(new_socket);
            continue;
        }

        send(new_socket, "OK", 2, 0);

        // Nhận thông tin file từ client
        char file_path[256];
        uint64_t file_size;
        recv(new_socket, file_path, sizeof(file_path), 0);
        recv(new_socket, (char*)&file_size, sizeof(file_size), 0);

        printf("Receiving file: %s (Size: %llu bytes)\n", file_path, file_size);

        // Mở file để ghi dữ liệu
        FILE* file = fopen(file_path, "wb");
        if (!file) {
            perror("Error opening file for writing");
            closesocket(new_socket);
            continue;
        }

        // Nhận và ghi dữ liệu vào file
        uint64_t received = 0;
        int bytes;
        time_t start_time = time(NULL);
        while ((bytes = recv(new_socket, buffer, BUFFER_SIZE, 0)) > 0) {
            fwrite(buffer, 1, bytes, file);
            received += bytes;
            printf("\rProgress: %.2f%%", (double)received / file_size * 100);
        }

        fclose(file);  // Đóng file sau khi ghi xong

        printf("\nFile saved to: %s\n", file_path);
        printf("Time elapsed: %ld seconds\n", time(NULL) - start_time);

        closesocket(new_socket);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
