/*
 * Secure File Transfer Client
 * 
 * Mô tả:
 * - Chương trình này kết nối đến một server qua socket TCP.
 * - Xác thực bằng chữ ký số RSA sử dụng OpenSSL.
 * - Sau khi xác thực thành công, chương trình gửi file từ máy client đến server.
 *
 * Cách biên dịch (Windows - Visual Studio):
 * - Yêu cầu: OpenSSL và Winsock2.
 * - Liên kết thư viện: libssl.lib, libcrypto.lib, ws2_32.lib
 *
 * Cách chạy chương trình:
 *   client.exe <source file> <destination path>
 */

 #include <stdio.h>
 #include <winsock2.h>
 #include <openssl/evp.h>
 #include <openssl/pem.h>
 #include <openssl/err.h>
 #include <openssl/rand.h>
 #include <stdint.h>
 #include <time.h>
 
 #pragma comment(lib, "ws2_32.lib")
 #pragma comment(lib, "libssl.lib")
 #pragma comment(lib, "libcrypto.lib")
 
 #define SERVER_IP "10.107.2.208" // Địa chỉ IP của server
 #define PORT 8080 // Cổng kết nối
 #define BUFFER_SIZE 1024 // Kích thước buffer truyền file
 
 /*
  * Đọc khóa riêng từ file PEM
  */
 EVP_PKEY* read_private_key(const char* filename) {
     FILE* file = fopen(filename, "r");
     if (!file) {
         perror("Error opening private key file");
         return NULL;
     }
     EVP_PKEY* pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
     fclose(file);
     return pkey;
 }
 
 int main(int argc, char* argv[]) {
     if (argc < 3) {
         printf("Usage: %s <source file> <destination path>\n", argv[0]);
         return 1;
     }
 
     char* source_path = argv[1];
     char* dest_path = argv[2];
 
     // Khởi tạo Winsock
     WSADATA wsa;
     WSAStartup(MAKEWORD(2, 2), &wsa);
     SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
     struct sockaddr_in server;
     server.sin_addr.s_addr = inet_addr(SERVER_IP);
     server.sin_family = AF_INET;
     server.sin_port = htons(PORT);
 
     // Kết nối đến server
     connect(sock, (struct sockaddr*)&server, sizeof(server));
     printf("Connected to server %s:%d\n", SERVER_IP, PORT);
 
     // Nhận challenge từ server
     unsigned char challenge[32];
     recv(sock, (char*)challenge, sizeof(challenge), 0);
 
     // Đọc khóa riêng
     EVP_PKEY* private_key = read_private_key("id_rsa.pem");
     if (!private_key) {
         closesocket(sock);
         WSACleanup();
         return 1;
     }
 
     // Ký challenge bằng RSA-SHA256
     EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
     EVP_PKEY_CTX* ctx;
     EVP_DigestSignInit(md_ctx, &ctx, EVP_sha256(), NULL, private_key);
     EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
     
     size_t sig_len;
     EVP_DigestSignUpdate(md_ctx, challenge, sizeof(challenge));
     EVP_DigestSignFinal(md_ctx, NULL, &sig_len);
     
     unsigned char* sig = (unsigned char*)malloc(sig_len);
     EVP_DigestSignFinal(md_ctx, sig, &sig_len);
 
     // Gửi chữ ký đến server
     uint32_t sig_len_net = htonl((uint32_t)sig_len);
     send(sock, (char*)&sig_len_net, sizeof(sig_len_net), 0);
     send(sock, (char*)sig, sig_len, 0);
 
     // Nhận phản hồi từ server
     char response[5] = {0};
     recv(sock, response, 4, 0);
 
     if (strcmp(response, "OK") == 0) {
         // Mở file cần gửi
         FILE* file = fopen(source_path, "rb");
         if (!file) {
             perror("Error opening file to send");
             closesocket(sock);
             return 1;
         }
 
         // Lấy kích thước file
         fseek(file, 0, SEEK_END);
         uint64_t file_size = ftell(file);
         rewind(file);
 
         // Gửi đường dẫn và kích thước file
         send(sock, dest_path, 256, 0);
         send(sock, (char*)&file_size, sizeof(file_size), 0);
 
         // Gửi dữ liệu file
         char buffer[BUFFER_SIZE];
         size_t bytes_read;
         uint64_t sent = 0;
         time_t start_time = time(NULL);
 
         while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
             send(sock, buffer, bytes_read, 0);
             sent += bytes_read;
             printf("\rProgress: %.2f%%", (double)sent / file_size * 100);
         }
         
         printf("\nFile sent successfully! Time elapsed: %ld seconds\n", time(NULL) - start_time);
         fclose(file);
     }
 
     // Dọn dẹp bộ nhớ
     free(sig);
     EVP_MD_CTX_free(md_ctx);
     EVP_PKEY_free(private_key);
     closesocket(sock);
     WSACleanup();
     return 0;
 }
 