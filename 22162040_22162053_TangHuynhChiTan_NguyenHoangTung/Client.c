/* Client.c */
#include <libssh/libssh.h>
//#include <libssh/callbacks.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024

int main() {
    char local_file[256], remote_path[256], server[256], username[256];
    int port = 22;
    
   
    printf("Nhập địa chỉ server: ");
    scanf("%255s", server);
    printf("Nhập tên đăng nhập: ");
    scanf("%255s", username);
    
    /* Tạo phiên SSH */
    ssh_session session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Không tạo được phiên SSH.\n");
        exit(EXIT_FAILURE);
    }
    ssh_options_set(session, SSH_OPTIONS_HOST, server);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    /* Chỉ định file khóa riêng từ /keys/ */
    ssh_options_set(session, SSH_OPTIONS_IDENTITY, "/keys/id_rsa");
    
    /* Kết nối tới server */
    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Lỗi kết nối: %s\n", ssh_get_error(session));
        ssh_free(session);
        exit(EXIT_FAILURE);
    }
    ssh_key ssh_private_key;
    /* Load khóa riêng từ file /keys/id_rsa */
    ssh_key key = NULL;
    rc = ssh_pki_import_privkey_file("/home/ubuntu/keys/id_rsa", NULL, NULL, NULL, &key);
    if (rc != SSH_OK) {
        fprintf(stderr, "Lỗi nhập khóa riêng: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        exit(EXIT_FAILURE);
    }
    printf("Nhập đường dẫn file cục bộ: ");
    scanf("%255s", local_file);
    printf("Nhập thư mục đích trên server (ví dụ: /home/username/upload): ");
    scanf("%255s", remote_path);
    /* Mở phiên SCP ở chế độ ghi */
    ssh_scp scp = ssh_scp_new(session, SSH_SCP_WRITE, remote_path);
    if (scp == NULL) {
        fprintf(stderr, "Không tạo được phiên SCP: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        exit(EXIT_FAILURE);
    }
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Không khởi tạo được SCP: %s\n", ssh_get_error(session));
        ssh_scp_free(scp);
        ssh_disconnect(session);
        ssh_free(session);
        exit(EXIT_FAILURE);
    }
    
    /* Mở file cục bộ và xác định kích thước file */
    FILE *fp = fopen(local_file, "rb");
    if (fp == NULL) {
        perror("Lỗi mở file cục bộ");
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        ssh_disconnect(session);
        ssh_free(session);
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    /* Lấy tên file từ đường dẫn (loại bỏ đường dẫn thư mục) */
    const char *filename = strrchr(local_file, '/');
    if (filename)
        filename++;  // Bỏ dấu '/'
    else
        filename = local_file;
    
    /* Tạo file mới trên server */
    rc = ssh_scp_push_file(scp, filename, file_size, S_IRUSR | S_IWUSR);
    if (rc != SSH_OK) {
        fprintf(stderr, "Lỗi tạo file trên server: %s\n", ssh_get_error(session));
        fclose(fp);
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        ssh_disconnect(session);
        ssh_free(session);
        exit(EXIT_FAILURE);
    }
    
    /* Đọc và gửi nội dung file */
    char buffer[BUFFER_SIZE];
    size_t nread;
    while ((nread = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        rc = ssh_scp_write(scp, buffer, nread);
        if (rc != SSH_OK) {
            fprintf(stderr, "Lỗi gửi dữ liệu: %s\n", ssh_get_error(session));
            fclose(fp);
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            ssh_disconnect(session);
            ssh_free(session);
            exit(EXIT_FAILURE);
        }
    }
    
    fclose(fp);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    ssh_disconnect(session);
    ssh_free(session);
    
    printf("Truyền file thành công.\n");
    return 0;
}
