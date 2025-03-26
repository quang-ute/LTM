/* Server.c */
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024

int main() {
    char remote_directory[256];
    int port = 22;
    
    printf("Nhập thư mục lưu file trên server: ");
    scanf("%255s", remote_directory);
    
    /* Tạo ssh_bind để lắng nghe kết nối */
    ssh_bind sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Không thể tạo ssh_bind.\n");
        exit(EXIT_FAILURE);
    }
    
    /* Thiết lập các tùy chọn cho ssh_bind */
    /* Chỉ định khóa riêng của server từ /keys/ */
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/home/ubuntu/keys/id_rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    
    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Lỗi khi lắng nghe: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    printf("Server đang lắng nghe tại port %d...\n", port);
    
    /* Tạo phiên SSH cho kết nối đến */
    ssh_session session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Không tạo được phiên SSH.\n");
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    
    if (ssh_bind_accept(sshbind, session) != SSH_OK) {
        fprintf(stderr, "Lỗi chấp nhận kết nối: %s\n", ssh_get_error(sshbind));
        ssh_free(session);
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    
    /* Thực hiện bắt tay (key exchange) */
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "Lỗi bắt tay: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    
    /* Xác thực người dùng.
       (Ví dụ đơn giản: ta dùng phương thức none và kiểm tra kết quả xác thực)
       Trong thực tế, bạn nên xử lý các thông điệp xác thực và xác minh key của client.) */
    if (ssh_userauth_none(session, NULL) != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Xác thực thất bại: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    printf("Client đã được xác thực thành công.\n");
    
    /* Tạo phiên SCP ở chế độ đọc để nhận file */
    ssh_scp scp = ssh_scp_new(session, SSH_SCP_READ, remote_directory);
    if (scp == NULL) {
        fprintf(stderr, "Không thể tạo phiên SCP: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    if (ssh_scp_init(scp) != SSH_OK) {
        fprintf(stderr, "Không khởi tạo được SCP: %s\n", ssh_get_error(session));
        ssh_scp_free(scp);
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    
    /* Chờ nhận yêu cầu file từ client */
    int rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_NEWFILE) {
        fprintf(stderr, "Không nhận được yêu cầu file mới.\n");
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    
    int file_size = ssh_scp_request_get_size(scp);
    const char *filename = ssh_scp_request_get_filename(scp);
    printf("Đang nhận file: %s (%d bytes)...\n", filename, file_size);
    
    if (ssh_scp_accept_request(scp) != SSH_OK) {
        fprintf(stderr, "Lỗi chấp nhận yêu cầu file: %s\n", ssh_get_error(session));
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    
    /* Mở file cục bộ để ghi dữ liệu */
    char local_filepath[512];
    snprintf(local_filepath, sizeof(local_filepath), "%s/%s", remote_directory, filename);
    FILE *fp = fopen(local_filepath, "wb");
    if (fp == NULL) {
        perror("Lỗi mở file để ghi");
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        exit(EXIT_FAILURE);
    }
    
    /* Nhận dữ liệu file qua SCP và ghi vào file cục bộ */
    char buffer[BUFFER_SIZE];
    int bytes;
    int total_bytes = 0;
    while (total_bytes < file_size) {
        bytes = ssh_scp_read(scp, buffer, sizeof(buffer));
        if (bytes == SSH_ERROR) {
            fprintf(stderr, "Lỗi đọc dữ liệu từ SCP: %s\n", ssh_get_error(session));
            fclose(fp);
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            ssh_disconnect(session);
            ssh_free(session);
            ssh_bind_free(sshbind);
            exit(EXIT_FAILURE);
        }
        fwrite(buffer, 1, bytes, fp);
        total_bytes += bytes;
    }
    fclose(fp);
    printf("File đã được lưu tại: %s\n", local_filepath);
    
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);
    return 0;
}
