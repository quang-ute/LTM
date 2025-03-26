#include <libssh/libssh.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

// Hàm lấy thời gian hiện tại
char *get_current_time() {
    time_t now;
    struct tm *timeinfo;
    static char buffer[80];
    
    time(&now);
    timeinfo = localtime(&now);
    
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

// Hàm kiểm tra xem một đường dẫn có phải là thư mục không
int is_directory(const char *path) {
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISDIR(path_stat.st_mode);
}

// Hàm gửi một file đến server
int send_file(ssh_session session, const char *source_file, const char *destination_dir) {
    ssh_scp scp;
    int rc;
    FILE *file;
    char *buffer;
    size_t size;
    struct stat s;
    char destination[1024];
    const char *filename;
    
    // Lấy kích thước file
    if (stat(source_file, &s) < 0) {
        fprintf(stderr, "Không thể lấy kích thước của file %s: %s\n", source_file, strerror(errno));
        return -1;
    }
    
    // Lấy tên file từ đường dẫn
    filename = strrchr(source_file, '/');
    if (filename == NULL) {
        filename = source_file;
    } else {
        filename++;
    }
    
    // Tạo đường dẫn đích hoàn chỉnh
    snprintf(destination, sizeof(destination), "%s/%s", destination_dir, filename);
    
    // Khởi tạo SCP
    scp = ssh_scp_new(session, SSH_SCP_WRITE, destination_dir);
    if (scp == NULL) {
        fprintf(stderr, "Lỗi tạo SCP: %s\n", ssh_get_error(session));
        return -1;
    }
    
    // Bắt đầu quá trình SCP
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Lỗi khởi tạo SCP: %s\n", ssh_get_error(session));
        ssh_scp_free(scp);
        return -1;
    }
    
    // Đọc file nguồn
    file = fopen(source_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Không thể mở file nguồn: %s\n", strerror(errno));
        ssh_scp_free(scp);
        return -1;
    }
    
    // Cấp phát bộ nhớ cho nội dung file
    buffer = malloc(s.st_size);
    if (buffer == NULL) {
        fprintf(stderr, "Không đủ bộ nhớ\n");
        fclose(file);
        ssh_scp_free(scp);
        return -1;
    }
    
    // Đọc nội dung file
    size = fread(buffer, 1, s.st_size, file);
    fclose(file);
    
    if (size != s.st_size) {
        fprintf(stderr, "Lỗi khi đọc file: %s\n", strerror(errno));
        free(buffer);
        ssh_scp_free(scp);
        return -1;
    }
    
    // Chỉ định đường dẫn và permission cho file đích
    rc = ssh_scp_push_file(scp, filename, s.st_size, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (rc != SSH_OK) {
        fprintf(stderr, "Không thể khởi tạo file trên server: %s\n", ssh_get_error(session));
        free(buffer);
        ssh_scp_free(scp);
        return -1;
    }
    
    // Gửi nội dung file
    rc = ssh_scp_write(scp, buffer, size);
    if (rc != SSH_OK) {
        fprintf(stderr, "Không thể ghi file trên server: %s\n", ssh_get_error(session));
        free(buffer);
        ssh_scp_free(scp);
        return -1;
    }
    
    // Giải phóng bộ nhớ
    free(buffer);
    ssh_scp_free(scp);
    
    printf("Đã gửi file: %s -> %s\n", source_file, destination);
    return 0;
}

// Hàm đếm và gửi tất cả file từ thư mục nguồn
int send_directory(ssh_session session, const char *source_dir, const char *destination_dir) {
    DIR *dir;
    struct dirent *entry;
    char source_path[1024];
    int count = 0;
    
    // Mở thư mục
    dir = opendir(source_dir);
    if (dir == NULL) {
        fprintf(stderr, "Không thể mở thư mục nguồn: %s\n", strerror(errno));
        return -1;
    }
    
    // Đọc tất cả các mục trong thư mục
    while ((entry = readdir(dir)) != NULL) {
        // Bỏ qua "." và ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Tạo đường dẫn đầy đủ cho file/thư mục
        snprintf(source_path, sizeof(source_path), "%s/%s", source_dir, entry->d_name);
        
        // Nếu là file thì gửi
        if (!is_directory(source_path)) {
            if (send_file(session, source_path, destination_dir) == 0) {
                count++;
            }
        }
        // Nếu là thư mục thì tạo đệ quy
        else {
            char dest_path[1024];
            ssh_scp scp;
            
            snprintf(dest_path, sizeof(dest_path), "%s/%s", destination_dir, entry->d_name);
            
            // Tạo thư mục con trên server
            scp = ssh_scp_new(session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, destination_dir);
            if (scp != NULL && ssh_scp_init(scp) == SSH_OK) {
                ssh_scp_push_directory(scp, entry->d_name, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
                ssh_scp_free(scp);
                
                // Gọi đệ quy
                int subcount = send_directory(session, source_path, dest_path);
                if (subcount > 0) {
                    count += subcount;
                }
            } else {
                fprintf(stderr, "Không thể tạo thư mục %s trên server\n", dest_path);
                if (scp) ssh_scp_free(scp);
            }
        }
    }
    
    closedir(dir);
    return count;
}

// Thử xác thực với một khóa cụ thể
int try_authenticate_with_key(ssh_session session, const char *key_path) {
    ssh_key private_key;
    int rc;
    
    printf("Đang thử xác thực với khóa: %s\n", key_path);
    
    // Kiểm tra file khóa tồn tại
    if (access(key_path, R_OK) != 0) {
        printf("Không tìm thấy khóa: %s\n", key_path);
        return SSH_AUTH_DENIED;
    }
    
    // Tải khóa riêng tư
    rc = ssh_pki_import_privkey_file(key_path, NULL, NULL, NULL, &private_key);
    if (rc != SSH_OK) {
        printf("Không thể tải khóa: %s\n", key_path);
        return SSH_AUTH_DENIED;
    }
    
    // Thử xác thực với khóa này
    rc = ssh_userauth_publickey(session, NULL, private_key);
    
    // In kết quả xác thực
    if (rc == SSH_AUTH_SUCCESS) {
        printf("Xác thực thành công với khóa: %s\n", key_path);
    } else {
        printf("Không thể xác thực với khóa: %s (Mã lỗi: %d)\n", key_path, rc);
    }
    
    // Giải phóng khóa
    ssh_key_free(private_key);
    
    return rc;
}

// Hàm main
int main(int argc, char **argv) {
    ssh_session session;
    int port = 22;
    const char *hostname_str;
    const char *username;
    const char *source_dir;
    const char *destination_dir;
    const char *privkey = NULL;
    int verbosity = SSH_LOG_NOLOG;
    int rc;
    int count;
    
    // Kiểm tra tham số dòng lệnh
    if (argc < 5) {
        fprintf(stderr, "Sử dụng: %s <thư_mục_nguồn> <hostname> <username> <thư_mục_đích> [port] [khóa_SSH]\n", argv[0]);
        return 1;
    }
    
    source_dir = argv[1];
    hostname_str = argv[2];
    username = argv[3];
    destination_dir = argv[4];
    
    // Lấy port từ tham số nếu có
    if (argc > 5) {
        port = atoi(argv[5]);
    }
    
    // Lấy đường dẫn khóa từ tham số nếu có
    if (argc > 6) {
        privkey = argv[6];
    }
    
    printf("==================================================\n");
    printf("SCP Client\n");
    printf("Thời gian: %s\n", get_current_time());
    printf("Máy cục bộ: %s\n", getenv("HOSTNAME") ? getenv("HOSTNAME") : "kali");
    printf("Thư mục nguồn: %s\n", source_dir);
    printf("Máy đích: %s:%d\n", hostname_str, port);
    printf("Người dùng: %s\n", username);
    printf("Thư mục đích: %s\n", destination_dir);
    printf("Khóa SSH: %s\n", privkey ? privkey : "(mặc định)");
    printf("==================================================\n");
    
    // Khởi tạo thư viện SSH
    ssh_init();
    
    // Tạo phiên SSH mới
    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Lỗi: không thể tạo phiên SSH\n");
        return 1;
    }
    
    // Thiết lập các tùy chọn kết nối
    ssh_options_set(session, SSH_OPTIONS_HOST, hostname_str);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    
    // Thiết lập các thuật toán khóa được chấp nhận
    ssh_options_set(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    
    // Kết nối đến server
    printf("Đang kết nối đến %s:%d...\n", hostname_str, port);
    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Lỗi kết nối: %s\n", ssh_get_error(session));
        ssh_free(session);
        return 1;
    }
    
    printf("Kết nối thành công!\n");
    
    // Danh sách các khóa sẽ thử
    const char *key_paths[] = {
        privkey,                    // Khóa được chỉ định trong tham số
        "~/.ssh/id_ed25519",        // Khóa Ed25519 mặc định
        "~/.ssh/id_rsa",            // Khóa RSA mặc định
        NULL
    };
    
    // Thử xác thực với từng khóa
    int auth_success = 0;
    int i = 0;
    
    while (key_paths[i] != NULL) {
        // Bỏ qua nếu là NULL (không có khóa chỉ định)
        if (key_paths[i] == NULL) {
            i++;
            continue;
        }
        
        // Thay thế ~ bằng $HOME
        char expanded_path[1024];
        if (key_paths[i][0] == '~') {
            snprintf(expanded_path, sizeof(expanded_path), "%s%s", getenv("HOME"), key_paths[i] + 1);
        } else {
            strncpy(expanded_path, key_paths[i], sizeof(expanded_path));
        }
        
        // Thử xác thực với khóa này
        rc = try_authenticate_with_key(session, expanded_path);
        
        if (rc == SSH_AUTH_SUCCESS) {
            auth_success = 1;
            break;
        }
        
        i++;
    }
    
    // Nếu không thành công với các khóa đã thử, thử với ssh-agent
    if (!auth_success) {
        printf("Đang thử xác thực với ssh-agent...\n");
        rc = ssh_userauth_publickey_auto(session, NULL, NULL);
        
        if (rc == SSH_AUTH_SUCCESS) {
            auth_success = 1;
            printf("Xác thực thành công với ssh-agent\n");
        } else {
            printf("Xác thực thất bại với ssh-agent: %s\n", ssh_get_error(session));
        }
    }
    
    // Kiểm tra kết quả xác thực
    if (!auth_success) {
        fprintf(stderr, "Lỗi xác thực: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }
    
    printf("Xác thực thành công!\n");
    
    // Gửi file từ thư mục nguồn
    printf("Đang gửi file từ %s đến %s:%s\n", source_dir, hostname_str, destination_dir);
    count = send_directory(session, source_dir, destination_dir);
    
    // Hiển thị kết quả
    if (count >= 0) {
        printf("Đã gửi thành công %d file\n", count);
    } else {
        fprintf(stderr, "Đã xảy ra lỗi khi gửi file\n");
    }
    
    // Đóng phiên SSH
    ssh_disconnect(session);
    ssh_free(session);
    ssh_finalize();
    
    return (count >= 0) ? 0 : 1;
}
