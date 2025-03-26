#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

// Cấu trúc để lưu trữ thông tin kết nối
typedef struct {
    ssh_session session;
    ssh_channel channel;
    int authenticated;
    const char *destination_dir;
} client_session_t;

// Khóa SSH được chấp nhận - THAY THẾ VỚI KHÓA CỦA BẠN
// Thay thế biến authorized_key đơn lẻ bằng mảng
const char *authorized_keys[] = {
    // Khóa RSA cũ
   
    
    // Thêm khóa Ed25519 mới (thay thế bằng khóa công khai thực của bạn)
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOTa4P4j/ffkXA3Nsu8dffAdUfyZF6mE4oVOZHf/WJ0 kali@kali",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCe6tq/fVDj19DZ4jup/jGgzySMO1g4+w/YYhLc+49ZuyGPBCL24+C8KsZfyMJHusSA7jlHxjZB3qxdjSvGsZqn2yvqbw5lePdaSYY4l8YKzYe8pF+gmmI5MssXq9GffWFsnS7LRdYsLypAQQN659fqSW7A9Qo5xiIzYfk3XoYr0KRmr9lX3XCkbtjHlIFzLadXJMnZN+EJwLfW1Hjo5+2Jt7E0XT/icj5KRGIlz082FrrqXfy1S0ioMXg6ymOWY9dCXffBWesvjeC4/WrHSVC1+4/3k7nToXZna3B+IHwC5fIjOAxfzT+/Lq5G1yuAISL7rffT6whtKEW1xQ/KebcB Khoalt0811@client",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCa8FQoeCKwWIfb+P10WJT8mn8iGr/lm7lWW/Ykd6+ICURgtU2MRc3rMB5m1wxZqCdKOmNqRlg1X3c59A7hP5cAhtGk1/droFJgb8MQCDJqgYekAAOyRmAp23e7eP1Z+2gbB7XcTTcA1SyNG7v0VCRieh1lecgQld6ylO7C0TaUxDVdTlxURTwBG7aCqxlPeYIdLKKfnPyGPDKtXeTgjUFVQdEc/Qgp7mxhjflKKjBHbvz5JScjXTmTSm5fmDK0sm+f//EY8ge4pDfiabh+PbIkMa2OaryASELQa9TTaIizB3ivbIvrSIKUuoXEmE75O8LJIHfolPZyBf95aahRewR3q+Yzx33nhd0ZvPEVEOAr/Ihm8i7fAaIMdRMnQjI8XQcLaXs7Dlonie1Y1XJX3ORIZX9MUBj8VhIzprsHwxptdkwvWqhu0UMqbzz1dgVe+Zp/JopzsMxw6cbmxTH59SjqBSobRcQYUOHse819WxMD1V8mAXOku9aE1cJCIlsaN1c= kali@kali"
    NULL
};
// Biến tín hiệu để xử lý khi kết thúc chương trình
volatile int keep_running = 1;

// Hàm lấy thời gian hiện tại dưới dạng chuỗi
char *get_current_time() {
    time_t now;
    struct tm *timeinfo;
    static char buffer[80];
    
    time(&now);
    timeinfo = localtime(&now);
    
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

// Hàm ghi log
void log_message(const char *format, ...) {
    va_list args;
    char buffer[1024];
    
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    printf("[%s] %s\n", get_current_time(), buffer);
    fflush(stdout);
}

// Hàm xử lý tín hiệu (Ctrl+C)
void signal_handler(int sig) {
    if (sig == SIGINT) {
        log_message("Đã nhận tín hiệu ngắt. Đang tắt server...");
        keep_running = 0;
    }
}

/// Hàm xác thực người dùng thông qua khóa công khai
int auth_publickey_callback(ssh_session session, const char *username,
                        struct ssh_key_struct *pubkey, char signature_state,
                        void *userdata) {
    (void)session;
    (void)username;
    (void)signature_state;
    (void)userdata;
    
    char *key_str = NULL;
    int rc = ssh_pki_export_pubkey_base64(pubkey, &key_str);
    
    if (rc != SSH_OK || key_str == NULL) {
        log_message("Lỗi khi xuất khóa công khai");
        return SSH_AUTH_DENIED;
    }
    
    // Hiển thị loại khóa để debug
    enum ssh_keytypes_e key_type = ssh_key_type(pubkey);
    log_message("Loại khóa được sử dụng: %d", (int)key_type);
    
    // So sánh khóa người dùng với khóa được chấp nhận
    char full_key[4096];
    const char *key_type_str;
    
    // Xác định loại khóa
    switch(key_type) {
        case SSH_KEYTYPE_RSA:
            key_type_str = "ssh-rsa";
            break;
        case SSH_KEYTYPE_ED25519:
            key_type_str = "ssh-ed25519";
            break;
        case SSH_KEYTYPE_ECDSA:
            key_type_str = "ecdsa-sha2-nistp256";
            break;
        default:
            key_type_str = "unknown";
            break;
    }
    
    // Tạo chuỗi khóa hoàn chỉnh với định dạng tương tự authorized_keys
    snprintf(full_key, sizeof(full_key), "%s %s", key_type_str, key_str);
    
    // Log toàn bộ thông tin khóa để debug
    log_message("Khóa đầy đủ: %s", full_key);
    
    // So sánh với tất cả các khóa được chấp nhận
    int i = 0;
    while (authorized_keys[i] != NULL) {
        // Debug: hiển thị khóa được so sánh
        log_message("So sánh với khóa được chấp nhận: %.30s...", authorized_keys[i]);
        
        if (strstr(authorized_keys[i], key_str) != NULL) {
            log_message("Xác thực thành công (khóa là chuỗi con)");
            free(key_str);
            return SSH_AUTH_SUCCESS;
        }
        
        // So sánh khóa không phân biệt khoảng trắng
        char *auth_key_copy = strdup(authorized_keys[i]);
        char *user_key_copy = strdup(full_key);
        
        if (auth_key_copy && user_key_copy) {
            // Xóa các ký tự khoảng trắng dư
            char *p = auth_key_copy;
            while (*p) {
                if (*p == ' ') *p = '+';
                p++;
            }
            
            p = user_key_copy;
            while (*p) {
                if (*p == ' ') *p = '+';
                p++;
            }
            
            if (strstr(auth_key_copy, user_key_copy) != NULL || 
                strstr(user_key_copy, auth_key_copy) != NULL) {
                free(auth_key_copy);
                free(user_key_copy);
                free(key_str);
                log_message("Xác thực thành công (so sánh đã chuẩn hóa)");
                return SSH_AUTH_SUCCESS;
            }
            
            free(auth_key_copy);
            free(user_key_copy);
        }
        
        i++;
    }
    
    log_message("Xác thực thất bại - Khóa không khớp");
    free(key_str);
    return SSH_AUTH_DENIED;
}
    // Tạo chuỗi khóa hoàn chỉnh với định dạng tương tự authorized_keys
    snprintf(full_key, sizeof(full_key), "%s %s", key_type, key_str);
    
    // Debug: in ra khóa đã cung cấp
    log_message("Khóa người dùng: %.50s...", full_key);
    
    // So sánh với khóa được chấp nhận (kiểm tra chuỗi con)
    if (strstr(authorized_key, key_str) != NULL) {
        log_message("Xác thực thành công với khóa công khai");
        free(key_str);
        return SSH_AUTH_SUCCESS;
    }
    
    // So sánh đầy đủ chuỗi khóa
    if (strcmp(full_key, authorized_key) == 0) {
        log_message("Xác thực thành công với khóa công khai");
        free(key_str);
        return SSH_AUTH_SUCCESS;
    }
    
    log_message("Xác thực thất bại - Khóa không khớp");
    free(key_str);
    return SSH_AUTH_DENIED;
}

// Hàm xử lý các phương thức xác thực (không sử dụng trong callbacks mới)
int auth_callback(ssh_session session, const char *username, const char *method,
                 void *userdata) {
    (void)session;
    log_message("Đang xác thực người dùng: %s, phương thức: %s", username, method);
    
    // Chỉ cho phép xác thực qua phương thức publickey
    if (strcmp(method, "publickey") == 0) {
        return SSH_AUTH_SUCCESS;
    }
    
    return SSH_AUTH_DENIED;
}

// Hàm nhận file SCP
int process_scp(ssh_session session, ssh_channel channel, const char *command, const char *destination_dir) {
    int rc;
    ssh_scp scp;
    
    // Phân tích lệnh SCP
    if (strncmp(command, "scp -t", 6) != 0) {
        log_message("Lệnh không phải SCP: %s", command);
        return SSH_ERROR;
    }
    
    // Khởi tạo SCP server
    scp = ssh_scp_new(session, SSH_SCP_WRITE, destination_dir);
    if (scp == NULL) {
        log_message("Không thể tạo phiên SCP: %s", ssh_get_error(session));
        return SSH_ERROR;
    }
    
    // Chấp nhận kết nối SCP
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        log_message("Không thể khởi tạo phiên SCP: %s", ssh_get_error(session));
        ssh_scp_free(scp);
        return rc;
    }
    
    log_message("Bắt đầu quá trình nhận file vào thư mục: %s", destination_dir);
    
    // Gửi xác nhận OK (0)
    char buffer[1] = {0};
    ssh_channel_write(channel, buffer, 1);
    
    // Xử lý các file được nhận
    while ((rc = ssh_scp_accept_request(scp)) == SSH_OK) {
        const char *filename = ssh_scp_request_get_filename(scp);
        int mode = ssh_scp_request_get_permissions(scp);
        size_t size = ssh_scp_request_get_size(scp);
        
        log_message("Nhận file: %s, kích thước: %zu bytes, quyền: %o", filename, size, mode);
        
        // Chấp nhận file
        ssh_scp_accept_request(scp);
        
        // Tạo đường dẫn đầy đủ cho file mới
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", destination_dir, filename);
        
        // Tạo file và ghi nội dung
        FILE *file = fopen(fullpath, "wb");
        if (file == NULL) {
            log_message("Không thể tạo file %s: %s", fullpath, strerror(errno));
            ssh_scp_deny_request(scp, "Không thể tạo file");
            continue;
        }
        
        // Đọc và ghi dữ liệu
        char *data = malloc(size);
        if (data == NULL) {
            log_message("Không thể cấp phát bộ nhớ cho file");
            fclose(file);
            ssh_scp_deny_request(scp, "Lỗi bộ nhớ");
            continue;
        }
        
        // Đọc dữ liệu từ phiên SCP
        ssh_scp_read(scp, data, size);
        
        // Ghi dữ liệu vào file
        size_t written = fwrite(data, 1, size, file);
        if (written != size) {
            log_message("Lỗi khi ghi file: %s", strerror(errno));
        }
        
        free(data);
        fclose(file);
        
        // Đặt quyền cho file
        chmod(fullpath, mode);
        
        log_message("Đã lưu file: %s", fullpath);
    }
    
    if (rc != SSH_EOF) {
        log_message("Lỗi khi nhận file: %s", ssh_get_error(session));
    }
    
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    
    return SSH_OK;
}

// Hàm xử lý kênh SSH (đã sửa)
int handle_channel(ssh_session session, ssh_channel channel, const char *destination_dir) {
    int rc;
    char buffer[4096];
    int nbytes;
    
    // Đợi lệnh (không cần gọi ssh_channel_open_session_reply_accept)
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
    if (nbytes <= 0) {
        log_message("Lỗi khi đọc lệnh");
        return SSH_ERROR;
    }
    
    buffer[nbytes] = 0;
    log_message("Nhận lệnh: %s", buffer);
    
    // Xử lý lệnh SCP
    rc = process_scp(session, channel, buffer, destination_dir);
    
    // Đóng kênh
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    
    return rc;
}

// Hàm xử lý phiên kết nối của client
void *client_thread(void *arg) {
    client_session_t *client = (client_session_t *)arg;
    ssh_session session = client->session;
    const char *destination_dir = client->destination_dir;
    ssh_channel channel = NULL;
    
    // Chờ kết nối
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        log_message("Lỗi kết nối SSH: %s", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        free(client);
        return NULL;
    }
    
    // Đặt callback cho xác thực (đã sửa)
    struct ssh_server_callbacks_struct server_cb = {
        .auth_password_function = NULL,
        .auth_pubkey_function = auth_publickey_callback,
        .userdata = NULL
        // Đã xóa auth_function không hợp lệ
    };
    
    ssh_callbacks_init(&server_cb);
    ssh_set_server_callbacks(session, &server_cb);
    
    // Vòng lặp xác thực
    while (1) {
        ssh_message message = ssh_message_get(session);
        if (message == NULL) {
            break;
        }
        
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            channel = ssh_message_channel_request_open_reply_accept(message);
            ssh_message_free(message);
            break;
        }
        
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }
    
    // Xử lý kênh nếu đã mở thành công
    if (channel != NULL) {
        handle_channel(session, channel, destination_dir);
        ssh_channel_free(channel);
    }
    
    log_message("Kết nối kết thúc");
    ssh_disconnect(session);
    ssh_free(session);
    free(client);
    
    return NULL;
}

// Hàm chính
int main(int argc, char **argv) {
    ssh_bind sshbind;
    ssh_session session;
    pthread_t tid;
    int port = 22;
    const char *destination_dir = ".";
    
    // Kiểm tra tham số dòng lệnh
    if (argc < 2) {
        printf("Sử dụng: %s <thư_mục_đích> [port]\n", argv[0]);
        return 1;
    }
    
    destination_dir = argv[1];
    
    // Xác định port từ tham số dòng lệnh
    if (argc > 2) {
        port = atoi(argv[2]);
    }
    
    // Thiết lập xử lý tín hiệu
    signal(SIGINT, signal_handler);
    
    printf("==================================================\n");
    printf("SCP Server khởi động\n");
    printf("Thời gian: %s\n", get_current_time());
    printf("Máy chủ: %s\n", getenv("HOSTNAME") ? getenv("HOSTNAME") : "kali");
    printf("Port: %d\n", port);
    printf("Thư mục đích: %s\n", destination_dir);
    printf("==================================================\n");
    printf("Đang lắng nghe kết nối tại port %d...\n\n", port);
    
    // Khởi tạo thư viện SSH
    ssh_init();
    
    // Tạo server binding
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Lỗi tạo SSH binding\n");
        return 1;
    }
    
    // Thiết lập binding
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    
    // Tạo khóa server nếu cần
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "/etc/ssh/ssh_host_ed25519_key");

    // Mở port để lắng nghe
    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Lỗi: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        return 1;
    }
    
    // Vòng lặp chính
    while (keep_running) {
        session = ssh_new();
        if (session == NULL) {
            log_message("Không thể tạo phiên SSH mới");
            continue;
        }
        
        // Chấp nhận kết nối
        if (ssh_bind_accept(sshbind, session) != SSH_ERROR) {
            client_session_t *client = malloc(sizeof(client_session_t));
            if (client == NULL) {
                ssh_disconnect(session);
                ssh_free(session);
                continue;
            }
            
            client->session = session;
            client->authenticated = 0;
            client->destination_dir = destination_dir;
            
            // Lấy thông tin địa chỉ của client
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);
            getpeername(ssh_get_fd(session), (struct sockaddr *)&addr, &addrlen);
            
            char ipstr[INET6_ADDRSTRLEN];
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&addr;
                inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
            } else {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
                inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
            }
            
            log_message("Kết nối mới đến từ: %s", ipstr);
            
            // Tạo thread mới để xử lý kết nối
            pthread_create(&tid, NULL, client_thread, client);
            pthread_detach(tid);
        } else {
            ssh_disconnect(session);
            ssh_free(session);
        }
    }
    
    log_message("Đang tắt server...");
    ssh_bind_free(sshbind);
    ssh_finalize();
    
    return 0;
}







 
