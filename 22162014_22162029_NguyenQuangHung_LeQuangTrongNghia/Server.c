#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#define KEYS_FOLDER "/home/qhung/"

void write_log(const char *message) {
    FILE *log_file = fopen("/home/qhung/ssh_server.log", "a");
    if (log_file == NULL) {
        perror("Không thể mở tệp log");
        return;
    }
    time_t now;
    time(&now);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';
    fprintf(log_file, "[%s] %s\n", time_str, message);
    fclose(log_file);
}

int authenticate_user(ssh_session session) {
    ssh_message message;
    char log_msg[256];
    ssh_key pubkey = NULL;

    write_log("Bắt đầu xác thực");
    while ((message = ssh_message_get(session)) != NULL) {
        const char *username = ssh_message_auth_user(message);
        if (username == NULL) {
            write_log("Không thể lấy username từ client");
            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
            ssh_message_reply_default(message);
            ssh_message_free(message);
            continue;
        }
        snprintf(log_msg, sizeof(log_msg), "Nhận yêu cầu xác thực từ user: %s", username);
        write_log(log_msg);

        if (ssh_message_type(message) == SSH_REQUEST_AUTH) {
            if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PUBLICKEY) {
                ssh_key client_pubkey = ssh_message_auth_pubkey(message);
                if (client_pubkey == NULL) {
                    snprintf(log_msg, sizeof(log_msg), "Không thể lấy khóa công khai từ client");
                    write_log(log_msg);
                    ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                    ssh_message_reply_default(message);
                    ssh_message_free(message);
                    continue;
                }

                int rc = ssh_pki_import_pubkey_file("/home/qhung/.ssh/authorized_keys", &pubkey);
                if (rc != SSH_OK) {
                    snprintf(log_msg, sizeof(log_msg), "Lỗi khi đọc authorized_keys: %s", ssh_get_error(session));
                    write_log(log_msg);
                    ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                    ssh_message_reply_default(message);
                    ssh_key_free(client_pubkey);
                    ssh_message_free(message);
                    continue;
                }

                if (ssh_key_cmp(client_pubkey, pubkey, SSH_KEY_CMP_PUBLIC) == 0) {
                    snprintf(log_msg, sizeof(log_msg), "Xác thực khóa công khai thành công cho user: %s", username);
                    write_log(log_msg);
                    ssh_message_auth_reply_success(message, 0);
                    ssh_key_free(pubkey);
                    ssh_key_free(client_pubkey);
                    ssh_message_free(message);
                    return SSH_AUTH_SUCCESS;
                } else {
                    snprintf(log_msg, sizeof(log_msg), "Khóa công khai không khớp cho user: %s", username);
                    write_log(log_msg);
                    ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                    ssh_message_reply_default(message);
                }
                ssh_key_free(pubkey);
                ssh_key_free(client_pubkey);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Phương thức xác thực %d không được hỗ trợ cho user: %s", 
                         ssh_message_subtype(message), username);
                write_log(log_msg);
                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                ssh_message_reply_default(message);
            }
        } else {
            snprintf(log_msg, sizeof(log_msg), "Tin nhắn không phải yêu cầu xác thực: type=%d", ssh_message_type(message));
            write_log(log_msg);
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }
    write_log("Xác thực bị từ chối: không nhận được tin nhắn hợp lệ");
    return SSH_AUTH_DENIED;
}

int handle_scp(ssh_session session, ssh_channel channel) {
    ssh_scp scp;
    char log_msg[256];
    int rc;

    write_log("Bắt đầu xử lý SCP");
    scp = ssh_scp_new(session, SSH_SCP_READ, "/home/qhung/uploaded_file");
    if (scp == NULL) {
        snprintf(log_msg, sizeof(log_msg), "Lỗi tạo SCP session: %s", ssh_get_error(session));
        write_log(log_msg);
        return -1;
    }
    write_log("SCP session được tạo");

    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        snprintf(log_msg, sizeof(log_msg), "Lỗi khởi tạo SCP: %s", ssh_get_error(session));
        write_log(log_msg);
        ssh_scp_free(scp);
        return -1;
    }
    write_log("Khởi tạo SCP thành công");

    write_log("Chờ yêu cầu SCP từ client");
    rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_NEWFILE) {
        snprintf(log_msg, sizeof(log_msg), "Không nhận được yêu cầu file mới: rc=%d", rc);
        write_log(log_msg);
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        return -1;
    }
    write_log("Nhận được yêu cầu file mới");

    long file_size = ssh_scp_request_get_size(scp);
    char *filename = strdup(ssh_scp_request_get_filename(scp));
    int permissions = ssh_scp_request_get_permissions(scp);
    snprintf(log_msg, sizeof(log_msg), "Nhận yêu cầu file: %s, kích thước: %ld bytes, quyền: %o", 
             filename, file_size, permissions);
    write_log(log_msg);

    ssh_scp_accept_request(scp);
    write_log("Đã chấp nhận yêu cầu SCP");

    FILE *file = fopen("/home/qhung/uploaded_file", "wb");
    if (file == NULL) {
        snprintf(log_msg, sizeof(log_msg), "Lỗi mở file để ghi: %s", strerror(errno));
        write_log(log_msg);
        free(filename);
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        return -1;
    }
    write_log("Mở file để ghi thành công");

    char buffer[4096];
    size_t total_received = 0;
    int nbytes;
    write_log("Bắt đầu nhận dữ liệu file");
    while (total_received < file_size && (nbytes = ssh_scp_read(scp, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, nbytes, file);
        total_received += nbytes;
        snprintf(log_msg, sizeof(log_msg), "Nhận %d bytes (tổng: %zu/%ld)", nbytes, total_received, file_size);
        write_log(log_msg);
    }

    if (nbytes < 0) {
        snprintf(log_msg, sizeof(log_msg), "Lỗi đọc dữ liệu SCP: %s", ssh_get_error(session));
        write_log(log_msg);
        fclose(file);
        free(filename);
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        return -1;
    }

    fclose(file);
    snprintf(log_msg, sizeof(log_msg), "Đã nhận file %s thành công (%zu bytes)", filename, total_received);
    write_log(log_msg);
    free(filename);

    ssh_scp_close(scp);
    ssh_scp_free(scp);
    write_log("Đóng SCP session");
    return 0;
}

int main(int argc, char *argv[]) {
    ssh_session session;
    ssh_bind sshbind;
    int port = 2222;
    int verbosity = SSH_LOG_PROTOCOL;
    char log_msg[256];

    printf("Starting SSH server...\n");
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        write_log("Lỗi khi tạo SSH bind");
        printf("Error creating sshbind\n");
        exit(1);
    }
    printf("sshbind created\n");

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, KEYS_FOLDER "ssh_server_key");

    if (ssh_bind_listen(sshbind) < 0) {
        snprintf(log_msg, sizeof(log_msg), "Lỗi khi lắng nghe socket: %s", ssh_get_error(sshbind));
        write_log(log_msg);
        printf("Bind error: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        exit(1);
    }
    snprintf(log_msg, sizeof(log_msg), "SSH server đang lắng nghe trên cổng %d", port);
    write_log(log_msg);
    printf("Server listening on port %d\n", port);

    while (1) {
        session = ssh_new();
        if (session == NULL) {
            write_log("Lỗi khi tạo SSH session");
            ssh_bind_free(sshbind);
            exit(1);
        }

        long timeout = 10; // Timeout 10 giây
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            snprintf(log_msg, sizeof(log_msg), "Lỗi khi chấp nhận kết nối: %s", ssh_get_error(sshbind));
            write_log(log_msg);
            ssh_free(session);
            continue;
        }
        snprintf(log_msg, sizeof(log_msg), "Đã chấp nhận kết nối từ client");
        write_log(log_msg);

        if (ssh_handle_key_exchange(session) != SSH_OK) {
            snprintf(log_msg, sizeof(log_msg), "Lỗi khi xử lý trao đổi khóa: %s", ssh_get_error(session));
            write_log(log_msg);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        write_log("Trao đổi khóa thành công");

        if (authenticate_user(session) != SSH_AUTH_SUCCESS) {
            write_log("Xác thực thất bại, ngắt kết nối");
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        ssh_channel channel = ssh_channel_new(session);
        if (channel == NULL) {
            snprintf(log_msg, sizeof(log_msg), "Lỗi khi tạo channel: %s", ssh_get_error(session));
            write_log(log_msg);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        write_log("Channel được tạo");

        if (ssh_channel_open_session(channel) != SSH_OK) {
            snprintf(log_msg, sizeof(log_msg), "Lỗi khi mở channel: %s", ssh_get_error(session));
            write_log(log_msg);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        write_log("Channel mở thành công");

        if (handle_scp(session, channel) < 0) {
            write_log("Lỗi khi xử lý SCP");
        }

        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
    }

    ssh_bind_free(sshbind);
    return 0;
}