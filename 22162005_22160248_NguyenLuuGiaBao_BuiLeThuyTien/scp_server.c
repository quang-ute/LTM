#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <pthread.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 2222
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 5

typedef struct {
    char filename[256];
    size_t filesize;
    char destination[512];
    time_t start_time;
    time_t end_time;
    char client_ip[INET_ADDRSTRLEN];
} file_transfer_info;

void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

void format_time(int seconds, char *buffer, size_t size) {
    int hours = seconds / 3600;
    int minutes = (seconds % 3600) / 60;
    int secs = seconds % 60;
    snprintf(buffer, size, "%02d:%02d:%02d", hours, minutes, secs);
}

void format_size(size_t size, char *buffer, size_t buf_size) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size_d = (double)size;
    while (size_d >= 1024.0 && unit_index < 4) {
        size_d /= 1024.0;
        unit_index++;
    }
    snprintf(buffer, buf_size, "%.2f %s", size_d, units[unit_index]);
}

int handle_scp_upload(ssh_session session, ssh_channel channel, const char *command, const char *client_ip) {
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    printf("[%s] [INFO] SCP upload command received from %s: %s\n", timestamp, client_ip, command);

    char destination[512] = {0};
    if (sscanf(command, "scp -t %511s", destination) != 1) {
        fprintf(stderr, "[%s] [ERROR] Invalid SCP upload command: %s\n", timestamp, command);
        return SSH_ERROR;
    }

    struct stat st = {0};
    if (stat(destination, &st) == -1) {
        if (mkdir(destination, 0755) == -1 && errno != EEXIST) {
            fprintf(stderr, "[%s] [ERROR] Failed to create directory %s: %s\n", timestamp, destination, strerror(errno));
            return SSH_ERROR;
        }
    }

    char ok = 0;
    ssh_channel_write(channel, &ok, 1);

    file_transfer_info transfer_info = {0};
    strncpy(transfer_info.destination, destination, sizeof(transfer_info.destination) - 1);
    strncpy(transfer_info.client_ip, client_ip, sizeof(transfer_info.client_ip) - 1);

    char buffer[BUFFER_SIZE];
    int nbytes = ssh_channel_read(channel, buffer, BUFFER_SIZE, 0);
    if (nbytes <= 0) {
        fprintf(stderr, "[%s] [ERROR] Failed to read file header: %s\n", timestamp, ssh_get_error(session));
        return SSH_ERROR;
    }
    buffer[nbytes] = '\0';

    long mode;
    size_t size;
    char filename[256];
    if (sscanf(buffer, "C%lo %zu %255s", &mode, &size, filename) != 3) {
        fprintf(stderr, "[%s] [ERROR] Invalid file header: %s\n", timestamp, buffer);
        return SSH_ERROR;
    }

    strncpy(transfer_info.filename, filename, sizeof(transfer_info.filename) - 1);
    transfer_info.filesize = size;
    transfer_info.start_time = time(NULL);

    char size_str[32];
    format_size(size, size_str, sizeof(size_str));
    get_timestamp(timestamp, sizeof(timestamp));
    printf("[%s] [INFO] Receiving %s (%s) from %s to %s\n", timestamp, filename, size_str, client_ip, destination);

    ssh_channel_write(channel, &ok, 1);

    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s", destination, filename);
    FILE *file = fopen(filepath, "wb");
    if (!file) {
        fprintf(stderr, "[%s] [ERROR] Failed to open %s: %s\n", timestamp, filepath, strerror(errno));
        return SSH_ERROR;
    }

    size_t total_received = 0;
    while (total_received < size) {
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes <= 0) {
            fclose(file);
            fprintf(stderr, "[%s] [ERROR] Failed to read file content: %s\n", timestamp, ssh_get_error(session));
            return SSH_ERROR;
        }
        fwrite(buffer, 1, nbytes, file);
        total_received += nbytes;

        char size_received[32];
        format_size(total_received, size_received, sizeof(size_received));
        get_timestamp(timestamp, sizeof(timestamp));
        printf("[%s] [PROGRESS] %s: %s/%s received from %s\n", timestamp, filename, size_received, size_str, client_ip);
    }

    fclose(file);
    ssh_channel_read(channel, buffer, 1, 0);
    ssh_channel_write(channel, &ok, 1);

    transfer_info.end_time = time(NULL);
    int transfer_time = transfer_info.end_time - transfer_info.start_time;
    char elapsed_time[32];
    format_time(transfer_time, elapsed_time, sizeof(elapsed_time));

    get_timestamp(timestamp, sizeof(timestamp));
    printf("[%s] [COMPLETE] Upload from %s: %s (%s) to %s, Time: %s\n", 
           timestamp, client_ip, filename, size_str, filepath, elapsed_time);
    return SSH_OK;
}

int handle_channel(ssh_session session, ssh_channel channel, const char *command, const char *client_ip) {
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    printf("[%s] [DEBUG] Handling command from %s: %s\n", timestamp, client_ip, command);

    if (strncmp(command, "scp -t", 6) == 0) {
        return handle_scp_upload(session, channel, command, client_ip);
    }
    printf("[%s] [ERROR] Unsupported command from %s: %s\n", timestamp, client_ip, command);
    return SSH_ERROR;
}

void *handle_connection(void *arg) {
    ssh_session session = (ssh_session)arg;
    ssh_channel channel = NULL;
    ssh_message message;
    char command[512] = {0};
    char timestamp[32];

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    getpeername(ssh_get_fd(session), (struct sockaddr *)&client_addr, &client_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

    get_timestamp(timestamp, sizeof(timestamp));
    printf("[%s] [DEBUG] Waiting for channel request from %s\n", timestamp, client_ip);

    while (1) {
        message = ssh_message_get(session);
        if (!message) {
            fprintf(stderr, "[%s] [ERROR] Failed to get message: %s\n", timestamp, ssh_get_error(session));
            break;
        }

        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN && 
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            channel = ssh_message_channel_request_open_reply_accept(message);
            get_timestamp(timestamp, sizeof(timestamp));
            printf("[%s] [INFO] Channel opened for %s\n", timestamp, client_ip);
            ssh_message_free(message);
            break;
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    if (!channel) {
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    int command_received = 0;
    while (!command_received) {
        message = ssh_message_get(session);
        if (!message) break;

        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL && 
            ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_EXEC) {
            strncpy(command, ssh_message_channel_request_command(message), sizeof(command) - 1);
            get_timestamp(timestamp, sizeof(timestamp));
            printf("[%s] [INFO] Command received from %s: %s\n", timestamp, client_ip, command);
            ssh_message_channel_request_reply_success(message);
            command_received = 1;
        }
        ssh_message_free(message);
    }

    if (command_received) {
        handle_channel(session, channel, command, client_ip);
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    get_timestamp(timestamp, sizeof(timestamp));
    printf("[%s] [INFO] Connection closed from %s\n", timestamp, client_ip);
    return NULL;
}

int main(int argc, char **argv) {
    ssh_bind sshbind;
    ssh_session session;
    pthread_t thread;
    int port = DEFAULT_PORT;
    char timestamp[32];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[i + 1]);
        }
    }

    ssh_init();
    sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "./ssh_host_rsa_key");

    if (ssh_bind_listen(sshbind) < 0) {
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(stderr, "[%s] [ERROR] Cannot listen on port %d: %s\n", timestamp, port, ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        ssh_finalize();
        return 1;
    }

    get_timestamp(timestamp, sizeof(timestamp));
    printf("[%s] [INFO] SCP Server started on port %d\n", timestamp, port);

    while (1) {
        session = ssh_new();
        if (session == NULL) continue;

        if (ssh_bind_accept(sshbind, session) != SSH_OK) {
            ssh_free(session);
            continue;
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        getpeername(ssh_get_fd(session), (struct sockaddr *)&client_addr, &client_len);
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        get_timestamp(timestamp, sizeof(timestamp));
        printf("[%s] [INFO] New connection from %s:%d\n", timestamp, client_ip, ntohs(client_addr.sin_port));

        if (ssh_handle_key_exchange(session) != SSH_OK) {
            fprintf(stderr, "[%s] [ERROR] Key exchange failed: %s\n", timestamp, ssh_get_error(session));
            ssh_free(session);
            continue;
        }

        get_timestamp(timestamp, sizeof(timestamp));
        printf("[%s] [INFO] Key exchange completed with %s\n", timestamp, client_ip);

        // Simplified authentication - accept any auth method
        ssh_message message;
        int authenticated = 0;
        while (!authenticated) {
            message = ssh_message_get(session);
            if (!message) {
                fprintf(stderr, "[%s] [ERROR] No auth message received\n", timestamp);
                break;
            }

            if (ssh_message_type(message) == SSH_REQUEST_AUTH) {
                ssh_message_auth_reply_success(message, 0);
                authenticated = 1;
                get_timestamp(timestamp, sizeof(timestamp));
                printf("[%s] [INFO] Authentication successful for %s (user: %s)\n", 
                       timestamp, client_ip, ssh_message_auth_user(message));
            }
            ssh_message_free(message);
        }

        if (!authenticated) {
            ssh_free(session);
            continue;
        }

        if (pthread_create(&thread, NULL, handle_connection, session) != 0) {
            ssh_free(session);
            continue;
        }
        pthread_detach(thread);
    }

    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}