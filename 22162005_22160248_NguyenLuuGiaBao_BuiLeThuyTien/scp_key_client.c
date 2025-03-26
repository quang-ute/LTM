#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <getopt.h>
#include <limits.h>

// Cấu trúc để theo dõi tiến trình truyền file
typedef struct {
    char filename[256];
    off_t filesize;
    off_t bytes_transferred;
    time_t start_time;
    time_t end_time;
} transfer_stats_t;

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -u <username> -h <host> -k <private_key_path> -s <source> -d <destination> [-p <port>] [--download]\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -u, --user       SSH username\n");
    fprintf(stderr, "  -h, --host       SSH host/IP address\n");
    fprintf(stderr, "  -k, --key        Path to private key file\n");
    fprintf(stderr, "  -s, --source     Source path (local for upload, remote for download)\n");
    fprintf(stderr, "  -d, --dest       Destination path (remote for upload, local for download)\n");
    fprintf(stderr, "  -p, --port       SSH port (default: 22)\n");
    fprintf(stderr, "  --download       Download from server instead of upload\n");
    fprintf(stderr, "  --help           Display this help message\n\n");
    fprintf(stderr, "Example (upload): %s -u seed -h 172.19.0.2 -k ~/.ssh/id_rsa -s ./local_dir/ -d ~/remote_dir/\n", prog_name);
    fprintf(stderr, "Example (download): %s -u seed -h 172.19.0.2 -k ~/.ssh/id_rsa -s ~/remote_dir/ -d ./local_dir/ --download\n", prog_name);
}

// Hiển thị tiến độ truyền file
void display_progress(transfer_stats_t *stats) {
    time_t current_time = time(NULL);
    double elapsed = difftime(current_time, stats->start_time);
    if (elapsed < 0.1) elapsed = 0.1; // Tránh chia cho 0
    
    double speed = stats->bytes_transferred / elapsed;
    double percent = (stats->bytes_transferred * 100.0) / stats->filesize;
    
    double remaining_bytes = stats->filesize - stats->bytes_transferred;
    double remaining_time = remaining_bytes / speed;
    
    char speed_unit[5] = "B/s";
    double display_speed = speed;
    
    if (display_speed > 1024) {
        display_speed /= 1024;
        strncpy(speed_unit, "KB/s", sizeof(speed_unit) - 1);
        speed_unit[sizeof(speed_unit) - 1] = '\0';
    }
    if (display_speed > 1024) {
        display_speed /= 1024;
        strncpy(speed_unit, "MB/s", sizeof(speed_unit) - 1);
        speed_unit[sizeof(speed_unit) - 1] = '\0';
    }
    
    printf("\r[%s] %.1f%% (%ld/%ld bytes) | %.2f %s | %.0fs elapsed | ETA: %.0fs", 
           stats->filename, percent, stats->bytes_transferred, stats->filesize, 
           display_speed, speed_unit, elapsed, remaining_time);
    fflush(stdout);
}

// Lấy tên file từ đường dẫn
const char* get_filename(const char *path) {
    const char *filename = strrchr(path, '/');
    if (filename == NULL) {
        return path;
    }
    return filename + 1;
}

// Tạo đường dẫn đầy đủ
char* construct_path(const char *base_path, const char *file) {
    const char *filename = get_filename(file);
    size_t base_len = strlen(base_path);
    size_t filename_len = strlen(filename);
    size_t total_len = base_len + filename_len + 2;
    
    char *full_path = malloc(total_len);
    if (full_path == NULL) {
        return NULL;
    }
    
    strcpy(full_path, base_path);
    if (base_len > 0 && base_path[base_len - 1] != '/') {
        strcat(full_path, "/");
    }
    strcat(full_path, filename);
    
    return full_path;
}

// Kiểm tra xem đường dẫn local có phải là thư mục không
int is_directory(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return 0;
    }
    return S_ISDIR(path_stat.st_mode);
}

// Upload một file qua SCP
int scp_upload_file(ssh_session session, const char *local_path, const char *remote_path) {
    struct stat file_stat;
    if (stat(local_path, &file_stat) != 0) {
        fprintf(stderr, "Error: Local file %s does not exist. Error: %s\n", local_path, strerror(errno));
        return -1;
    }
    
    transfer_stats_t stats;
    const char *filename = get_filename(local_path);
    strncpy(stats.filename, filename, sizeof(stats.filename) - 1);
    stats.filename[sizeof(stats.filename) - 1] = '\0';
    stats.filesize = file_stat.st_size;
    stats.bytes_transferred = 0;
    stats.start_time = time(NULL);
    
    ssh_scp scp = ssh_scp_new(session, SSH_SCP_WRITE, remote_path);
    if (scp == NULL) {
        fprintf(stderr, "Error creating SCP session: %s\n", ssh_get_error(session));
        return -1;
    }
    
    int rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SCP: %s\n", ssh_get_error(session));
        ssh_scp_free(scp);
        return -1;
    }
    
    int local_fd = open(local_path, O_RDONLY);
    if (local_fd < 0) {
        fprintf(stderr, "Error opening local file %s: %s\n", local_path, strerror(errno));
        ssh_scp_free(scp);
        return -1;
    }
    
    printf("Starting upload: %s (%ld bytes) to %s\n", stats.filename, stats.filesize, remote_path);
    
    rc = ssh_scp_push_file(scp, filename, file_stat.st_size, 0644);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error pushing file: %s\n", ssh_get_error(session));
        close(local_fd);
        ssh_scp_free(scp);
        return -1;
    }
    
    char buffer[16384];
    ssize_t bytes_read;
    
    while ((bytes_read = read(local_fd, buffer, sizeof(buffer))) > 0) {
        rc = ssh_scp_write(scp, buffer, bytes_read);
        if (rc != SSH_OK) {
            fprintf(stderr, "\nError writing file data: %s\n", ssh_get_error(session));
            close(local_fd);
            ssh_scp_free(scp);
            return -1;
        }
        
        stats.bytes_transferred += bytes_read;
        display_progress(&stats);
    }
    
    if (bytes_read < 0) {
        fprintf(stderr, "\nError reading from local file: %s\n", strerror(errno));
        close(local_fd);
        ssh_scp_free(scp);
        return -1;
    }
    
    stats.end_time = time(NULL);
    double transfer_time = difftime(stats.end_time, stats.start_time);
    if (transfer_time < 0.1) transfer_time = 0.1;
    
    double avg_speed = stats.filesize / transfer_time;
    char speed_unit[5] = "B/s";
    double display_speed = avg_speed;
    
    if (display_speed > 1024) {
        display_speed /= 1024;
        strncpy(speed_unit, "KB/s", sizeof(speed_unit) - 1);
    }
    if (display_speed > 1024) {
        display_speed /= 1024;
        strncpy(speed_unit, "MB/s", sizeof(speed_unit) - 1);
    }
    
    printf("\nUpload completed: %s (%.2f %s, %ld bytes in %.1f seconds)\n", 
           stats.filename, display_speed, speed_unit, stats.filesize, transfer_time);
    
    close(local_fd);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return 0;
}

// Download một file qua SCP
int scp_download_file(ssh_session session, const char *remote_path, const char *local_path) {
    ssh_scp scp = ssh_scp_new(session, SSH_SCP_READ, remote_path);
    if (scp == NULL) {
        fprintf(stderr, "Error creating SCP session: %s\n", ssh_get_error(session));
        return -1;
    }

    int rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SCP: %s\n", ssh_get_error(session));
        ssh_scp_free(scp);
        return -1;
    }

    rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_NEWFILE) {
        fprintf(stderr, "Error receiving file request: %s\n", ssh_get_error(session));
        ssh_scp_free(scp);
        return -1;
    }

    int file_size = ssh_scp_request_get_size(scp);
    const char *filename = ssh_scp_request_get_filename(scp);
    
    transfer_stats_t stats;
    strncpy(stats.filename, filename, sizeof(stats.filename) - 1);
    stats.filename[sizeof(stats.filename) - 1] = '\0';
    stats.filesize = file_size;
    stats.bytes_transferred = 0;
    stats.start_time = time(NULL);

    int local_fd = open(local_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (local_fd < 0) {
        fprintf(stderr, "Error opening local file %s: %s\n", local_path, strerror(errno));
        ssh_scp_free(scp);
        return -1;
    }

    printf("Starting download: %s (%ld bytes) to %s\n", stats.filename, stats.filesize, local_path);
    ssh_scp_accept_request(scp);

    char buffer[16384];
    int bytes_read;

    while ((bytes_read = ssh_scp_read(scp, buffer, sizeof(buffer))) > 0) {
        if (write(local_fd, buffer, bytes_read) != bytes_read) {
            fprintf(stderr, "Error writing to local file: %s\n", strerror(errno));
            close(local_fd);
            ssh_scp_free(scp);
            return -1;
        }
        stats.bytes_transferred += bytes_read;
        display_progress(&stats);
    }

    if (bytes_read < 0) {
        fprintf(stderr, "Error reading from remote file: %s\n", ssh_get_error(session));
        close(local_fd);
        ssh_scp_free(scp);
        return -1;
    }

    stats.end_time = time(NULL);
    double transfer_time = difftime(stats.end_time, stats.start_time);
    if (transfer_time < 0.1) transfer_time = 0.1;
    
    double avg_speed = stats.filesize / transfer_time;
    char speed_unit[5] = "B/s";
    double display_speed = avg_speed;
    
    if (display_speed > 1024) {
        display_speed /= 1024;
        strncpy(speed_unit, "KB/s", sizeof(speed_unit) - 1);
    }
    if (display_speed > 1024) {
        display_speed /= 1024;
        strncpy(speed_unit, "MB/s", sizeof(speed_unit) - 1);
    }
    
    printf("\nDownload completed: %s (%.2f %s, %ld bytes in %.1f seconds)\n", 
           stats.filename, display_speed, speed_unit, stats.filesize, transfer_time);

    close(local_fd);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return 0;
}

// Upload tất cả file trong thư mục (đệ quy)
int scp_upload_directory(ssh_session session, const char *local_dir, const char *remote_dir) {
    DIR *dir = opendir(local_dir);
    if (dir == NULL) {
        fprintf(stderr, "Error opening directory %s: %s\n", local_dir, strerror(errno));
        return -1;
    }
    
    int success_count = 0, fail_count = 0;
    struct dirent *entry;
    
    printf("Uploading files from directory: %s\n", local_dir);
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char local_path[PATH_MAX];
        snprintf(local_path, PATH_MAX, "%s/%s", local_dir, entry->d_name);
        
        char *remote_path = construct_path(remote_dir, entry->d_name);
        if (remote_path == NULL) {
            fprintf(stderr, "Error constructing remote path for %s\n", entry->d_name);
            continue;
        }
        
        if (is_directory(local_path)) {
            printf("Skipping subdirectory: %s (recursive upload not implemented)\n", entry->d_name);
            free(remote_path);
            continue;
        }
        
        if (scp_upload_file(session, local_path, remote_path) == 0) {
            success_count++;
        } else {
            fail_count++;
        }
        free(remote_path);
    }
    
    closedir(dir);
    printf("\nDirectory upload completed: %d files uploaded, %d failed\n", success_count, fail_count);
    return (fail_count == 0) ? 0 : -1;
}

// Kiểm tra thư mục từ xa tồn tại và liệt kê file (dùng lệnh ls qua SSH channel)
int list_remote_directory(ssh_session session, const char *remote_dir, char *file_list[], int *file_count) {
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "Error creating channel: %s\n", ssh_get_error(session));
        return -1;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return -1;
    }

    char command[PATH_MAX];
    snprintf(command, PATH_MAX, "ls -A %s", remote_dir);
    if (ssh_channel_request_exec(channel, command) != SSH_OK) {
        fprintf(stderr, "Error executing ls command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }

    char buffer[1024];
    int nbytes;
    *file_count = 0;

    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[nbytes] = '\0';
        char *token = strtok(buffer, "\n");
        while (token != NULL && *file_count < 256) {
            file_list[*file_count] = strdup(token);
            (*file_count)++;
            token = strtok(NULL, "\n");
        }
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return 0;
}

// Download tất cả file trong thư mục từ xa (không đệ quy)
int scp_download_directory(ssh_session session, const char *remote_dir, const char *local_dir) {
    char *file_list[256];
    int file_count = 0;
    int success_count = 0, fail_count = 0;

    if (list_remote_directory(session, remote_dir, file_list, &file_count) != 0) {
        return -1;
    }

    if (file_count == 0) {
        printf("No files found in remote directory: %s\n", remote_dir);
        return 0;
    }

    printf("Downloading files from remote directory: %s\n", remote_dir);

    for (int i = 0; i < file_count; i++) {
        char remote_path[PATH_MAX];
        snprintf(remote_path, PATH_MAX, "%s/%s", remote_dir, file_list[i]);

        char *local_path = construct_path(local_dir, file_list[i]);
        if (local_path == NULL) {
            fprintf(stderr, "Error constructing local path for %s\n", file_list[i]);
            free(file_list[i]);
            continue;
        }

        if (scp_download_file(session, remote_path, local_path) == 0) {
            success_count++;
        } else {
            fail_count++;
        }

        free(local_path);
        free(file_list[i]);
    }

    printf("\nDirectory download completed: %d files downloaded, %d failed\n", success_count, fail_count);
    return (fail_count == 0) ? 0 : -1;
}

// Hàm kiểm tra xem đường dẫn từ xa có phải là thư mục không
int is_remote_directory(ssh_session session, const char *remote_path) {
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        return 0;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return 0;
    }

    char command[PATH_MAX];
    snprintf(command, PATH_MAX, "test -d %s && echo DIR || echo FILE", remote_path);

    if (ssh_channel_request_exec(channel, command) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return 0;
    }

    char buffer[16];
    int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
    buffer[nbytes] = '\0';

    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return (strncmp(buffer, "DIR", 3) == 0);
}

int main(int argc, char *argv[]) {
    char *username = NULL;
    char *hostname = NULL;
    char *priv_key_path = NULL;
    char *source_path = NULL;
    char *dest_path = NULL;
    int port = 22;
    int download_mode = 0;

    static struct option long_options[] = {
        {"user", required_argument, 0, 'u'},
        {"host", required_argument, 0, 'h'},
        {"key", required_argument, 0, 'k'},
        {"source", required_argument, 0, 's'},
        {"dest", required_argument, 0, 'd'},
        {"port", required_argument, 0, 'p'},
        {"download", no_argument, 0, 'D'},
        {"help", no_argument, 0, 'H'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "u:h:k:s:d:p:DH", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'u': username = optarg; break;
            case 'h': hostname = optarg; break;
            case 'k': priv_key_path = optarg; break;
            case 's': source_path = optarg; break;
            case 'd': dest_path = optarg; break;
            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "Invalid port number: %s\n", optarg);
                    exit(-1);
                }
                break;
            case 'D': download_mode = 1; break;
            case 'H': print_usage(argv[0]); exit(0);
            default: print_usage(argv[0]); exit(-1);
        }
    }

    if (!username || !hostname || !priv_key_path || !source_path || !dest_path) {
        fprintf(stderr, "Error: Missing required arguments\n");
        print_usage(argv[0]);
        exit(-1);
    }

    printf("Connecting to %s@%s:%d...\n", username, hostname, port);
    ssh_session my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        exit(-1);
    }

    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, username);

    int rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to %s:%d: %s\n", hostname, port, ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    printf("Connected to %s. Verifying server identity...\n", hostname);

    printf("Loading private key: %s\n", priv_key_path);
    ssh_key priv_key;
    rc = ssh_pki_import_privkey_file(priv_key_path, NULL, NULL, NULL, &priv_key);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error importing private key: %s\n", ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    printf("Authenticating with key...\n");
    rc = ssh_userauth_publickey(my_ssh_session, NULL, priv_key);
    ssh_key_free(priv_key);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    printf("Authentication successful!\n");

    int result;
    if (download_mode) {
        // Download mode: source là remote, dest là local
        if (is_remote_directory(my_ssh_session, source_path)) {
            printf("Source is a remote directory. Preparing to download multiple files...\n");
            if (!is_directory(dest_path)) {
                fprintf(stderr, "Error: Destination must be a directory for downloading a remote directory\n");
                ssh_disconnect(my_ssh_session);
                ssh_free(my_ssh_session);
                exit(-1);
            }
            result = scp_download_directory(my_ssh_session, source_path, dest_path);
        } else {
            printf("Source is a remote file. Preparing to download single file...\n");
            char *local_file_path;
            if (is_directory(dest_path)) {
                // Nếu đích là thư mục, tạo đường dẫn đầy đủ cho file đích
                local_file_path = construct_path(dest_path, source_path);
                if (!local_file_path) {
                    fprintf(stderr, "Error: Failed to construct local file path\n");
                    ssh_disconnect(my_ssh_session);
                    ssh_free(my_ssh_session);
                    exit(-1);
                }
            } else {
                local_file_path = strdup(dest_path);
            }
            result = scp_download_file(my_ssh_session, source_path, local_file_path);
            free(local_file_path);
        }
    } else {
        // Upload mode: source là local, dest là remote
        if (is_directory(source_path)) {
            printf("Source is a directory. Preparing to upload multiple files...\n");
            result = scp_upload_directory(my_ssh_session, source_path, dest_path);
        } else {
            printf("Source is a file. Preparing to upload single file...\n");
            result = scp_upload_file(my_ssh_session, source_path, dest_path);
        }
    }

    printf("Closing connection...\n");
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    printf("Connection closed.\n");

    return result;
}