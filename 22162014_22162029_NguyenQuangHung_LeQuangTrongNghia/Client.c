#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

// Hàm lấy kích thước tệp
long get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

// Hàm kiểm tra xem đường dẫn có phải là thư mục không
int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return 0;
}

// Hàm tạo thư mục từ xa nếu chưa tồn tại
int create_remote_dir(ssh_session session, const char *remote_path) {
    sftp_session sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error creating SFTP session: %s\n", ssh_get_error(session));
        return -1;
    }

    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    int rc = sftp_mkdir(sftp, remote_path, 0755);
    if (rc != SSH_OK && sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS) {
        fprintf(stderr, "Error creating remote directory %s: %s\n", remote_path, ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    sftp_free(sftp);
    return 0;
}

// Hàm đẩy một tệp với thông tin chi tiết
int push_file(ssh_session session, ssh_scp scp, const char *local_file, const char *remote_file) {
    int rc;
    char buffer[4096];
    FILE *local_fp;
    clock_t start_time, end_time;
    double time_taken;

    long file_size = get_file_size(local_file);
    if (file_size < 0) {
        fprintf(stderr, "Error getting size of %s: %s\n", local_file, strerror(errno));
        return -1;
    }

    local_fp = fopen(local_file, "rb");
    if (local_fp == NULL) {
        fprintf(stderr, "Error opening %s: %s\n", local_file, strerror(errno));
        return -1;
    }

    scp = ssh_scp_new(session, SSH_SCP_WRITE, remote_file);
    if (scp == NULL) {
        fprintf(stderr, "Error creating SCP session: %s\n", ssh_get_error(session));
        fclose(local_fp);
        return -1;
    }

    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SCP: %s\n", ssh_get_error(session));
        fclose(local_fp);
        ssh_scp_free(scp);
        return -1;
    }

    rc = ssh_scp_push_file(scp, remote_file, file_size, 0644);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error starting file transfer: %s\n", ssh_get_error(session));
        fclose(local_fp);
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        return -1;
    }

    printf("Starting transfer: %s (Size: %ld bytes)\n", local_file, file_size);
    start_time = clock();

    size_t total_written = 0;
    while (total_written < file_size) {
        size_t to_read = (file_size - total_written < sizeof(buffer)) ? 
                         file_size - total_written : sizeof(buffer);
        size_t nread = fread(buffer, 1, to_read, local_fp);
        if (nread == 0) {
            if (feof(local_fp)) {
                fprintf(stderr, "Unexpected end of file %s: read %zu of %ld bytes\n", 
                        local_file, total_written, file_size);
            } else if (ferror(local_fp)) {
                fprintf(stderr, "Error reading %s: %s\n", local_file, strerror(errno));
            }
            fclose(local_fp);
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            return -1;
        }
        rc = ssh_scp_write(scp, buffer, nread);
        if (rc != SSH_OK) {
            fprintf(stderr, "Error writing to %s: %s\n", remote_file, ssh_get_error(session));
            fclose(local_fp);
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            return -1;
        }
        total_written += nread;
        printf("Transferring %s: %zu/%ld bytes completed\n", local_file, total_written, file_size);
    }

    end_time = clock();
    time_taken = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    fclose(local_fp);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    printf("Completed transfer: %s to %s (Size: %ld bytes, Time: %.3f seconds)\n", 
           local_file, remote_file, file_size, time_taken);
    return 0;
}

// Hàm đẩy tất cả tệp trong thư mục
int push_files_in_dir(ssh_session session, ssh_scp scp, const char *local_dir, const char *remote_dir) {
    DIR *dir;
    struct dirent *entry;
    clock_t start_time, end_time;
    double total_time = 0;
    int file_count = 0;

    if (!(dir = opendir(local_dir))) {
        fprintf(stderr, "Error opening directory %s: %s\n", local_dir, strerror(errno));
        return -1;
    }

    printf("Starting to push files from %s to %s\n", local_dir, remote_dir);
    start_time = clock();

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char local_path[1024];
        snprintf(local_path, sizeof(local_path), "%s/%s", local_dir, entry->d_name);

        if (!is_directory(local_path)) { // Chỉ xử lý tệp
            char remote_path[1024];
            snprintf(remote_path, sizeof(remote_path), "%s/%s", remote_dir, entry->d_name);

            if (push_file(session, scp, local_path, remote_path) < 0) {
                closedir(dir);
                return -1;
            }
            file_count++;
        }
    }

    end_time = clock();
    total_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    closedir(dir);
    printf("Completed pushing %d files from %s to %s (Total time: %.3f seconds)\n", 
           file_count, local_dir, remote_dir, total_time);
    return 0;
}

// Hàm xử lý push chung
int push_item(ssh_session session, ssh_scp scp, const char *local_path, const char *remote_path) {
    if (create_remote_dir(session, remote_path) < 0) {
        return -1;
    }

    if (is_directory(local_path)) {
        return push_files_in_dir(session, scp, local_path, remote_path);
    } else {
        return push_file(session, scp, local_path, remote_path);
    }
}

int main(int argc, char *argv[]) {
    ssh_session my_ssh_session;
    ssh_scp scp = NULL;
    int rc;

    if (argc < 4 || (strcmp(argv[1], "push") != 0)) {
        fprintf(stderr, "Usage: %s push <local_file1_or_dir1> <local_file2_or_dir2> ... <remote_dir>\n", argv[0]);
        exit(1);
    }

    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        exit(1);
    }

    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "192.168.189.128");
    unsigned int port = 2222;
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "qhung");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_IDENTITY, "/home/qhung/.ssh/id_ed25519");

    printf("Attempting to connect to %s:%u as user %s...\n", "192.168.189.128", port, "qhung");
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(1);
    }

    printf("Connection established. Authenticating...\n");
    rc = ssh_userauth_publickey_auto(my_ssh_session, NULL, NULL);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating: %s\n", ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(1);
    }

    printf("Successfully connected and authenticated to %s:%u as %s!\n", 
           "192.168.189.128", port, "qhung");

    char *destination = argv[argc - 1];
    int item_count = argc - 3;

    for (int i = 0; i < item_count; i++) {
        char *local_item = argv[i + 2];
        char remote_path[1024];

        if (is_directory(local_item)) {
            snprintf(remote_path, sizeof(remote_path), "%s", destination);
        } else {
            snprintf(remote_path, sizeof(remote_path), "%s/%s", 
                    destination, strrchr(local_item, '/') ? strrchr(local_item, '/') + 1 : local_item);
        }

        if (push_item(my_ssh_session, scp, local_item, remote_path) < 0) {
            fprintf(stderr, "Failed to push %s\n", local_item);
        }
    }

    printf("Disconnecting from server...\n");
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    printf("Disconnected successfully.\n");

    return 0;
}