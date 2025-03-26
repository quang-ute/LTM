#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>  // Add this to define O_WRONLY, O_RDONLY, O_CREAT, O_TRUNC

#define BUFFER_SIZE 4096

// Function to upload file to remote server using SFTP
int upload_file(ssh_session session, const char *local_path, const char *remote_path) {
    sftp_session sftp;
    sftp_file file;
    FILE *local_file;
    int rc;
    char buffer[BUFFER_SIZE];
    size_t nread;

    // Open local file
    local_file = fopen(local_path, "rb");
    if (local_file == NULL) {
        fprintf(stderr, "Error opening local file: %s\n", local_path);
        return -1;
    }

    // Initialize SFTP session
    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error creating SFTP session: %s\n", ssh_get_error(session));
        fclose(local_file);
        return -1;
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        fclose(local_file);
        return -1;
    }

    // Open remote file for writing
    file = sftp_open(sftp, remote_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (file == NULL) {
        fprintf(stderr, "Error opening remote file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        fclose(local_file);
        return -1;
    }

    // Transfer file data
    while ((nread = fread(buffer, 1, sizeof(buffer), local_file)) > 0) {
        ssize_t nwritten = sftp_write(file, buffer, nread);
        if (nwritten != nread) {
            fprintf(stderr, "Error writing file data: %s\n", ssh_get_error(session));
            sftp_close(file);
            sftp_free(sftp);
            fclose(local_file);
            return -1;
        }
    }

    fclose(local_file);
    sftp_close(file);
    sftp_free(sftp);
    return 0;
}

// Function to download file from remote server using SFTP
/*
    The download_file function is similar to the upload_file function, but in reverse.
    It opens a remote file for reading and a local file for writing, then reads data from the remote file and writes it to the local file.
    The file size is determined by getting the file attributes using sftp_fstat, and the download progress is displayed as a percentage.
*/
int download_file(ssh_session session, const char *remote_path, const char *local_path) {
    sftp_session sftp;
    sftp_file file;
    FILE *local_file;
    int rc;
    char buffer[BUFFER_SIZE];

    // Initialize SFTP session
    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error creating SFTP session: %s\n", ssh_get_error(session));
        return -1;
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    // Open remote file for reading
    file = sftp_open(sftp, remote_path, O_RDONLY, 0);
    if (file == NULL) {
        fprintf(stderr, "Error opening remote file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    // Get file attributes to determine file size
    sftp_attributes attrs = sftp_fstat(file);
    if (attrs == NULL) {
        fprintf(stderr, "Error getting file attributes: %s\n", ssh_get_error(session));
        sftp_close(file);
        sftp_free(sftp);
        return -1;
    }

    uint64_t file_size = attrs->size;
    sftp_attributes_free(attrs);

    // Open local file for writing
    local_file = fopen(local_path, "wb");
    if (local_file == NULL) {
        fprintf(stderr, "Error opening local file: %s\n", local_path);
        sftp_close(file);
        sftp_free(sftp);
        return -1;
    }

    // Read file data
    uint64_t total_read = 0;
    ssize_t nread;
    while ((nread = sftp_read(file, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, nread, local_file);
        total_read += nread;
        printf("\rDownloading... %.2f%%", (float)total_read / file_size * 100);
        fflush(stdout);
    }

    if (nread < 0) {
        fprintf(stderr, "\nError reading file: %s\n", ssh_get_error(session));
        fclose(local_file);
        sftp_close(file);
        sftp_free(sftp);
        return -1;
    }

    printf("\nDownload complete\n");

    fclose(local_file);
    sftp_close(file);
    sftp_free(sftp);
    return 0;
}

int main(int argc, char *argv[]) {
    ssh_session my_ssh_session;
    int rc;

    if (argc != 5) {
        fprintf(stderr, "Usage: %s <upload|download> <local_path> <remote_path> <password>\n", argv[0]);
        return -1;
    }

    // Initialize SSH session
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        return -1;
    }

    // Set connection options
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "10.107.3,29");// Modify this IP
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "zyna");// Modify this user

    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        return -1;
    }

    // Authenticate
    rc = ssh_userauth_password(my_ssh_session, NULL, argv[4]);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating: %s\n", ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return -1;
    }

    // Perform file transfer
    if (strcmp(argv[1], "upload") == 0) {
        printf("Uploading %s to %s...\n", argv[2], argv[3]);
        rc = upload_file(my_ssh_session, argv[2], argv[3]);
    } else if (strcmp(argv[1], "download") == 0) {
        printf("Downloading %s to %s...\n", argv[3], argv[2]);
        rc = download_file(my_ssh_session, argv[3], argv[2]);
    } else {
        fprintf(stderr, "Invalid operation. Use 'upload' or 'download'\n");
        rc = -1;
    }

    if (rc == 0) {
        printf("File transfer completed successfully!\n");
    }

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return rc;
}