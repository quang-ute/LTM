#include <libssh/server.h>
#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <pwd.h>

#define BUFFER_SIZE 16384
#define DEFAULT_PORT 2222
#define MAX_CLIENTS 10

typedef struct {
    uint64_t file_size;
    char filename[256];
} file_metadata_t;

// Structure to maintain client connection and data
typedef struct {
    ssh_session session;
    ssh_channel channel;
    int thread_id;
    char dest_dir[256];
    struct timeval start_time;
} client_info_t;

// Get current time in milliseconds
uint64_t get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

// Calculate elapsed time in seconds
double get_elapsed_time(struct timeval *start) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec - start->tv_sec) + 
           (now.tv_usec - start->tv_usec) / 1000000.0;
}

// Format time into HH:MM:SS.mmm format
void format_time(double seconds, char *buffer) {
    int hours = (int)seconds / 3600;
    int mins = ((int)seconds % 3600) / 60;
    int secs = (int)seconds % 60;
    int ms = (int)((seconds - (int)seconds) * 1000);
    
    sprintf(buffer, "%02d:%02d:%02d.%03d", hours, mins, secs, ms);
}

// Format size into human-readable format
void format_size(uint64_t size, char *buffer) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size_d = size;
    
    while (size_d >= 1024 && unit < 4) {
        size_d /= 1024;
        unit++;
    }
    
    sprintf(buffer, "%.2f %s", size_d, units[unit]);
}

// Create directory if it doesn't exist
int ensure_directory(const char *path) {
    struct stat st = {0};
    
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0755) != 0) {
            fprintf(stderr, "Error creating directory %s: %s\n", 
                    path, strerror(errno));
            return -1;
        }
        printf("Created directory: %s\n", path);
    }
    
    return 0;
}

// Handle client connection and file transfers
void* handle_client(void *arg) {
    client_info_t *client = (client_info_t*)arg;
    ssh_channel channel = client->channel;
    int rc;
    char buffer[BUFFER_SIZE];
    char time_buffer[20];
    char size_buffer[20];
    
    printf("Client %d: Connection accepted\n", client->thread_id);
    
    // Create destination directory if it doesn't exist
    if (ensure_directory(client->dest_dir) != 0) {
        ssh_channel_close(channel);
        return NULL;
    }
    
    while (1) {
        // Receive file metadata
        file_metadata_t metadata;
        rc = ssh_channel_read(channel, &metadata, sizeof(metadata), 0);
        
        if (rc <= 0) {
            if (rc < 0)
                fprintf(stderr, "Client %d: Error reading metadata\n", client->thread_id);
            break;  // Connection closed or error
        }
        
        // Check if this is the end marker
        if (metadata.file_size == 0 && metadata.filename[0] == '\0') {
            printf("Client %d: All files transferred successfully\n", client->thread_id);
            break;
        }
        
        // Create full path for destination file
        char dest_path[512];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", 
                client->dest_dir, metadata.filename);
        
        // Print file information
        format_size(metadata.file_size, size_buffer);
        printf("Client %d: Receiving file: %s (%s)\n", 
               client->thread_id, metadata.filename, size_buffer);
        
        // Start timing
        struct timeval file_start;
        gettimeofday(&file_start, NULL);
        
        // Open file for writing
        FILE *file = fopen(dest_path, "wb");
        if (!file) {
            fprintf(stderr, "Client %d: Error creating file %s: %s\n", 
                    client->thread_id, dest_path, strerror(errno));
            // Send error to client
            int error_code = -1;
            ssh_channel_write(channel, &error_code, sizeof(error_code));
            continue;
        }
        
        // Send OK to client
        int status = 0;
        ssh_channel_write(channel, &status, sizeof(status));
        
        // Receive and write file data
        uint64_t bytes_received = 0;
        uint64_t last_progress = 0;
        int progress_interval = metadata.file_size / 20;  // Show progress every 5%
        if (progress_interval < 1) progress_interval = 1;
        
        while (bytes_received < metadata.file_size) {
            uint64_t remaining = metadata.file_size - bytes_received;
            size_t to_read = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
            
            rc = ssh_channel_read(channel, buffer, to_read, 0);
            if (rc <= 0) {
                if (rc < 0)
                    fprintf(stderr, "Client %d: Error reading file data\n", client->thread_id);
                break;
            }
            
            size_t written = fwrite(buffer, 1, rc, file);
            if (written != rc) {
                fprintf(stderr, "Client %d: Error writing to file: %s\n", 
                        client->thread_id, strerror(errno));
                break;
            }
            
            bytes_received += rc;
            
            // Show progress periodically
            if (bytes_received - last_progress >= progress_interval) {
                double progress = (double)bytes_received / metadata.file_size * 100;
                double elapsed = get_elapsed_time(&file_start);
                format_time(elapsed, time_buffer);
                
                printf("Client %d: %s - %.2f%% complete (%s elapsed)\r", 
                       client->thread_id, metadata.filename, progress, time_buffer);
                fflush(stdout);
                
                last_progress = bytes_received;
            }
        }
        
        // Close file
        fclose(file);
        
        // Check if we received all data
        if (bytes_received == metadata.file_size) {
            double elapsed = get_elapsed_time(&file_start);
            format_time(elapsed, time_buffer);
            
            double transfer_rate = (metadata.file_size / 1024.0) / elapsed;
            printf("\nClient %d: File %s received successfully (%s elapsed, %.2f KB/s)\n", 
                   client->thread_id, metadata.filename, time_buffer, transfer_rate);
            
            // Send confirmation to client
            int success = 1;
            ssh_channel_write(channel, &success, sizeof(success));
        } else {
            fprintf(stderr, "\nClient %d: File %s transfer incomplete\n", 
                    client->thread_id, metadata.filename);
            
            // Send error to client
            int error_code = -2;
            ssh_channel_write(channel, &error_code, sizeof(error_code));
        }
    }
    
    // Calculate total session time
    double total_time = get_elapsed_time(&client->start_time);
    format_time(total_time, time_buffer);
    printf("Client %d: Session complete, total time: %s\n", client->thread_id, time_buffer);
    
    // Clean up
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    free(client);
    return NULL;
}

int authenticate(ssh_session session) {
    ssh_message message;
    ssh_key pubkey;
    int auth_attempts = 0;
    int authenticated = 0;
    
    do {
        message = ssh_message_get(session);
        if (!message) {
            break;
        }
        
        if (ssh_message_type(message) == SSH_REQUEST_AUTH &&
            ssh_message_subtype(message) == SSH_AUTH_METHOD_PUBLICKEY) {
            
            pubkey = ssh_message_auth_pubkey(message);
            printf("Public key authentication attempt from %s\n", 
                   ssh_message_auth_user(message));
            
            // In a real application, you'd verify the key against authorized_keys
            // Here we'll just accept any public key for demonstration
            ssh_message_auth_reply_success(message, 0);
            authenticated = 1;
            ssh_message_free(message);
            
        } else {
            ssh_message_reply_default(message);
            ssh_message_free(message);
        }
        
        auth_attempts++;
        
    } while (!authenticated && auth_attempts < 5);
    
    return authenticated;
}

int main(int argc, char *argv[]) {
    ssh_bind sshbind;
    ssh_session session;
    int port = DEFAULT_PORT;
    char dest_dir[256] = "./received_files";
    char host_key_path[512] = "/etc/ssh/ssh_host_rsa_key"; // Default location
    int client_count = 0;
    pthread_t threads[MAX_CLIENTS];
    
    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            strncpy(dest_dir, argv[i + 1], sizeof(dest_dir) - 1);
            i++;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            strncpy(host_key_path, argv[i + 1], sizeof(host_key_path) - 1);
            i++;
        } else {
            fprintf(stderr, "Usage: %s [-p port] [-d destination_directory] [-k host_key_path]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }
    
    printf("Secure Copy Server starting\n");
    printf("Destination directory: %s\n", dest_dir);
    printf("Host key: %s\n", host_key_path);
    printf("Listening on port: %d\n", port);
    
    // Rest of the code remains the same
    
    // Configure SSH server - Update this part
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, host_key_path);
    
    // Ensure destination directory exists
    if (ensure_directory(dest_dir) != 0) {
        return EXIT_FAILURE;
    }
    
    // Initialize SSH server
    ssh_init();
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Failed to create SSH server: Out of memory\n");
        return EXIT_FAILURE;
    }
    
    // Get SSH key files path
    char key_path[512];
    struct passwd *pw = getpwuid(getuid());
    snprintf(key_path, sizeof(key_path), "%s/.ssh/id_rsa", pw->pw_dir);
    
    // Configure SSH server
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, key_path);
    
    // Start listening
    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Error listening: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        ssh_finalize();
        return EXIT_FAILURE;
    }
    
    printf("Server started, waiting for connections...\n");
    
    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "Failed to create session: Out of memory\n");
            continue;
        }
        
        // Accept connection
        if (ssh_bind_accept(sshbind, session) != SSH_OK) {
            fprintf(stderr, "Error accepting connection: %s\n", ssh_get_error(sshbind));
            ssh_free(session);
            continue;
        }
        
        printf("New connection from %s\n", 
               ssh_get_clientbanner(session) ? ssh_get_clientbanner(session) : "Unknown client");
        
        // Key exchange
        if (ssh_handle_key_exchange(session) != SSH_OK) {
            fprintf(stderr, "Key exchange failed: %s\n", ssh_get_error(session));
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        
        // Authenticate client
        if (!authenticate(session)) {
            fprintf(stderr, "Authentication failed\n");
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        
        printf("Client authenticated successfully\n");
        
        // Accept channel
        ssh_channel channel = ssh_channel_new(session);
        if (channel == NULL) {
            fprintf(stderr, "Error creating channel: %s\n", ssh_get_error(session));
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        
        if (ssh_channel_open_session(channel) != SSH_OK) {
            fprintf(stderr, "Error opening channel: %s\n", ssh_get_error(session));
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        
        // Create client info struct
        client_info_t *client = malloc(sizeof(client_info_t));
        if (!client) {
            fprintf(stderr, "Out of memory\n");
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        
        client->session = session;
        client->channel = channel;
        client->thread_id = client_count++;
        strncpy(client->dest_dir, dest_dir, sizeof(client->dest_dir) - 1);
        gettimeofday(&client->start_time, NULL);
        
        // Create thread to handle client
        if (pthread_create(&threads[client->thread_id % MAX_CLIENTS], NULL, 
                          handle_client, client) != 0) {
            fprintf(stderr, "Error creating thread\n");
            free(client);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }
        
        // Detach thread so it can clean up itself
        pthread_detach(threads[client->thread_id % MAX_CLIENTS]);
    }
    
    // Cleanup (we never reach here in this simple example)
    ssh_bind_free(sshbind);
    ssh_finalize();
    
    return EXIT_SUCCESS;
}