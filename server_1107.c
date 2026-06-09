#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <crypt.h>
#include <ctype.h>

#define PORT 50107
#define SID 1011 
#define MAX_PAYLOAD 4096
#define BASE_PATH "/home/barani/Documents/ie2102/IT24101107/baranifernando/"
#define USER_FILE BASE_PATH "users.txt"
#define SESSION_FILE BASE_PATH "sessions.txt"
#define LOG_FILE BASE_PATH "server_IT24101107.log"
#define LOCKOUT_FILE BASE_PATH "lockout.txt"
#define TOKEN_TIMEOUT 300 

void write_log(const char *event, struct sockaddr_in *client_addr, const char *details) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;
    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strlen(ts) - 1] = '\0'; 
    fprintf(fp, "[%s] PID:%d IP:%s PORT:%d EVENT:%s DETAILS:%s\n",
            ts, getpid(), inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), event, details);
    fclose(fp);
}

void send_response(int sock, int ok, const char *msg) {
    char resp[1024];
    snprintf(resp, sizeof(resp), "%s 200 SID:%04d %s\n", ok ? "OK" : "ERR", SID, msg);
    send(sock, resp, strlen(resp), 0);
}

ssize_t read_line(int sock, char *buffer, size_t maxlen) {
    size_t i = 0; char c;
    while (i < maxlen - 1) {
        if (recv(sock, &c, 1, 0) <= 0) return -1;
        if (c == '\n') break;
        buffer[i++] = c;
    }
    buffer[i] = '\0';
    return i;
}

ssize_t read_nbytes(int sock, char *buffer, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = recv(sock, buffer + total, n - total, 0);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

int is_valid_username(const char *user) {
    int len = strlen(user);
    if (len < 4 || len > 20) return 0;
    while (*user) { if (!isalnum(*user++)) return 0; }
    return 1;
}

int is_locked(const char *user) {
    FILE *fp = fopen(LOCKOUT_FILE, "r");
    if (!fp) return 0;
    char u[64];
    int dummy_val;
    int total_failures = 0;

    while (fscanf(fp, "%s %d", u, &dummy_val) != EOF) {
        if (strcmp(u, user) == 0) {
            total_failures++;
        }
    }
    fclose(fp);

    if (total_failures >= 3) return 1;
    return 0;
}

void add_failed_attempt(const char *user) {
    FILE *fp = fopen(LOCKOUT_FILE, "a");
    if (fp) { fprintf(fp, "%s 1\n", user); fclose(fp); }
}

int register_user(const char *user, const char *pass) {
    char salt[13] = "$6$87654321$";
    char *hash = crypt(pass, salt);
    FILE *fp = fopen(USER_FILE, "a");
    if (!fp) return 0;
    fprintf(fp, "%s:%s\n", user, hash);
    fclose(fp);
    return 1;
}

int login_user(const char *user, const char *pass, char *out_token) {
    FILE *fp = fopen(USER_FILE, "r");
    if (!fp) return 0;
    char line[512], u[64], h[256];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63[^:]:%255s", u, h) == 2 && strcmp(u, user) == 0) {
            if (strcmp(crypt(pass, h), h) == 0) {
                snprintf(out_token, 32, "TK%ld%d", time(NULL), rand()%99);
                FILE *sfp = fopen(SESSION_FILE, "a");
                fprintf(sfp, "%s:%s:%ld\n", user, out_token, time(NULL));
                fclose(sfp); fclose(fp); return 1;
            }
        }
    }
    fclose(fp); return 0;
}

int check_token(const char *token) {
    FILE *fp = fopen(SESSION_FILE, "r");
    if (!fp) return 0;
    char line[256], u[64], t[32]; long last;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63[^:]:%31[^:]:%ld", u, t, &last) == 3 && strcmp(t, token) == 0) {
            if (difftime(time(NULL), last) < TOKEN_TIMEOUT) { fclose(fp); return 1; }
        }
    }
    fclose(fp); return 0;
}

void handle_client(int client_sock, struct sockaddr_in *client_addr) {
    char header[64], payload[MAX_PAYLOAD + 1];
    time_t last_cmd = 0;

    while (1) {
        if (read_line(client_sock, header, sizeof(header)) <= 0) break;
        int len = 0;
        sscanf(header, "LEN:%d", &len);

        if (len > MAX_PAYLOAD) {
            send_response(client_sock, 0, "Payload Too Large");
            continue;
        }
        if (read_nbytes(client_sock, payload, len) <= 0) break;
        payload[len] = '\0';

        if (time(NULL) - last_cmd < 1) { 
            send_response(client_sock, 0, "Rate limit exceeded"); continue; 
        }
        last_cmd = time(NULL);

        char cmd[16], a1[64], a2[64], tk[64];
        int n = sscanf(payload, "%15s %63s %63s %63s", cmd, a1, a2, tk);

        if (strcmp(cmd, "REGISTER") == 0) {
            if (is_valid_username(a1) && register_user(a1, a2)) {
                send_response(client_sock, 1, "User Registered");
                write_log("REGISTER", client_addr, a1);
            } else send_response(client_sock, 0, "Registration Fail");
        } 
        else if (strcmp(cmd, "LOGIN") == 0) {
            char token[32];
            if (is_locked(a1)) {
                send_response(client_sock, 0, "Account Locked");
                write_log("LOGIN_BLOCKED", client_addr, a1);
            } else if (login_user(a1, a2, token)) {
                send_response(client_sock, 1, token);
                write_log("LOGIN_SUCCESS", client_addr, a1);
            } else {
                add_failed_attempt(a1);
                send_response(client_sock, 0, "Auth Fail");
                write_log("LOGIN_FAIL", client_addr, a1);
            }
        }
        else {
            if (n >= 2 && check_token(a1)) { 
                if (strcmp(cmd, "LOGOUT") == 0) {
                    send_response(client_sock, 1, "Logged Out");
                    write_log("LOGOUT", client_addr, "Success");
                } else {
                    send_response(client_sock, 1, "Command Executed");
                    write_log(cmd, client_addr, "Success");
                }
            } else {
                send_response(client_sock, 0, "Access Denied");
                write_log(cmd, client_addr, "Invalid Token");
            }
        }
    }
}

void sigchld_handler(int s) { while(waitpid(-1, NULL, WNOHANG) > 0); }

int main() {
    srand(time(NULL));
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addrlen = sizeof(client_addr);

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed"); return 1;
    }
    listen(server_sock, 10);
    printf("Server Active on Port %d\n", PORT);

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addrlen);
        if (fork() == 0) {
            close(server_sock);
            handle_client(client_sock, &client_addr);
            close(client_sock);
            exit(0);
        }
        close(client_sock);
    }
    return 0;
}
