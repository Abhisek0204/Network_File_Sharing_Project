#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace fs = std::filesystem;
using uint64 = unsigned long long;

const int BACKLOG = 10;
const size_t BUFFER_SIZE = 4096;

std::mutex cout_mtx;

ssize_t send_all(int sock, const void* buf, size_t len) {
    size_t total = 0;
    const char* ptr = (const char*)buf;
    while (total < len) {
        ssize_t sent = send(sock, ptr + total, len - total, 0);
        if (sent <= 0) return sent;
        total += sent;
    }
    return total;
}

ssize_t recv_all(int sock, void* buf, size_t len) {
    size_t total = 0;
    char* ptr = (char*)buf;
    while (total < len) {
        ssize_t rec = recv(sock, ptr + total, len - total, 0);
        if (rec <= 0) return rec;
        total += rec;
    }
    return total;
}

bool send_uint32(int sock, uint32_t v) {
    uint32_t net = htonl(v);
    return send_all(sock, &net, sizeof(net)) == sizeof(net);
}

bool recv_uint32(int sock, uint32_t &v) {
    uint32_t net;
    if (recv_all(sock, &net, sizeof(net)) != sizeof(net)) return false;
    v = ntohl(net);
    return true;
}

bool send_uint64(int sock, uint64 v) {
    uint64 net = htobe64(v);
    return send_all(sock, &net, sizeof(net)) == sizeof(net);
}

bool recv_uint64(int sock, uint64 &v) {
    uint64 net;
    if (recv_all(sock, &net, sizeof(net)) != sizeof(net)) return false;
    v = be64toh(net);
    return true;
}

/* --- OpenSSL helpers --- */

// Derive a 32-byte key from password using SHA256
void derive_key_from_password(const std::string &password, unsigned char key[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)password.data(), password.size());
    SHA256_Final(key, &ctx);
}

// AES-256-CBC encrypt buffer -> writes encrypted bytes to out (vector)
bool aes_encrypt_stream(int in_fd, std::ostream &out_stream, const unsigned char key[32]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) { EVP_CIPHER_CTX_free(ctx); return false; }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }

    // send iv as first 16 bytes (caller should write it before encrypted size)
    out_stream.write((char*)iv, sizeof(iv));

    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    while (true) {
        ssize_t r = read(in_fd, inbuf, BUFFER_SIZE);
        if (r < 0) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (r == 0) break;
        if (1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)r)) { EVP_CIPHER_CTX_free(ctx); return false; }
        out_stream.write((char*)outbuf, outlen);
    }
    if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) { EVP_CIPHER_CTX_free(ctx); return false; }
    out_stream.write((char*)outbuf, outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES decrypt: receive iv first, then ciphertext bytes from socket, write plaintext to out_fd
bool aes_decrypt_from_socket(int sock, const unsigned char key[32], uint64 cipher_size, int out_fd) {
    // read iv (16)
    unsigned char iv[16];
    if (recv_all(sock, iv, sizeof(iv)) != sizeof(iv)) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }

    unsigned char inbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint64 remaining = cipher_size;
    while (remaining > 0) {
        size_t toread = (size_t)std::min<uint64>(BUFFER_SIZE, remaining);
        ssize_t r = recv_all(sock, inbuf, toread);
        if (r <= 0) { EVP_CIPHER_CTX_free(ctx); return false; }
        int outlen = 0;
        if (1 != EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, (int)r)) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (outlen > 0) {
            if (write(out_fd, outbuf, outlen) != outlen) { EVP_CIPHER_CTX_free(ctx); return false; }
        }
        remaining -= r;
    }
    int outlen = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (outlen > 0) write(out_fd, outbuf, outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/* --- Simple user DB (in-memory). In production use a proper DB --- */
struct User {
    std::string username;
    std::string password_hash_hex; // store hex string of SHA256(password)
};

std::vector<User> users_db = {
    // default user: username "admin", password "pass123"
    // compute SHA256("pass123") hex offline or at startup
};

std::string to_hex(const unsigned char *buf, size_t len) {
    std::ostringstream ss;
    ss << std::hex;
    for (size_t i=0;i<len;i++){
        ss << std::setw(2) << std::setfill('0') << (int)buf[i];
    }
    return ss.str();
}

std::string sha256_hex(const std::string &s) {
    unsigned char hash[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)s.data(), s.size());
    SHA256_Final(hash, &ctx);
    return to_hex(hash, 32);
}

bool check_user_credentials(const std::string &username, const std::string &password) {
    std::string h = sha256_hex(password);
    for (auto &u: users_db) {
        if (u.username == username && u.password_hash_hex == h) return true;
    }
    return false;
}

void init_users_db() {
    // initialize default user admin:pass123
    users_db.clear();
    User admin;
    admin.username = "admin";
    admin.password_hash_hex = sha256_hex("pass123");
    users_db.push_back(admin);
}

void safe_log(const std::string &s) {
    std::lock_guard<std::mutex> lg(cout_mtx);
    std::cout << s << std::endl;
}

void handle_client(int client_sock, const std::string& shared_dir) {
    safe_log("[client] Connected");
    // Protocol:
    // 1) client sends username length (uint32) then username bytes
    // 2) client sends password length (uint32) then password bytes
    uint32_t ulen=0;
    if (!recv_uint32(client_sock, ulen)) { close(client_sock); return; }
    std::string uname; uname.resize(ulen);
    if (recv_all(client_sock, uname.data(), ulen) != (ssize_t)ulen) { close(client_sock); return; }

    uint32_t plen=0;
    if (!recv_uint32(client_sock, plen)) { close(client_sock); return; }
    std::string passwd; passwd.resize(plen);
    if (recv_all(client_sock, passwd.data(), plen) != (ssize_t)plen) { close(client_sock); return; }

    if (!check_user_credentials(uname, passwd)) {
        const char *resp = "ERR:AUTH\n";
        send_all(client_sock, resp, strlen(resp));
        close(client_sock);
        safe_log("[client] Auth failed for user: " + uname);
        return;
    }
    send_all(client_sock, "OK:AUTH\n", 8);
    safe_log("[client] Auth OK for user: " + uname);

    // derive encryption key from password
    unsigned char key[32];
    derive_key_from_password(passwd, key);

    while (true) {
        uint32_t cmdlen=0;
        if (!recv_uint32(client_sock, cmdlen)) break;
        std::string cmd; cmd.resize(cmdlen);
        if (recv_all(client_sock, cmd.data(), cmdlen) != (ssize_t)cmdlen) break;
        std::istringstream iss(cmd);
        std::string verb; iss >> verb;
        if (verb == "LIST") {
            std::string listing;
            for (auto &p : fs::directory_iterator(shared_dir)) {
                listing += p.path().filename().string() + "\n";
            }
            send_uint32(client_sock, (uint32_t)listing.size());
            if (!listing.empty()) send_all(client_sock, listing.data(), listing.size());
        } else if (verb == "DOWNLOAD") {
            std::string fname; iss >> fname;
            fs::path fpath = fs::path(shared_dir) / fs::path(fname).filename();
            if (!fs::exists(fpath) || !fs::is_regular_file(fpath)) {
                // send zero size
                send_uint64(client_sock, 0);
            } else {
                // We'll encrypt file and send: first send encrypted_size (uint64), then iv(16) then ciphertext
                // To compute encrypted size we can either pre-buffer into memory (not ideal) or stream: we will stream by sending an initial non-zero marker (1), then send encrypted payload length as 8 bytes placeholder -> better: simpler approach: create a temporary encrypted file.
                fs::path tmp = fs::temp_directory_path() / ("enc_" + fname);
                // open input and output
                int in_fd = open(fpath.c_str(), O_RDONLY);
                if (in_fd < 0) { send_uint64(client_sock, 0); continue; }
                std::ofstream ofs(tmp, std::ios::binary);
                // For building encrypted file: first write IV (16) then ciphertext
                unsigned char iv[16];
                if (!RAND_bytes(iv, sizeof(iv))) { close(in_fd); ofs.close(); send_uint64(client_sock, 0); continue; }
                ofs.write((char*)iv, sizeof(iv));
                // set up EVP
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
                unsigned char inbuf[BUFFER_SIZE];
                unsigned char outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
                int outlen;
                while (true) {
                    ssize_t r = read(in_fd, inbuf, BUFFER_SIZE);
                    if (r <= 0) break;
                    EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)r);
                    if (outlen > 0) ofs.write((char*)outbuf, outlen);
                }
                EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
                if (outlen>0) ofs.write((char*)outbuf, outlen);
                EVP_CIPHER_CTX_free(ctx);
                close(in_fd);
                ofs.close();
                // now send encrypted file size
                uint64 enc_sz = fs::file_size(tmp);
                send_uint64(client_sock, enc_sz);
                // send encrypted file bytes
                int enc_fd = open(tmp.c_str(), O_RDONLY);
                if (enc_fd < 0) { send_uint64(client_sock, 0); continue; }
                ssize_t r;
                unsigned char buf[BUFFER_SIZE];
                while ((r = read(enc_fd, buf, BUFFER_SIZE)) > 0) {
                    if (send_all(client_sock, buf, r) != r) break;
                }
                close(enc_fd);
                fs::remove(tmp);
            }
        } else if (verb == "UPLOAD") {
            std::string fname; iss >> fname;
            // client will send: uint64 encrypted_size, then IV+ ciphertext (we expect IV is first 16 bytes of the ciphertext stream)
            uint64 enc_sz = 0;
            if (!recv_uint64(client_sock, enc_sz)) break;
            if (enc_sz == 0) { /* nothing */ continue; }
            fs::path outpath = fs::path(shared_dir) / fs::path(fname).filename();
            int out_fd = open(outpath.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (out_fd < 0) {
                // drain bytes
                unsigned char tmpbuf[BUFFER_SIZE];
                uint64 rem = enc_sz;
                while (rem > 0) {
                    size_t toread = (size_t)std::min<uint64>(BUFFER_SIZE, rem);
                    if (recv_all(client_sock, tmpbuf, toread) != (ssize_t)toread) break;
                    rem -= toread;
                }
                continue;
            }
            // perform AES decrypt from socket to out_fd
            if (!aes_decrypt_from_socket(client_sock, key, enc_sz, out_fd)) {
                close(out_fd);
                continue;
            }
            close(out_fd);
            // ack
            send_all(client_sock, "OK:UP\n", 6);
        } else if (verb == "QUIT") {
            break;
        } else {
            send_uint32(client_sock, 0);
        }
    }

    close(client_sock);
    safe_log("[client] Disconnected");
}

int main(int argc, char* argv[]) {
    int port = 9000;
    std::string shared_dir = "shared_files";
    if (argc > 1) port = std::stoi(argv[1]);
    if (argc > 2) shared_dir = argv[2];

    init_users_db();
    fs::create_directories(shared_dir);

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        perror("socket");
        return 1;
    }
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_sock, BACKLOG) < 0) { perror("listen"); return 1; }
    std::cout << "Server listening on 0.0.0.0:" << port << ", shared dir: " << shared_dir << "\n";

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) { perror("accept"); continue; }
        std::thread(handle_client, client_sock, shared_dir).detach();
    }
    close(listen_sock);
    return 0;
}
