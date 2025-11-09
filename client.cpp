#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>


#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace fs = std::filesystem;
using uint64 = unsigned long long;

const size_t BUFFER_SIZE = 4096;

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

// SHA256 derive key
void derive_key_from_password(const std::string &password, unsigned char key[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)password.data(), password.size());
    SHA256_Final(key, &ctx);
}

// Encrypt a local file and send: write IV (16) then ciphertext. We will compute ciphertext size by streaming to memory file (tmp) for simplicity.
bool encrypt_file_and_send(int sock, const std::string &localpath, const unsigned char key[32]) {
    int in_fd = open(localpath.c_str(), O_RDONLY);
    if (in_fd < 0) return false;
    // write encrypted data to temporary file
    std::string tmp = "/tmp/enc_temp.bin";
    std::ofstream ofs(tmp, std::ios::binary);
    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) { close(in_fd); ofs.close(); return false; }
    ofs.write((char*)iv, sizeof(iv));
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
    // send encrypted file size, then contents
    uint64 enc_sz = fs::file_size(tmp);
    if (!send_uint64(sock, enc_sz)) { fs::remove(tmp); return false; }
    // send file bytes
    int enc_fd = open(tmp.c_str(), O_RDONLY);
    if (enc_fd < 0) { fs::remove(tmp); return false; }
    ssize_t r;
    unsigned char buf[BUFFER_SIZE];
    while ((r = read(enc_fd, buf, BUFFER_SIZE)) > 0) {
        if (send_all(sock, buf, r) != r) break;
    }
    close(enc_fd);
    fs::remove(tmp);
    return true;
}

// Decrypt incoming encrypted stream of given size and save to localpath
bool receive_encrypted_and_decrypt(int sock, const std::string &localpath, const unsigned char key[32], uint64 enc_sz) {
    // read iv first (16)
    unsigned char iv[16];
    if (recv_all(sock, iv, sizeof(iv)) != sizeof(iv)) return false;
    FILE *out = fopen(localpath.c_str(), "wb");
    if (!out) return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    uint64 remaining = enc_sz - sizeof(iv); // because server wrote iv first in encrypted file
    unsigned char inbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    while (remaining > 0) {
        size_t toread = (size_t)std::min<uint64>(BUFFER_SIZE, remaining);
        if (recv_all(sock, inbuf, toread) != (ssize_t)toread) {
            EVP_CIPHER_CTX_free(ctx); fclose(out); return false;
        }
        int outlen = 0;
        if (1 != EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, (int)toread)) { EVP_CIPHER_CTX_free(ctx); fclose(out); return false; }
        if (outlen > 0) fwrite(outbuf, 1, outlen, out);
        remaining -= toread;
    }
    int outlen = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) { EVP_CIPHER_CTX_free(ctx); fclose(out); return false; }
    if (outlen > 0) fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_free(ctx);
    fclose(out);
    return true;
}

int connect_and_auth(const std::string &server, int port, const std::string &username, const std::string &password) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server.c_str(), &serv_addr.sin_addr) <= 0) { close(s); return -1; }
    if (connect(s, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) { close(s); return -1; }

    // send username then password (each length-prefixed)
    send_uint32(s, (uint32_t)username.size());
    if (username.size()) send_all(s, username.data(), username.size());
    send_uint32(s, (uint32_t)password.size());
    if (password.size()) send_all(s, password.data(), password.size());
    // read response
    char resp[64];
    ssize_t r = recv(s, resp, sizeof(resp)-1, 0);
    if (r <= 0) { close(s); return -1; }
    resp[r] = '\0';
    std::string rs(resp);
    if (rs.rfind("OK:AUTH", 0) == 0) return s;
    close(s);
    return -1;
}

int main(int argc, char* argv[]) {
    std::string server = "127.0.0.1";
    int port = 9000;
    std::string username = "admin";
    std::string password = "pass123";
    if (argc > 1) server = argv[1];
    if (argc > 2) port = std::stoi(argv[2]);
    if (argc > 3) username = argv[3];
    if (argc > 4) password = argv[4];

    int s = connect_and_auth(server, port, username, password);
    if (s < 0) {
        std::cerr << "Authentication failed or cannot connect\n";
        return 1;
    }
    std::cout << "Authenticated.\n";
    unsigned char key[32];
    derive_key_from_password(password, key);

    while (true) {
        std::cout << "Enter command (LIST / DOWNLOAD <file> / UPLOAD <local_path> / QUIT): ";
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string verb; iss >> verb;
        // send command
        send_uint32(s, (uint32_t)line.size());
        send_all(s, line.data(), line.size());
        if (verb == "LIST") {
            uint32_t sz = 0;
            if (!recv_uint32(s, sz)) { std::cerr << "No response\n"; break; }
            if (sz == 0) { std::cout << "(no files)\n"; continue; }
            std::string listing; listing.resize(sz);
            if (recv_all(s, listing.data(), sz) != (ssize_t)sz) { std::cerr << "Incomplete\n"; break; }
            std::cout << "Files on server:\n" << listing;
        } else if (verb == "DOWNLOAD") {
            std::string fname; iss >> fname;
            uint64 enc_sz = 0;
            if (!recv_uint64(s, enc_sz)) { std::cerr << "No reply\n"; break; }
            if (enc_sz == 0) { std::cout << "File not found on server.\n"; continue; }
            // receive encrypted data and decrypt
            // server wrote IV (16) + ciphertext, and enc_sz equals total bytes (IV + ciphertext)
            std::string out = "./client_downloads/" + fs::path(fname).filename().string();
            fs::create_directories("./client_downloads");
            if (!receive_encrypted_and_decrypt(s, out, key, enc_sz)) { std::cerr << "Download failed\n"; continue; }
            std::cout << "Download saved to " << out << "\n";
        } else if (verb == "UPLOAD") {
            std::string local; iss >> local;
            if (local.empty()) { std::cout << "Specify local path\n"; continue; }
            if (!fs::exists(local) || !fs::is_regular_file(local)) { std::cout << "Local file not found.\n"; continue; }
            // encrypt and send: client first sends uint64 enc_sz then bytes (enc includes iv at start)
            if (!encrypt_file_and_send(s, local, key)) { std::cout << "Upload failed\n"; continue; }
            char buf[64];
            ssize_t r = recv(s, buf, sizeof(buf)-1, 0);
            if (r>0) { buf[r]=0; std::string ack(buf); if (ack.rfind("OK:UP",0)==0) std::cout << "Upload successful.\n"; else std::cout << "Upload response: " << ack << "\n"; }
        } else if (verb == "QUIT") {
            break;
        } else {
            uint32_t dummy=0; recv_uint32(s,dummy); // consume
        }
    }

    close(s);
    return 0;
}
