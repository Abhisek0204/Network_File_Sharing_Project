#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

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

bool send_uint64(int sock, uint64_t v) {
    uint64_t net = htobe64(v);
    return send_all(sock, &net, sizeof(net)) == sizeof(net);
}

bool recv_uint64(int sock, uint64_t &v) {
    uint64_t net;
    if (recv_all(sock, &net, sizeof(net)) != sizeof(net)) return false;
    v = be64toh(net);
    return true;
}

int main(int argc, char* argv[]) {
    std::string server = "127.0.0.1";
    int port = 9000;
    std::string password = "pass123";
    if (argc > 1) server = argv[1];
    if (argc > 2) port = std::stoi(argv[2]);
    if (argc > 3) password = argv[3];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address\n"; return 1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect"); return 1;
    }

    // send password length (uint32) then password bytes
    send_uint32(sock, password.size());
    send_all(sock, password.data(), password.size());
    char buf[128];
    ssize_t r = recv(sock, buf, sizeof(buf)-1, 0);
    if (r <= 0) { std::cerr << "No response from server\n"; close(sock); return 1; }
    buf[r] = '\\0';
    std::string resp(buf);
    if (resp.rfind("OK:AUTH", 0) != 0) {
        std::cerr << "Authentication failed: " << resp << "\n";
        close(sock);
        return 1;
    }
    std::cout << "Authenticated.\n";

    while (true) {
        std::cout << "Enter command (LIST / DOWNLOAD <file> / UPLOAD <local_path> / QUIT): ";
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string verb; iss >> verb;
        // send command length + command
        send_uint32(sock, line.size());
        send_all(sock, line.data(), line.size());
        if (verb == "LIST") {
            uint32_t sz = 0;
            if (!recv_uint32(sock, sz)) { std::cerr << "No reply\n"; break; }
            if (sz == 0) { std::cout << "(no files)\n"; continue; }
            std::string listing; listing.resize(sz);
            if (recv_all(sock, listing.data(), sz) != (ssize_t)sz) { std::cerr << "Incomplete\n"; break; }
            std::cout << "Files on server:\n" << listing;
        } else if (verb == "DOWNLOAD") {
            std::string fname; iss >> fname;
            uint32_t marker = 0;
            if (!recv_uint32(sock, marker)) { std::cerr << "No reply\n"; break; }
            if (marker == 0) { std::cout << "File not found on server.\n"; continue; }
            uint64_t fsize = 0;
            if (!recv_uint64(sock, fsize)) { std::cerr << "No size\n"; break; }
            fs::path out = fs::path(".") / fs::path(fname).filename();
            std::ofstream ofs(out, std::ios::binary);
            uint64_t received = 0;
            char buf2[BUFFER_SIZE];
            while (received < fsize) {
                size_t toread = std::min<uint64_t>(BUFFER_SIZE, fsize - received);
                ssize_t rr = recv_all(sock, buf2, toread);
                if (rr <= 0) break;
                ofs.write(buf2, rr);
                received += rr;
                // simple progress
                std::cout << "\rDownloaded " << received << " / " << fsize << " bytes" << std::flush;
            }
            std::cout << "\nDownload saved to " << out.string() << "\n";
        } else if (verb == "UPLOAD") {
            std::string local; iss >> local;
            if (!fs::exists(local) || !fs::is_regular_file(local)) { std::cout << "Local file not found.\n"; continue; }
            uint64_t fsize = fs::file_size(local);
            // After sending command, send uint64 size then file bytes
            send_uint64(sock, fsize);
            std::ifstream ifs(local, std::ios::binary);
            char buf3[BUFFER_SIZE];
            uint64_t sent = 0;
            while (ifs) {
                ifs.read(buf3, BUFFER_SIZE);
                std::streamsize rr = ifs.gcount();
                if (rr>0) {
                    send_all(sock, buf3, rr);
                    sent += rr;
                    std::cout << "\rUploaded " << sent << " / " << fsize << " bytes" << std::flush;
                } else break;
            }
            std::cout << "\n";
            // wait for ack
            ssize_t rr = recv(sock, buf, sizeof(buf)-1, 0);
            if (rr>0) { buf[rr]='\\0'; std::string ack(buf); if (ack.rfind("OK:UP",0)==0) std::cout << "Upload successful\n"; else std::cout << "Upload response: " << ack << "\n"; }
        } else if (verb == "QUIT") {
            break;
        } else {
            // server will respond with zero marker we can ignore
            uint32_t dummy=0;
            recv_uint32(sock,dummy);
        }
    }

    close(sock);
    return 0;
}
