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

namespace fs = std::filesystem;

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

void handle_client(int client_sock, const std::string& shared_dir, const std::string& password) {
    try {
        {
            std::lock_guard<std::mutex> lg(cout_mtx);
            std::cout << "[Client " << client_sock << "] Connected\n";
        }
        // Authentication: client sends uint32 length then password bytes
        uint32_t plen = 0;
        if (!recv_uint32(client_sock, plen)) {
            close(client_sock); return;
        }
        std::string recv_pwd;
        recv_pwd.resize(plen);
        if (recv_all(client_sock, recv_pwd.data(), plen) != (ssize_t)plen) {
            close(client_sock); return;
        }
        if (recv_pwd != password) {
            const char* err = "ERR:AUTH\n";
            send_all(client_sock, err, strlen(err));
            close(client_sock);
            {
                std::lock_guard<std::mutex> lg(cout_mtx);
                std::cout << "[Client " << client_sock << "] Auth failed\n";
            }
            return;
        } else {
            const char* ok = "OK:AUTH\n";
            send_all(client_sock, ok, strlen(ok));
        }

        while (true) {
            // receive uint32 command length then command
            uint32_t cmdlen = 0;
            if (!recv_uint32(client_sock, cmdlen)) break;
            std::string cmd;
            cmd.resize(cmdlen);
            if (recv_all(client_sock, cmd.data(), cmdlen) != (ssize_t)cmdlen) break;
            std::istringstream iss(cmd);
            std::string verb; iss >> verb;
            if (verb == "LIST") {
                std::string listing;
                for (auto &p : fs::directory_iterator(shared_dir)) {
                    listing += p.path().filename().string() + "\n";
                }
                uint32_t sz = listing.size();
                send_uint32(client_sock, sz);
                if (sz>0) send_all(client_sock, listing.data(), sz);
            } else if (verb == "DOWNLOAD") {
                std::string fname; iss >> fname;
                fs::path fpath = fs::path(shared_dir) / fs::path(fname).filename();
                if (!fs::exists(fpath) || !fs::is_regular_file(fpath)) {
                    send_uint32(client_sock, 0);
                } else {
                    uint64_t fsize = fs::file_size(fpath);
                    send_uint32(client_sock, 1); // non-zero marker
                    send_uint64(client_sock, fsize);
                    std::ifstream ifs(fpath, std::ios::binary);
                    char buf[BUFFER_SIZE];
                    uint64_t sent = 0;
                    while (ifs) {
                        ifs.read(buf, BUFFER_SIZE);
                        std::streamsize r = ifs.gcount();
                        if (r>0) {
                            send_all(client_sock, buf, r);
                            sent += r;
                        } else break;
                    }
                }
            } else if (verb == "UPLOAD") {
                std::string fname; iss >> fname;
                uint64_t fsize = 0;
                if (!recv_uint64(client_sock, fsize)) break;
                fs::path fpath = fs::path(shared_dir) / fs::path(fname).filename();
                std::ofstream ofs(fpath, std::ios::binary);
                uint64_t received = 0;
                char buf[BUFFER_SIZE];
                while (received < fsize) {
                    size_t toread = (size_t)std::min<uint64_t>(BUFFER_SIZE, fsize - received);
                    ssize_t r = recv_all(client_sock, buf, toread);
                    if (r <= 0) break;
                    ofs.write(buf, r);
                    received += r;
                }
                const char* ok = "OK:UP\n";
                send_all(client_sock, ok, strlen(ok));
            } else if (verb == "QUIT") {
                break;
            } else {
                // unknown command -> send zero
                send_uint32(client_sock, 0);
            }
        }
    } catch (const std::exception &e) {
        std::lock_guard<std::mutex> lg(cout_mtx);
        std::cerr << "[Client " << client_sock << "] Exception: " << e.what() << "\n";
    }
    close(client_sock);
    {
        std::lock_guard<std::mutex> lg(cout_mtx);
        std::cout << "[Client " << client_sock << "] Disconnected\n";
    }
}

int main(int argc, char* argv[]) {
    int port = 9000;
    std::string shared_dir = "shared_files";
    std::string password = "pass123";
    if (argc > 1) port = std::stoi(argv[1]);
    if (argc > 2) shared_dir = argv[2];
    if (argc > 3) password = argv[3];

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

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(listen_sock, BACKLOG) < 0) {
        perror("listen");
        return 1;
    }

    std::cout << "Server listening on 0.0.0.0:" << port << ", shared dir: " << shared_dir << "\n";

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }
        std::thread(handle_client, client_sock, shared_dir, password).detach();
    }

    close(listen_sock);
    return 0;
}
