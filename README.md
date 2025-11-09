# Network File Sharing (C++) - Project

## Overview
This project implements a simple TCP-based network file sharing application in C++17.
It includes:
- `server.cpp` : Multi-threaded server that serves files from a `shared_files/` directory.
- `client.cpp` : Interactive client to LIST, DOWNLOAD, and UPLOAD files.
- `Makefile`   : Build instructions.
- `README.md`  : This file.

## Features
- Simple password-based authentication (password sent in plain text) — **do not use on untrusted networks**.
- LIST: lists files in the shared directory.
- DOWNLOAD <filename>: download a file from the server to current directory.
- UPLOAD <local_path>: upload a local file to the server's shared directory.
- QUIT: close connection.

## Build (Linux)
Requirements: g++ with C++17 support, make.
```bash
make
```

## Run server
```bash
./server [port] [shared_dir] [password]
# examples
./server
./server 9000 shared_files pass123
```

The server will create the shared directory if it does not exist.

## Run client
```bash
./client [server_ip] [port] [password]
# example
./client 127.0.0.1 9000 pass123
```

Then enter commands interactively:
- `LIST`
- `DOWNLOAD example.txt`
- `UPLOAD /path/to/localfile.txt`
- `QUIT`

## Notes & Security
- This is a learning/demo project. For production use TLS, stronger auth, and better error handling.
- Tested on Linux (Ubuntu).

## Troubleshooting
- If `bind` fails, ensure port is not in use and you have permission.
- For large files, ensure enough disk space in `shared_files/`.
