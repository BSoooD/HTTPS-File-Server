# HTTPS File Server

A simple HTTPS file server with Argon2id password hashing, optional Cloudflared tunnel, self-signed ECC certs and ability to serve a chosen directory.

Usage:
`--cloudflare` - enable the Cloudflared tunnel.
`--port PORT` - choose a different port (default is 8443)
`--dir DIR` - choose a different directory to serve (default is current directory)

Example:
`.\https-file-server.exe --cloudflare --dir "C:\Users" --port 6432` - serves C:\Users on port 6432 with Cloudflared tunnel.
