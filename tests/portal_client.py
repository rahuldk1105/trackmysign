#!/usr/bin/env python3
"""A WebSocket client acting like the GST portal page, for tests/run.sh.

  portal_client.py sign <ca.cer> <port> <origin> <outdir> <tobesigned> <pan>
      Connects to wss://127.0.0.1:<port> trusting only <ca.cer>, saves the
      greeting and the reply to <outdir>/greeting.txt and <outdir>/reply.txt.
  portal_client.py refused <ca.cer> <port> <origin>
      Succeeds when the handshake is answered with 403.
"""
import base64
import os
import socket
import ssl
import struct
import sys


def connect(ca, port, origin):
    ctx = ssl.create_default_context(cadata=open(ca, "rb").read())
    raw = socket.create_connection(("127.0.0.1", port), timeout=30)
    s = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(
        (
            f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"Origin: {origin}\r\n\r\n"
        ).encode()
    )
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(1)
        if not chunk:
            break
        head += chunk
    status = int(head.split(b" ", 2)[1]) if head else 0
    return s, status


def recv_exact(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise EOFError("connection closed")
        out += chunk
    return out


def read_text(s):
    while True:
        b1, b2 = recv_exact(s, 2)
        opcode, n = b1 & 0x0F, b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", recv_exact(s, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", recv_exact(s, 8))[0]
        payload = recv_exact(s, n)
        if opcode == 1:
            return payload.decode()
        if opcode == 8:
            raise EOFError("closed by the server")


def send_text(s, text):
    data = text.encode()
    mask = os.urandom(4)
    n = len(data)
    head = bytes([0x81])
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def main():
    mode, ca, port, origin = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    s, status = connect(ca, port, origin)
    if mode == "refused":
        sys.exit(0 if status == 403 else 1)
    out, data, pan = sys.argv[5], sys.argv[6], sys.argv[7]
    if status != 101:
        sys.exit(f"handshake answered {status}")
    with open(os.path.join(out, "greeting.txt"), "w", newline="") as f:
        f.write(read_text(s))
    # Exactly what the portal's dscAction sends.
    send_text(
        s,
        "action=sign\ntobesigned=" + data + "\npanNo=" + pan + "\nsigntype=1\nexpirycheck=true"
        "\nissuername=\ncertclass=2|3\ncerttype=DSC\ncertdetails=",
    )
    with open(os.path.join(out, "reply.txt"), "w", newline="") as f:
        f.write(read_text(s))


if __name__ == "__main__":
    main()
