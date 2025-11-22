import socket
import struct
import threading
import sys

from crypto import load_cipher, encrypt_message, decrypt_message


HOST = "0.0.0.0"
PORT = 5000


def send_encrypted_loop(conn: socket.socket, cipher) -> None:
    """
    Read user input from stdin, encrypt it, and send to peer.
    """
    try:
        while True:
            msg = input("")
            if not msg:
                continue

            ciphertext = encrypt_message(cipher, msg)
            header = struct.pack("!I", len(ciphertext))
            conn.sendall(header + ciphertext)
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Stopping send loop.")
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def recv_encrypted_loop(conn: socket.socket, cipher) -> None:
    """
    Receive messages:
      1. Read 4-byte length
      2. Read ciphertext
      3. Decrypt and print
    """
    try:
        while True:
            header = _recv_exact(conn, 4)
            if not header:
                print("[!] Connection closed by peer.")
                break

            (length,) = struct.unpack("!I", header)
            ciphertext = _recv_exact(conn, length)
            if not ciphertext:
                print("[!] Connection closed while reading message.")
                break

            try:
                plaintext = decrypt_message(cipher, ciphertext)
                print(f"[Peer] {plaintext}")
            except Exception as e:
                print(f"[!] Failed to decrypt message: {e}")
    except KeyboardInterrupt:
        print("\n[!] Stopping receive loop.")
    finally:
        conn.close()


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    """
    Receive exactly `size` bytes from the socket.
    Returns empty bytes if connection is closed.
    """
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def main():
    cipher = load_cipher()

    port = PORT
    if len(sys.argv) >= 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("[!] Invalid port, using default:", PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, port))
        server_sock.listen(1)

        print(f"[+] Listening on {HOST}:{port} ...")
        conn, addr = server_sock.accept()
        print(f"[+] Connection established from {addr[0]}:{addr[1]}")

        recv_thread = threading.Thread(
            target=recv_encrypted_loop, args=(conn, cipher), daemon=True
        )
        send_thread = threading.Thread(
            target=send_encrypted_loop, args=(conn, cipher), daemon=True
        )

        recv_thread.start()
        send_thread.start()

        try:
            recv_thread.join()
        except KeyboardInterrupt:
            print("\n[!] Server shutting down.")


if __name__ == "__main__":
    main()
