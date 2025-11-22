import socket
import struct
import threading
import sys

from crypto import load_cipher, encrypt_message, decrypt_message


def send_encrypted_loop(sock: socket.socket, cipher) -> None:
    """
    Read user input, encrypt it, and send it with a length prefix.
    """
    try:
        while True:
            msg = input("")
            if not msg:
                continue

            ciphertext = encrypt_message(cipher, msg)
            header = struct.pack("!I", len(ciphertext))
            sock.sendall(header + ciphertext)
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Stopping send loop.")
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def recv_encrypted_loop(sock: socket.socket, cipher) -> None:
    """
    Read incoming encrypted messages and print them.
    """
    try:
        while True:
            header = _recv_exact(sock, 4)
            if not header:
                print("[!] Connection closed by server.")
                break

            (length,) = struct.unpack("!I", header)
            ciphertext = _recv_exact(sock, length)
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
        sock.close()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """
    Receive exactly `size` bytes from the socket.
    Returns empty bytes if connection is closed.
    """
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def main():
    cipher = load_cipher()

    if len(sys.argv) < 3:
        print("Usage: python client.py <server_ip> <port>")
        print("Example: python client.py 127.0.0.1 5000")
        sys.exit(1)

    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("[!] Invalid port.")
        sys.exit(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        print(f"[+] Connected to server at {host}:{port}")

        recv_thread = threading.Thread(
            target=recv_encrypted_loop, args=(sock, cipher), daemon=True
        )
        send_thread = threading.Thread(
            target=send_encrypted_loop, args=(sock, cipher), daemon=True
        )

        recv_thread.start()
        send_thread.start()

        try:
            recv_thread.join()
        except KeyboardInterrupt:
            print("\n[!] Client shutting down.")


if __name__ == "__main__":
    main()
