import socket
import struct
import threading
import sys
import queue
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

from crypto import load_cipher, encrypt_message, decrypt_message


def recv_exact(sock: socket.socket, size: int) -> bytes:
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


class ChatClientGUI:
    def __init__(self, root: tk.Tk, host: str, port: int):
        self.root = root
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.cipher = load_cipher()
        self.incoming = queue.Queue()

        self.root.title(f"P2P Secure Chat - Client ({host}:{port})")

        # UI layout
        self.text_area = ScrolledText(root, wrap=tk.WORD, state="disabled", height=20, width=60)
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        bottom_frame = tk.Frame(root)
        bottom_frame.pack(padx=10, pady=(0, 10), fill=tk.X)

        self.entry = tk.Entry(bottom_frame)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", self.on_send)

        send_btn = tk.Button(bottom_frame, text="Send", command=self.on_send)
        send_btn.pack(side=tk.LEFT, padx=(5, 0))

        # Start background network thread
        threading.Thread(target=self.network_worker, daemon=True).start()

        # Periodically check for incoming messages
        self.root.after(100, self.poll_incoming)

        self.append_text("[System] Connecting to server...\n")

    def append_text(self, text: str) -> None:
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, text)
        self.text_area.see(tk.END)
        self.text_area.config(state="disabled")

    def on_send(self, event=None) -> None:
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, tk.END)

        if self.sock is None:
            self.append_text("[System] Not connected.\n")
            return

        try:
            ciphertext = encrypt_message(self.cipher, msg)
            header = struct.pack("!I", len(ciphertext))
            self.sock.sendall(header + ciphertext)
            self.append_text(f"[You] {msg}\n")
        except Exception as e:
            self.append_text(f"[System] Failed to send: {e}\n")

    def network_worker(self) -> None:
        """
        Runs in a background thread.
        Connects to the server and continuously receives messages.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            self.sock = sock
            self.incoming.put("[System] Connected to server.\n")

            while True:
                header = recv_exact(sock, 4)
                if not header:
                    self.incoming.put("[System] Connection closed by server.\n")
                    break

                (length,) = struct.unpack("!I", header)
                ciphertext = recv_exact(sock, length)
                if not ciphertext:
                    self.incoming.put("[System] Connection closed while reading message.\n")
                    break

                try:
                    plaintext = decrypt_message(self.cipher, ciphertext)
                    self.incoming.put(f"[Peer] {plaintext}\n")
                except Exception as e:
                    self.incoming.put(f"[System] Failed to decrypt message: {e}\n")

        except Exception as e:
            self.incoming.put(f"[System] Error connecting/receiving: {e}\n")
        finally:
            if self.sock is not None:
                self.sock.close()
                self.sock = None

    def poll_incoming(self) -> None:
        """
        Runs on the Tkinter main thread.
        Pulls messages from the queue and updates the text box.
        """
        try:
            while True:
                msg = self.incoming.get_nowait()
                self.append_text(msg)
        except queue.Empty:
            pass

        # Poll again after 100ms
        self.root.after(100, self.poll_incoming)


def main():
    if len(sys.argv) < 3:
        print("Usage: py gui_client.py <server_ip> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    root = tk.Tk()
    app = ChatClientGUI(root, host, port)
    root.mainloop()


if __name__ == "__main__":
    main()
