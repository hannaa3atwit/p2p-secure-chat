import socket
import struct
import threading
import sys
import queue
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

from crypto import load_cipher, encrypt_message, decrypt_message, get_key_fingerprint


def recv_exact(conn: socket.socket, size: int) -> bytes:
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


class ChatServerGUI:
    def __init__(self, root: tk.Tk, host: str, port: int):
        self.root = root
        self.host = host
        self.port = port
        self.server_sock: socket.socket | None = None
        self.client_sock: socket.socket | None = None
        self.cipher = load_cipher()
        self.fingerprint = get_key_fingerprint()
        self.incoming = queue.Queue()
        self.running = True

        self.root.title("P2P Secure Chat - Server (Intro)")

        # Frames for intro and chat
        self.intro_frame = tk.Frame(root)
        self.chat_frame: tk.Frame | None = None

        self.build_intro_ui()

    # ---------- Intro screen ----------

    def build_intro_ui(self) -> None:
        self.intro_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            self.intro_frame,
            text="P2P Secure Chat - Server",
            font=("Segoe UI", 16, "bold"),
        )
        title.pack(pady=(0, 10))

        desc = (
            "This chat uses end-to-end encryption with a shared secret key.\n\n"
            "• Messages are encrypted using the Fernet algorithm (AES + HMAC).\n"
            "• Only peers with the same secret key can read the messages.\n"
            "• The short key fingerprint below lets you verify that both sides\n"
            "  are using the same encryption key.\n\n"
            "If the fingerprint shown here matches the client's fingerprint,\n"
            "your encryption setup matches."
        )

        label = tk.Label(
            self.intro_frame,
            text=desc,
            justify=tk.LEFT,
            anchor="w",
            font=("Segoe UI", 10),
        )
        label.pack(pady=(0, 10), anchor="w")

        fp_label = tk.Label(
            self.intro_frame,
            text=f"Key fingerprint: {self.fingerprint}",
            font=("Consolas", 11, "bold"),
            fg="blue",
        )
        fp_label.pack(pady=(5, 15), anchor="w")

        start_btn = tk.Button(
            self.intro_frame,
            text="Start Encrypted Chat",
            font=("Segoe UI", 11, "bold"),
            command=self.start_chat,
        )
        start_btn.pack(pady=(5, 0))

    def start_chat(self) -> None:
        """Switch from intro page to the main chat UI and start the server thread."""
        self.intro_frame.destroy()
        self.build_chat_ui()

        # Start background network thread
        threading.Thread(target=self.network_worker, daemon=True).start()

        # Periodically check for incoming messages
        self.root.after(100, self.poll_incoming)

        self.append_text("[System] Starting server...\n")
        self.append_text(f"[System] Key fingerprint: {self.fingerprint}\n")

    # ---------- Chat screen ----------

    def build_chat_ui(self) -> None:
        self.root.title(f"P2P Secure Chat - Server ({self.host}:{self.port})")
        self.chat_frame = tk.Frame(self.root)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        self.text_area = ScrolledText(
            self.chat_frame, wrap=tk.WORD, state="disabled", height=20, width=60
        )
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        bottom_frame = tk.Frame(self.chat_frame)
        bottom_frame.pack(padx=10, pady=(0, 10), fill=tk.X)

        self.entry = tk.Entry(bottom_frame)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", self.on_send)

        send_btn = tk.Button(bottom_frame, text="Send", command=self.on_send)
        send_btn.pack(side=tk.LEFT, padx=(5, 0))

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def append_text(self, text: str) -> None:
        if not hasattr(self, "text_area"):
            return
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, text)
        self.text_area.see(tk.END)
        self.text_area.config(state="disabled")

    def on_send(self, event=None) -> None:
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, tk.END)

        if self.client_sock is None:
            self.append_text("[System] No client connected.\n")
            return

        try:
            ciphertext = encrypt_message(self.cipher, msg)
            header = struct.pack("!I", len(ciphertext))
            self.client_sock.sendall(header + ciphertext)
            self.append_text(f"[You] {msg}\n")
        except Exception as e:
            self.append_text(f"[System] Failed to send: {e}\n")

    def network_worker(self) -> None:
        """
        Runs in a background thread.
        Listens for one client, then receives messages in a loop.
        """
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(1)

            self.server_sock = server_sock
            self.incoming.put(f"[System] Listening on {self.host}:{self.port} ...\n")

            conn, addr = server_sock.accept()
            self.client_sock = conn
            self.incoming.put(f"[System] Client connected from {addr[0]}:{addr[1]}\n")

            while self.running:
                header = recv_exact(conn, 4)
                if not header:
                    self.incoming.put("[System] Connection closed by client.\n")
                    break

                (length,) = struct.unpack("!I", header)
                ciphertext = recv_exact(conn, length)
                if not ciphertext:
                    self.incoming.put("[System] Connection closed while reading message.\n")
                    break

                try:
                    plaintext = decrypt_message(self.cipher, ciphertext)
                    self.incoming.put(f"[Peer] {plaintext}\n")
                except Exception as e:
                    self.incoming.put(f"[System] Failed to decrypt message: {e}\n")

        except Exception as e:
            self.incoming.put(f"[System] Server error: {e}\n")
        finally:
            if self.client_sock is not None:
                self.client_sock.close()
                self.client_sock = None
            if self.server_sock is not None:
                self.server_sock.close()
                self.server_sock = None

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

        if self.running:
            self.root.after(100, self.poll_incoming)

    def on_close(self) -> None:
        """
        Called when the window is closed.
        """
        self.running = False
        if self.client_sock is not None:
            try:
                self.client_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.client_sock.close()
        if self.server_sock is not None:
            self.server_sock.close()
        self.root.destroy()


def main():
    host = "0.0.0.0"
    port = 5000

    if len(sys.argv) >= 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("Invalid port, using default 5000.")

    root = tk.Tk()
    app = ChatServerGUI(root, host, port)
    root.mainloop()


if __name__ == "__main__":
    main()
