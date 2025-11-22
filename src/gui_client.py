import socket
import struct
import threading
import sys
import queue
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

from crypto import load_cipher, encrypt_message, decrypt_message, get_key_fingerprint


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
        self.fingerprint = get_key_fingerprint()
        self.incoming = queue.Queue()

        # Intro title first
        self.root.title("P2P Secure Chat - Client (Intro)")

        # Frames for intro and chat
        self.intro_frame = tk.Frame(root)
        self.chat_frame: tk.Frame | None = None

        self.build_intro_ui()

    # ---------- Intro screen ----------

    def build_intro_ui(self) -> None:
        self.intro_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            self.intro_frame,
            text="P2P Secure Chat - Client",
            font=("Segoe UI", 16, "bold"),
        )
        title.pack(pady=(0, 10))

        desc = (
            "This chat uses end-to-end encryption with a shared secret key.\n\n"
            "• Messages are encrypted using the Fernet algorithm (AES + HMAC).\n"
            "• Only peers with the same secret key can read the messages.\n"
            "• The short key fingerprint below lets you verify that both sides\n"
            "  are using the same encryption key.\n\n"
            "If the fingerprint shown here matches the server's fingerprint,\n"
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
            text="Join Encrypted Chat",
            font=("Segoe UI", 11, "bold"),
            command=self.start_chat,
        )
        start_btn.pack(pady=(5, 0))

    def start_chat(self) -> None:
        """Switch from intro page to main chat UI and connect to the server."""
        self.intro_frame.destroy()
        self.build_chat_ui()

        # Start background network thread
        threading.Thread(target=self.network_worker, daemon=True).start()

        # Periodically check for incoming messages
        self.root.after(100, self.poll_incoming)

        self.append_text("[System] Connecting to server...\n")
        self.append_text(f"[System] Key fingerprint: {self.fingerprint}\n")

    # ---------- Chat screen ----------

    def build_chat_ui(self) -> None:
        self.root.title(f"P2P Secure Chat - Client ({self.host}:{self.port})")
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

        # $ button for crypto prices
        crypto_btn = tk.Button(bottom_frame, text="$", width=3, command=self.show_crypto_prices)
        crypto_btn.pack(side=tk.LEFT, padx=(5, 0))

    def append_text(self, text: str) -> None:
        if not hasattr(self, "text_area"):
            # If intro is showing, just ignore
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

    # ---------- Crypto prices popup (with 24h change + auto-refresh) ----------

    def show_crypto_prices(self) -> None:
        """Open a small window that shows live crypto prices with 24h change."""
        prices_win = tk.Toplevel(self.root)
        prices_win.title("Crypto Prices")
        prices_win.geometry("280x230")

        status_label = tk.Label(
            prices_win,
            text="Loading prices...",
            font=("Consolas", 11),
            justify=tk.LEFT,
            anchor="w",
        )
        status_label.pack(padx=10, pady=(10, 5), fill=tk.X)

        # Frame to hold individual coin labels
        coins_frame = tk.Frame(prices_win)
        coins_frame.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)

        # Store per-coin labels so we can update their text/color
        coin_labels: dict[str, tk.Label] = {}

        # Auto-refresh checkbox
        auto_var = tk.BooleanVar(value=False)

        def update_ui(prices: dict | None, error: str | None = None) -> None:
            """Update labels in the main Tk thread."""
            if error is not None:
                status_label.config(text=f"Failed to load prices:\n{error}")
                return

            status_label.config(text="Current prices (USD, 24h change):")

            mapping = {
                "bitcoin": "BTC",
                "ethereum": "ETH",
                "solana": "SOL",
                "dogecoin": "DOGE",
            }

            for cid, sym in mapping.items():
                info = prices.get(cid)
                if not info:
                    text = f"{sym}: N/A"
                    change_color = "black"
                else:
                    price = info.get("usd")
                    change = info.get("usd_24h_change")
                    if price is None:
                        text = f"{sym}: N/A"
                        change_color = "black"
                    else:
                        if change is not None:
                            # format like +3.21% or -1.05%
                            sign = "+" if change >= 0 else ""
                            text = f"{sym}: ${price:,.2f} ({sign}{change:.2f}%)"
                            change_color = "green" if change > 0 else ("red" if change < 0 else "black")
                        else:
                            text = f"{sym}: ${price:,.2f}"
                            change_color = "black"

                if sym not in coin_labels:
                    lbl = tk.Label(
                        coins_frame,
                        text=text,
                        font=("Consolas", 11),
                        justify=tk.LEFT,
                        anchor="w",
                        fg=change_color,
                    )
                    lbl.pack(anchor="w")
                    coin_labels[sym] = lbl
                else:
                    coin_labels[sym].config(text=text, fg=change_color)

        def fetch_once() -> None:
            """Fetch prices in a background thread, then update UI safely."""
            try:
                import requests
            except ImportError:
                prices_win.after(
                    0,
                    lambda: update_ui(None, "`requests` not installed. Run: pip install requests"),
                )
                return

            try:
                url = (
                    "https://api.coingecko.com/api/v3/simple/price"
                    "?ids=bitcoin,ethereum,solana,dogecoin"
                    "&vs_currencies=usd"
                    "&include_24hr_change=true"
                )
                resp = requests.get(url, timeout=5)
                data = resp.json()
                prices_win.after(0, lambda: update_ui(data, None))
            except Exception as e:
                prices_win.after(0, lambda: update_ui(None, str(e)))

        def schedule_refresh() -> None:
            """Refresh now, and if auto-refresh is on, schedule again."""
            fetch_once()
            if auto_var.get():
                # Refresh every 30 seconds
                prices_win.after(30000, schedule_refresh)

        # Controls at bottom: auto-refresh + manual refresh button
        controls_frame = tk.Frame(prices_win)
        controls_frame.pack(padx=10, pady=(0, 10), fill=tk.X)

        auto_chk = tk.Checkbutton(
            controls_frame,
            text="Auto-refresh every 30s",
            variable=auto_var,
            command=lambda: schedule_refresh() if auto_var.get() else None,
        )
        auto_chk.pack(side=tk.LEFT)

        refresh_btn = tk.Button(
            controls_frame,
            text="Refresh now",
            command=fetch_once,
        )
        refresh_btn.pack(side=tk.RIGHT)

        # Initial load
        fetch_once()

    # ---------- Networking ----------

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
            self.incoming.put("[System] Error connecting/receiving: {e}\n")
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
