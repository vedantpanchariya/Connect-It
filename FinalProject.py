import socket
import os
import threading
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

BUFFER_SIZE = 1024 * 1024
PORT = 5001
selected_files = []

def get_sender_ip():
    return socket.gethostbyname(socket.gethostname())

def get_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(BUFFER_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()

def send_files():
    global selected_files
    selected_files = filedialog.askopenfilenames()
    if not selected_files:
        messagebox.showerror("Error", "No files selected!")
        return

    try:
        sender_ip = get_sender_ip()
        sender_ip_label.config(text=f"Your IP: {sender_ip}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((sender_ip, PORT))
        sock.listen(1)
        messagebox.showinfo("Waiting", f"Waiting for connection on IP: {sender_ip}, Port: {PORT}...")

        client, addr = sock.accept()
        messagebox.showinfo("Connected", f"Connected to {addr}")

        # Send number of files
        client.sendall(str(len(selected_files)).encode('utf-8'))
        client.recv(16)  # ACK

        for file_path in selected_files:
            file_size = os.path.getsize(file_path)
            file_hash = get_file_hash(file_path)
            file_name = os.path.basename(file_path)
            metadata = f"{file_name}|{file_size}|{file_hash}"
            client.sendall(metadata.encode('utf-8'))
            client.recv(16)  # ACK

            progress_bar["maximum"] = file_size
            progress_bar["value"] = 0
            progress_label.config(text=f"Sending: {file_name}")

            sent_bytes = 0
            with open(file_path, "rb") as file:
                while True:
                    data = file.read(BUFFER_SIZE)
                    if not data:
                        break
                    client.sendall(data)
                    sent_bytes += len(data)
                    progress_bar["value"] = sent_bytes
                    root.update_idletasks()

        progress_label.config(text="All Files Sent Successfully!")
        messagebox.showinfo("Success", "All Files Sent Successfully!")
        sock.close()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send files: {e}")

def receive_files():
    try:
        receiver_ip = server_ip_entry.get().strip()
        if not receiver_ip:
            messagebox.showerror("Error", "Enter sender's IP address!")
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((receiver_ip, PORT))

        file_count = int(sock.recv(16).decode('utf-8'))
        sock.sendall(b'ACK')

        save_path = filedialog.askdirectory()
        if not save_path:
            messagebox.showerror("Error", "No folder selected!")
            return

        for _ in range(file_count):
            metadata = sock.recv(1024).decode('utf-8', errors="ignore").strip()
            sock.sendall(b'ACK')

            file_name, file_size, file_hash = metadata.split("|")
            file_size = int(file_size.strip())
            full_path = os.path.join(save_path, file_name)

            progress_bar["maximum"] = file_size
            progress_bar["value"] = 0
            progress_label.config(text=f"Receiving: {file_name}")

            received_bytes = 0
            with open(full_path, "wb") as file:
                while received_bytes < file_size:
                    data = sock.recv(min(BUFFER_SIZE, file_size - received_bytes))
                    if not data:
                        break
                    file.write(data)
                    received_bytes += len(data)
                    progress_bar["value"] = received_bytes
                    root.update_idletasks()

            if get_file_hash(full_path) != file_hash:
                progress_label.config(text=f"{file_name} - Corrupted!")
                messagebox.showerror("Error", f"File '{file_name}' corrupted!")
                return

        progress_label.config(text="All Files Received Successfully!")
        messagebox.showinfo("Success", "All Files Received Successfully!")
        sock.close()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to receive files: {e}")

def send_thread():
    threading.Thread(target=send_files, daemon=True).start()

def receive_thread():
    threading.Thread(target=receive_files, daemon=True).start()

# === UI ===
root = tk.Tk()
root.title("CONNECT IT")
root.geometry("500x550")
root.configure(bg="#ecf0f1")
root.resizable(False, False)

tk.Label(root, text="CONNECT IT", font=("Arial", 18, "bold"), bg="#ecf0f1", fg="#2c3e50").pack(pady=15)
sender_ip_label = tk.Label(root, text=f"Your IP: {get_sender_ip()}", font=("Arial", 10, "bold"), bg="#ecf0f1", fg="black")
sender_ip_label.pack(pady=10)

frame = tk.Frame(root, bg="#ecf0f1")
frame.pack(pady=10)

style = {
    "font": ("Arial", 12, "bold"),
    "fg": "white",
    "padx": 15,
    "pady": 10,
    "borderwidth": 0,
    "relief": "flat",
    "width": 10
}

tk.Button(frame, text="📤 Send", command=send_thread, bg="#2ecc71", **style).grid(row=0, column=0, padx=15, pady=5)
tk.Button(frame, text="📥 Receive", command=receive_thread, bg="#e74c3c", **style).grid(row=0, column=1, padx=15, pady=5)

tk.Label(root, text="Enter Sender IP:", font=("Arial", 10), bg="#ecf0f1").pack(pady=5)
server_ip_entry = tk.Entry(root, width=30, font=("Arial", 10))
server_ip_entry.pack(pady=5, ipady=4)

ttk.Style().configure("TProgressbar", thickness=10, background="#3498db", troughcolor="#bdc3c7", borderwidth=1)

progress_label = tk.Label(root, text="", font=("Arial", 10), bg="#ecf0f1")
progress_label.pack(pady=5)

progress_bar = ttk.Progressbar(root, length=400, mode="determinate", style="TProgressbar")
progress_bar.pack(pady=5)

root.mainloop()
