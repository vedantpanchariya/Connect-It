import socket
import os
import threading
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

BUFFER_SIZE = 1024 * 1024  # 1MB for faster transfer
PORT = 5001  # Port for file transfer
filename = None

# Function to Get Sender's IP Address
def get_sender_ip():
    return socket.gethostbyname(socket.gethostname())

# Function to Select File and Send
def send_file():
    global filename
    filename = filedialog.askopenfilename()
    if not filename:
        messagebox.showerror("Error", "No file selected!")
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

        file_size = os.path.getsize(filename)
        file_hash = get_file_hash(filename)

        metadata = f"{os.path.basename(filename)}|{file_size}|{file_hash}"
        client.sendall(metadata.encode('utf-8'))

        progress_bar["maximum"] = file_size
        progress_bar["value"] = 0
        progress_label.config(text="Sending...")

        sent_bytes = 0
        with open(filename, "rb") as file:
            while True:
                data = file.read(BUFFER_SIZE)
                if not data:
                    break
                client.sendall(data)
                sent_bytes += len(data)
                progress_bar["value"] = sent_bytes
                root.update_idletasks()

        progress_label.config(text="File Sent Successfully!")
        messagebox.showinfo("Success", "File Sent Successfully!")
        sock.close()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send file: {e}")

# Function to Receive File
def receive_file():
    try:
        receiver_ip = server_ip_entry.get().strip()
        if not receiver_ip:
            messagebox.showerror("Error", "Enter sender's IP address!")
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((receiver_ip, PORT))

        metadata = sock.recv(1024).decode('utf-8', errors="ignore").strip()
        file_info = metadata.split("|")
        if len(file_info) != 3:
            raise ValueError("Invalid File metadata received!")

        filename, file_size, file_hash = file_info
        file_size = file_size.strip()

        if not file_size.isdigit():
            raise ValueError(f"Invalid File Size received:'{file_size}'")

        file_size = int(file_size)

        save_path = filedialog.askdirectory()
        if not save_path:
            messagebox.showerror("Error", "No folder selected!")
            return

        full_path = os.path.join(save_path, filename)

        progress_bar["maximum"] = file_size
        progress_bar["value"] = 0
        progress_label.config(text="Receiving...")

        received_bytes = 0
        with open(full_path, "wb") as file:
            while received_bytes < file_size:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    break
                file.write(data)
                received_bytes += len(data)
                progress_bar["value"] = received_bytes
                root.update_idletasks()

        received_file_hash = get_file_hash(full_path)
        if received_file_hash == file_hash:
            progress_label.config(text="File Received Successfully!")
            messagebox.showinfo("Success", "File Received Successfully!")
        else:
            progress_label.config(text="File Corrupted")
            messagebox.showerror("Error", "File Transfer Failed: Corrupted Data")

        sock.close()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to receive file: {e}")

# Function to Get File Hash
def get_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(BUFFER_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()

# Function to Run Send and Receive in Threads
def send_file_thread():
    threading.Thread(target=send_file, daemon=True).start()

def receive_file_thread():
    threading.Thread(target=receive_file, daemon=True).start()

# Initialize Main Window
root = tk.Tk()
root.title("File Transfer (Windows)")
root.geometry("500x550")
root.configure(bg="#ecf0f1")
root.resizable(False, False)

# UI Components
title_label = tk.Label(root, text="CONNECT IT", font=("Arial", 18, "bold"), bg="#ecf0f1", fg="#2c3e50")
title_label.pack(pady=15)

# Display Sender's IP
sender_ip_label = tk.Label(root, text=f"Your IP: {get_sender_ip()}", font=("Arial", 10, "bold"), bg="#ecf0f1", fg="black")
sender_ip_label.pack(pady=10)

# Frame to Hold Buttons Side by Side
button_frame = tk.Frame(root, bg="#ecf0f1")
button_frame.pack(pady=10)

# Styling for Rounded Buttons
button_style = {
    "font": ("Arial", 12, "bold"),
    "fg": "white",
    "padx": 15,
    "pady": 10,
    "borderwidth": 0,
    "relief": "flat",
    "width": 10
}

send_btn = tk.Button(button_frame, text="📤 Send", command=send_file_thread, bg="#2ecc71", **button_style)
send_btn.grid(row=0, column=0, padx=15, pady=5)

receive_btn = tk.Button(button_frame, text="📥 Receive", command=receive_file_thread, bg="#e74c3c", **button_style)
receive_btn.grid(row=0, column=1, padx=15, pady=5)

# Move "No file selected" text below Send button
file_label = tk.Label(root, text="No file selected", font=("Arial", 10), bg="#ecf0f1", fg="black")
file_label.pack(pady=5)

# Receiver Input Field
tk.Label(root, text="Enter Sender IP:", font=("Arial", 10), bg="#ecf0f1").pack(pady=5)
server_ip_entry = tk.Entry(root, width=30, font=("Arial", 10))
server_ip_entry.pack(pady=5, ipady=4)

# Progress Bar Styling
style = ttk.Style()
style.theme_use("clam")
style.configure("TProgressbar", thickness=10, background="#3498db", troughcolor="#bdc3c7", borderwidth=1)

progress_label = tk.Label(root, text="", font=("Arial", 10), bg="#ecf0f1")
progress_label.pack(pady=5)

progress_bar = ttk.Progressbar(root, length=400, mode="determinate", style="TProgressbar")
progress_bar.pack(pady=5)

root.mainloop()

