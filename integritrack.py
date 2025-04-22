import os
import json
import tkinter as tk
from tkinter import messagebox, Toplevel, filedialog
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import hashlib

# List to store monitored files and their hashes
monitored_files = []
log_file_path = os.path.join(os.path.expanduser("~/Desktop"), "file_hash_log.json")  # Path to Desktop

# Function to calculate the SHA-256 hash of a file
def calculate_file_hash(file_path):
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
    except Exception:
        return "Hash not available (access denied or file not readable)"
    return hash_sha256.hexdigest()

# GUI setup
root = tk.Tk()
root.title("File Integrity Monitor - Integritrack 1.0 by Klatu ")
root.configure(bg="#1e1e1e")

# Variable to store the selected directory
selected_directory = ""

def log_message(message, event_type):
    timestamp = datetime.now().strftime("%B %d, %Y, %H:%M:%S")
    full_message = f"[{timestamp}] {message}\n"
    
    color = {
        "created": "#32CD32",
        "modified": "#00FFFF",
        "deleted": "#FF4500",
        "start": "#00FA9A",
        "stop": "#FF6347",
    }.get(event_type, "white")

    log_text.insert(tk.END, "==============================\n", "separator")
    log_text.insert(tk.END, f"[{timestamp}]", "timestamp")
    log_text.insert(tk.END, f" {message}\n", event_type)
    log_text.insert(tk.END, "==============================\n\n", "separator")
    
    log_text.tag_configure(event_type, foreground=color)
    log_text.tag_configure("separator", foreground="gray")
    log_text.tag_configure("timestamp", foreground="white")

    # Automatically scroll to the bottom
    log_text.see(tk.END)

def show_monitored_files():
    if not monitored_files:
        messagebox.showinfo("Monitored Files", "No files monitored yet.")
        return

    files_window = Toplevel(root)
    files_window.title("Monitored Files")
    files_window.configure(bg="#1e1e1e")

    files_listbox = tk.Listbox(files_window, width=70, height=15, bg="#252526", fg="white", font=("Arial", 12))
    files_listbox.pack(padx=10, pady=10)

    for file in monitored_files:
        files_listbox.insert(tk.END, file['name'])

    def show_hashes(event):
        selected_index = files_listbox.curselection()
        if selected_index:
            file_name = files_listbox.get(selected_index)
            file_details = next((file for file in monitored_files if file['name'] == file_name), None)
            if file_details:
                show_hash_window(file_details)

    files_listbox.bind("<Double-1>", show_hashes)

    close_button = tk.Button(files_window, text="Close", command=files_window.destroy, bg="#007ACC", fg="white")
    close_button.pack(pady=5)

def show_hash_window(file_details):
    hash_window = Toplevel(root)
    hash_window.title(f"Hash History for {file_details['name']}")
    hash_window.configure(bg="#1e1e1e")

    # Create a frame to hold the text area and the close button
    hash_frame = tk.Frame(hash_window, bg="#1e1e1e")
    hash_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    hash_text = tk.Text(hash_frame, bg="#252526", fg="white", font=("Arial", 12))
    hash_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Track the last displayed hash to avoid duplicates
    last_hash = None

    # Display all hashes as versions from latest to oldest
    for index, entry in enumerate(file_details['hashes']):  # Use original order
        version_label = f"Version {index + 1}: {entry['hash']} | Timestamp: {entry['timestamp']}\n"
        
        # Only display the entry if the hash is different from the last displayed hash
        if entry['hash'] != last_hash:
            if index == len(file_details['hashes']) - 1:  # Highlight the latest version (last in original order)
                hash_text.insert(tk.END, version_label, "latest")
            else:
                hash_text.insert(tk.END, version_label)

            # Update the last_hash to the current entry's hash
            last_hash = entry['hash']

            # Add a separator line
            hash_text.insert(tk.END, "==============================\n", "separator")

    # Configure tags for coloring
    hash_text.tag_configure("latest", foreground="#32CD32")  # Green color for the latest version
    hash_text.tag_configure("separator", foreground="gray")  # Gray color for the separator

    close_hash_button = tk.Button(hash_frame, text="Close", command=hash_window.destroy, bg="#007ACC", fg="white")
    close_hash_button.pack(pady=5)

def save_log_to_json():
    with open(log_file_path, 'w') as log_file:
        json.dump(monitored_files, log_file, indent=4)

def clear_log_file():
    with open(log_file_path, 'w') as log_file:
        json.dump([], log_file)

class DirectoryEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            if os.path.getsize(event.src_path) == 0:
                log_message(f"File created: '{event.src_path}' | No hash value available (file is empty)", "created")
            else:
                file_hash = calculate_file_hash(event.src_path)
                timestamp = datetime.now().strftime("%B %d, %Y, %H:%M:%S")
                existing_file = next((file for file in monitored_files if file['name'] == event.src_path), None)
                if existing_file:
                    existing_file['hashes'].append({"hash": file_hash, "timestamp": timestamp})
                    log_message(f"File modified: '{event.src_path}' | Hash: {file_hash}", "modified")
                else:
                    monitored_files.append({"name": event.src_path, "hashes": [{"hash": file_hash, "timestamp": timestamp}]})
                    log_message(f"File created: '{event.src_path}' | Hash: {file_hash}", "created")
                save_log_to_json()

    def on_modified(self, event):
        if not event.is_directory:
            file_hash = calculate_file_hash(event.src_path)
            timestamp = datetime.now().strftime("%B %d, %Y, %H:%M:%S")
            existing_file = next((file for file in monitored_files if file['name'] == event.src_path), None)
            if existing_file:
                existing_file['hashes'].append({"hash": file_hash, "timestamp": timestamp})
                log_message(f"File modified: '{event.src_path}' | Hash: {file_hash}", "modified")
            else:
                monitored_files.append({"name": event.src_path, "hashes": [{"hash": file_hash, "timestamp": timestamp}]})
                log_message(f"File created: '{event.src_path}' | Hash: {file_hash}", "created")
            save_log_to_json()

    def on_deleted(self, event):
        if not event.is_directory:
            log_message(f"File deleted: '{event.src_path}'", "deleted")

monitoring_state = False
observer = None

def toggle_monitoring():
    global monitoring_state, observer, selected_directory
    if not selected_directory:
        messagebox.showwarning("Directory Not Selected", "Please select a directory to monitor.")
        return

    try:
        if monitoring_state:
            monitoring_state = False
            observer.stop()
            observer.join()
            start_stop_button.config(text="Start Monitoring", bg="#28a745", state=tk.NORMAL)  # Change text back to Start Monitoring
            select_directory_button.config(state=tk.NORMAL)  # Enable the Select Directory button
            log_message("Stopped monitoring.", "stop")
            clear_log_file()
            # Prompt to select a directory again
            messagebox.showinfo("Monitoring Stopped", "You can select a new directory to monitor.")
        else:
            monitoring_state = True
            observer = Observer()
            event_handler = DirectoryEventHandler()
            observer.schedule(event_handler, selected_directory, recursive=False)
            observer.start()
            start_stop_button.config(text="Stop Monitoring", bg="#0E8A16", state=tk.NORMAL)  # Change text to Stop Monitoring
            select_directory_button.config(state=tk.DISABLED)  # Disable the Select Directory button
            log_message(f"Started monitoring {selected_directory}.", "start")
            clear_log_file()
    except Exception as e:
        log_message(f"Error: {str(e)}", "deleted")


def select_directory():
    global selected_directory
    selected_directory = filedialog.askdirectory(title="Select Directory to Monitor")
    if selected_directory:
        messagebox.showinfo("Directory Selected", f"Monitoring will be set to: {selected_directory}")
        start_stop_button.config(state=tk.NORMAL)  # Enable the Start Monitoring button
        select_directory_button.config(state=tk.DISABLED)  # Disable the Select Directory button

log_text = tk.Text(
    root,
    width=70,
    height=25,
    font=("Arial", 12),
    bg="#252526",
    fg="white",
    insertbackground="white",
    borderwidth=0
)
log_text.pack(padx=15, pady=15, fill="both", expand=True)

# Create a frame to hold the buttons
button_frame = tk.Frame(root, bg="#1e1e1e")
button_frame.pack(pady=10)

select_directory_button = tk.Button(
    button_frame,
    text="Select Directory",
    command=select_directory,
    font=("Arial", 14),
    width=15,
    height=2,
    bg="#007bff",  # Blue color
    fg="white",
    activebackground="#0056b3",
    activeforeground="white",
    bd=0,
    relief="flat",
    cursor="hand2"
)
select_directory_button.pack(side=tk.LEFT, padx=5)

start_stop_button = tk.Button(
    button_frame,
    text="Start Monitoring",
    command=toggle_monitoring,
        font=("Arial", 14),
    width=15,
    height=2,
    bg="#28a745",  # Green color
    fg="white",
    activebackground="#218838",
    activeforeground="white",
    bd=0,
    relief="flat",
    cursor="hand2"
)
start_stop_button.pack(side=tk.LEFT, padx=5)
start_stop_button.config(state=tk.DISABLED)  # Initially disable the button

files_button = tk.Button(
    button_frame,
    text="Files Monitored",
    command=show_monitored_files,
    font=("Arial", 14),
    width=15,
    height=2,
    bg="#ffc107",  # Yellow color
    fg="black",
    activebackground="#e0a800",
    activeforeground="black",
    bd=0,
    relief="flat",
    cursor="hand2"
)
files_button.pack(side=tk.LEFT, padx=5)

root.mainloop()

