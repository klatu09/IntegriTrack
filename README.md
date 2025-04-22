# Integritrack 1.0 by Klatu 🔒

**Integritrack** is a real-time file integrity monitoring tool with a sleek Tkinter GUI. It detects file creations, modifications, and deletions in a selected directory and logs their SHA-256 hashes along with timestamps. This project is designed for cybersecurity analysts, digital forensic investigators, and developers who need to monitor changes in critical directories.

## 🧠 Features

- ✅ **Real-time monitoring** of a selected directory
- 📁 **Tracks file creation, modification, and deletion**
- 🔐 **SHA-256 hashing** for file integrity verification
- 📜 **Detailed logs** with timestamps and color-coded events
- 📊 **GUI history viewer** for each file’s hash version history
- 💾 **Logs saved to JSON** on Desktop (`file_hash_log.json`)
- 🧠 **Built-in file viewer** to inspect monitored files and hash history
- 🎨 Dark-themed GUI built with **Tkinter**


## 🚀 Getting Started

### Requirements

- Python 3.7+
- Packages:
  - `tkinter` (usually preinstalled with Python)
  - `watchdog`

### Installation

1. git clone https://github.com/klatu09/IntegriTrack.git
2. cd Integritrack
3. pip install watchdog
4. python integritrack.py

### 🧠 How It Works 
- The tool uses the watchdog library to observe file system events.
- When a file is created or modified, it computes its SHA-256 hash.
- The hash and timestamp are stored in-memory and exported to a JSON file.
- Historical hashes help identify unauthorized or unexpected changes.


### 🕹️ How to Use ###
1. Launch the program.
2. Click Select Directory to choose a folder to monitor.
3. Press Start Monitoring to begin tracking changes.
4. View logs in real-time within the GUI.
5. Click Show Monitored Files to view hash histories.


## ⚠️ Disclaimer
- This tool is for educational and ethical use only. Do not use it to monitor directories without permission.


## 🧑‍💻 Author
- Klatu





