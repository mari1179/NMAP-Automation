import subprocess
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from datetime import datetime
import os
import re
import pandas as pd


def parse_input_file(filepath):
    ext = os.path.splitext(filepath)[-1].lower()
    district_map = {}

    try:
        if ext == ".txt":
            current_district = None
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.endswith(':'):
                        current_district = line[:-1]
                        district_map[current_district] = []
                    elif current_district:
                        district_map[current_district].append(line)

        elif ext in [".csv", ".xlsx"]:
            if ext == ".csv":
                df = pd.read_csv(filepath)
            else:
                df = pd.read_excel(filepath, engine='openpyxl')

            df.fillna('', inplace=True)
            for _, row in df.iterrows():
                district = str(row[1]).strip()
                ips = []
                for val in row[2:]:
                    matches = re.findall(r'\d+\.\d+\.\d+\.\d+(?:/\d+)?', str(val))
                    ips.extend(matches)
                if district and ips:
                    district_map[district] = ips
        else:
            raise ValueError("Unsupported file type")

    except Exception as e:
        messagebox.showerror("File Error", f"Error reading file:\n{e}")
        return {}

    return district_map

# --- OS Detection Parsing ---
def extract_os_info(output):
    os_section = ""
    windows_info = []
    other_info = []

    match_lines = re.findall(r'OS match: (.+?) \((\d+)%\)', output)
    if not match_lines:
        detail_lines = re.findall(r'OS details: (.+)', output)
        if detail_lines:
            os_name = detail_lines[0]
            accuracy = "90"
            match_lines = [(os_name, accuracy)]

    if not match_lines:
        guess_lines = re.findall(r'OS guesses: (.+)', output)
        if guess_lines:
            guesses = guess_lines[0].split(",")
            best_guess = guesses[0].strip()
            match_lines = [(best_guess, "80")]

    if match_lines:
        os_name, acc = match_lines[0]
        os_section += f"[🧠 OS Detected] {os_name} (Accuracy: {acc}%)\n"
        if "windows" in os_name.lower():
            windows_info.append((os_name, acc))
        else:
            other_info.append((os_name, acc))
    else:
        os_section += "[⚠️ No OS match found]\n"
        other_info.append(("Unknown", "0"))

    return os_section, windows_info, other_info

# --- Script Check Parser ---
def parse_script_output(output, script_patterns):
    results = {}
    for pattern in script_patterns:
        if re.search(rf"\|\s+{re.escape(pattern)}\b", output):
            results[pattern] = True
        else:
            results[pattern] = False
    return results

# --- IP Scanner ---
def scan_ip(ip, save_dir, windows_hosts, other_hosts):
    result_text.insert(tk.END, f"\n[+] Scanning IP: {ip}\n")
    root.update()

    command = [
        "nmap", "-O", "-T4", "-A",
        "--top-ports", "100",
        "--script", "vuln,default,sshv1,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
        ip
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            result_text.insert(tk.END, f"[✖] Scan error for {ip}:\n{result.stderr}\n")
            return

        output = result.stdout
        combined_report = f"\n[+] Nmap Full Report for {ip}\n"
        combined_report += "=" * 70 + "\n"
        combined_report += f"\n[📅 Scan Time] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        combined_report += "-" * 70 + "\n"

        os_info, win_list, oth_list = extract_os_info(output)
        combined_report += os_info + "\n"

        for osname, acc in win_list:
            windows_hosts.append((ip, osname, acc))
        for osname, acc in oth_list:
            other_hosts.append((ip, osname, acc))

        script_check = parse_script_output(output, [
            "vulners", "vuln", "sshv1", "ssh2-enum-algos", "ssh-hostkey", "ssh-auth-methods"
        ])

        combined_report += "--- Vulnerability & SSH Results ---\n"
        combined_report += "[✔] Vulnerability scripts found issues.\n" if any(script_check.get(k, False) for k in ["vuln", "vulners"]) else "[!] No vulnerabilities found by 'vuln' scripts.\n"
        combined_report += "[✔] SSH scripts found potential issues.\n" if any(script_check.get(k, False) for k in ["sshv1", "ssh2-enum-algos", "ssh-hostkey", "ssh-auth-methods"]) else "[!] No SSH issues found.\n"

        combined_report += "\n--- Raw Nmap Output ---\n"
        combined_report += output

        combined_report += "\n\n--- WINDOWS HOSTS DETECTED ---\n"
        for ip_addr, osname, acc in windows_hosts:
            combined_report += f"💻 {ip_addr} - {osname} (Accuracy: {acc}%)\n"

        combined_report += "\n--- OTHER OS HOSTS DETECTED ---\n"
        for ip_addr, osname, acc in other_hosts:
            combined_report += f"🧹 {ip_addr} - {osname} (Accuracy: {acc}%)\n"

        filename = os.path.join(save_dir, f"{ip.replace('/', '_')}.txt")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(combined_report)

        result_text.insert(tk.END, f"[✔] Scan completed for {ip}. Saved to {filename}\n")

    except Exception as e:
        result_text.insert(tk.END, f"[!] Exception during scanning {ip}: {e}\n")

    result_text.insert(tk.END, "-" * 80 + "\n")
    root.update()

# --- Scanning Flow ---
def threaded_scan():
    file_path = filedialog.askopenfilename(title="Select IP File", filetypes=[("Supported Files", "*.txt *.csv *.xlsx")])
    if not file_path:
        scan_button.config(state=tk.NORMAL)
        return

    output_base = filedialog.askdirectory(title="Select Folder to Save Scan Results")
    if not output_base:
        scan_button.config(state=tk.NORMAL)
        return

    result_text.delete(1.0, tk.END)
    district_map = parse_input_file(file_path)

    for district, ip_list in district_map.items():
        district_safe = district.replace(" ", "_")
        district_path = os.path.join(output_base, district_safe)
        os.makedirs(district_path, exist_ok=True)

        result_text.insert(tk.END, f"\n🏙️ Scanning District: {district} ({len(ip_list)} IPs)\n")
        result_text.insert(tk.END, "=" * 60 + "\n")
        root.update()

        windows_hosts = []
        other_hosts = []

        for ip in ip_list:
            scan_ip(ip, district_path, windows_hosts, other_hosts)

    scan_button.config(state=tk.NORMAL)
    messagebox.showinfo("Scan Complete", "✅ All scans finished successfully!")

def start_scan_thread():
    scan_button.config(state=tk.DISABLED)
    thread = threading.Thread(target=threaded_scan)
    thread.start()

# --- GUI Setup ---
root = tk.Tk()
root.title("Unified Nmap Scanner - OS + Vuln Summary")
root.geometry("1000x700")
root.configure(bg="#f0f0f0")

frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=10)

scan_button = tk.Button(
    frame,
    text="📂 Select IP File & Start Scan",
    command=start_scan_thread,
    bg="#4a90e2",
    fg="white",
    font=("Arial", 12, "bold"),
    padx=20,
    pady=5
)
scan_button.pack()

result_text = scrolledtext.ScrolledText(
    root,
    wrap=tk.WORD,
    width=120,
    height=35,
    font=("Courier New", 10)
)
result_text.pack(padx=10, pady=10)

root.mainloop()
