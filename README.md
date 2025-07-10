# 🎯 Unified Nmap Scanner - OS Detection + Vulnerability Report (GUI)

A Python GUI tool built with Tkinter that automates `nmap` scanning for:

- ✅ Operating System (OS) Detection  
- ✅ Top 100 Open Ports  
- ✅ Vulnerability Detection (`vuln`, `vulners` scripts)  
- ✅ SSH Analysis (`sshv1`, `ssh2-enum-algos`, `ssh-auth-methods`, `ssh-hostkey`)  
- ✅ Clean `.txt` reports saved per IP/subnet  
- ✅ Multi-threaded GUI — fast and responsive!

---

## 🚀 Features

- Supports `.txt`, `.csv`, or `.xlsx` input files  
- Detects Windows and Other OS types using `nmap -O`  
- Uses Nmap's NSE scripts for vulnerability scanning  
- Analyzes SSH algorithms, auth methods, and host keys  
- GUI stays responsive using threading  
- Saves organized output in district-wise folders

---

## 📂 Input File Format

You can use any of the following file types:

### `.txt` Format:
Simple list of IPs or CIDR subnets:
```
10.170.0.1
10.170.1.2/30
192.168.10.10
```

### `.csv` or `.xlsx` Format:
Each row may contain multiple IPs across columns. The tool extracts all valid IPs using regex.

Example:

| District   | IP1          | IP2          | IP3          |
|------------|--------------|--------------|--------------|
| Name    | 10.170.0.1   | 192.168.1.10 | 10.0.0.0/30  |
| Name | 172.16.5.5   | 10.170.10.15 | 192.168.10.1 |

---

## 📦 Requirements

Make sure the following Python packages are installed:
```
pandas
openpyxl
```

Install using:
```
pip install -r requirements.txt
```

Also, ensure **Nmap** is installed and accessible from the command line:
```
nmap -v
```

---

## 🛠️ How to Use

1. Run the script:
```
python unified_nmap_gui.py
```

2. In the GUI:
- Click "📂 Select IP File & Start Scan"
- Choose a `.txt`, `.csv`, or `.xlsx` file with IPs/subnets
- Choose a folder to save output
- Wait for the results (progress shown in GUI)

---

## 📄 Output

For each IP/subnet scanned, a `.txt` file will be generated with:

- Scan time
- OS match with accuracy %
- Detected vulnerabilities
- SSH-related issues
- Raw Nmap output

Each file is saved in the folder you selected, grouped by district if applicable.

---

## 🔍 Nmap Command Used Internally

```
nmap -O -T4 -A --top-ports 100 --script vuln,default,sshv1,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods <IP>
```

---

## 👤 Author

**Mari Ganesh** 
Email: mariganesh2004@gmail.com  


---

## ⚠️ Disclaimer

This tool is for **authorized use only**.  
Do not scan any system or network without proper permission.
