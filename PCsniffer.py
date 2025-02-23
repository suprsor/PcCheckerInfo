This is the raw coding behind my PC checker, with a list of everything it does, you may review the code to ensure safety and more, also if you have any suggestions to add, please message @suprsor on discord to contact me. 

import os
import sys
import subprocess
import datetime 
import logging
import asyncio
import discord # type: ignore
from discord.ext import commands # type: ignore
import webbrowser
import threading
import tkinter as tk
from tkinter import messagebox
import shutil
from datetime import datetime

# Secure Configuration (Replace these values)
DISCORD_TOKEN = '  # Replace with your bot token
CHANNEL_ID =   # Replace with your channel ID
AUTHORIZED_KEY = ''  # Replace with your secret key

# Log file setup
LOG_FILE_PATH_EXE = 'pc_checker_log_exe.txt'
LOG_FILE_PATH_ZIP = 'pc_checker_log_zip.txt'
LOG_FILE_PATH_RAR = 'pc_checker_log_rar.txt'
LOG_FILE_PATH_TLSCAN = 'pc_checker_log_tlscan.txt'
LOG_FILE_PATH_SYSINFO = 'pc_checker_log_sysinfo.txt'
LOG_FILE_PATH_SUSFILES = 'pc_checker_log_susfiles.txt'
LOG_FILE_PATH_CFG = 'pc_checker_log_pf.txt'
LOG_FILE_PATH_PF = 'pc_checker_log_pf.txt'
MAX_LOG_SIZE = 8 * 1024 * 1024  # 8MB max per file

# Delete previous log files if they exist and recreate them empty
for log_file in [LOG_FILE_PATH_EXE, LOG_FILE_PATH_ZIP, LOG_FILE_PATH_RAR, LOG_FILE_PATH_TLSCAN, LOG_FILE_PATH_SYSINFO, LOG_FILE_PATH_SUSFILES, LOG_FILE_PATH_CFG, LOG_FILE_PATH_PF]:
    if os.path.exists(log_file):
        os.remove(log_file)
    with open(log_file, 'w') as f:
        pass

# Create log files if they don't exist
for log_file in [LOG_FILE_PATH_EXE, LOG_FILE_PATH_ZIP, LOG_FILE_PATH_RAR, LOG_FILE_PATH_TLSCAN, LOG_FILE_PATH_SYSINFO, LOG_FILE_PATH_SUSFILES, LOG_FILE_PATH_CFG, LOG_FILE_PATH_PF]:
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            pass

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def log_message(message, file_path):
    logging.debug(f"Logging message: {message}")
    print(message)
    with open(file_path, 'a') as log_file:
        log_file.write(message + '\n')
    logging.info(message)

def get_windows_settings():
    log_message("Fetching Windows Settings...", LOG_FILE_PATH_SYSINFO)
    log_last_install_date()
    check_secure_boot()

def get_antivirus_settings():
    log_message("Fetching Antivirus Settings...", LOG_FILE_PATH_SYSINFO)
    check_antivirus_status()
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled,FirewallEnabled'], capture_output=True, text=True)
        log_message("Antivirus Settings:", LOG_FILE_PATH_SYSINFO)
        log_message(result.stdout, LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching antivirus settings: {e}", LOG_FILE_PATH_SYSINFO)

def get_pc_information():
    log_message("Fetching PC Information...", LOG_FILE_PATH_SYSINFO)
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-ComputerInfo'], capture_output=True, text=True)
        log_message("PC Information:", LOG_FILE_PATH_SYSINFO)
        log_message(result.stdout, LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching PC information: {e}", LOG_FILE_PATH_SYSINFO)
    
    list_connected_devices()

def find_suspicious_files():
    log_message("Finding suspicious files...", LOG_FILE_PATH_SUSFILES)
    keywords = ["cheat", "hack", "injector", "mod", "bypass", "crack", "spoof", "exploit", "trainer", "patch",
                "unlock", "script", "dll", "loader", "ghost", "silent", "undetect", "unlocker", "booster", "aim",
                "norecoil", "ESP", "wallhack", "auto", "rage", "godmode", "trigger", "nospread", "spoofer", "macro",
                "lua", "AIO"]

    suspicious_files = []
    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]

    for drive in drives:
        for root, _, files in os.walk(drive, topdown=True):
            for file in files:
                if any(keyword in file.lower() for keyword in keywords):
                    suspicious_files.append(os.path.join(root, file))

    if suspicious_files:
        log_message("Found suspicious files:", LOG_FILE_PATH_SUSFILES)
        for file in suspicious_files:
            log_message(file, LOG_FILE_PATH_SUSFILES)
    else:
        log_message("No suspicious files found.", LOG_FILE_PATH_SUSFILES)

def find_archive_files():
    logging.debug("Finding archive files...")
    archive_files_exe = []
    archive_files_zip = []
    archive_files_rar = []
    archive_files_tlscan = []
    archive_files_pf = []
    archive_files_cfg = []
    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]

    for drive in drives:
        for root, _, files in os.walk(drive, topdown=True):
            for file in files:
                if file.lower().endswith('.exe'):
                    archive_files_exe.append(os.path.join(root, file))
                elif file.lower().endswith('.zip'):
                    archive_files_zip.append(os.path.join(root, file))
                elif file.lower().endswith('.rar'):
                    archive_files_rar.append(os.path.join(root, file))
                elif file.lower().endswith('.tlscan'):
                    archive_files_tlscan.append(os.path.join(root, file))
                elif file.lower().endswith('.pf'):
                    archive_files_pf.append(os.path.join(root, file))
                elif file.lower().endswith('.cfg'):
                    archive_files_cfg.append(os.path.join(root, file))

    if archive_files_exe:
        log_message("Found .exe files:", LOG_FILE_PATH_EXE)
        for file in archive_files_exe:
            log_message(file, LOG_FILE_PATH_EXE)
    else:
        log_message("No suspicious .exe files found.", LOG_FILE_PATH_EXE)

    if archive_files_zip:
        log_message("Found .zip files:", LOG_FILE_PATH_ZIP)
        for file in archive_files_zip:
            log_message(file, LOG_FILE_PATH_ZIP)
    else:
        log_message("No suspicious .zip files found.", LOG_FILE_PATH_ZIP)

    if archive_files_rar:
        log_message("Found .rar files:", LOG_FILE_PATH_RAR)
        for file in archive_files_rar:
            log_message(file, LOG_FILE_PATH_RAR)
    else:
        log_message("No suspicious .rar files found.", LOG_FILE_PATH_RAR)

    if archive_files_tlscan:
        log_message("Found .tlscan files:", LOG_FILE_PATH_TLSCAN)
        for file in archive_files_tlscan:
            log_message(file, LOG_FILE_PATH_TLSCAN)
    else:
        log_message("No suspicious .tlscan files found.", LOG_FILE_PATH_TLSCAN)
    
    if archive_files_pf:
        log_message("Found .pf files:", LOG_FILE_PATH_PF)
        for file in archive_files_pf:
            log_message(file, LOG_FILE_PATH_PF)
    else:
        log_message("No .pf files found.", LOG_FILE_PATH_PF)
    
    if archive_files_cfg:
        log_message("Found .cfg files:", LOG_FILE_PATH_CFG)
        for file in archive_files_cfg:
            log_message(file, LOG_FILE_PATH_CFG)
    else:
        log_message("No .cfg files found.", LOG_FILE_PATH_CFG)

def get_windows_settings():
    log_message("Fetching Windows Settings...", LOG_FILE_PATH_SYSINFO)
    log_last_install_date()
    check_secure_boot()

def log_last_install_date():
    try:
        result = subprocess.run(['powershell', '-Command', "(Get-CimInstance Win32_OperatingSystem).InstallDate"], capture_output=True, text=True)
        install_date = result.stdout.strip()
        log_message(f"Windows Installation Date: {install_date}", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Windows Installation Date: {e}", LOG_FILE_PATH_SYSINFO)

def check_secure_boot():
    try:
        result = subprocess.run(['powershell', '-Command', "Confirm-SecureBootUEFI"], capture_output=True, text=True)
        status = result.stdout.strip()
        log_message(f"Secure Boot Status: {status}", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Secure Boot status: {e}", LOG_FILE_PATH_SYSINFO)

def get_antivirus_settings():
    log_message("Fetching Antivirus Settings...", LOG_FILE_PATH_SYSINFO)
    check_real_time_protection()
    check_firewall_status()
    check_cfg_status()
    check_memory_integrity_status()
    check_vulnerable_driver_blocklist()
    check_dma_kernel_protection()

def check_antivirus_status():
    try:
        result = subprocess.run(['powershell', '-Command', "Get-MpComputerStatus | Select-Object AMRunningMode"], capture_output=True, text=True)
        status = result.stdout.strip()
        log_message(f"Antivirus Status: {status}", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Antivirus status: {e}", LOG_FILE_PATH_SYSINFO)

def get_pc_information():
    log_message("Fetching PC Information...", LOG_FILE_PATH_SYSINFO)
    log_computer_specifications()
    list_connected_devices()
    list_dma_devices()

def list_connected_devices():
    try:
        result = subprocess.run(['powershell', '-Command', "Get-PnpDevice | Where-Object { $_.Present -eq $true } | Select-Object Name, Manufacturer"], capture_output=True, text=True)
        devices = result.stdout.strip()
        log_message(f"Connected Devices:\n{devices}", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching connected devices: {e}", LOG_FILE_PATH_SYSINFO)

def get_system_info():
    log_message("Starting system information collection...", LOG_FILE_PATH_SYSINFO)
    get_windows_settings()
    get_antivirus_settings()
    get_pc_information()
    find_suspicious_files()
    find_archive_files()
    log_message("System information collection complete.", LOG_FILE_PATH_SYSINFO)

def check_real_time_protection():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled'], capture_output=True, text=True)
        log_message("Real Time Protection Status:", LOG_FILE_PATH_SYSINFO)
        log_message(result.stdout, LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Real Time Protection status: {e}", LOG_FILE_PATH_SYSINFO)

def check_firewall_status():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-NetFirewallProfile | Select-Object Name, Enabled'], capture_output=True, text=True)
        log_message("Firewall Status:", LOG_FILE_PATH_SYSINFO)
        log_message(result.stdout, LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Firewall status: {e}", LOG_FILE_PATH_SYSINFO)

def check_cfg_status():
    try:
        # Placeholder for CFG status check command
        log_message("CFG Status: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching CFG status: {e}", LOG_FILE_PATH_SYSINFO)

def check_memory_integrity_status():
    try:
        # Placeholder for Memory Integrity status check command
        log_message("Memory Integrity Status: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Memory Integrity status: {e}", LOG_FILE_PATH_SYSINFO)

def check_vulnerable_driver_blocklist():
    try:
        # Placeholder for Microsoft Vulnerable Driver Blocklist check command
        log_message("Microsoft Vulnerable Driver Blocklist: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Microsoft Vulnerable Driver Blocklist: {e}", LOG_FILE_PATH_SYSINFO)

def check_dma_kernel_protection():
    try:
        # Placeholder for DMA Kernel protection check command
        log_message("DMA Kernel Protection: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching DMA Kernel Protection: {e}", LOG_FILE_PATH_SYSINFO)

def log_protection_history():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-MpThreatDetection | Select-Object DetectionType, ThreatName, TimeDetected'], capture_output=True, text=True)
        log_message("Protection History:", LOG_FILE_PATH_SYSINFO)
        log_message(result.stdout, LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching protection history: {e}", LOG_FILE_PATH_SYSINFO)

def log_computer_specifications():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-ComputerInfo'], capture_output=True, text=True)
        log_message("Computer Specifications:", LOG_FILE_PATH_SYSINFO)
        log_message(result.stdout, LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching computer specifications: {e}", LOG_FILE_PATH_SYSINFO)

def list_dma_devices():
    try:
        # Placeholder for listing DMA devices command
        log_message("DMA Devices: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error listing DMA devices: {e}", LOG_FILE_PATH_SYSINFO)

def send_logs_to_channel(channel, client):
    logging.debug("Sending logs to channel...")
    for file_path in [LOG_FILE_PATH_EXE, LOG_FILE_PATH_ZIP, LOG_FILE_PATH_RAR, LOG_FILE_PATH_TLSCAN, LOG_FILE_PATH_SYSINFO, LOG_FILE_PATH_SUSFILES, LOG_FILE_PATH_CFG, LOG_FILE_PATH_PF]:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            file_size = os.path.getsize(file_path)
            if file_size <= MAX_LOG_SIZE:
                with open(file_path, 'rb') as log_file:
                    asyncio.run_coroutine_threadsafe(
                        channel.send(file=discord.File(log_file, filename=os.path.basename(file_path))),
                        client.loop
                    )
            else:
                part_number = 1
                with open(file_path, 'rb') as log_file:
                    while chunk := log_file.read(MAX_LOG_SIZE):
                        part_filename = f'{file_path}_part{part_number}.txt'
                        with open(part_filename, 'wb') as part_file:
                            part_file.write(chunk)

                        with open(part_filename, 'rb') as part_file:
                            asyncio.run_coroutine_threadsafe(
                                channel.send(file=discord.File(part_file, filename=os.path.basename(part_filename))),
                                client.loop
                            )

                        os.remove(part_filename)  # Cleanup after sending
                        part_number += 1
        else:
            asyncio.run_coroutine_threadsafe(
                channel.send(f"{file_path} is empty or missing."),
                client.loop
            )

    # Create a folder and move all .txt files into it
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    folder_name = f"{timestamp}PC-Check"
    os.makedirs(folder_name, exist_ok=True)

    for file_path in [LOG_FILE_PATH_EXE, LOG_FILE_PATH_ZIP, LOG_FILE_PATH_RAR, LOG_FILE_PATH_TLSCAN, LOG_FILE_PATH_SYSINFO, LOG_FILE_PATH_SUSFILES, LOG_FILE_PATH_CFG, LOG_FILE_PATH_PF]:
        if os.path.exists(file_path):
            shutil.move(file_path, os.path.join(folder_name, os.path.basename(file_path)))

def get_r6_usernames():
    logging.debug("Getting R6 usernames...")
    r6_folder = os.path.join(os.path.expanduser('~'), 'OneDrive', 'Documents', 'My Games', 'Rainbow Six - Siege')
    log_message(f"Checking path: {r6_folder}", LOG_FILE_PATH_EXE)

    if os.path.exists(r6_folder):
        log_message(f"R6 folder exists: {os.path.isdir(r6_folder)}", LOG_FILE_PATH_EXE)
        usernames = [f for f in os.listdir(r6_folder) if os.path.isdir(os.path.join(r6_folder, f)) and len(f) == 36 and '-' in f]
        log_message(f"Found R6 usernames: {usernames}", LOG_FILE_PATH_EXE)
        return usernames
    else:
        log_message("R6 folder not found.", LOG_FILE_PATH_EXE)
        return []

def open_stats():
    usernames = get_r6_usernames()
    for username in usernames:
        profile_url = f'https://stats.cc/siege/{username}'
        webbrowser.open(profile_url)

# Define the is_running variable globally
is_running = False

client = commands.Bot(command_prefix='!', intents=discord.Intents.default())

async def start_full_process():
    logging.debug("Starting full process...")
    global is_running
    if is_running:
        log_message("Process is already running.", LOG_FILE_PATH_SYSINFO)
        return

    is_running = True
    try:
        await client.wait_until_ready()
        channel = client.get_channel(CHANNEL_ID)
        if not channel:
            print(f"Channel with ID {CHANNEL_ID} not found")
            return

        get_system_info()
        check_secure_boot()
        check_antivirus_status()
        list_connected_devices()
        log_last_install_date()
        # open_stats()  # Comment out or remove this line if you don't want to open stats
        find_archive_files()

        send_logs_to_channel(channel, client)
    finally:
        is_running = False

def display_prompt():
    logging.debug("Displaying prompt...")

    entry = None  # Define entry variable

    def on_continue():
        entered_key = entry.get()
        if entered_key == AUTHORIZED_KEY:
            root.destroy()
            threading.Thread(target=asyncio.run, args=(start_full_process(),)).start()
        else:
            error_label.config(text="You have entered an incorrect key.")
            entry.delete(0, 'end')

    def on_cancel():
        root.destroy()
        os._exit(1)

    def open_link(event):
        webbrowser.open_new(r"https://github.com/suprsor/PcCheckerInfo/edit/main/README.md")

    # Create the main window
    root = tk.Tk()
    root.title("PC Checker")
    root.configure(bg="black")  # Set the background color
    root.geometry("500x500")  # Set the window size to 800x600

    # Create and place the labels and entry widgets
    text_widget = tk.Text(root, wrap="word", bg="black", fg="dark gray", insertbackground="red", relief="flat", height=20, width=60)
    text_widget.insert("1.0", (
        "Welcome to Suprsor's PC checker\n\n"
        "This application scans for:\n"
        "- Dma cheats\n"
        "- Internal cheats\n"
        "- Linked Rainbow 6 accounts\n"
        "- Secure boot status\n"
        "- Windows installation date\n"
        "- and more.\n\n"
        "This software requires a key to run in order to prevent abuse of software.\n\n"
        "If you would like to review the code you may visit "
    ))
    text_widget.insert("end", "this site", ("link",))
    text_widget.insert("end", "\n\nIf you have any questions please contact ")
    text_widget.insert("end", "Socials, and Contact me.", ("link",))
    text_widget.tag_configure("link", foreground="blue", underline=True)
    text_widget.tag_bind("link", "<Button-1>", lambda e: webbrowser.open_new("https://guns.lol/suprsor"))
    text_widget.config(state="disabled")
    text_widget.grid(row=0, column=0, padx=10, pady=10)

    entry_label = tk.Label(root, text="Enter your key:", bg="black", fg="dark gray")
    entry_label.grid(row=1, column=0, padx=10, pady=5)

    entry = tk.Entry(root, width=50, bg="dark gray", fg="red", insertbackground="red")
    entry.insert(0, "Please enter your key here.")
    entry.bind("<FocusIn>", lambda args: entry.delete('0', 'end') if entry.get() == "Please enter your key here." else None)
    entry.grid(row=2, column=0, padx=10, pady=5)

    error_label = tk.Label(root, text="", bg="black", fg="red")
    error_label.grid(row=3, column=0, padx=10, pady=5)

    # Create and place the buttons
    button_frame = tk.Frame(root, bg="black")
    button_frame.grid(row=4, column=0, padx=10, pady=10, sticky="ew")

    cancel_button = tk.Button(button_frame, text="Cancel", command=on_cancel, bg="gray", fg="red")
    cancel_button.pack(side="left", padx=5, pady=5)

    continue_button = tk.Button(button_frame, text="Continue", command=on_continue, bg="gray", fg="red")
    continue_button.pack(side="left", padx=5, pady=5, expand=True)

    open_stats_button = tk.Button(button_frame, text="Open Stats", command=open_stats, bg="gray", fg="red")
    open_stats_button.pack(side="right", padx=5, pady=5)

    # Run the main loop
    root.mainloop()

intents = discord.Intents.default()
intents.message_content = True
client = commands.Bot(command_prefix='!', intents=intents)

@client.event
async def on_ready():
    logging.debug("Bot is ready.")
    print(f'Logged in as {client.user}')
    display_prompt()

if __name__ == "__main__":
    logging.debug("Starting the script...")
    
    client.run(DISCORD_TOKEN)
