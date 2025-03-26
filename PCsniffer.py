This is the raw coding behind my PC checker, with a list of everything it does, you may review the code to ensure safety and more, also if you have any suggestions to add, please message @suprsor on discord to contact me. 
import os
import sys
import subprocess
import datetime 
import logging
import asyncio
import discord 
from discord.ext import commands 
import webbrowser
import threading
import tkinter as tk
from tkinter import messagebox
from dotenv import load_dotenv


load_dotenv()


intents = discord.Intents.default()
intents.message_content = True  


client = commands.Bot(command_prefix='!', intents=intents)


DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')  
AUTHORIZED_KEY = os.getenv('AUTHORIZED_KEY', 'Example') 


channel_id_env = os.getenv('CHANNEL_ID')
if not channel_id_env or not channel_id_env.isdigit():
    raise ValueError("Invalid or missing CHANNEL_ID in the .env file. Please provide a valid channel ID.")

CHANNEL_ID = int(channel_id_env)  
print(f"Loaded CHANNEL_ID: {CHANNEL_ID}")

@client.command(name='setlogchannels')
async def set_log_channels(ctx, channel_id: int):
    await ctx.send("The log channel is static and cannot be changed.")


LOG_FILE_PATH_EXE = 'PcSnifferLog_exe.txt'
LOG_FILE_PATH_ZIP = 'PcSnifferLog_zip.txt'
LOG_FILE_PATH_RAR = 'PcSnifferLog_rar.txt'
LOG_FILE_PATH_TLSCAN = 'PcSnifferLog_tlscan.txt'
LOG_FILE_PATH_SYSINFO = 'PcSnifferLog_sysinfo.txt'
LOG_FILE_PATH_SUSFILES = 'PcSnifferLog_susfiles.txt'
LOG_FILE_PATH_CFG = 'PcSnifferLog_cfg.txt'
LOG_FILE_PATH_PF = 'PcSnifferLog_pf.txt'
MAX_LOG_SIZE = 8 * 1024 * 1024  


for log_file in [LOG_FILE_PATH_EXE, LOG_FILE_PATH_ZIP, LOG_FILE_PATH_RAR, LOG_FILE_PATH_TLSCAN, LOG_FILE_PATH_SYSINFO, LOG_FILE_PATH_SUSFILES, LOG_FILE_PATH_CFG, LOG_FILE_PATH_PF]:
    if os.path.exists(log_file):
        os.remove(log_file)
    with open(log_file, 'w') as f:
        pass


for log_file in [LOG_FILE_PATH_EXE, LOG_FILE_PATH_ZIP, LOG_FILE_PATH_RAR, LOG_FILE_PATH_TLSCAN, LOG_FILE_PATH_SYSINFO, LOG_FILE_PATH_SUSFILES, LOG_FILE_PATH_CFG, LOG_FILE_PATH_PF]:
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            pass



logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def log_message(message, file_path):
    logging.debug(f"Logging message: {message}")
    print(message)
    
    with open(file_path, 'a', encoding='utf-8') as log_file:
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
    keywords = ["cheat", "hack","bypass", "crack", "spoof", "exploit",
           "script", "loader", "silent", "unlocker",
                "norecoil", "ESP", "wallhack", "rage", "trigger", "nospread", "spoofer", "macro", "AIO"]

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
        result = subprocess.run(['powershell', '-WindowStyle', 'Hidden', '-Command', "(Get-CimInstance Win32_OperatingSystem).InstallDate"], capture_output=True, text=True)
        install_date = result.stdout.strip()
        log_message(f"Windows Installation Date: {install_date}", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Windows Installation Date: {e}", LOG_FILE_PATH_SYSINFO)
def check_secure_boot():
    try:
        result = subprocess.run(['powershell', '-WindowStyle', 'Hidden', '-Command', "Confirm-SecureBootUEFI"], capture_output=True, text=True)
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
    log_protection_history()

def check_antivirus_status():
    try:
        result = subprocess.run(['powershell', '-WindowStyle', 'Hidden', '-Command', "Get-MpComputerStatus | Select-Object AMRunningMode"], capture_output=True, text=True)
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
        result = subprocess.run(['powershell', '-WindowStyle', 'Hidden', '-Command', "Get-PnpDevice | Where-Object { $_.Present -eq $true } | Select-Object Name, Manufacturer"], capture_output=True, text=True)
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
        log_message("CFG Status: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching CFG status: {e}", LOG_FILE_PATH_SYSINFO)

def check_memory_integrity_status():
    try:
       
        log_message("Memory Integrity Status: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Memory Integrity status: {e}", LOG_FILE_PATH_SYSINFO)

def check_vulnerable_driver_blocklist():
    try:
       
        log_message("Microsoft Vulnerable Driver Blocklist: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching Microsoft Vulnerable Driver Blocklist: {e}", LOG_FILE_PATH_SYSINFO)

def check_dma_kernel_protection():
    try:
      
        log_message("DMA Kernel Protection: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching DMA Kernel Protection: {e}", LOG_FILE_PATH_SYSINFO)

def log_protection_history():
    try:
        result = subprocess.run(['powershell', '-WindowStyle', 'Hidden', '-Command', 'Get-MpThreatDetection | Select-Object DetectionType, ThreatName, TimeDetected'], capture_output=True, text=True)
        log_message("Protection History:", LOG_FILE_PATH_SYSINFO)
        log_message(result.stdout, LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching protection history: {e}", LOG_FILE_PATH_SYSINFO)

def log_computer_specifications():
    try:
        result = subprocess.run(['powershell', '-WindowStyle', 'Hidden', '-Command', 'Get-ComputerInfo'], capture_output=True, text=True)
        log_message("Computer Specifications:", LOG_FILE_PATH_SYSINFO)
        log_message(result.stdout, LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error fetching computer specifications: {e}", LOG_FILE_PATH_SYSINFO)

def list_dma_devices():
    try:
      
        log_message("DMA Devices: Not Implemented", LOG_FILE_PATH_SYSINFO)
    except Exception as e:
        log_message(f"Error listing DMA devices: {e}", LOG_FILE_PATH_SYSINFO)


def send_logs_to_channel(channel):
    logging.debug("Sending logs to channel...")
    for file_path in [LOG_FILE_PATH_EXE, LOG_FILE_PATH_ZIP, LOG_FILE_PATH_RAR, LOG_FILE_PATH_TLSCAN, LOG_FILE_PATH_SYSINFO, LOG_FILE_PATH_SUSFILES, LOG_FILE_PATH_CFG,LOG_FILE_PATH_PF ]:
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

                        os.remove(part_filename) 
                        part_number += 1
        else:
            asyncio.run_coroutine_threadsafe(
                channel.send(f"{file_path} is empty or missing."),
                client.loop
            )

def admin_logs_to_channel(channel, log_files):
    """
    Sends specific log files to the Discord channel.
    :param channel: The Discord channel object.
    :param log_files: A list of log file paths to send.
    """
    logging.debug("Sending admin-requested logs to channel...")
    if not isinstance(channel, discord.TextChannel):
        logging.error("Invalid channel object. Ensure the CHANNEL_ID is correct and the bot has access to the channel.")
        return

    for file_path in log_files:
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

                        os.remove(part_filename) 
                        part_number += 1
        else:
            asyncio.run_coroutine_threadsafe(
                channel.send(f"{file_path} is empty or missing."),
                client.loop
            )

def admin_send_log_to_channel(log_file_path, process_name):
    """
    Sends a specific log file to the Discord channel.
    :param log_file_path: The path to the log file to send.
    :param process_name: The name of the process for logging purposes.
    """
    try:
        channel = client.get_channel(CHANNEL_ID)
        if not channel:
            logging.error(f"Channel with ID {CHANNEL_ID} not found.")
            return

        if os.path.exists(log_file_path) and os.path.getsize(log_file_path) > 0:
            with open(log_file_path, 'rb') as log_file:
                asyncio.run_coroutine_threadsafe(
                    channel.send(file=discord.File(log_file, filename=os.path.basename(log_file_path))),
                    client.loop
                )
            logging.info(f"{process_name} log file {log_file_path} sent to the channel.")
        else:
            asyncio.run_coroutine_threadsafe(
                channel.send(f"{log_file_path} is empty or missing."),
                client.loop
            )
            logging.warning(f"{process_name} log file {log_file_path} is empty or missing.")
    except Exception as e:
        logging.error(f"Error sending {process_name} log file: {e}")

def get_r6_usernames_and_open_profiles():
    logging.debug("Getting R6 usernames and opening profiles...")
    r6_folder = os.path.join(os.path.expanduser('~'), 'OneDrive', 'Documents', 'My Games', 'Rainbow Six - Siege')
    log_message(f"Checking path: {r6_folder}", LOG_FILE_PATH_EXE)
    
    if os.path.exists(r6_folder):
        log_message(f"R6 folder exists: {os.path.isdir(r6_folder)}", LOG_FILE_PATH_EXE)
        usernames = [f for f in os.listdir(r6_folder) if os.path.isdir(os.path.join(r6_folder, f)) and len(f) == 36 and '-' in f]
        log_message(f"Found R6 usernames: {usernames}", LOG_FILE_PATH_EXE)
        
        def open_profile(username):
            profile_url = f'https://stats.cc/siege/{username}'
            webbrowser.open(profile_url)
            log_message(f"Opened profile for {username}", LOG_FILE_PATH_EXE)

        for username in usernames:
            threading.Thread(target=open_profile, args=(username,)).start()
            
        return usernames
    else:
        log_message("R6 folder not found.", LOG_FILE_PATH_EXE)
        return []


is_running = False

async def start_full_process(update_status):
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
        
        steps = [
            ("Fetching Windows Settings...", get_windows_settings),
            ("Fetching Antivirus Settings...", get_antivirus_settings),
            ("Fetching PC Information...", get_pc_information),
            ("Finding suspicious files...", find_suspicious_files),
            ("Finding archive files...", find_archive_files),
            ("Sending logs to channel...", lambda: send_logs_to_channel(channel))
        ]
        
        total_steps = len(steps)
        
        for i, (message, step) in enumerate(steps):
            update_status(message, int((i / total_steps) * 100))
            step()
        
        update_status("Process complete.", 100)
    finally:
        is_running = False

import threading

def display_admin_prompt():
    logging.debug("Displaying admin prompt...")

    def on_admin_authenticate():
        entered_key = admin_entry.get()
        if entered_key == os.getenv('ADMIN_KEY', 'Suprsor137$!!$'):
            admin_prompt.destroy()
            display_admin_panel()
        else:
            admin_error_label.config(text="Incorrect admin key.")
            admin_entry.delete(0, 'end')

    def on_admin_cancel():
        admin_prompt.destroy()

    admin_prompt = tk.Toplevel()
    admin_prompt.title("Admin Authentication")
    admin_prompt.configure(bg="black")
    admin_prompt.geometry("400x200")

    admin_label = tk.Label(admin_prompt, text="Enter Admin Key:", bg="black", fg="dark gray")
    admin_label.pack(pady=10)

    admin_entry = tk.Entry(admin_prompt, width=30, bg="dark gray", fg="red", insertbackground="red")
    admin_entry.pack(pady=5)

    admin_error_label = tk.Label(admin_prompt, text="", bg="black", fg="red")
    admin_error_label.pack(pady=5)

    admin_button_frame = tk.Frame(admin_prompt, bg="black")
    admin_button_frame.pack(pady=10)

    admin_cancel_button = tk.Button(admin_button_frame, text="Cancel", command=on_admin_cancel, bg="gray", fg="red")
    admin_cancel_button.pack(side="left", padx=5)

    admin_continue_button = tk.Button(admin_button_frame, text="Authenticate", command=on_admin_authenticate, bg="gray", fg="red")
    admin_continue_button.pack(side="right", padx=5)


def display_admin_panel():
    logging.debug("Displaying admin panel...")

    def change_auth_key():
        def on_change_key():
            new_key = key_entry.get()
            if new_key:
                with open('.env', 'r') as file:
                    lines = file.readlines()
                with open('.env', 'w') as file:
                    for line in lines:
                        if line.startswith("AUTHORIZED_KEY="):
                            file.write(f"AUTHORIZED_KEY={new_key}\n")
                        else:
                            file.write(line)
                key_prompt.destroy()
                messagebox.showinfo("Success", "AUTHORIZED_KEY updated successfully.")
            else:
                messagebox.showerror("Error", "Key cannot be empty.")

        key_prompt = tk.Toplevel()
        key_prompt.title("Change Auth Key")
        key_prompt.configure(bg="black")
        key_prompt.geometry("400x200")

        key_label = tk.Label(key_prompt, text="Enter new AUTHORIZED_KEY:", bg="black", fg="dark gray")
        key_label.pack(pady=10)

        key_entry = tk.Entry(key_prompt, width=30, bg="dark gray", fg="red", insertbackground="red")
        key_entry.pack(pady=5)

        key_button = tk.Button(key_prompt, text="Change Key", command=on_change_key, bg="gray", fg="red")
        key_button.pack(pady=10)

    def admin_bypass():
        threading.Thread(target=asyncio.run, args=(start_full_process(lambda msg, prog: None),)).start()
        admin_panel.destroy()

def start_specific_process(process_function, process_name, log_file_path):
        def run_process():
            try:
               
                process_function()
                
                
                admin_send_log_to_channel(log_file_path, process_name)
                
                messagebox.showinfo("Process Complete", f"{process_name} has completed, and the log file has been sent.")
            except Exception as e:
                logging.error(f"Error in {process_name}: {e}")
                messagebox.showerror("Error", f"An error occurred while running {process_name}.")
        
       
        threading.Thread(target=run_process).start()

def start_specific_process(process_function, process_name, log_file_path):
        def run_process():
            try:
          
                process_function()
                
               
                admin_send_log_to_channel(log_file_path, process_name)
                
                messagebox.showinfo("Process Complete", f"{process_name} has completed, and the log file has been sent.")
            except Exception as e:
                logging.error(f"Error in {process_name}: {e}")
                messagebox.showerror("Error", f"An error occurred while running {process_name}.")
        
       
        threading.Thread(target=run_process).start()

def start_specific_process(process_function, process_name, log_file_path):
        def run_process():
            try:
           
                process_function()
                
         
                admin_send_log_to_channel(log_file_path, process_name)
                
                messagebox.showinfo("Process Complete", f"{process_name} has completed, and the log file has been sent.")
            except Exception as e:
                logging.error(f"Error in {process_name}: {e}")
                messagebox.showerror("Error", f"An error occurred while running {process_name}.")
        
  
        threading.Thread(target=run_process).start()

    def start_specific_process(process_function, process_name, log_file_path):
        def run_process():
            try:
              
                process_function()
                
           
                admin_send_log_to_channel(log_file_path, process_name)
                
                messagebox.showinfo("Process Complete", f"{process_name} has completed, and the log file has been sent.")
            except Exception as e:
                logging.error(f"Error in {process_name}: {e}")
                messagebox.showerror("Error", f"An error occurred while running {process_name}.")
        
        
        threading.Thread(target=run_process).start()

    admin_panel = tk.Toplevel()
    admin_panel.title("Admin Panel")
    admin_panel.configure(bg="black")
    admin_panel.geometry("400x400")

    change_key_button = tk.Button(admin_panel, text="Change Auth Key", command=change_auth_key, bg="gray", fg="red")
    change_key_button.pack(pady=10)

    bypass_button = tk.Button(admin_panel, text="Admin Bypass", command=admin_bypass, bg="gray", fg="red")
    bypass_button.pack(pady=10)

    tk.Label(admin_panel, text="Start Specific Processes:", bg="black", fg="yellow").pack(pady=10)

    buttons = [
        ("Find SYSINFO", get_pc_information, LOG_FILE_PATH_SYSINFO),
        ("Find CFG", lambda: find_archive_files(), LOG_FILE_PATH_CFG),
        ("Find PF", lambda: find_archive_files(), LOG_FILE_PATH_PF),
        ("Find TLscan", lambda: find_archive_files(), LOG_FILE_PATH_TLSCAN),
        ("Find EXE", lambda: find_archive_files(), LOG_FILE_PATH_EXE),
    ]

    for name, func, log_path in buttons:
        tk.Button(admin_panel, text=name, command=lambda f=func, n=name, lp=log_path: start_specific_process(f, n, lp), bg="gray", fg="red").pack(pady=5)

def display_prompt():
    logging.debug("Displaying prompt...")

    entry = None  

    def update_status(message, progress):
        if message == "Process complete.":
            message += " You may now exit the program."
        status_label.config(text=f"{message} ({progress}%)")
        root.update_idletasks()

    def on_continue():
        if messagebox.askyesno("Confirmation", "Are you sure you want to continue?"):
            entered_key = entry.get()
            if entered_key == AUTHORIZED_KEY:
                update_status("Starting the process...", 0)
                continue_button.pack_forget()  
                threading.Thread(target=asyncio.run, args=(start_full_process(update_status),)).start()
            else:
                error_label.config(text="You have entered an incorrect key.")
                entry.delete(0, 'end')

    def on_cancel():
        if messagebox.askyesno("Confirmation", "Are you sure you want to cancel?"):
            root.destroy()
            os._exit(1)

    def open_stats():
        if messagebox.askyesno("Confirmation", "Are you sure you want to show stats?"):
            logging.debug("Opening stats...")
            usernames = get_r6_usernames_and_open_profiles()
            if usernames:
                for username in usernames:
                    profile_url = f'https://stats.cc/siege/{username}'
                    webbrowser.open(profile_url)
            else:
                messagebox.showinfo("Stats", "No R6 usernames found.")

    def open_admin():
        display_admin_prompt()

   
    root = tk.Tk()
    root.title("PC Checker")
    root.configure(bg="black")
    root.geometry("500x500")


    root.iconbitmap('c:/Users/motor/Downloads/pc check/favicon.ico')  

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
        "If you would like to review the code you may visit here: "
    ))
    text_widget.insert("end", " My Github Guide For More Info. ", ("link",))
    text_widget.insert("end", "\n\nIf you have any questions please press the following link. ")
    text_widget.insert("end", "Contacts and more.", ("link",))
    text_widget.tag_configure("link", foreground="blue", underline=True)
    text_widget.tag_bind("link", "<Button-1>", lambda e: webbrowser.open_new("https://guns.lol/suprsor"))
    text_widget.config(state="disabled")
    text_widget.grid(row=0, column=0, padx=10, pady=8)

    entry_label = tk.Label(root, text="Enter your key:", bg="black", fg="dark gray")
    entry_label.grid(row=1, column=0, padx=10, pady=2)

    entry = tk.Entry(root, width=50, bg="dark gray", fg="red", insertbackground="red")
    entry.grid(row=2, column=0, padx=10, pady=2)

    error_label = tk.Label(root, text="", bg="black", fg="red")
    error_label.grid(row=3, column=0, padx=10, pady=2)

  
    status_label = tk.Label(root, text="", bg="black", fg="yellow")
    status_label.grid(row=4, column=0, padx=10, pady=2)

   
    button_frame = tk.Frame(root, bg="black")
    button_frame.grid(row=5, column=0, padx=10, pady=18, sticky="ew")

    cancel_button = tk.Button(button_frame, text="Cancel", command=on_cancel, bg="gray", fg="red")
    cancel_button.pack(side="left", padx=5, pady=2)

    continue_button = tk.Button(button_frame, text="Continue", command=on_continue, bg="gray", fg="red")
    continue_button.pack(side="left", padx=5, pady=2, expand=True)

    open_stats_button = tk.Button(button_frame, text="Open Stats", command=open_stats, bg="gray", fg="red")
    open_stats_button.pack(side="right", padx=5, pady=2)

    admin_button = tk.Button(button_frame, text="Admin", command=open_admin, bg="gray", fg="red")
    admin_button.pack(side="right", padx=5, pady=2)

    
    root.mainloop()

def run_display_prompt():
    threading.Thread(target=display_prompt).start()

@client.event
async def on_ready():
    logging.debug("Bot is ready.")
    print(f'Logged in as {client.user}')
    run_display_prompt()

if __name__ == "__main__":
    logging.debug("Starting the script...")
    client.run(DISCORD_TOKEN)
