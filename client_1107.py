import socket

HOST = "127.0.0.1"
PORT = 50107

def send_command(sock, cmd, arg1="", arg2="", token=""):
    parts = [p for p in [cmd, arg1, arg2, token] if p]
    payload = " ".join(parts)
    header = f"LEN:{len(payload)}\n"
    sock.sendall(header.encode())
    sock.sendall(payload.encode())
    response = sock.recv(4096).decode()
    return response.strip()

def main():
    session_token = ""
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        try:
            client.connect((HOST, PORT))
            print(f"Server on Port {PORT}")

            while True:
                user_input = input("\n> ").strip()
                if not user_input:
                    continue

                parts = user_input.split()
                cmd = parts[0].upper()

                if cmd == "EXIT":
                    print("Closing connection...")
                    break

                elif cmd == "REGISTER":
                    if len(parts) != 3:
                        print("Usage: REGISTER <username> <password>")
                        continue
                    resp = send_command(client, "REGISTER", parts[1], parts[2])
                    print(f"Server: {resp}")

                elif cmd == "LOGIN":
                    if len(parts) != 3:
                        print("Usage: LOGIN <username> <password>")
                        continue
                    resp = send_command(client, "LOGIN", parts[1], parts[2])
                    print(f"Server: {resp}")
                    
                    if resp.startswith("OK"):
                        session_token = resp.split()[-1]
                        print(f"[*] Login successful. Session token saved.")

                else:
                    if not session_token:
                        print("Error: Access Denied. You must LOGIN first.")
                        continue
                    
                    resp = send_command(client, cmd, session_token)
                    print(f"Server: {resp}")

                    if cmd == "LOGOUT" and resp.startswith("OK"):
                        session_token = ""
                        print("[*] Local session cleared.")

        except ConnectionRefusedError:
            print("Error: Could not connect to server. Is it running?")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
