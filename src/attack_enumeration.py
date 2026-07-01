import time
from pymodbus.client import ModbusTcpClient

# normal traffic reads the same few boxes over and over
HOST = "127.0.0.1"
PORT = 5020

def main():
    client = ModbusTcpClient(HOST, port=PORT)
    client.connect()
    print("attacker connected. enumerating registers 0-149...")
    for addr in range(0, 150):
        client.read_holding_registers(address=addr, count=1)  # one box at a time, walking the map
    print("done. swept 150 distinct addresses.")
    client.close()

if __name__ == "__main__":
    main()