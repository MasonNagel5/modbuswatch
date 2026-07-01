import time
from pymodbus.client import ModbusTcpClient


# normal traffic comes from 127.0.0.1 which is the known control room
# here the attacker connects FROM 127.0.0.2, a machine that shouldn't be talking to the plc
# in a real plant, a modbus command from an unknown ip means an intruder is on the network


HOST = "127.0.0.1"
PORT = 5020

def main():
    # make us call from an unusual source
    client = ModbusTcpClient(HOST, port=PORT, source_address=("127.0.0.2", 0))
    client.connect()
    print("unauthorized client (127.0.0.2) connected. sending reads...")
    for i in range(5):
        client.read_holding_registers(address=0, count=5)
        print(f"  read from 127.0.0.2 #{i + 1}")
        time.sleep(0.3)
    client.close()
    print("done.")

if __name__ == "__main__":
    main()