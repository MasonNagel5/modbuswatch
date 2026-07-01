import time
from pymodbus.client import ModbusTcpClient

# attack 1: unauthorized function code.
# normal traffic only uses read commands (fc 1,2,3,4).
# here the attacker sends fc 17 which is unheard of
# in real life this is an intruder probing the plc to figure out what it is.
HOST = "127.0.0.1"
PORT = 5020

def main():
    client = ModbusTcpClient(HOST, port=PORT)
    client.connect()  # dial the plc, same as a normal client would
    print("attacker connected. sending unauthorized function code (fc 17)...")
    for i in range(5):
        client.report_slave_id()          # fc 17: NOT one of the normal four
        print(f"  sent fc 17 report-server-id #{i + 1}")
        time.sleep(0.5)
    client.close()
    print("done.")

if __name__ == "__main__":
    main()