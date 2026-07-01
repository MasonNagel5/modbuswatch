import time
from pymodbus.client import ModbusTcpClient

# this is the control room. it reads the plc over and over, like checking gauges.
HOST = "127.0.0.1"
PORT = 5020

def main():
    client = ModbusTcpClient(HOST, port=PORT)
    client.connect()  # dial the plc
    print("control room connected. polling once a second (ctrl+c to stop).")
    try:
        while True:
            # one normal poll = the four everyday read commands, to the normal box range.
            # we throw the answers away. we just want realistic traffic on the wire.
            client.read_holding_registers(address=0, count=10)  # fc 3
            client.read_input_registers(address=0, count=10)    # fc 4
            client.read_coils(address=0, count=8)               # fc 1
            client.read_discrete_inputs(address=0, count=8)     # fc 2
            print("poll sent: fc 1/2/3/4 reads")
            time.sleep(1.0)  # wait a second, then go again
    except KeyboardInterrupt:
        print("\nstopping control room.")
    finally:
        client.close()  # hang up

if __name__ == "__main__":
    main()