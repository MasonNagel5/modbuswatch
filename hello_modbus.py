import threading, time
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock
from pymodbus.client import ModbusTcpClient

# The PLC's memory: 200 "holding registers" pre-filled with values 0..199.
# A register is just a numbered storage slot the PLC exposes over the network.
store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, list(range(200))))
context = ModbusServerContext(slaves=store, single=True)

def run_server():
    # This is the pretend PLC, it listens on port 502 
    StartTcpServer(context=context, address=("127.0.0.1", 5020))

# Start the PLC in the background so the script can also act as the client.
threading.Thread(target=run_server, daemon=True).start()
time.sleep(1)  # give the server a second to come up

# This is the pretend control room. Connect to the PLC.
client = ModbusTcpClient("127.0.0.1", port=5020)
client.connect()

rr = client.read_holding_registers(address = 100, count = 3)

print(rr.registers)

client.close()