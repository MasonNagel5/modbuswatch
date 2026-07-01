from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock
)

# this is the fake plc. it just sits and waits for someone to read or write its boxes.
HOST = "127.0.0.1"  # this same computer
PORT = 5020         # the "line" clients call in on

def build_context():
    # a plc has four kinds of storage, and modbus reads each with a different command.
    # we make all four so normal traffic can use all four read commands.
    coils           = ModbusSequentialDataBlock(0, [0] * 200)        # on/off outputs (fc 1)
    discrete_inputs = ModbusSequentialDataBlock(0, [0] * 200)        # on/off sensors (fc 2)
    holding_regs    = ModbusSequentialDataBlock(0, list(range(200))) # numbers, read/write (fc 3)
    input_regs      = ModbusSequentialDataBlock(0, list(range(200))) # numbers, read only (fc 4)

    # zero_mode=True makes box 100 actually mean box 100 (fixes the off-by-one)
    store = ModbusSlaveContext(
        co=coils, di=discrete_inputs, hr=holding_regs, ir=input_regs,
        zero_mode=True,
    )
    return ModbusServerContext(slaves=store, single=True)

# our rule for this lab:
#   boxes 0-99    = normal sensor values (only read normally)
#   boxes 100-120 = setpoints, sensitive. writing here is an attack later.
if __name__ == "__main__":
    # turn the plc on and wait forever
    print(f"plc listening on {HOST}:{PORT}")
    StartTcpServer(context=build_context(), address=(HOST, PORT))