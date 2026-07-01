import time, csv, threading
from pymodbus.client import ModbusTcpClient

# reuse the four attack scripts you already built
from attack_unauthorized_fc import main as attack_unauthorized_fc
from attack_enumeration import main as attack_enumeration
from attack_sensitive_write import main as attack_sensitive_write
from attack_unauthorized_client import main as attack_unauthorized_client

HOST, PORT = "127.0.0.1", 5020
GROUND_TRUTH = "ground_truth.csv"

stop_normal = threading.Event()

def normal_loop():
    # background control room
    client = ModbusTcpClient(HOST, port=PORT); client.connect()
    while not stop_normal.is_set():
        client.read_holding_registers(address=0, count=10)
        client.read_coils(address=0, count=8)
        time.sleep(1.0)
    client.close()

def log_attack(writer, label, details):
    # write the answer-key row and then the caller fires the attack
    writer.writerow([f"{time.time():.3f}", label, details])
    print(f"fired {label}")

def main():
    # start normal traffic humming in the background
    threading.Thread(target=normal_loop, daemon=True).start()
    print("normal traffic running. warming up 5s...")
    time.sleep(5)

    with open(GROUND_TRUTH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "label", "details"])  # header row

        log_attack(writer, "UNAUTHORIZED_FC", "fc17 report server id")
        attack_unauthorized_fc(); time.sleep(3)

        log_attack(writer, "REGISTER_ENUMERATION", "swept registers 0-149")
        attack_enumeration(); time.sleep(3)

        log_attack(writer, "SENSITIVE_REGISTER_WRITE", "wrote value to reg 100")
        attack_sensitive_write(); time.sleep(3)

        log_attack(writer, "UNAUTHORIZED_CLIENT", "modbus from 127.0.0.2")
        attack_unauthorized_client(); time.sleep(3)

    print("all attacks fired. letting normal traffic run 3 more seconds...")
    time.sleep(3)
    stop_normal.set()
    print(f"done. answer key written to {GROUND_TRUTH}")

if __name__ == "__main__":
    main()