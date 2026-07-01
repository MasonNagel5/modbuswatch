@load base/protocols/modbus

module ModbusWatch;

export {
    redef enum Notice::Type += {
        Unauthorized_Function_Code,
        Register_Enumeration,
        Sensitive_Register_Write,
        Unauthorized_Client,
    };
}

# lab runs modbus on 5020, not the default 502
event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_MODBUS, 5020/tcp);
}

# what "normal" looks like on this network:
const allowed_function_codes: set[count] = { 1, 2, 3, 4, 6, 16 };  # reads + legit write codes
const authorized_clients: set[addr] = { 127.0.0.1 };               # the known control room
const sensitive_start = 100;   # setpoint registers 100-120 are protected
const sensitive_end = 120;
const enum_threshold = 20;      # more distinct addresses than this = a scan

# remember which register addresses each source has read (resets after 30s)
global scan_tracker: table[addr] of set[count] &create_expire=30sec;

# attack 1 (weird function code) + attack 4 (stranger on the network)
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
    if ( ! is_orig ) return;   # only client -> plc requests

    if ( headers$function_code !in allowed_function_codes )
        NOTICE([$note=Unauthorized_Function_Code, $conn=c,
                $msg=fmt("unauthorized modbus function code %d from %s",
                         headers$function_code, c$id$orig_h)]);

    if ( c$id$orig_h !in authorized_clients )
        NOTICE([$note=Unauthorized_Client, $conn=c,
                $msg=fmt("modbus request from unauthorized client %s", c$id$orig_h)]);
}

# attack 3 (write to a protected setpoint register, fc 6)
event modbus_write_single_register_request(c: connection, headers: ModbusHeaders,
                                           address: count, value: count) {
    if ( address >= sensitive_start && address <= sensitive_end )
        NOTICE([$note=Sensitive_Register_Write, $conn=c,
                $msg=fmt("write to protected register %d (value %d) from %s",
                         address, value, c$id$orig_h)]);
}

# attack 2 (register enumeration / recon scan, fc 3)
event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders,
                                            start_address: count, quantity: count) {
    if ( c$id$orig_h !in scan_tracker )
        scan_tracker[c$id$orig_h] = set();
    add scan_tracker[c$id$orig_h][start_address];
    if ( |scan_tracker[c$id$orig_h]| == enum_threshold + 1 )
        NOTICE([$note=Register_Enumeration, $conn=c,
                $msg=fmt("register enumeration from %s: %d distinct addresses in window",
                         c$id$orig_h, |scan_tracker[c$id$orig_h]|)]);
}