# MITRE ATT&CK for ICS Mapping

Each attack class in this lab maps to a technique from the [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) matrix. The mappings are deliberately conservative: each is a behavior the technique directly describes.

| Attack class | Technique | ID | Why it maps |
|---|---|---|---|
| Unauthorized function code | Unauthorized Command Message | T0855 | The attacker issues a Modbus function code the process never uses (FC 17, Report Server ID): an unauthorized command to a control-system asset. |
| Register enumeration | Remote System Information Discovery | T0846 | Sweeping the register map to learn the PLC's layout is discovery of control-system information before acting. |
| Write to protected register | Modify Parameter | T0836 | Writing to a setpoint register changes a parameter that governs the physical process. |
| Unauthorized client | Remote Services | T0886 | A Modbus request from an IP outside the authorized set indicates use of remote services to reach the controller. |

Three of the four attacks (T0855, T0846, T0886) leave no signature in the process data itself. That is the point of this project: process-based anomaly detection is blind to reconnaissance, unauthorized access, and commands caught before they take effect. Catching them requires watching the network.