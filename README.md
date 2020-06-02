# TCP-Hijacking branch

This is a demo of tcp-hijacking attack:

1. The **attacker** being on the same link as the **victim**, and is able to overhear the traffic between the the **victim** and the **remote endpoint** of the connection;
2. The **attacker** detects that connection establishment is happening (SYN's are being exchanged), and records the chosen initial sequence numbers, from either side
3. The **attacker**, then, sends a TCP segment with the RST flag set, and spoofing the IP address of the **remote endpoint** of the connection, to the  **victim**
