Dojo: Introduction to Cybersecurity

Module: Intercepting Communication

One of my favourite modules.

We learn to write (and send) our own Ethernet frames, IP packets, ARP requests, as well as MITM attacks (ARP Poisoning) using Scapy.

We also learn to trick our kernel into believing that we have a certain IP address (using the ip addr add command)

We learn UDP, how it is connectionless, and how easy it is to spoof an IP address and send UDP packets.
We learn TCP, connection-oriented (handshakes), and that it is significantly harder to spoof due to the (seq,ack) numbers and checksums.
Nonetheless, a MITM type of attack is possible with TCP.

Tools/commands used: nc, Scapy, ip
