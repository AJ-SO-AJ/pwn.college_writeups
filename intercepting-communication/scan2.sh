# Same as Scan 1 but this time the subnet is 10.0.0.0/16, so 16 bits for the host part -> 65k addresses.
# Pinging would take 1 hour if we somehow pinged 10 hosts in 1 second.
# Use nmap with its optimisation options to make it quicker.

nmap -T5 --min-rate 3000 -n -v 10.0.0.0/16

# Fastest timing, 3000 packets minimum, no DNS resolution.
# Then netcat to get the flag.
