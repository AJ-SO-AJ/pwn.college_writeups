# Connect to an unknown remote host on a 10.0.0.0/24 (8 bit host part) on port 31337.
# 10.0.0.0 is the network address (we can skip scanning on this address)
# 10.0.0.1 is our host address (we can skip scanning on this address)
# 10.0.0.255 is the broadcast address (we can skip scanning on this address)
# So we need to ping 10.0.0.2 through 10.0.0.254. Whoever gives us an ICMP Reply back, we find the host.
for i in $(seq 2 254); do timeout 2 ping "10.0.0.$i"; done

# The answer was .136. Now we can nc

nc 10.0.0.136 31337

# Prints us the flag
