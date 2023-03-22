from scapy.all import rdpcap
from scapy.layers.inet import TCP

# read all data from pcap file
fp = rdpcap("telnet.pcap")

server_ip = "10.10.10.12"
client_ip = "10.10.10.13"

server = list()
client = list()

# iterate over all packets
for each in fp:
    try:
        # get that packets that source ip is equal to client ip
        if each.haslayer(TCP) and each[1].src == client_ip:
            client.append(each[2][1].load)
        # get that packets that source ip is equal to server ip
        elif each.haslayer(TCP) and each[1].src == server_ip:
            server.append(each[2][1].load)
    except(AttributeError, IndexError):
        pass

# write server data to file
with open("server.txt", "w") as f:
    for each in server:
        try:
            f.write(each.decode())
        except UnicodeDecodeError:
            pass

# write client data to file
with open("client.txt", "w") as f:
    for each in client:
        try:
            f.write(each.decode())
        except UnicodeDecodeError:
            pass