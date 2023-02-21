
def split_packet(pkt):
    pkt_hex = pkt.hex()
    ip_header = ip_header_data(pkt_hex)
    tcp_header = tcp_header_data(pkt_hex)


def ip_header_data(pkt_hex):
    # ip header = 20 bytes
    ip_length = pkt_hex[1]
    # print(ip_length)
    ip_length_bytes = ""
    if ip_length == "5":
        ip_length_bytes = 2 * 20
    elif ip_length == "6":
        ip_length_bytes = 2 * 32
    ip_payload = pkt_hex[:ip_length_bytes]
    print("ip: " + ip_payload)
    return ip_payload

def tcp_header_data(pkt_hex):
    # tcp header = 32 bytes in opcua communication
    tcp_payload_length = int(pkt_hex[64], 16) * 4
    tcp_payload = pkt_hex[40:tcp_payload_length * 2 + 40]
    print(tcp_payload_length)
    print("tcp: " + tcp_payload)
    return tcp_payload

def opcua_payload_data(pkt_hex):
    # opcua payload at the end of packet
    opcua_payload = pkt_hex[104:]
    return opcua_payload

