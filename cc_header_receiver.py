from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP

from packet_interpreter import extract_packet_data

message = ""

def alter_and_drop(pkt):
    global message
    urg_bits = 0x20
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        print(opcua_data.__str__())
        if pl.getlayer(TCP).flags & urg_bits:
            message_length = int(pl[TCP].urgptr, 16) - 61440
            if message_length != 0:
                message_bits = opcua_data.payload[112:113]
                message += str(message_bits)
            else:
                message_bits = opcua_data.payload[112:113]
                message += str(message_bits)
                print(bytes.decode(bytes.fromhex(message)))


nfqueue = NetfilterQueue()
nfqueue.bind(1, alter_and_drop)
try:
    call(['sudo iptables -D INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    call(['sudo iptables -I INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    nfqueue.run()
except (Exception, KeyboardInterrupt) as e:
    call(['sudo iptables -D INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    print(e)
    nfqueue.unbind()
