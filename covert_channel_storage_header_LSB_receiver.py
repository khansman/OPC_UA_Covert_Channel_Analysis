import sys

from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP

from Help_Functions.packet_interpreter import extract_packet_data

message = ""


def alter_and_drop(pkt):
    global message
    urg_bits = 0x20
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadResponse" and (pl.getlayer(TCP).flags & urg_bits):
            message_length = int(pl[TCP].urgptr) - 61440
            sys.stdout.write("\r\t Remaining packages: {} ".format(message_length/2))
            sys.stdout.flush()
            if message_length > 0:
                message_bits = bin(int(opcua_data.payload[112:113], 16)).replace('0b', '').zfill(4)[:2]
                message += str(message_bits)
            else:
                message_bits = bin(int(opcua_data.payload[112:113], 16)).replace('0b', '').zfill(4)[:2]
                message += str(message_bits)
                message_string = ''.join(chr(int(message[i*8:i*8+8], 2)) for i in range(len(message)//8))
                print("\n")
                sys.stdout.write("\r\t Message: {} ".format(message_string)+"\n")
                sys.stdout.flush()
                message = ''
        pkt.accept()


nfqueue = NetfilterQueue()
print("\n [*] Receiver online!")
print("\n\t Waiting for incoming message...")
nfqueue.bind(1, alter_and_drop)
try:
    call(['sudo iptables -D INPUT -p tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    call(['sudo iptables -A INPUT -p tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    nfqueue.run()
except (Exception, KeyboardInterrupt) as e:
    call(['sudo iptables -D INPUT -p tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    print(e)
    nfqueue.unbind()
