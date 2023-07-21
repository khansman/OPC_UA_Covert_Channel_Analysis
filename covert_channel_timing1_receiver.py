import sys

from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP

from packet_interpreter import extract_packet_data

message = ""
init_packet = False
interpacket_time = -1


def alter_and_drop(pkt):
    global message
    global init_packet
    global interpacket_time
    urg_bits = 0x20
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        if pl.getlayer(TCP).flags & urg_bits:
            message_length = int(pl[TCP].urgptr) - 61440
            if init_packet is False:
                interpacket_time = pkt.time
                init_packet = True
            else:
                if message_length != 0:
                    interpacket_time = pkt.time - interpacket_time
                    if interpacket_time < 1:
                        message += "0"
                    else:
                        message += "1"
                else:
                    message_string = ''.join(chr(int(message[i * 8:i * 8 + 8], 2)) for i in range(len(message) // 8))
                    print("\n")
                    sys.stdout.write("\r\t Message: {} ".format(message_string) + "\n")
                    sys.stdout.flush()
                    message = ''
                    init_packet = False
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
