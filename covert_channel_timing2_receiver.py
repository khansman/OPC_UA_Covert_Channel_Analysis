import time

from packet_interpreter import extract_packet_data
from repeater import Repeater
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

sequence_drop_packet = 0
retransmission_list = []
message = ""


def alter_and_drop(pkt):
    print("Counter: " + str(alter_and_drop.counter))
    alter_and_drop.counter += 1
    global sequence_drop_packet
    global retransmission_list
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadRequest":
            if pl[TCP].seq == sequence_drop_packet:
                print("TCP Retransmission! " + str(pl[TCP].seq))
                retransmission_list.append(pl[TCP].seq)
                pkt.accept()
            elif pl[TCP].seq != sequence_drop_packet:
                print("Skip")
                pkt.accept()


alter_and_drop.counter = 0


def interpret_message():
    global retransmission_list
    global message
    if len(retransmission_list) > 3:
        message += "1"
    else:
        message += "0"


if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, alter_and_drop)
    repeater = Repeater(60,interpret_message)
    try:
        call(['sudo iptables -D OUTPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -I OUTPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        nfqueue.run()
    except (Exception, KeyboardInterrupt) as e:
        call(['sudo iptables -D OUTPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        print(e)
        nfqueue.unbind()
