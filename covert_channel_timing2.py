import time

from packet_interpreter import extract_packet_data
from repeater import Repeater
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

letters = ''.join(format(ord(x), 'b').zfill(8) for x in "Dies ist ein Test")
sequence_drop_packet = 0
id_drop_packet = 0


def alter_and_drop(pkt):
    alter_and_drop.counter += 1
    global sequence_drop_packet
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "Read":
            if pl[TCP].seq == sequence_drop_packet:
                print("TCP Retransmission!")
                pkt.accept()
            elif pl[TCP].seq != sequence_drop_packet and alter_and_drop.counter % 5 == 0:
                pkt.drop()


alter_and_drop.counter = 0

if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, alter_and_drop)
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
