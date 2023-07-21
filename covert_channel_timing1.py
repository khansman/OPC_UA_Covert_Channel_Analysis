import sys

from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send

from opcua_data_class import OpcuaData
from packet_interpreter import extract_packet_data

message = "Dies ist ein Test"
letters = ''.join(format(ord(x), 'b').zfill(8) for x in message)
init_packet = False


def alter_and_drop(pkt):
    global letters
    global init_packet

    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        if len(letters) != 0 and init_packet is False:
            pl.getlayer(TCP).flags = 0x38
            pl.getlayer(TCP).urgptr = hex(61440 + len(letters))
            del pl[IP].len
            del pl[IP].chksum
            del pl[TCP].chksum
            init_packet = True
            pkt.drop()
            pl.show2()
            send(pl)
        if len(letters) != 0 and init_packet is True:
            pl.getlayer(TCP).flags = 0x38
            pl.getlayer(TCP).urgptr = hex(61440 + len(letters))
            del pl[IP].len
            del pl[IP].chksum
            del pl[TCP].chksum
            pkt.drop()
            pl.show2()
            if letters[0] == '1':
                send(pl, inter=1)
                letters = letters[1:]
            else:
                send(pl)
        else:
            pkt.accept()


if __name__ == "__main__":
    # global message
    # message = sys.argv[1]
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
