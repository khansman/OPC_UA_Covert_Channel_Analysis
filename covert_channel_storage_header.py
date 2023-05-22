from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send

from packet_interpreter import extract_packet_data


def alter_and_drop(pkt):
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        # encoding_mask = opcua_data.payload[112:114]
        opcua_payload = opcua_data.payload
        new_opcua_payload = opcua_payload[:112] + "07" + opcua_payload[114:]
        pl[Raw].load = new_opcua_payload
        del pl[IP].len
        del pl[IP].chksum
        del pl[TCP].len
        del pl[TCP].chksum
        pkt.drop()
        pl.show2()
        send(pl)
        print(opcua_data.__str__())


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
