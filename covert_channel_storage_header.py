import sys

from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send

from opcua_data_class import OpcuaData
from packet_interpreter import extract_packet_data

message = ""
letters = ''.join(format(ord(x), 'b').zfill(8) for x in message)


def alter_payload(opcua_data: OpcuaData):
    global letters
    payload = opcua_data.payload
    # print(payload)
    new_value = hex(int(letters[:2]+'00', 2))[2:]
    letters = letters[2:]
    new_payload = payload[:112] + new_value + payload[113:]
    return bytes.fromhex(new_payload)


def alter_and_drop(pkt):
    global letters

    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "Read":
            print(opcua_data.__str__())
            if len(letters) != 0:
                new_opcua_payload = alter_payload(opcua_data)
                pl[Raw].load = new_opcua_payload
                pl.getlayer(TCP).flags = 0x38
                pl.getlayer(TCP).urgptr = hex(61440+len(letters))
                del pl[IP].len
                del pl[IP].chksum
                del pl[TCP].chksum
                pkt.drop()
                pl.show2()
                send(pl)
            else:
                pkt.accept()
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
