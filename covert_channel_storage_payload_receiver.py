import sys

from Help_Functions.packet_interpreter import extract_packet_data
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from Help_Functions.opcua_data_class import OpcuaData
from scapy.layers.inet import IP, TCP

message = ""

def extract_message(opcua_data: OpcuaData, message_length: int):
    global message
    if message_length > 0:
        payload_value = opcua_data.payload[opcua_data.start:opcua_data.end]
        payload_value = "".join([m[1:2]+m[0:1] for m in [payload_value[::-1][i:i+2] for i in range(0, len(payload_value), 2)]])
        payload_binary = bin(int(payload_value, 16))[2:].zfill(8)
        message += payload_binary[len(payload_binary)-1]
        return
    else:
        payload_value = opcua_data.payload[opcua_data.start:opcua_data.end]
        payload_value = "".join(
            [m[1:2] + m[0:1] for m in [payload_value[::-1][i:i + 2] for i in range(0, len(payload_value), 2)]])
        payload_binary = bin(int(payload_value, 16))[2:].zfill(8)
        message += payload_binary[len(payload_binary) - 1]
        print(" [*] Nachricht vollständig empfangen: \n" + message)
        message = ""
        return


def alter_and_drop(pkt):
    urg_bits = 0x20
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        print(opcua_data.__str__())
        if opcua_data.rsp_type == "ReadResponse" and (pl.getlayer(TCP).flags & urg_bits):
            message_length = int(pl[TCP].urgptr) - 61440
            sys.stdout.write("\r\t Remaining packages: {} ".format(message_length / 2))
            sys.stdout.flush()
            extract_message(opcua_data, message_length)
        pkt.accept()


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
