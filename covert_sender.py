from packet_interpreter import extract_packet_data
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from opcua_data_class import OpcuaData
import struct


def alter_payload(opcua_data: OpcuaData):
    payload = opcua_data.payload
    # print(payload)
    new_value = 0.5
    new_value_hex = hex(struct.unpack('L', struct.pack('>d', new_value))[0])[2:].zfill(16)
    new_payload = payload[:opcua_data.start] + new_value_hex + payload[opcua_data.end:]
    return new_payload


def print_and_accept(pkt):
    pkt.retain()
    opcua_data = extract_packet_data(pkt)
    print(opcua_data.__str__())
    pkt.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
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
