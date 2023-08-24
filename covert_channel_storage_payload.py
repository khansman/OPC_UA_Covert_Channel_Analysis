from Help_Functions.packet_interpreter import extract_packet_data
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from Help_Functions.opcua_data_class import OpcuaData
from scapy.layers.inet import IP, TCP
from scapy.all import send, Raw
import struct

message = "Dies ist ein Test"
letters = ''.join(format(ord(x), 'b').zfill(8) for x in message)

# Parameter:    1. LSB    2. MSB

def alter_payload(opcua_data: OpcuaData):
    global letters
    payload_value = opcua_data.payload[opcua_data.start:opcua_data.end]
    payload_value = "".join([m[1:2]+m[0:1] for m in [payload_value[::-1][i:i+2] for i in range(0, len(payload_value), 2)]])
    payload_binary = bin(int(payload_value, 16))[2:].zfill(8)
    new_value_bin = payload_binary[:-1]+letters[0]
    new_value_hex_be = hex(int(str(new_value_bin), 2))[2:].zfill(16)
    new_value_dec = struct.unpack('>d', bytes.fromhex(new_value_hex_be))[0]
    new_value_hex_le = str(hex(struct.unpack('L', struct.pack('>d', new_value_dec))[0])[2:].zfill(16))
    new_payload = opcua_data.payload[:opcua_data.start] + new_value_hex_le + opcua_data.payload[opcua_data.end:]
    letters = letters[1:]
    return bytes.fromhex(new_payload)


def alter_and_drop(pkt):
    global letters
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadResponse" and len(letters) > 0:
            new_payload = alter_payload(opcua_data)
            pl[Raw].load = new_payload
            pl.getlayer(TCP).flags = 0x38
            pl.getlayer(TCP).urgptr = 61440 + len(letters)
            del pl[TCP].chksum
            del pl[IP].chksum
            pkt.drop()
            send(pl, verbose=False)
        else:
            pkt.accept()

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
