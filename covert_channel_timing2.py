import time

from packet_interpreter import extract_packet_data
from repeater import Repeater
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

letters = ''.join(format(ord(x), 'b').zfill(8) for x in "Dies ist ein Test")

sequence_drop_packet = 0
drop_packet_flag = 5


def alter_and_drop(pkt):
    print("Counter: "+str(alter_and_drop.counter))
    alter_and_drop.counter += 1
    global sequence_drop_packet
    global drop_packet_flag
    global letters#
    print(letters)
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadResponse":
            if drop_packet_flag and letters[0] == '1':
                print("Drop "+ str(pl[TCP].seq))
                drop_packet_flag = False
                time.sleep(0.5)
                pkt.drop()
            else:
                print("Accept")
                pkt.accept()
            #if pl[TCP].seq == sequence_drop_packet:
             #   print("TCP Retransmission! "+str(pl[TCP].seq))
              #  pkt.accept()
            #elif pl[TCP].seq != sequence_drop_packet and drop_packet_flag:
             #   print("Drop")
              #  sequence_drop_packet = pl[TCP].seq
               # drop_packet_flag = False
                #pkt.drop()
            #else:
             #   pkt.accept()


def set_drop_flag():
    global drop_packet_flag
    if not drop_packet_flag:
        print("Flag: True")
        drop_packet_flag = True

def drop_message_bits():
    global letters
    if drop_message_bits.counter != 0:
        letters = letters[1:]
        print(letters)
    drop_message_bits.counter += 1


drop_message_bits.counter = 0


alter_and_drop.counter = 0

if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, alter_and_drop)
    repeater_flag = Repeater(5, set_drop_flag)
    message_bits = Repeater(30, drop_message_bits)
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
        repeater_flag.stop()
        message_bits.stop()
        nfqueue.unbind()
