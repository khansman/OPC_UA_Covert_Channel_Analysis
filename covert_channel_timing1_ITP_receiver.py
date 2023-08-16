import time

import numpy

from Help_Functions.packet_interpreter import extract_packet_data
from Help_Functions.repeater import Repeater
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP

message = ""
message_length = -1
prev_packet_time = -1
init_packet_received = False
ipt_list = []


def alter_and_drop(pkt):
    global prev_packet_time
    global init_packet_received
    global message_length
    global message
    global ipt_list
    urg_bits = 0x20
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadResponse":
            if pl.getlayer(TCP).flags & urg_bits and not init_packet_received:
                prev_packet_time = pl.time
                init_packet_received = True
                message_length = pl.getlayer(TCP).urgptr - 61440
                print("Incoming Message!")
                ipt_interpreter.start()
            elif init_packet_received and message_length > 0:
                ipt = pl.time - prev_packet_time
                print(ipt)
                ipt_list.append(ipt)
        else:
            prev_packet_time = pl.time
        pkt.accept()


def ipt_interpret():
    global ipt_list
    global message
    global message_length
    avg = numpy.average(ipt_list)
    print(avg)
    if message_length > 0 and len(ipt_list) > 0:
        if avg > 0.1:
            message += "1"
            message_length -= 1
            print(message)
            ipt_list = []
        else:
            message += "0"
            message_length -= 1
            print(message)
            ipt_list = []
    elif message_length == 0:
        message_string = ''.join(chr(int(message[i * 8:i * 8 + 8], 2)) for i in range(len(message) // 8))
        print(" [*] Nachricht vollständig empfangen: \n" + message_string)


if __name__ == "__main__":
    now = time.time()
    nfqueue = NetfilterQueue()
    ipt_interpreter = Repeater(20, ipt_interpret)
    nfqueue.bind(1, alter_and_drop)
    try:
        call(['sudo iptables -D INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -D OUTPUT -p tcp -m tcp --dport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -I INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -I OUTPUT -p tcp -m tcp --dport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        nfqueue.run()
    except (Exception, KeyboardInterrupt) as e:
        call(['sudo iptables -D INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -D OUTPUT -p tcp -m tcp --dport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        print(e)
        nfqueue.unbind()
        ipt_interpreter.stop()
