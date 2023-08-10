import time

from Help_Functions.packet_interpreter import extract_packet_data
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP

message = ""
message_length = -1
prev_packet_time = -1
init_packet_received = False


def alter_and_drop(pkt):
    global prev_packet_time
    global init_packet_received
    global message_length
    global message
    urg_bits = 0x20
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadResponse":
            if pl.getlayer(TCP).flags & urg_bits:
                prev_packet_time = pl.time - now
                init_packet_received = True
                message_length = pl.getlayer(TCP).urgptr - 61440

                print("Incoming Message!")
            if init_packet_received and message_length > 0:
                ipt = (pl.time-now)-prev_packet_time
                prev_packet_time = pl.time
                if ipt > 1.1:
                    message += "1"
                    message_length -= 1
                else:
                    message += "0"
                    message_length -= 1
            elif message_length == 0:
                print(message)
        pkt.accept()


if __name__ == "__main__":
    now = time.time()
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
