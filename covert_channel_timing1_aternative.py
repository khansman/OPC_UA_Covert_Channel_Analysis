import time

from packet_interpreter import extract_packet_data
from repeater import Repeater
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP
from scapy.sendrecv import send



letters = ''.join(format(ord(x), 'b').zfill(8) for x in "Dies ist ein Test")
packet_times = []
offset = 0


def alter_and_drop(pkt):
    global packet_times
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadResponse":
            packet_times.append(pl.time)
            time.sleep(1)
            if offset != 0:
                time.sleep(1)
        pkt.accept()


def calc_interpacket_avg():
    global packet_times
    print(packet_times)
    interpacket_avg = 0
    for x in packet_times[1:]:
        interpacket_time = x-packet_times[packet_times.index(x)-1]
        interpacket_avg += interpacket_time
    interpacket_avg /= len(packet_times)-1
    print("Durchschnitt: "+str(interpacket_avg))
    packet_times = []


if __name__ == "__main__":
    # global message
    # message = sys.argv[1]
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, alter_and_drop)
    repeater = Repeater(5, calc_interpacket_avg)
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
        repeater.stop()
        nfqueue.unbind()
