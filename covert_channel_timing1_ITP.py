import time

from scapy.sendrecv import send

from Help_Functions.packet_interpreter import extract_packet_data
from Help_Functions.repeater import Repeater
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP

message = "Dies ist ein Test"
letters = ''.join(format(ord(x), 'b').zfill(8) for x in message)
offset = False
init_packet_send = False

# Parameter:    1. alle 20s    2. alle 5s

def alter_and_drop(pkt):
    global init_packet_send
    global offset
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadResponse":
            if not init_packet_send:
                pl.getlayer(TCP).flags = 0x38
                pl.getlayer(TCP).urgptr = 61440 + len(letters)
                init_packet_send = True
                send(pl)
                print("Init Package sent!")
                set_cc_flag()
                repeater.start()
                pkt.drop()
            else:
                if offset and len(letters) > 0:
                    time.sleep(0.2)
                    print("Delay 0.2s")
                    # offset = False
                else:
                    print("No Delay")
                pkt.accept()
        else:
            print("Request")
            pkt.accept()


def set_cc_flag():
    global offset
    global letters
    if init_packet_send and len(letters) > 0:
        if letters[0] == '1':
            offset = True
            letters = letters[1:]
            print(letters)
            print("Offset = 0.2s")
        else:
            offset = False
            letters = letters[1:]
            print(letters)
            print("kein Offset")
    else:
        offset = False
        print("Message sent successfully!")


if __name__ == "__main__":
    print("Nachricht: "+message)
    print("Binärkodierung: "+letters)
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, alter_and_drop)
    repeater = Repeater(20, set_cc_flag)
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
