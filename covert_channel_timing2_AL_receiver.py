from Help_Functions.packet_interpreter import extract_packet_data
from Help_Functions.repeater import Repeater
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call
from scapy.layers.inet import IP, TCP

sequence_drop_packet = 0
retransmission_list = []
message = ""
init_packet_recv = False
message_length = -1


def alter_and_drop(pkt):
    alter_and_drop.counter += 1
    global sequence_drop_packet
    global retransmission_list
    global init_packet_recv
    global message_length
    pkt.retain()
    pl = IP(pkt.get_payload())
    if pl.haslayer("IP") and pl.haslayer("TCP"):
        opcua_data = extract_packet_data(pl)
        if opcua_data.rsp_type == "ReadResponse":
            if not init_packet_recv and pl.getlayer(TCP).flags & 0x20:
                message_length = pl.getlayer(TCP).urgptr - 61440
                init_packet_recv = True
                print("Incoming Message!")
                repeater.start()
            if init_packet_recv and len(message) != message_length:
                if pl[TCP].seq == sequence_drop_packet:
                    print("TCP Retransmission! " + str(pl[TCP].seq))
                    retransmission_list.append(pl[TCP].seq)
                    sequence_drop_packet = pl[TCP].seq
                elif pl[TCP].seq != sequence_drop_packet:
                    sequence_drop_packet = pl[TCP].seq
                    print("Accept")
            elif init_packet_recv and len(message) == message_length:
                message_string = ''.join(chr(int(message[i * 8:i * 8 + 8], 2)) for i in range(len(message) // 8))
                print(message_string)
        pkt.accept()


alter_and_drop.counter = 0


def interpret_message():
    global retransmission_list
    global message
    if len(retransmission_list) > 3:
        message += "1"
    else:
        message += "0"
    print(message)
    retransmission_list = []


if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, alter_and_drop)
    repeater = Repeater(20, interpret_message)
    try:
        call(['sudo iptables -D OUTPUT -p tcp -m tcp --dport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -I OUTPUT -p tcp -m tcp --dport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -D INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -I INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        nfqueue.run()
    except (Exception, KeyboardInterrupt) as e:
        call(['sudo iptables -D OUTPUT -p tcp -m tcp --dport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        call(['sudo iptables -D INPUT -p tcp -m tcp --sport 4840 -j NFQUEUE --queue-num 1'],
             shell=True, stdout=DEVNULL, stderr=STDOUT)
        print(e)
        nfqueue.unbind()
