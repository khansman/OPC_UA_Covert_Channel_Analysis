from packet_interpreter import split_packet
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, call

def print_and_accept(pkt):
    pkt.retain()
    pl = pkt.get_payload()
    split_packet(pl)
    pkt.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    call(['sudo iptables -D OUTPUT -p tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    call(['sudo iptables -I OUTPUT -p tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    nfqueue.run()
except KeyboardInterrupt:
    call(['sudo iptables -D OUTPUT -p tcp --sport 4840 -j NFQUEUE --queue-num 1'],
         shell=True, stdout=DEVNULL, stderr=STDOUT)
    print("")

nfqueue.unbind()
