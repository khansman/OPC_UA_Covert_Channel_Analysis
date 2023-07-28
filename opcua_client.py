import getopt
import sys
from sys import exit
from repeater import Repeater

from matplotlib import pyplot as plt
from matplotlib.animation import FuncAnimation
from opcua import Client

x, y, z = [], [], []


def init():
    line1.set_data(x, y)
    return line1,


def on_close():
    print(" [*] Client disconnecting...")
    client.disconnect()
    print(" [*] Client disconnected!")
    sys.exit(0)


def update_data(*argv):
    global x
    global y

    sys.stdout.write("\r\t [*] Updating Data " + update_data.counter % 5 * ".")
    sys.stdout.flush()

    try:
        new_value= tempsens_value.get_value()
    except Exception as e:
        print("Timeout Error!")
        new_value = -1

    if len(x) < 50:
        x.append(update_data.counter)
    if len(y) < 50:
        y.append(new_value)
    else:
        y.pop(0)
        y.append(new_value)
    update_data.counter += 1


update_data.counter = 0


def animate(i):
    line1.set_data(x, y)
    return line1,


if __name__ == "__main__":
    ip = ""
    port = ""

    if len(sys.argv) > 1:
        argv = sys.argv[1:]
        opts, args = getopt.getopt(argv, "hi:p:", ["help=", "ip="])
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print(
                    "\n Usage: \n\t opcua_server.py [-i, --ip] = 127.0.0.1"
                    "\n\t opcua_server.py [-h, --help]\n")
                sys.exit(0)
            elif opt in ("-i", "--ip"):
                ip = arg
    else:
        print(
            "\n Usage: \n\t opcua_server.py [-i, --ip] = 127.0.0.1 \n\t opcua_server.py [-h, --help]\n")
        sys.exit()


    try:
        client_ip = "opc.tcp://" + ip + ":4840"
        client = Client(client_ip, timeout=10)
        # client.set_security_string("Basic256Sha256,SignAndEncrypt,certificate.pem,key.pem")
        print(" [*] Client connecting...")
        client.connect()
    except ConnectionRefusedError:
        print("\n [***] Connection refused! Server not running! [***] \n")
        exit(1)

    print(" [*] Client connected to " + client_ip + "!\n")
    client.get_namespace_array()
    objects = client.get_objects_node()
    tempsens = objects.get_children()[1]
    tempsens_value = tempsens.get_children()[2]
    repeat = Repeater(1, update_data, client)

    try:
        figure = plt.figure()

        axis = plt.axes(xlim=(0, 50),
                        ylim=(-1.5, 1.5))

        line1, = axis.plot(x, y, linewidth=1, label="S1_Temperature")
        L = plt.legend(loc=1)

        anim = FuncAnimation(figure, animate,
                             init_func=init,
                             frames=60,
                             interval=200,
                             blit=True)
        plt.show()
        figure.canvas.mpl_connect('close_event', on_close())

    except (Exception, KeyboardInterrupt) as e:
        print(e)
        print(" [*] Client disconnecting...")
        repeat.stop()
        client.disconnect()
        print(" [*] Client disconnected!")
        plt.close('all')
        sys.exit()
