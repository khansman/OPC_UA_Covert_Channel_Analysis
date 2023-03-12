import getopt
import sys
from sys import exit

from matplotlib import pyplot as plt
from matplotlib.animation import FuncAnimation
from opcua import Client

ip = ""
port = ""
figure = plt.figure()

if len(sys.argv) > 1:
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "hi:p:", ["help=", "ip=", "port="])
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(
                "\n Usage: \n\t opcua_server.py [-i, --ip] = 127.0.0.1 [-o, --port] = 4841 "
                "\n\t opcua_server.py [-h, --help]\n")
            sys.exit(0)
        elif opt in ("-i", "--ip"):
            ip = arg
        elif opt in ("-p", "--port"):
            port = arg
else:
    print(
        "\n Usage: \n\t opcua_server.py [-i, --ip] = 127.0.0.1 [-o, --port] = 4841 \n\t opcua_server.py [-h, --help]\n")
    sys.exit()

client_ip = "opc.tcp://" + ip + ":" + port
client = Client(client_ip)
# client.set_security_string("Basic256Sha256,SignAndEncrypt,certificate.pem,key.pem")
try:
    print(" [*] Client connecting...")
    client.connect()
except ConnectionRefusedError:
    print("\n [***] Connection refused! Server not running! [***] \n")
    exit(1)

print(" [*] Client connected to " + client_ip + "!")
client.get_namespace_array()
objects = client.get_objects_node()
tempsens = objects.get_children()[1]
# windsens = objects.get_children()[2]

try:

    axis = plt.axes(xlim=(0, 50),
                    ylim=(-1.5, 1.5))

    x, y, z = [], [], []
    line1, = axis.plot(x, y, linewidth=1, label="S1_Temperature")
    L = plt.legend(loc=1)

    # line2, = axis.plot(x, z, linewidth=1)

    def init():
        line1.set_data(x, y)
        # line2.set_data(x, z)
        return line1,  # , line2,


    def on_close():
        print(" [*] Client disconnecting...")
        client.disconnect()
        print(" [*] Client disconnected!")
        sys.exit(0)


    def animate(i):
        if len(x) < 50:
            x.append(int(i))
        if len(y) < 50:
            y.append(tempsens.get_children()[2].get_value())
        else:
            y.pop(0)
            y.append(tempsens.get_children()[2].get_value())
        # if len(z) < 50:
        #    z.append(windsens.get_children()[2].get_value())
        # else:
        #    z.pop(0)
        #    z.append(windsens.get_children()[2].get_value())
        line1.set_data(x, y)
        # line2.set_data(x, z)
        return line1,  # , line2,


    anim = FuncAnimation(figure, animate,
                         init_func=init,
                         frames=200,
                         interval=500,
                         blit=True)
    plt.show()

    # anim.save("OPCUA_Client_anim.mp4", writer='ffmpeg', fps=30)

    figure.canvas.mpl_connect('close_event', on_close())

except (Exception, KeyboardInterrupt) as e:
    try:
        print(" [*] Client disconnecting...")
        client.disconnect()
        print(" [*] Client disconnected!")
        plt.close('all')
        sys.exit()
    except Exception as e:
        sys.exit()
