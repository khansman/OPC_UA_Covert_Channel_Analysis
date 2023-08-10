import getopt
import sys
from sys import exit

from matplotlib import pyplot as plt
from opcua import Client

ip = ""
port = ""

if len(sys.argv) > 1:
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "hi:p:", ["help=", "ip=", "port="])
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(
                "\n Usage: \n\t opcua_server.py [-i, --ip] = 127.0.0.1 [-o, --port] = 4841 \n\t opcua_server.py [-h, "
                "--help]\n")
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

x, y, z = [], [], []
figure, ax = plt.subplots()

plt.ion()
plt.show()

print(" [*] Client connected to " + client_ip + "!")
client.get_namespace_array()
objects = client.get_objects_node()
tempsens = objects.get_children()[1]
windsens = objects.get_children()[2]

k = 1
plt.draw()

try:
    while True:

        plt.xlim(0, 50)
        plt.ylim(-1.5, 1.5)

        if len(x) < 50:
            x.append(int(k))
        if len(y) < 50:
            y.append(tempsens.get_children()[2].get_value())
        else:
            y.pop(0)
            y.append(tempsens.get_children()[2].get_value())
        if len(z) < 50:
            z.append(windsens.get_children()[2].get_value())
        else:
            z.pop(0)
            z.append(windsens.get_children()[2].get_value())

        plt.plot(x, y, color='red', label='temperature', linewidth=1, marker=".")
        plt.plot(x, z, color='blue', label='windspeed', linewidth=1, marker=".")
        plt.legend(['temperature', 'windspeed'], loc='upper left')
        sys.stdout.write("\r [*] Updating data ...")
        sys.stdout.flush()
        plt.pause(0.2)
        plt.clf()
        k += 1

except Exception as e:
    print("\n ACCESS DENIED > " + str(e) + "\n")

except KeyboardInterrupt:
    print(" [*] Client disconnecting...")
    client.disconnect()
    print(" [*] Client disconnected!")
