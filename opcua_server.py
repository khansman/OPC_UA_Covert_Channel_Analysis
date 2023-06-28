import getopt
import sys
from opcua import Server
from time import sleep
import functions

temperate_old = 0
windspeed_old = 0
temperate = 0
windspeed = 0
counter = 1
ip = ""

if len(sys.argv) > 1:
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "hi:", ["help=", "ip="])
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(
                "\n Usage: \n\t opcua_server.py [-i, --ip] = 127.0.0.1 \n\t opcua_server.py [-h, --help]\n")
            sys.exit(0)
        elif opt in ("-i", "--ip"):
            ip = arg
else:
    print(
        "\n Usage: \n\t opcua_server.py [-i, --ip] = 127.0.0.1 \n\t opcua_server.py [-h, --help]\n")
    sys.exit()

server = Server()
server.set_server_name("OpcUa Test Server")
server_endpoint = "opc.tcp://" + ip + ":4840"
server.set_endpoint(server_endpoint)

# ENCRYPTION SETUP

# server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
# server.load_certificate("certificate.pem")
# server.load_private_key("key.pem")


server.register_namespace("Station1")
objects = server.get_objects_node()

'''
Object 1:  
    - temperature sensor:
    - 4 variables
            - vendor Name (not writable)
            - serial Number (not writable)
            - temperature (WRITABLE)
            - state of danger (WRITABLE)
'''
objectStation_Temp = objects.add_object('n=2;s="TS1"', "TempSensor1")
tempsens_vn = objectStation_Temp.add_variable('n=2;s="S1_VendorName"', "TS1 Vendor Name", "Sensor VULKAN")
tempsens_sn = objectStation_Temp.add_variable('n=2;s="S1_SerialNumber"', "TS1 Serial Number", 12345678)
tempsens_temp = objectStation_Temp.add_variable('n=2;s="S1_Temperature"', "TS1 Temperature", 15)
tempsens_temp.set_writable()
tempsens_danger = objectStation_Temp.add_variable('n=2;s="S1_Danger"', "TS1 State of Danger", False)
tempsens_danger.set_writable()

'''
Object 2:  
    - wind sensor:
    - 3 variables
            - vendor Name (not writable)
            - serial Number (not writable)
            - windspeed (WRITABLE)
'''
objectStation_Wind = objects.add_object('n=2;s="WS1"', "WindSensor1")
windsens_vn = objectStation_Wind.add_variable('n=2;s="WS1_VendorName"', "WS1 Vendor Name", "Sensor STORM")
windsens_sn = objectStation_Wind.add_variable('n=2;s="WS1_SerialNumber"', "WS1 Serial Number", 98765432)
windsens_speed = objectStation_Wind.add_variable('n=2;s="WS1_Windspeed"', "WS1 Windspeed", 11)
windsens_speed.set_writable()

print("\n [*] Starting Server!\n")
server.start()
print("\n [*] Server online!\n")

try:
    data_mode = input("\t Please enter the mode of data generation (linear,random,sinus,cosinus): ")
    print("\n\t Updating Data ...")
    if data_mode == "linear":
        while True:
            temperature, temperate_old = functions.linear(temperate_old)
            tempsens_temp.set_value(temperature)
            windspeed, windspeed_old = functions.linear(windspeed_old)
            windsens_speed.set_value(windspeed)
            sys.stdout.write("\r\t Temperature: {} ".format(round(temperature, 3)) + "\t Windspeed: {}".format(
                round(windspeed, 3)) + "\t Total Updates: {}".format(counter))
            sys.stdout.flush()
            counter += 1
            sleep(0.2)
    elif data_mode == "random":
        while True:
            temperature, temperate_old = functions.random_value(27, 100)
            tempsens_temp.set_value(temperature)
            windspeed, windspeed_old = functions.random_value(11, 50)
            windsens_speed.set_value(windspeed)
            sys.stdout.write("\r\t Temperature: {} ".format(round(temperature, 3)) + "\t Windspeed: {}".format(
                round(windspeed, 3)) + "\t Total Updates: {}".format(counter))
            sys.stdout.flush()
            counter += 1
            sleep(0.2)
    elif data_mode == "sinus":
        while True:
            temperature, temperate_old = functions.sinus(temperate_old)
            tempsens_temp.set_value(temperature)
            windspeed, windspeed_old = functions.cosinus(windspeed_old)
            windsens_speed.set_value(windspeed)
            sys.stdout.write("\r\t Temperature: {} ".format(round(temperature, 3)) + "\t Windspeed: {}".format(
                round(windspeed, 3)) + "\t Total Updates: {}".format(counter))
            sys.stdout.flush()
            counter += 1
            sleep(0.2)
    elif data_mode == "cosinus":
        while True:
            temperature, temperate_old = functions.cosinus(temperate_old)
            tempsens_temp.set_value(temperature)
            windspeed, windspeed_old = functions.sinus(windspeed_old)
            windsens_speed.set_value(windspeed)
            sys.stdout.write("\r\t Temperature: {} ".format(round(temperature, 3)) + "\t Windspeed: {}".format(
                round(windspeed, 3)) + "\t Total Updates: {}".format(counter))
            sys.stdout.flush()
            counter += 1
            sleep(0.2)
    else:
        print("Please execute the program again and enter a valid data mode!")
        sys.exit()

except KeyboardInterrupt:
    server.stop()
    print("\n\n [*] Server offline!\n")
