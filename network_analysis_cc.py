import scapy.sendrecv
from scapy.all import *
from numpy import quantile, array
import itertools

from Help_Functions.packet_interpreter import extract_packet_data


def write_packets(pkt):
    write_packets.counter += 1
    sys.stdout.write("\r\t [*] Writing Packets: \t " + str(write_packets.counter))
    sys.stdout.flush()
    writer.write(pkt)
    writer.flush()


write_packets.counter = 0


def cc_detection(capture, mode):
    if mode == "init":
        ccd_header(capture, mode)
        ccd_inter_packet_times(capture, mode)
    else:
        ccd_payload(capture)
        ccd_header(capture, mode)
        ccd_artificial_loss(capture)
        ccd_inter_packet_times(capture, mode)



def ccd_inter_packet_times(capture, mode):
    ipt_list_res = []
    ipt_list_req = []
    print("\n\t" + u'\u2500' * 10)
    print("\t [*] Evaluating IPT CC Pattern ... ")
    print("\t" + u'\u2500' * 10)
    for x in capture[1:]:
        last_object = capture[capture.index(x) - 1]
        opcua_data = extract_packet_data(x.payload)
        if opcua_data.rsp_type == "ReadResponse":
            ipt_list_res.append((x.time - now) - (last_object.time - now))
        elif opcua_data.rsp_type == "ReadRequest":
            ipt_list_req.append((x.time - now) - (last_object.time - now))

    average_1, average_2 = sum(ipt_list_req) / len(ipt_list_req), sum(ipt_list_res) / len(ipt_list_res)
    var_1 = abs(sum((x - average_1) ** 2 for x in ipt_list_req) / len(ipt_list_req))
    var_2 = abs(sum((x - average_2) ** 2 for x in ipt_list_res) / len(ipt_list_res))
    std_1, std_2 = math.sqrt(var_1), math.sqrt(var_2)

    print("\t [*] Average ReadRequest: " + str(average_1) +
          "\n\t [*] Average ReadResponse: " + str(average_2))
    print("\t [*] Variance ReadRequest: " + str(var_1) +
          "\n\t [*] Variance ReadResponse: " + str(var_2))
    print("\t [*] Standard Deviation ReadRequest: " + str(std_1) +
          "\n\t [*] Standard Deviation ReadResponse: " + str(std_2))

    ipt_req_extract = [average_1, var_1, std_1]
    ipt_res_extract = [average_2, var_2, std_2]
    # print(ipt_res_extract)
    # print(ipt_req_extract)

    if mode == "init":
        file = open("CC_IPT_Clean_Data.txt", "w")
        ipt_res_data = repr("ReadResponse: "+"#"+str(average_2)+"#"+str(var_2)+"#"+str(std_2))
        ipt_req_data = repr("ReadRequest: "+"#"+str(average_1)+"#"+str(var_1)+"#"+str(std_1))
        file.write(ipt_res_data + "\n" + ipt_req_data)
        print("\t [*] Extracted IPT Data written to CC_IPT_Clean-Data.txt")
        file.close()

    else:
        file = open("CC_IPT_Clean_Data.txt", "r")
        content = file.readlines()
        file.close()
        read_res_data = content[0].replace("\n", "").split("#")
        read_req_data = content[1].replace("\n", "").split("#")
        ipt_res_data = [float(read_res_data[1]), float(read_res_data[2]), float(read_res_data[3][:-1])]
        ipt_req_data = [float(read_req_data[1]), float(read_req_data[2]), float(read_req_data[3][1:-1])]
        # print(ipt_res_data)
        # print(ipt_req_data)
        difference_res = []
        difference_req = []
        for i in range(len(ipt_req_extract)):
            difference_res.append(ipt_res_extract[i-1] - ipt_res_data[i-1])
            difference_req.append(ipt_req_extract[i-1] - ipt_req_data[i-1])
        # print(difference_res)
        # print(difference_req)

        print("\n\t [*] Result: " + str(difference_res[0] > 0.01))
        # print("\t [*] Result ReadRequest: "+str(difference_req[0] > 0.1 and difference_req[2] > 0.01))


def ccd_artificial_loss(capture):
    print("\n\t" + u'\u2500' * 10)
    print("\t [*] Evaluating Articial Loss CC Pattern ... ")
    print("\t" + u'\u2500' * 10)
    retransmission_count = 0
    init_packet_seq = capture[0].seq
    for x in capture[1:]:
        opcua_data = extract_packet_data(x)
        if x.seq == init_packet_seq and opcua_data.rsp_type in ["ReadResponse", "ReadRequest"]:
            retransmission_count += 1
        init_packet_seq = x.seq
    print("\t [*] Number of detected Retransmission: " + str(retransmission_count))
    print("\t [*] Result: " + str(retransmission_count > 3))


def ccd_payload(capture):
    print("\n\t" + u'\u2500' * 10)
    print("\t [*] Evaluating User-Data Value Modulation CC Pattern ... ")
    print("\t" + u'\u2500' * 10)
    accuracy_list = []
    for x in capture:
        opcua_data = extract_packet_data(x.payload)
        if opcua_data.rsp_type == "ReadResponse":
            accuracy_list.append(len(str(opcua_data.target_dec).split(".")[1]))
    accuracy_list = array(accuracy_list)
    outliers = accuracy_list[(accuracy_list > quantile(accuracy_list, 0.9))].tolist()
    print("\t [*] Detected Anomalies: "+str(outliers))
    print("\t [*] Result: " + str(len(outliers))+" - " + str(len(outliers) > 0))
    return [len(outliers) > 0, len(outliers), outliers]


def ccd_header(capture, mode):
    print("\n\t" + u'\u2500' * 10)
    print("\t [*] Evaluating Reserved/Unused CC Pattern ...")
    print("\t" + u'\u2500' * 10)
    print("\t [*] Extracting Packet Pattern ...")
    pattern = ""
    pattern_build = False
    for a, b in itertools.combinations(capture, 2):
        opcua_data_a = extract_packet_data(a)
        opcua_data_b = extract_packet_data(b)
        if opcua_data_a.rsp_type == "ReadResponse" and opcua_data_b.rsp_type == "ReadResponse":
            if not pattern_build:
                pattern = '0' * len(opcua_data_a.payload)
                pattern_build = True
            for x in range(len(opcua_data_a.payload)):
                if (opcua_data_a.payload[x] == opcua_data_b.payload[x]) and opcua_data_a.payload[x] == "0":
                    if pattern[x] != "#":
                        pattern = pattern[:x] + "0" + pattern[x + 1:]
                else:
                    if pattern[x] == "0":
                        pattern = pattern[:x] + "#" + pattern[x + 1:]
    print("\t [*] New Pattern : " + pattern)
    if mode == "init":
        file = open("PCAPs/ReadResponse_Pattern.txt", "w")
        pattern_str = repr(pattern)
        file.write("Clean Pattern: " + pattern_str + "\n")
        print("\t [*] Extracted Pattern written to ReadResponse_Pattern.txt")
        file.close()
    else:
        file = open("ReadResponse_Pattern.txt", 'r')
        clean_pattern = file.readlines()[-1].split("'")[1]
        print("\t [*] Clean Pattern : " + clean_pattern)
        sus_pos = 0
        for x in range(len(clean_pattern)):
            if clean_pattern[x] != pattern[x]:
                print("\t [*] Suspicious Activity on Position " + str(x))
                sus_pos += 1
        print("\t [*] Result: "+str(sus_pos)+" - "+str(sus_pos > 0))


if __name__ == "__main__":
    mode = ""
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "i")
    for opt, arg in opts:
        if opt in ("-i", "--init"):
            mode = "init"
            print("\t [*] Initialisation Mode activated!")
    now = time.time()
    pcap_file = input("\t [*] Please enter PCAP file name: ")
    writer = PcapWriter("PCAPs/"+pcap_file)
    sys.stdout.write("\r\t [*] Waiting for Packets ... \n")
    sys.stdout.flush()
    filter_sniff = "(tcp[tcpflags] & tcp-push == tcp-push) and port 4840"
    capture = scapy.sendrecv.sniff(iface=["eth0"], filter=filter_sniff, timeout=300, prn=write_packets)
    cc_detection(capture, mode)
