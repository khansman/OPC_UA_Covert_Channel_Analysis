import struct
from opcua_data_class import OpcuaData
from scapy.layers.inet import IP, TCP


def extract_packet_data(pl):

    pl_src = str(pl[IP].src)
    pl_dst = str(pl[IP].dst)
    tcp_chksum = str(hex(pl[TCP].chksum))
    opcua_payload = bytes(pl[TCP].payload).hex()

    if len(opcua_payload) > 0:
        message_type = bytes.fromhex(opcua_payload[:6]).decode("utf-8")
        response_type_numeric = int(bytearray.fromhex(opcua_payload[52:56])[::-1].hex(), 16)

        # chunk_type = bytes.fromhex(opcua_payload[6:8]).decode("utf-8")
        # message_size_bytes = int(bytearray.fromhex(opcua_payload[8:16])[::-1].hex(), 16)
        # secure_channel_id = int(bytearray.fromhex(opcua_payload[16:24])[::-1].hex(), 16)
        # secure_token_id = int(bytearray.fromhex(opcua_payload[24:32])[::-1].hex(), 16)
        # security_sequence_id = int(bytearray.fromhex(opcua_payload[32:40])[::-1].hex(), 16)
        # security_request_id = int(bytearray.fromhex(opcua_payload[40:48])[::-1].hex(), 16)

        response_type = ""
        if response_type_numeric == 464:
            response_type = "CreateSession"
        elif response_type_numeric == 470:
            response_type = "ActivateSession"
        elif response_type_numeric == 634:
            response_type = "Read"
        elif response_type_numeric == 530:
            response_type = "Browse"

        if message_type == "MSG" and response_type == "Read":
            extract_packet_data.counter += 1
            # opcua_response_header = opcua_payload[56:104]
            # timestamp_bytes = int(bytearray.fromhex(opcua_response_header[0:16])[::-1].hex(), 16)*100/1000
            # time_zero = datetime(1601, 1, 1, 0, 0, 0, 0)
            # timestamp = time_zero+timedelta(microseconds=timestamp_bytes)

            opcua_data_values = opcua_payload[104:len(opcua_payload) - 8]
            value_variant = opcua_data_values[10:28]
            value_hex = value_variant[2:18]
            value_readable, = struct.unpack('d', bytes.fromhex(value_hex))
            variant_type = value_variant[:2]
            # array_size = opcua_data_values[:8]
            # encoding_mask = opcua_data_values[8:10]
            # source_timestamp = opcua_data_values[len(opcua_data_values)-16:]

            return OpcuaData(extract_packet_data.counter, opcua_payload, pl_src, pl_dst, str(pl[IP].sport),
                             str(pl[IP].dport), tcp_chksum, message_type, response_type,
                             value_hex, value_readable, 116, 132, variant_type)
        return OpcuaData(extract_packet_data.counter, opcua_payload, pl_src, pl_dst, str(pl[IP].sport),
                         str(pl[IP].dport), tcp_chksum, message_type, response_type, "0", "0", "---", "---", "X")
    else:
        return OpcuaData(extract_packet_data.counter, opcua_payload, pl_src, pl_dst, str(pl[IP].sport),
                         str(pl[IP].dport), tcp_chksum, "X", "X", "0", "0", "---", "---", "X")


extract_packet_data.counter = 0
