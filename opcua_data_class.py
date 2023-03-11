class OpcuaData:

    def __init__(self, counter, payload, src, dst, sport, dport, chksum, message_type, response_type, covert_target_hex,
                 covert_target_dec, loc_start, loc_end, variant_type):
        self.number = counter
        self.payload = payload
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.chksum = chksum
        self.msg_type = message_type
        self.rsp_type = response_type
        self.target_hex = covert_target_hex
        self.target_dec = covert_target_dec
        self.start = loc_start
        self.end = loc_end
        self.vrt_type = variant_type

    def __str__(self):
        return f" [**] Opcua Object Data {self.number} [**] \n [0] Payload: {self.payload} \n " \
               f"[1] Source: {self.src}:{self.sport} \n [2] Destination: {self.dst}:{self.dport} \n " \
               f"[3] Checksum: {self.chksum} \n " \
               f"[4] Message Type: {self.msg_type} \n [5] Response Type: {self.rsp_type} \n " \
               f"[6] Target HEX: {self.target_hex} \n [7] Target DEC: {self.target_dec} \n " \
               f"[8] Start Location: {self.start} \n [9] End Location: {self.end} \n"
