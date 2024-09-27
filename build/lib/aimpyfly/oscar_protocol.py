import struct
import logging
from .log_utils import get_custom_logger

class OSCARProtocol:
    FLAP_HEADER_SIZE = 6
    logger = get_custom_logger(name="OSCAR",level=logging.WARNING)
    def parse_flap_header(self, data):
        if len(data) < 6:
            raise ValueError("FLAP header must be at least 6 bytes long")
        
        # FLAP header format: * (1 byte), channel (1 byte), sequence number (2 bytes), data length (2 bytes)
        asterisk, channel, seq_num, data_length = struct.unpack('!BBHH', data[:6])
        
        if asterisk != 0x2A:
            raise ValueError("Invalid FLAP header: Missing asterisk")
        
        return channel, seq_num, data_length

    def create_snac_with_tlvs(self, family, subtype, flags, req_id, tlvs):
        snac_header = struct.pack('>HHHL', family, subtype, flags, req_id)
        tlv_data = b''.join(self.create_tlv(tlv_type, tlv_value) for tlv_type, tlv_value in tlvs)
        return snac_header + tlv_data

    def parse_snac(self, data):
        if len(data) < 10:
            raise ValueError("SNAC header must be at least 10 bytes long")
        
        # SNAC header format: Family ID (2 bytes), Subtype ID (2 bytes), Flags (2 bytes), Request ID (4 bytes)
        family_id, subtype_id, flags, request_id = struct.unpack('!HHHI', data[:10])
        snac_data = data[10:]
        
        return family_id, subtype_id, flags, request_id, snac_data

    def create_flap(self, channel, seq_num, data=b''):
        # FLAP header: * (1 byte), Channel (1 byte), Sequence Number (2 bytes), Data Length (2 bytes)
        flap_header = struct.pack('!BBHH', 0x2A, channel, seq_num, len(data))
        return flap_header + data
    
    def read_flap(self, data):
        if len(data) < self.FLAP_HEADER_SIZE:
            raise ValueError("Data too short to be a valid FLAP")
        flap_id = data[0]
        if flap_id != 0x2A:
            raise ValueError("Invalid FLAP id")
        channel = data[1]
        seq_num = (data[2] << 8) | data[3]
        data_size = (data[4] << 8) | data[5]
        flap_data = data[self.FLAP_HEADER_SIZE:self.FLAP_HEADER_SIZE + data_size]
        return f"Flap information: \n	Received Hex: {data.hex()} \n	Channel: {channel} \n	Sequence: {seq_num} \n	Flap Data: {flap_data.hex()}"
    
    def create_snac(self, family_id, subtype_id, flags, request_id, data=b''):
        # SNAC header: Family ID (2 bytes), Subtype ID (2 bytes), Flags (2 bytes), Request ID (4 bytes)
        snac_header = struct.pack('!HHHI', family_id, subtype_id, flags, request_id)
        return snac_header + data
    
    def read_snac(self, data):
        if len(data) < 10:
            raise ValueError("Data too short to be a valid SNAC")
        family_id = (data[0] << 8) | data[1]
        subtype_id = (data[2] << 8) | data[3]
        flags = (data[4] << 8) | data[5]
        req_id = (data[6] << 24) | (data[7] << 16) | (data[8] << 8) | data[9]
        snac_data = data[10:]
        return family_id, subtype_id, flags, req_id, snac_data
    
    def create_tlv(self, tlv_type, tlv_value):
        tlv_header = struct.pack('!HH', tlv_type, len(tlv_value))
        return tlv_header + tlv_value
        
    def read_tlv(self, data):
        if len(data) < 4:
            raise ValueError("Data too short to be a valid TLV")
        tlv_type = (data[0] << 8) | data[1]
        length = (data[2] << 8) | data[3]
        tlv_value = data[4:4 + length]
        return tlv_type, length, tlv_value
    
    def read_tlvs(self, data):
        tlvs = {}
        offset = 0
        self.logger.info(f"Starting to read TLVs from data of length {len(data)}")
        self.logger.debug(f"Raw TLV data: {data.hex()}")
        while offset < len(data):
            if len(data) - offset < 2:
                self.logger.warning(f"Not enough data for TLV type at offset {offset}")
                break
            tlv_type = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2

            if tlv_type == 0x000E:  # Special handling for chat server URL
                end = data.find(b'\x00', offset)
                if end == -1:
                    end = len(data)
                tlv_value = data[offset:end]
                tlv_length = len(tlv_value)
                offset = end + 1  # Skip the null terminator
            elif tlv_type == 0x0006:  # Special handling for cookie
                tlv_length = 256  # Cookie is always 256 bytes
                tlv_value = data[offset:offset+tlv_length]
                offset += tlv_length
            else:
                if len(data) - offset < 2:
                    self.logger.warning(f"Not enough data for TLV length at offset {offset}")
                    break
                tlv_length = struct.unpack('!H', data[offset:offset+2])[0]
                offset += 2
                if offset + tlv_length > len(data):
                    self.logger.warning(f"TLV data exceeds buffer: Type 0x{tlv_type:04X}, Length {tlv_length}, Remaining data {len(data) - offset}")
                    break
                tlv_value = data[offset:offset+tlv_length]
                offset += tlv_length

            tlvs[tlv_type] = tlv_value
            self.logger.info(f"Found TLV: Type 0x{tlv_type:04X}, Length {len(tlv_value)}")
            self.logger.debug(f"TLV 0x{tlv_type:04X} value: {tlv_value.hex()}")

        self.logger.info(f"Finished reading TLVs. Total TLVs found: {len(tlvs)}")
        return tlvs
        
    def parse_user_info(self, data):
        offset = 0
        # Screen name length (1 byte)
        sn_length = data[offset]
        offset += 1
        
        # Screen name (variable length)
        screen_name = data[offset:offset+sn_length].decode('utf-8', errors='ignore')
        offset += sn_length
        
        # Additional user info can be parsed here if necessary
        
        return screen_name