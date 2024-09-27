import struct
import asyncio
import time
import re
import os
import errno
import logging
from .oscar_protocol import OSCARProtocol
from .log_utils import get_custom_logger
class AIMClient:
    

    def __init__(self, server, port, username, password, loglevel=logging.WARNING, logger=None):
        self.host = server
        self.port = int(port)
        self.username = username
        self.password = password
        self.sock = None
        self.seq_num = 0
        self.oscar = OSCARProtocol()
        self.bos_server = ""
        self.auth_cookie = None
        self.on_message_received = None
        self.message_history = []
        self.message_callback = None
        
        if logger is None:
            self.logger = get_custom_logger(level=loglevel)
        else:
            self.logger = logger

    def set_message_callback(self, callback):
        self.message_callback = callback
        self.logger.info(f"Message callback set: {callback}")

    def roast_password(self, password):
        
        """Roast the password using the XOR roasting method."""
        roast_table = [0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92, 0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C]
        roasted_pass = bytearray(len(password))
        for i in range(len(password)):
            roasted_pass[i] = password[i] ^ roast_table[i % len(roast_table)]
        return bytes(roasted_pass)
    
    async def process_incoming_packets(self):
        self.logger.info("Started processing incoming packets")
        while True:
            try:
                flap_packet = await self.read_complete_flap()
                if not flap_packet:
                    self.logger.debug("No FLAP received, continuing")
                    continue
        
                flap_header = flap_packet[:6]
                flap_data = flap_packet[6:]
        
                flap_id, channel, seq_num, data_length = struct.unpack('>BBHH', flap_header)
        
                if flap_id != 0x2a:
                    self.logger.error(f"Invalid FLAP ID: 0x{flap_id:02x}")
                    continue
        
                self.logger.info(f"FLAP: Channel {channel}, Sequence {seq_num}, Length {data_length}")
        
                if channel == 0x01:
                    await self.handle_channel_1(flap_data)
                elif channel == 0x02:
                    self.logger.info("Received SNAC packet, handling")
                    await self.handle_channel_2(flap_data)
                elif channel == 0x04:
                    self.logger.info("Received disconnect notification")
                    break
                elif channel == 0x05:
                    self.logger.debug("Received keep-alive packet")
                else:
                    self.logger.warning(f"Received unknown FLAP channel: {channel}")
        
            except ConnectionError as e:
                if e.errno == errno.EPIPE:
                    self.logger.error("Broken pipe error occurred while processing packets")
                    break
                else:
                    self.logger.error(f"Connection error occurred: {e}")
                    break
            except Exception as e:
                self.logger.error(f"Unexpected error occurred while processing packets: {e}")
                break
        
            await asyncio.sleep(0.1)  # Small delay to prevent tight loop
        
        self.logger.info("Stopped processing incoming packets")
    
    async def handle_channel_1(self, data):
        # Handle connection-related packets
        self.logger.info("Received connection-related packet")
        self.logger.debug(f"Channel 1 Data: {data.hex()}")
    
    async def handle_channel_2(self, data):
        if len(data) < 10:
            self.logger.error("Incomplete SNAC header")
            return
        
        family_id, subtype_id, flags, request_id = struct.unpack('!HHHL', data[:10])
        snac_data = data[10:]
        
        self.logger.info(f"SNAC: Family 0x{family_id:04x}, Subtype 0x{subtype_id:04x}, Flags 0x{flags:04x}, Request ID {request_id}")
        
        if family_id == 0x0004:
            if subtype_id == 0x000c:  # ICBM Error
                await self.handle_icbm_error(snac_data)
            elif subtype_id == 0x000b:  # ICBM Acknowledgement
                self.logger.info("Received ICBM Acknowledgement")
            elif subtype_id == 0x0007:  # Incoming IM
                await self.handle_incoming_im(snac_data)
            else:
                self.logger.warning(f"Received unknown ICBM subtype: 0x{subtype_id:04x}")
        else:
            handler = self.get_snac_handler(family_id, subtype_id)
            if handler:
                await handler(snac_data, flags, request_id)
            else:
                self.logger.warning(f"Unhandled SNAC: Family 0x{family_id:04x}, Subtype 0x{subtype_id:04x}")
                await self.handle_unknown_snac(family_id, subtype_id, snac_data, flags, request_id)
    
    def get_snac_handler(self, family_id, subtype_id):
        handlers = {
            (0x0001, 0x0003): self.handle_server_ready,
            (0x0001, 0x0007): self.handle_rate_limits,
            (0x0001, 0x0013): self.handle_motd,
            # Could afford to add a lot more to this list, but these made sign on less noisy.
        }
        return handlers.get((family_id, subtype_id))
    
    async def handle_unknown_snac(self, family_id, subtype_id, data, flags, request_id):
        self.logger.info(f"Parsing unknown SNAC: Family 0x{family_id:04x}, Subtype 0x{subtype_id:04x}")
        self.parse_tlvs(data)
    
    async def handle_server_ready(self, data, flags, request_id):
        self.logger.info("Server is ready")
    
    async def handle_rate_limits(self, data, flags, request_id):
        self.logger.info("Received rate limits information")
        self.parse_rate_limits(data)
        await self.send_rate_ack()
    
    def parse_rate_limits(self, data):
        try:
            offset = 0
            num_classes, = struct.unpack('!H', data[offset:offset+2])
            offset += 2
            self.logger.debug(f"Number of rate classes: {num_classes}")
        
            for i in range(num_classes):
                if offset + 34 > len(data):
                    self.logger.error(f"Incomplete rate class data for class {i+1}")
                    break
        
                class_id, window, clear, alert, limit, disconnect, current, max_level, last_time, current_state = struct.unpack('!H8I', data[offset:offset+34])
                offset += 34
        
                self.logger.debug(f"Rate class {class_id}:")
                self.logger.debug(f"  Window: {window} ms")
                self.logger.debug(f"  Clear: {clear}")
                self.logger.debug(f"  Alert: {alert}")
                self.logger.debug(f"  Limit: {limit}")
                self.logger.debug(f"  Disconnect: {disconnect}")
                self.logger.debug(f"  Current: {current}")
                self.logger.debug(f"  Max Level: {max_level}")
                self.logger.debug(f"  Last Time: {last_time}")
                self.logger.debug(f"  Current State: {current_state}")
        
            if offset + 2 > len(data):
                self.logger.error("Incomplete rate group data")
                return
        
            num_groups, = struct.unpack('!H', data[offset:offset+2])
            offset += 2
            self.logger.info(f"Number of rate groups: {num_groups}")
        
            for i in range(num_groups):
                if offset + 4 > len(data):
                    self.logger.error(f"Incomplete rate group header for group {i+1}")
                    break
        
                group_id, num_pairs = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                self.logger.info(f"Rate group {group_id}: {num_pairs} SNAC pairs")
        
                for j in range(num_pairs):
                    if offset + 4 > len(data):
                        self.logger.error(f"Incomplete SNAC pair data for group {i+1}, pair {j+1}")
                        break
        
                    family, subtype = struct.unpack('!HH', data[offset:offset+4])
                    offset += 4
                    self.logger.info(f"  SNAC family 0x{family:04x}, subtype 0x{subtype:04x}")
        
            self.logger.info("Rate limits parsing completed")
        
        except Exception as e:
            self.logger.error(f"Error parsing rate limits: {e}")
            import traceback
            traceback.print_exc()
    
    async def send_rate_ack(self):
        try:
            self.seq_num = (self.seq_num + 1) % 0x10000
            snac_data = b''  # No additional data needed for this acknowledgement
            snac_packet = self.oscar.create_snac(0x0001, 0x0008, 0x0000, self.seq_num, snac_data)
            flap_packet = self.oscar.create_flap(0x02, self.seq_num, snac_packet)
            
            self.logger.info("Sending Rate Limits Acknowledgement")
            self.logger.info(flap_packet, "Rate Ack FLAP packet:")
            
            self.writer.write(flap_packet)
            await self.writer.drain()
            
            self.logger.info("Rate Limits Acknowledgement sent successfully")
        except Exception as e:
            self.logger.error(f"Error sending rate acknowledgement: {e}")
            import traceback
            traceback.print_exc()
    
    async def handle_motd(self, data, flags, request_id):
        self.logger.info("Received Message of the Day")
    
    async def handle_icbm_error(self, data):
        if len(data) < 10:
            self.logger.error("Incomplete ICBM Error data")
            return
        
        cookie = data[:8]
        error_code, = struct.unpack('!H', data[8:10])
        self.logger.error(f"ICBM Error: Cookie {cookie.hex()}, Error Code 0x{error_code:04x}")
        
        error_messages = {
            0x0001: "Invalid ICBM parameters",
            0x0002: "Service unavailable",
            0x0003: "Client rate limit exceeded",
            0x0004: "Sender too evil",
            0x0005: "Receiver too evil",
            }
            
        error_message = error_messages.get(error_code, "Unknown error")
        self.logger.error(f"ICBM Error: {error_message}")
    
    async def handle_incoming_im(self, data):
        try:
            self.logger.debug(f"Handling incoming message. Raw data: {data.hex()}")
        
            offset = 0
            
            # Extract ICBM Cookie (8 bytes)
            cookie = data[offset:offset+8]
            offset += 8
            self.logger.debug(f"ICBM Cookie: {cookie.hex()}")
        
            # Extract Channel ID (2 bytes)
            channel = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            self.logger.debug(f"Channel: {channel}")
        
            if channel != 0x01:
                self.logger.warning(f"Unsupported channel: {channel}")
                return
        
            # Extract sender information
            sender_length = data[offset]
            offset += 1
            sender = data[offset:offset + sender_length].decode('utf-8', errors='replace')
            offset += sender_length
            self.logger.info(f"Sender: {sender}")
        
            # Find HTML content
            html_start = data.find(b'<HTML>')
            html_end = data.find(b'</HTML>') + 7  # Include the closing tag
        
            self.logger.info(f"HTML content start: {html_start}, end: {html_end}")
        
            if html_start != -1 and html_end != -1:
                html_content = data[html_start:html_end].decode('utf-8', errors='replace')
                self.logger.info(f"HTML content: {html_content}")
                
                # Extract text content from HTML
                message = re.sub('<[^<]+?>', '', html_content)
                message = message.strip()
        
                self.logger.info(f"Extracted message: {message}")
        
                if self.message_callback:
                    self.logger.info(f"Calling message callback with sender: {sender}, message: {message}")
                    await self.message_callback(sender, message)
                else:
                    self.logger.warning("Message callback not set")
            else:
                self.logger.warning("No HTML content found in the incoming data")
                self.logger.debug(f"Remaining data after sender: {data[offset:].hex()}")
        
        except Exception as e:
            self.logger.error(f"Error parsing incoming message: {e}")
            import traceback
            traceback.print_exc()
    
    async def read_flap(self, timeout=30.0):
        try:
            # Read FLAP header
            flap_header = await asyncio.wait_for(self.read_exact(6), timeout)
            if len(flap_header) < 6:
                self.logger.error(f"Incomplete FLAP header: {flap_header.hex()}")
                return None
    
            channel, seq_num, data_length = struct.unpack('>BHH', flap_header[1:6])
            self.logger.debug(f"FLAP Header: Channel {channel}, Sequence {seq_num}, Length {data_length}")
    
            # Read FLAP data in chunks
            flap_data = b""
            chunk_size = 4096  # 4KB chunks
            start_time = time.time()
            while len(flap_data) < data_length:
                remaining = min(chunk_size, data_length - len(flap_data))
                try:
                    chunk = await asyncio.wait_for(self.reader.read(remaining), 5.0)
                except asyncio.TimeoutError:
                    self.logger.warning(f"Timeout while reading FLAP data, got {len(flap_data)}/{data_length} bytes")
                    break
                if not chunk:
                    self.logger.error("Connection closed while reading FLAP data")
                    break
                flap_data += chunk
                self.logger.info(f"Read {len(chunk)} bytes, total {len(flap_data)}/{data_length}")
                
                # Check if we've exceeded the overall timeout
                if time.time() - start_time > timeout:
                    self.logger.error("Overall timeout while reading FLAP data")
                    break
    
            full_flap = flap_header + flap_data
            self.logger.debug(f"Partial FLAP packet ({len(full_flap)} bytes): {full_flap.hex()}")
            return full_flap
    
        except Exception as e:
            self.logger.error(f"Error reading FLAP packet: {e}")
            return None
    
    def parse_tlvs(self, data):
        tlvs = {}
        offset = 0
        data_len = len(data)
        
        while offset < data_len - 4:
            try:
                # Read Type and Length (2 bytes each)
                tlv_type = struct.unpack('!H', data[offset:offset+2])[0]
                tlv_length = struct.unpack('!H', data[offset+2:offset+4])[0]
                offset += 4
        
                # Extract Value
                tlv_value = data[offset:offset+tlv_length]
                offset += tlv_length
        
                tlvs[tlv_type] = tlv_value
                self.logger.debug(f"Found TLV: Type 0x{tlv_type:04X}, Length {tlv_length}")
                self.logger.debug(f"TLV 0x{tlv_type:04X} value: {tlv_value.hex()}")
        
            except Exception as e:
                self.logger.error(f"Error parsing TLV at offset {offset}: {e}")
                break
        
        if offset != data_len:
            self.logger.info(f"Finished reading TLVs. Total TLVs found: {len(tlvs)}")
        else:
            self.logger.info(f"Finished reading TLVs. Total TLVs found: {len(tlvs)}")
        
        return tlvs

    async def read_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = await self.reader.read(n - len(data))
            if not chunk:
                break
            data += chunk
        return data
    
    async def read_complete_flap(self, timeout=60.0):
        try:
            # Read FLAP header
            flap_header = await asyncio.wait_for(self.read_exact(6), timeout)
            if len(flap_header) < 6:
                self.logger.info("No incoming FLAPs to process. Sending keep-alive.")
                await self.send_keep_alive()
                return None
        
            flap_id, channel, seq_num, data_length = struct.unpack('>BBHH', flap_header)
            self.logger.debug(f"FLAP Header: ID 0x{flap_id:02x}, Channel {channel}, Sequence {seq_num}, Length {data_length}")
        
            if flap_id != 0x2a:
                self.logger.warning(f"Invalid FLAP ID: 0x{flap_id:02x}")
                return None
        
            # Read FLAP data
            flap_data = await asyncio.wait_for(self.read_exact(data_length), timeout)
            if len(flap_data) < data_length:
                self.logger.warning(f"Incomplete FLAP data: expected {data_length}, got {len(flap_data)}")
                return None
        
            full_flap = flap_header + flap_data
            self.logger.debug(f"Complete FLAP packet ({len(full_flap)} bytes)")
            self.logger.debug(f"FLAP packet: {full_flap.hex()}")
            return full_flap
        
        except asyncio.TimeoutError:
            self.logger.info("No incoming FLAPs to process. Sending keep-alive.")
            await self.send_keep_alive()
            return None
        except Exception as e:
            self.logger.error(f"Error reading FLAP packet: {e}")
            return None
    
    async def send_keep_alive(self):
        try:
            self.seq_num = (self.seq_num + 1) % 0x10000
            keep_alive_packet = self.oscar.create_flap(0x05, self.seq_num, b'')
            self.writer.write(keep_alive_packet)
            await self.writer.drain()
            self.logger.info("Sent keep-alive packet")
            self.logger.debug(f"Keep-alive FLAP packet: {keep_alive_packet.hex()}")
        except Exception as e:
            self.logger.error(f"Error sending keep-alive packet: {e}")
        
    async def connect(self):
        
        reader, writer = await asyncio.open_connection(self.host, self.port)
        self.reader, self.writer = reader, writer
        self.logger.info(f"Connected to {self.host}:{self.port}")
        
        
        await asyncio.sleep(0.5)
        await self.authenticate()
        await self.connect_to_bos()
        
    async def authenticate(self):
        # Receive connection acknowledge
        flap_packet = await self.reader.read(10)
        if len(flap_packet) < 10:
            self.logger.error(f"Received invalid connection acknowledge packet: {flap_packet.hex()}")
        else:
            self.logger.debug(f"Received raw data: {flap_packet.hex()}")
            self.logger.debug(f"\nConnection Acknowledge:\n {self.oscar.read_flap(flap_packet)}")
        
        # Roasting the password using the roast_password method
        roasted_password = self.roast_password(self.password.encode('utf-8'))
        
        # Log the roasted password
        self.logger.debug(f"Roasted Password: {roasted_password.hex()}")
        
        # Add this log to check the encoded username
        encoded_username = self.username.encode('utf-8')
        self.logger.debug(f"Encoded Username: {encoded_username.hex()}")
        
        # Create and send Authorization Request
        self.seq_num = (self.seq_num + 1) % 0x10000
        protocol_version = struct.pack("!I", 0x00000001)
        tlv_screen_name = self.oscar.create_tlv(0x0001, self.username.encode('utf-8'))
        tlv_password = self.oscar.create_tlv(0x0002, roasted_password)
        tlv_client_profile = self.oscar.create_tlv(0x0003, b"AOL Instant Messenger (SM)")
        tlv_unknown = self.oscar.create_tlv(0x0016, struct.pack("!H", 0x0001))
        tlv_client_ver_major = self.oscar.create_tlv(0x0017, struct.pack("!H", 1))  
        tlv_client_ver_minor = self.oscar.create_tlv(0x0018, struct.pack("!H", 0))  
        tlv_client_ver_build = self.oscar.create_tlv(0x001a, struct.pack("!H", 1)) 
        tlv_country_code = self.oscar.create_tlv(0x000e, b"us")
        tlv_language_code = self.oscar.create_tlv(0x000f, b"en")
        tlv_unknown2 = self.oscar.create_tlv(0x0009, struct.pack("!H", 0x0015))
        
        auth_data = (protocol_version + tlv_screen_name + tlv_password + tlv_client_profile + tlv_unknown +
                     tlv_client_ver_major + tlv_client_ver_minor + tlv_client_ver_build +
                     tlv_country_code + tlv_language_code + tlv_unknown2)
        
        # Log the full authorization request
        self.logger.debug(f"Authorization Request (auth_data): {auth_data.hex()}")
        
        # FLAP Packet Header
        channel = 0x01
        data_len = len(auth_data)
        flap_header = struct.pack("!BBH", 0x2A, channel, self.seq_num) + struct.pack("!H", data_len)
        
        # Complete FLAP Packet
        flap_packet = flap_header + auth_data
        
        # Send and process through the reader
        self.writer.write(flap_packet)
        await self.writer.drain()
        self.logger.debug(f"\nSent Authorization Request: \n  {self.oscar.read_flap(flap_packet)}")
        
        try:
            # Receive and process server response
            initial_response = await asyncio.wait_for(self.reader.read(1024), timeout=5.0)
            self.logger.debug(f"Received initial raw data: {initial_response .hex()}")
            if not await self.parse_authorization_response(initial_response):
                self.logger.error("Authentication failed")
                return False
            return True
        except asyncio.TimeoutError:
            self.logger.error("Timeout while waiting for server response")
            return False
        except Exception as e:
            self.logger.error(f"Error during authentication: {e}")
            return False

    async def parse_authorization_response(self, initial_response):
        response = initial_response
        while len(response) < 6:
            chunk = await self.reader.read(6 - len(response))
            if not chunk:
                raise ConnectionError("Connection closed while reading FLAP header")
            response += chunk
        
        channel, length = struct.unpack('>BxH', response[1:5])
        self.logger.info(f"FLAP Header: Channel {channel}, Length {length}")
        
        full_length = 6 + length
        while len(response) < full_length:
            chunk = await self.reader.read(full_length - len(response))
            if not chunk:
                break  # We'll process what we have instead of raising an exception
            response += chunk
            self.logger.debug(f"Received additional data: {chunk.hex()}")
        
        self.logger.debug(f"Full response received: {response.hex()}")
        
        data = response[6:]
        index = 0
        while index < len(data):
            if index + 4 > len(data):
                self.logger.error(f"Incomplete TLV at index {index}")
                break
            tlv_type, tlv_length = struct.unpack("!HH", data[index:index+4])
            if index + 4 + tlv_length > len(data):
                self.logger.error(f"Incomplete TLV value for type {tlv_type} at index {index}")
                break
            tlv_value = data[index+4:index+4+tlv_length]
            
            if tlv_type == 0x0005:
                self.bos_server = tlv_value.decode('utf-8')
                self.logger.info(f"BOS Server Address: {self.bos_server}")
            elif tlv_type == 0x0006:
                self.auth_cookie = tlv_value
                self.logger.debug(f"Authorization Cookie: {self.auth_cookie.hex()}")
            elif tlv_type == 0x0008:  # Error code
                error_code = struct.unpack("!H", tlv_value)[0]
                self.logger.error(f"Error Code: {error_code}")
            elif tlv_type == 0x0004:  # Error URL
                error_url = tlv_value.decode('utf-8')
                self.logger.error(f"Error URL: {error_url}")
            elif tlv_type == 0x000b:  # Error message
                error_message = tlv_value.decode('utf-8')
                self.logger.error(f"Error Message: {error_message}")
            else:
                self.logger.debug(f"Unknown TLV: Type {tlv_type:#06x}, Value: {tlv_value.hex()}")
            
            index += 4 + tlv_length
        
        if not self.bos_server or not self.auth_cookie:
            self.logger.error("Failed to extract BOS server or auth cookie")
            return False
        
        return True

    async def connect_to_bos(self):
        if not self.bos_server:
            self.logger.error("BOS server address not available")
            return False
        
        try:
            bos_server_parts = self.bos_server.split(':')
            if len(bos_server_parts) != 2:
                self.logger.error(f"Invalid BOS server address format: {self.bos_server}")
                return False
            bos_host, bos_port = bos_server_parts
            bos_port = int(bos_port)
            self.logger.info(f"Connecting to BOS Server at {bos_host}:{bos_port}")
        
            self.reader, self.writer = await asyncio.open_connection(bos_host, bos_port)
            self.logger.info(f"Connected to BOS Server: {bos_host}:{bos_port}")
        
            # Wait for connection acknowledge
            flap_packet = await self.read_flap(timeout=10.0)
            if flap_packet:
                self.logger.info("Received FLAP response from BOS server")
                # Send BOS SignOn command with authorization cookie
                return await self.send_bos_signon()
            else:
                self.logger.warning("Did not receive complete FLAP response from BOS server, but continuing...")
                return await self.send_bos_signon()
        
        except Exception as e:
            self.logger.error(f"Error connecting to BOS Server: {e}")
            return False
    
    async def send_bos_signon(self):
        self.seq_num = (self.seq_num + 1) % 0x10000
        fixed_data = struct.pack("!HH", 0x0000, 0x0001)
        tlv_auth_cookie = self.oscar.create_tlv(0x0006, self.auth_cookie)
        bos_signon_data = fixed_data + tlv_auth_cookie
        flap_packet = self.oscar.create_flap(0x01, self.seq_num, bos_signon_data)
        self.writer.write(flap_packet)
        await self.writer.drain()
        self.logger.debug(f"\nSent BOS SignOn: \n  {self.oscar.read_flap(flap_packet)}")
        
        response = await self.read_flap()
        if response:
            self.logger.debug(f"Received FLAP after BOS SignOn: {self.oscar.read_flap(response)}")
        else:
            self.logger.warning("Did not receive complete response after BOS SignOn, but continuing...")
        
        # Continue with the next steps of the authentication process
        await self.send_rate_request()
        return True
    
    async def send_rate_request(self):
        # Increment the sequence number for the request
        self.seq_num = (self.seq_num + 1) % 0x10000
        
        # Create a SNAC header for the rate request
        family_id = 0x0001  # Family ID for rate information
        subtype_id = 0x0006  # Subtype ID for rate request
        flags = 0x0000  # Flags for the request
        request_id = self.seq_num  # Unique request ID
        
        # SNAC data for rate request (usually empty)
        snac_data = b''
        
        # Create the SNAC packet
        snac_packet = self.oscar.create_snac(family_id, subtype_id, flags, request_id, snac_data)
        
        # Create the FLAP packet with channel 0x02 (SNAC data)
        flap_packet = self.oscar.create_flap(0x02, self.seq_num, snac_packet)
        
        # Send the FLAP packet
        self.writer.write(flap_packet)
        await self.writer.drain()
        self.logger.debug(f"\nSent Rate Request: \n  {self.oscar.read_flap(flap_packet)}")
        
        # Receive and process the rate response
        await asyncio.sleep(5) # Yuck!
        response = await self.reader.read(4096)
        self.logger.debug(f"Received raw data: {response.hex()}")
        if len(response) > 0:
            try:
                # Parse the FLAP packet
                flap_info = self.oscar.read_flap(response)
                self.logger.debug(f"Received FLAP response: {flap_info}")
                
                # Process rate information and continue (e.g., client ready)
                await self.send_client_ready()
            except ValueError as e:
                self.logger.error(f"Error parsing FLAP/SNAC: {e}")
    
    async def send_client_ready(self):
        self.seq_num = (self.seq_num + 1) % 0x10000
        family_id = 0x0001  # OService family
        subtype_id = 0x0002  # Client Ready subtype
        flags = 0x0000
        request_id = self.seq_num
        
        # Declare supported families and their versions
        supported_families = [
            (0x0001, 0x0003),  # OService
            (0x0002, 0x0001),  # Location
            (0x0003, 0x0001),  # Buddy
            (0x0004, 0x0001),  # ICBM
            (0x0006, 0x0001),  # Invite
            (0x0008, 0x0001),  # Privacy Management
            (0x0009, 0x0001),  # User Lookup
            (0x000A, 0x0001),  # Stats
            (0x000B, 0x0001),  # Reporting
            (0x000D, 0x0001),  # Chat Navigation
            (0x000E, 0x0001),  # Chat
            (0x0013, 0x0001),  # Server-Side Information
        ]
        
      
        client_ready_data = b''.join(struct.pack('>HH', family, version) for family, version in supported_families)
        
        # Create and send the SNAC packet
        snac_packet = self.oscar.create_snac(family_id, subtype_id, flags, request_id, client_ready_data)
        flap_packet = self.oscar.create_flap(0x02, self.seq_num, snac_packet)
        
        try:
            self.writer.write(flap_packet)
            await self.writer.drain()
            self.logger.info("Sent Client Ready")
            self.logger.debug(f"\nClient Ready Flap: \n  {self.oscar.read_flap(flap_packet)}")
        except Exception as e:
            self.logger.error(f"Error sending Client Ready: {e}")
            raise
    
    async def send_message(self, recipient, message):
        try:
            self.logger.info(f"Attempting to send message to {recipient}: {message}")
            
            # Increment sequence number
            self.seq_num = (self.seq_num + 1) % 0x10000
            
            # Create ICBM Cookie (8 random bytes)
            cookie = os.urandom(8)
            
            # Create HTML content
            html_content = f'<HTML><BODY BGCOLOR="#ffffff"><FONT LANG="0">{message}</FONT></BODY></HTML>'
            
            # Create SNAC data
            snac_data = (
                cookie +  # ICBM Cookie
                struct.pack('!H', 0x0001) +  # Channel
                struct.pack('!B', len(recipient)) +  # Recipient length
                recipient.encode('utf-8') +  # Recipient
                struct.pack('!H', 0x0002) +  # TLV type
                struct.pack('!H', len(html_content) + 0x0D) +  # TLV length
                struct.pack('!B', 0x05) +  # Unknown byte
                struct.pack('!H', 0x0100) +  # Unknown word
                struct.pack('!H', 0x0101) +  # Unknown word
                struct.pack('!H', 0x0101) +  # Unknown word
                struct.pack('!H', len(html_content) + 0x04) +  # Message length + 4
                struct.pack('!H', 0x0000) +  # Unknown word
                struct.pack('!H', 0x0000) +  # Unknown word
                html_content.encode('utf-8')  # Message content
            )
            
            # Create SNAC packet
            snac_packet = self.oscar.create_snac(0x0004, 0x0006, 0x0000, self.seq_num, snac_data)
            
            # Create FLAP packet
            flap_packet = self.oscar.create_flap(0x02, self.seq_num, snac_packet)
            
            self.logger.info(f"Sending FLAP packet (length: {len(flap_packet)})")
            self.logger.debug(f"FLAP packet contents: {flap_packet.hex()}")
            
            # Send the packet
            self.writer.write(flap_packet)
            await self.writer.drain()
            
            self.logger.info(f"Message sent to {recipient}")
            
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")
            import traceback
            traceback.print_exc()