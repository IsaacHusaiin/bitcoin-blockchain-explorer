
"""
Author: Isaac Yushaiyin
Filename: lab5.py
Date: December 8, 2024
Purpose: Implements a Bitcoin Blockchain Explorer using the Bitcoin P2P protocol. This project focuses on
         interacting with a Bitcoin node to query blockchain data, retrieve blocks, and modify blockchain
         values for experimental purposes. The implementation includes the following features:

         - **Message Construction and Parsing**:
           Implements Bitcoin-specific message construction and parsing, adhering to the Bitcoin P2P protocol.
           This includes messages such as `version`, `getblocks`, `getdata`, `ping`, and more.

         - **Block Retrieval**:
           Uses the Bitcoin P2P protocol to retrieve blocks from a connected Bitcoin node. Retrieves block
           data starting from the genesis block and processes inventory messages to fetch specific blocks.

         - **Transaction Parsing**:
           Parses Bitcoin transactions within blocks, including inputs, outputs, and Coinbase transactions.
           Displays detailed transaction information for analysis.

         - **Checksum and Hashing**:
           Implements checksum verification and double-SHA256 hashing for message integrity and blockchain data.

         - **Merkle Root and Block Hash Validation**:
           Validates Merkle roots and block hashes, demonstrating the importance of integrity in blockchain data.

         - **Experimental Block Modification**:
           Alters the value of a Bitcoin block's transaction output and recalculates dependent fields such as
           Merkle root and block hash. Verifies the implications of tampering with blockchain data.

         - **Network Communication**:
           Establishes TCP connections with a Bitcoin node, handles message exchanges, and manages
           timeouts for asynchronous communication.

         - **Scalability and Protocol Compliance**:
           Ensures compliance with the Bitcoin protocol while being adaptable for different blockchain experiments.

         This project showcases the principles of distributed systems and blockchain, including
         cryptographic integrity, decentralized communication, and the role of protocols in ensuring system security.

Usage Instructions:
1. **Run the Explorer**:
   Use the following command to run the script and retrieve a specific block:
   python3 lab5.py 5122 (this is last 4 degit of my su id) between 1 < 873865
   for your computer safety , please use smaller number because it takes soooo long to finish running if u use large
   block number
   """





import random
import time
import socket
import sys
from time import strftime, gmtime
from hashlib import sha256



"""network connection parameters"""
BTC_IP = '18.27.79.17'  # Peer IPv4 address, u can get this from nodes_main.txt
BTC_PORT = 8333         # Bitcoin  default port
BTC_PEER_ADDRESS = (BTC_IP, BTC_PORT)  # IP Port for connection
BTC_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket

"""Constants"""
MAX_BLOCKS = 500  # Maximum blocks from inv message
BLOCK_GENESIS = bytes.fromhex('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')  # Genesis block hash
MY_IP = '127.0.0.1'  # IP_address. pls use same format ip address
START_STRING = bytes.fromhex('f9beb4d9')  # Magic bytes for Bitcoin Mainnet
EMPTY_STRING = b''  # Correct way to create an empty bytes object
HEADER_SIZE = 24  # Bitcoin message header size (24 bytes)
COMMAND_SIZE = 12  # Command field size in the Bitcoin header (12 bytes)
VERSION = 70015  # Protocol version (Bitcoin Core 0.13.2+)
BLOCK_NUMBER= 5122 # this is useless btw , just writing it to fill space, read usage instruction
BUFFER_SIZE = 64000  # Buffer size for socket receive
PREFIX = '  '  # Prefix for formatting logs


def compactsize_t(n):
    """
      Converts an integer into its CompactSize encoding used in the Bitcoin protocol.
      CompactSize is a variable-length encoding for integers, used to save space.

      Parameters:
      - n (int): The integer to be encoded.

      Returns:
      - bytes: The CompactSize encoded representation of the integer.

      Logic:
      - For values less than 252, the value is encoded as a single unsigned byte.
      - For values between 252 and 0xFFFF, the value is prefixed with 0xFD and encoded as a 16-bit unsigned integer.
      - For values between 0xFFFF and 0xFFFFFFFF, the value is prefixed with 0xFE and encoded as a 32-bit unsigned integer.
      - For values larger than 0xFFFFFFFF, the value is prefixed with 0xFF and encoded as a 64-bit unsigned integer.
      """
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    """
      Decodes a CompactSize encoded integer from a byte array.
      CompactSize is a variable-length encoding used in the Bitcoin protocol to represent integers.

      Parameters:
      - b (bytes): The byte array containing the CompactSize encoded integer.

      Returns:
      - tuple:
          - bytes: The bytes that represent the encoded CompactSize integer.
          - int: The decoded integer value.

      Logic:
      - The first byte (`key`) determines the length of the encoded integer:
          - If `key` is 0xFF, the integer is 8 bytes long (64 bits).
          - If `key` is 0xFE, the integer is 4 bytes long (32 bits).
          - If `key` is 0xFD, the integer is 2 bytes long (16 bits).
          - Otherwise, the integer is a single byte.
      - Based on the `key`, the corresponding bytes are extracted and decoded.
      """
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])



"""Below codes are given by professor, so im not gonna add any comments"""
def bool_t(flag):

    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):

    pch_i_pv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pch_i_pv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):

    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):

    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n):
    """Marshal integer to unsigned, 16 bit"""
    return int(n).to_bytes(2, byteorder='little', signed=False)


def int32_t(n):
    """Marshal integer to signed, 32 bit"""
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    """Marshal integer to unsigned, 32 bit"""
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    """Marshal integer to signed, 64 bit"""
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    """Marshal integer to unsigned, 64 bit"""
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    """Unmarshal signed integer"""
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b):
    """Unmarshal unsigned integer"""
    return int.from_bytes(b, byteorder='little', signed=False)


def swap_endian(b: bytes):

    swapped = bytearray.fromhex(b.hex())
    swapped.reverse()
    return swapped
def build_message(command, payload):

    return message_header(command, payload) + payload


def version_message():

    version = int32_t(VERSION)  # Version 70015
    services = uint64_t(0)  # Unnamed - not full node
    timestamp = int64_t(int(time.time()))  # Current UNIX epoch
    addr_recv_services = uint64_t(1)  # Full node
    addr_recv_ip_address = ipv6_from_ipv4(BTC_IP)  # Big endian
    addr_recv_port = uint16_t(BTC_PORT)
    addr_trans_services = uint64_t(0)  # Identical to services
    addr_trans_ip_address = ipv6_from_ipv4(MY_IP)  # Big endian
    addr_trans_port = uint16_t(BTC_PORT)
    nonce =uint64_t(0)
    user_agent_bytes = compactsize_t(0)  # 0 so no user agent field
    start_height = int32_t(0)
    relay = bool_t(False)
    return b''.join([version, services, timestamp,
                     addr_recv_services, addr_recv_ip_address, addr_recv_port,
                     addr_trans_services, addr_trans_ip_address, addr_trans_port,
                     nonce, user_agent_bytes, start_height, relay])








def create_getdata_message(tx_type, header_hash):
    """
        Constructs a Bitcoin 'getdata' message payload.

        The 'getdata' message is used in Bitcoin's protocol to request data, such as blocks or transactions,
        from a peer. This function creates the payload for such a message, specifying the type of data
        (e.g., block or transaction) and the hash of the data being requested.

        Parameters:
        - tx_type (int): The type of data being requested (e.g., 1 for transactions, 2 for blocks).
        - header_hash (bytes): The hash of the data being requested, typically in the form of a 32-byte block
          or transaction identifier.

        Returns:
        - bytes: The serialized payload for the 'getdata' message.

        Example:
        - Input: tx_type=2, header_hash=<block_hash>
        - Output: Serialized payload as bytes.
        """

    count = compactsize_t(1)
    entry_type =uint32_t(tx_type)
    entry_hash = bytes.fromhex(header_hash.hex())
    return count + entry_type + entry_hash


def create_getblocks_payload(header_hash):
    """
        Constructs a Bitcoin 'getblocks' message payload.

        The 'getblocks' message is used to request a set of block headers from a peer, starting
        from a specific block hash. The message helps to retrieve blocks that are not yet known
        to the requesting node.

        Parameters:
        - header_hash (bytes): The hash of the block from which the peer should start sending headers.
          This is typically the hash of the latest block known to the requesting node.

        Returns:
        - bytes: The serialized payload for the 'getblocks' message.

        Example:
        - Input: header_hash=<block_hash>
        - Output: Serialized payload for 'getblocks' message.
        """
    version = uint32_t(VERSION)
    hash_count = compactsize_t(1)
    # Assuming we pass in an already computed sha256(sha256(block)) hash
    block_header_hashes = bytes.fromhex(header_hash.hex())
    # Always ask for max number of blocks
    stop_hash = b'\0' * 32
    return b''.join([version, hash_count, block_header_hashes, stop_hash])


def ping_message():
    """Generates a 'ping' message payload for the Bitcoin protocol."""
    return uint64_t(random.getrandbits(64))


def message_header(command, payload):
    """
        Constructs a Bitcoin message header.

        The message header is a 24-byte structure that precedes every Bitcoin message
        payload. It contains metadata about the message, including the magic bytes,
        command name, payload size, and a checksum for verification.

        Parameters:
        - command (str): The command name (e.g., 'version', 'ping') as a string.
        - payload (bytes): The message payload in bytes.

        Returns:
        - bytes: A 24-byte header containing:
            1. Magic bytes: Identifies the Bitcoin network (e.g., mainnet, testnet).
            2. Command name: ASCII-encoded command, padded with null bytes to 12 bytes.
            3. Payload size: The length of the payload in bytes, serialized as a 32-bit unsigned integer.
            4. Checksum: The first 4 bytes of the double SHA-256 hash of the payload.

        Key Points:
        - The magic bytes (START_STRING) differentiate between Bitcoin mainnet and testnet.
        - The command name indicates the type of message being sent.
        - The checksum ensures the integrity of the payload during transmission.
        """

    magic = START_STRING
    command_name = command.encode('ascii')
    while len(command_name) < COMMAND_SIZE:
        command_name += b'\0'
    payload_size = uint32_t(len(payload))
    check_sum = calculate_checksum(payload)
    return b''.join([magic, command_name, payload_size, check_sum])


def calculate_checksum(payload):
    """Calculates the checksum for a Bitcoin message payload."""
    return hash(payload)[:4]


def hash(payload: bytes):
    """    Computes the double SHA-256 hash of a given payload."""

    return sha256(sha256(payload).digest()).digest()


def sat_to_btc(sat):
    """ Converts a value from satoshis to bitcoins."""
    return sat * 0.00000001


def btc_to_sat(btc):
    """ Converts a value from bitcoin to satoshis."""
    return btc * 10e7


def print_message(msg, text=None, height=None):
    """
       Parses and prints a Bitcoin message.

       This function dissects a Bitcoin message, extracting and printing its header,
       payload, and associated metadata based on the message type. It also handles
       various Bitcoin-specific commands to provide detailed insights into the content.

       Parameters:
       - msg (bytes): The full Bitcoin message, including the header and payload.
       - text (str, optional): Additional descriptive text to display with the message.
       - height (int, optional): The block height for context, used for certain message types.

       Key Functionality:
       - Prints the message size and a truncated preview of the message.
       - Calls `print_header` to parse and display the message header.
       - Computes and prints the `header_hash` if the message is of type 'block'.
       - Delegates message-specific handling to appropriate functions based on the command:
           - 'version': Calls `print_version_msg`.
           - 'sendcmpct': Calls `print_sendcmpct_message`.
           - 'ping'/'pong': Calls `print_ping_pong_message`.
           - 'addr': Calls `print_addr_message`.
           - 'feefilter': Calls `print_feefilter_message`.
           - 'getblocks': Calls `print_getblocks_message`.
           - 'inv'/'getdata'/'notfound': Calls `print_inv_message`.
           - 'block': Calls `print_block_message`.

       Returns:
       - str: The command type extracted from the message header.

       Key Points:
       - Handles and prints a wide variety of Bitcoin network messages.
       - Provides a structured and readable output for debugging and analysis.
       """

    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[HEADER_SIZE:]
    command = print_header(msg[:HEADER_SIZE], calculate_checksum(payload))
    if payload:
        header_hash =swap_endian(hash(payload[:80])).hex() if command == 'block' else ''
        print('{}{} {}'.format(PREFIX, command.upper(), header_hash))
        print(PREFIX + '-' * 56)

    if command == 'version':
        print_version_msg(payload)
    elif command == 'sendcmpct':
        display_compact_block_message(payload)
    elif command == 'ping' or command == 'pong':
        print_ping_pong_message(payload)
    elif command == 'addr':
        print_addr_message(payload)
    elif command == 'feefilter':
        display_fee_filter_details(payload)
    elif command == 'getblocks':
        print_getblocks_message(payload)
    elif command == 'inv' or command == 'getdata' or command == 'notfound':
        print_inv_message(payload, height)
    elif command == 'block':
        print_block_message(payload)
    return command


def print_inv_message(payload, height):
    """
       Parses and prints the 'inv' (inventory) message payload from the Bitcoin protocol.

       This function decodes the inventory message, which contains a list of block or
       transaction identifiers, and prints each entry in a structured format.

       Parameters:
       - payload (bytes): The message payload containing the inventory data.
       - height (int, optional): The block height for context, used as a starting point
         for numbering the inventory items.

       Key Functionality:
       - Decodes the compact size prefix to determine the number of inventory entries.
       - Iterates through the inventory list, extracting each entry's type and hash.
       - Prints the total count of inventory items and their details in a formatted layout.

       Details:
       - Each inventory entry consists of a 4-byte type field and a 32-byte hash.
       - The type field indicates whether the entry represents a block or a transaction.

       Output:
       - Provides a detailed log of the inventory message, including:
         - Total count of entries.
         - Each entry's type (as an integer) and hash (in hexadecimal).
         - Block hash representation (split into two 32-character lines for readability).

       Example:
       - If the payload contains inventory for 2 blocks:
           1. Type: Block, Hash: <hex>
           2. Type: Block, Hash: <hex>
       """

    count_bytes, count =unmarshal_compactsize(payload)
    i = len(count_bytes)
    inventory = []
    for _ in range(count):
        inv_entry = payload[i: i + 4], payload[i + 4:i + 36]
        inventory.append(inv_entry)
        i += 36

    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, count_bytes.hex(), count))
    for i, (tx_type, tx_hash) in enumerate(inventory, start=height if height else 1):
        print('\n{}{:32} type: {}\n{}-'
              .format(prefix, tx_type.hex(),unmarshal_uint(tx_type), prefix))
        block_hash = swap_endian(tx_hash).hex()
        print('{}{:32}\n{}{:32} block #{} hash'.format(prefix, block_hash[:32], prefix, block_hash[32:], i))


def print_getblocks_message(payload):
    """
        Parses and prints the 'getblocks' message payload from the Bitcoin protocol.

        This function decodes the 'getblocks' message, which requests block header hashes
        starting from a specific block, and prints the details in a structured format.

        Parameters:
        - payload (bytes): The message payload containing version, hash count, block hashes,
          and stop hash.

        Key Functionality:
        - Extracts and prints the version of the protocol.
        - Decodes the compact size field to determine the number of block hashes.
        - Iterates through the block header hashes, printing each hash in a readable format.
        - Prints the stop hash, which indicates the last desired block in the sequence.

        Details:
        - The payload includes:
            - A 4-byte version field.
            - A compact size prefix indicating the number of block header hashes.
            - A list of 32-byte block header hashes.
            - A 32-byte stop hash to signal the end of the range.
        - Block hashes are printed in their big-endian form.

        Output:
        - Provides a detailed log of the 'getblocks' message, including:
          - Protocol version.
          - Number of requested block hashes.
          - Each block hash (split into two 32-character lines for readability).
          - The stop hash at the end of the range.

        Example:
        - If the payload requests 2 block hashes:
            - Version: <version>
            - Hash count: 2
            - Block hash #1: <hash>
            - Block hash #2: <hash>
            - Stop hash: <hash>
        """

    version = payload[:4]
    hash_count_bytes, hash_count =unmarshal_compactsize(payload[4:])
    i = 4 + len(hash_count_bytes)
    block_header_hashes = []
    for _ in range(hash_count):
        block_header_hashes.append(payload[i:i + 32])
        i += 32
    stop_hash = payload[i:]

    prefix = PREFIX * 2
    print('{}{:32} version: {}'.format(prefix, version.hex(),unmarshal_uint(version)))
    print('{}{:32} hash count: {}'.format(prefix, hash_count_bytes.hex(), hash_count))
    for hash in block_header_hashes:
        hash_hex =swap_endian(hash).hex()
        print('\n{}{:32}\n{}{:32} block header hash # {}: {}'
              .format(prefix, hash_hex[:32], prefix, hash_hex[32:], 1,unmarshal_uint(hash)))
    stop_hash_hex = stop_hash.hex()
    print('\n{}{:32}\n{}{:32} stop hash: {}'
          .format(prefix, stop_hash_hex[:32], prefix, stop_hash_hex[32:],unmarshal_uint(stop_hash)))


def display_fee_filter_details(feerate):
    """
        Displays the details of a Bitcoin 'feefilter' message.

        The 'feefilter' message is used in the Bitcoin protocol to communicate a minimum transaction
        fee rate below which transactions will not be relayed or accepted into the mempool.

        Parameters:
        - feerate (bytes): The payload containing the fee rate (in satoshis per byte).

        Key Functionality:
        - Decodes the fee rate from its raw byte representation.
        - Prints the fee rate in a formatted structure, including its hex and numerical representation.

        Details:
        - The fee rate is sent as a 64-bit unsigned integer in little-endian format.
        - This function extracts and converts the fee rate to its numerical value for readability.

        Output:
        - Logs the fee rate as:
          - Hexadecimal representation of the fee rate.
          - Decoded numerical value of the fee rate.

        Example:
        - Input: feerate = b'\x40\x0d\x03\x00\x00\x00\x00\x00'
        - Output:
            Fee Rate (Hex): 400d030000000000
            Fee Rate (Value): 200 sat/byte
        """

    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, feerate.hex(),unmarshal_uint(feerate)))



def print_addr_message(payload):
    """
        Parses and displays the details of a Bitcoin 'addr' message payload.

        The 'addr' message is used in the Bitcoin protocol to share information about known nodes on the network.

        Parameters:
        - payload (bytes): The raw byte payload of the 'addr' message.

        Key Functionality:
        - Extracts and decodes the following details from the payload:
          - The number of IP addresses shared in the message (ip_addr_count).
          - The epoch timestamp when the node was last seen.
          - The services advertised by the node (e.g., full node, relay node).
          - The IP address (IPv4/IPv6) of the node.
          - The port number on which the node is listening.

        Steps:
        - Reads the compact size-encoded count of addresses.
        - Extracts the address details: timestamp, services, IP address, and port.
        - Converts raw data (e.g., bytes) into human-readable formats (e.g., IPv4 string, GMT time).

        Output:
        - Logs the following information for each node:
          - Address count (hex and value).
          - Epoch timestamp (hex and readable GMT).
          - Advertised services (hex and decoded value).
          - Host address (hex and readable IPv4).
          - Port (hex and decoded value).

        Example:
        - Input: payload = b'...\x00\x01\x00\x00\x01\x7f\x00\x00\x01\x20\x8d'
        - Output:
            - Count: 1
            - Epoch Time: Wed, 20 Nov 2024 15:45:00 GMT
            - Services: 1 (Full Node)
            - Host: 127.0.0.1
            - Port: 8333
        """
    ip_count_bytes, ip_addr_count = unmarshal_compactsize(payload)
    i = len(ip_count_bytes)
    epoch_time, services, ip_addr, port = \
        payload[i:i + 4], payload[i + 4:i + 12], \
        payload[i + 12:i + 28], payload[i + 28:]
    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, ip_count_bytes.hex(), ip_addr_count))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} services: {}'.format(prefix, services.hex(),unmarshal_uint(services)))
    print('{}{:32} host: {}'.format(prefix, ip_addr.hex(), ipv6_to_ipv4(ip_addr)))
    print('{}{:32} port: {}'.format(prefix, port.hex(), unmarshal_uint(port)))


def print_ping_pong_message(nonce):
    """
       Displays the details of a Bitcoin 'ping' or 'pong' message.
       """
    prefix = PREFIX * 2
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(), unmarshal_uint(nonce)))


def display_compact_block_message(payload):
    """
       Displays details of a 'compact block' message in the Bitcoin protocol.

       The 'compact block' message facilitates the efficient transmission of new blocks by minimizing redundancy in data.
       """

    announce, version = payload[:1], payload[1:]
    prefix = PREFIX * 2
    print('{}{:32} announce: {}'.format(prefix, announce.hex(), bytes(announce) != b'\0'))
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))


def print_version_msg(b):
    """
        Parses and displays the details of a Bitcoin 'version' message payload.

        The 'version' message is used during the initial handshake to exchange information about nodes.

        Parameters:
        - b (bytes): The raw payload of the 'version' message.

        Key Functionality:
        - Extracts and decodes fields like protocol version, services, timestamps, and host information.
        - Interprets the user agent, starting block height, and relay flag.
        - Displays the information in a human-readable format for debugging and analysis.

        Steps:
        - Parses individual fields sequentially, including version, services, timestamps, IP addresses, and ports.
        - Converts byte representations to human-readable values (e.g., epoch time to GMT).
        - Formats and logs the extracted values with appropriate labels.

        Output:
        - Example:
            - Version: 70015
            - My Services: 0000000000000000
            - Your Host: 192.168.1.1
            - User Agent: "/Satoshi:0.21.1/"
            - Start Height: 123456
            - Relay: False
        """

    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = PREFIX * 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(),ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(),ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'
          .format(prefix, start_height.hex(),unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))







def change_block_value(block, block_number, new_amt):
    """
        Modifies the value field in a Bitcoin block, recalculates dependent hashes,
        and verifies the integrity of the modified block.

        Parameters:
        - block (bytes): The original Bitcoin block in raw byte format.
        - block_number (int): The block's position in the blockchain for reference.
        - new_amt (int): The new value (in satoshis) to set in the block's transaction output.

        Key Functionality:
        - Navigates to the transaction output section of the block to locate the value field.
        - Replaces the old value with the new value and updates the Merkle root and block hash.
        - Verifies that the updated Merkle root and block hash match the new transaction data.
        - Prints detailed logs of the changes for debugging and validation.

        Steps:
        1. Parse the block's structure to locate the transaction output value.
        2. Extract and display the old value for comparison.
        3. Update the block's transaction output value with the new amount.
        4. Recalculate the Merkle root to reflect the updated transaction data.
        5. Recalculate the block hash and verify integrity with the new data.
        6. Print the updated values and hashes for validation.

        Output:
        - Example:
            - Block 5122: change value from 12.5 BTC to 10.0 BTC
            - Old value: 12.5 BTC = 1250000000 sat
            - Old Merkle Hash: abc123... verified hash(txn) = def456...
            - New value: 10.0 BTC = 1000000000 sat
            - New Merkle Hash: ghi789...
            - New Block Hash: jkl012...

        Returns:
        - The modified block with updated values and recalculated hashes.
        """


    # Jump to the value index in the block
    txn_count_bytes = unmarshal_compactsize(block[104:])[0]
    index = 104 + len(txn_count_bytes)
    version = block[index:index + 4]
    index += 4
    tx_in_count_bytes = unmarshal_compactsize(block[index:])[0]
    index += len(tx_in_count_bytes)
    tx_in = parse_coinbase(block[index:], version)[0]
    index += len(b''.join(tx_in))
    txn_out_count_bytes = unmarshal_compactsize(block[index:])[0]
    index += len(txn_out_count_bytes)

    # Display old value
    old_value_bytes = block[index:index + 8]
    old_value = unmarshal_uint(old_value_bytes)
    print('Block {}: change value from {} BTC to {} BTC'
          .format(block_number, sat_to_btc(old_value), sat_to_btc(new_amt)))
    print('-' * 41)
    print('{:<24}'.format('old value:') + '{} BTC = {} sat'.format(sat_to_btc(old_value), old_value))

    # Verify old merkle hash
    old_merkle = swap_endian(block[60:92])
    calc_old_merkle =swap_endian(hash(block[104 + len(tx_in_count_bytes):]))
    print('{:<24}'.format('old merkle hash:') + old_merkle.hex())
    print('{:<24}'.format('verify old merkle hash:') + 'hash(txn) = {}'.format(calc_old_merkle.hex()))
    old_hash = swap_endian(hash(block[HEADER_SIZE:HEADER_SIZE + 80]))
    print('{:<24}'.format('old block hash:') + old_hash.hex())

    print('*' * 16)

    # Change the value bytes in the block
    block = block.replace(block[index:index + 8], uint64_t(new_amt))
    new_value_bytes = block[index:index + 8]
    new_value =unmarshal_uint(new_value_bytes)
    print('{:<24}'.format('new value:') + '{} BTC = {} sat'.format(sat_to_btc(new_value), new_value))

    # Calculate and display new merkle root
    calc_new_merkle = hash(block[104 + len(tx_in_count_bytes):])
    block = block.replace(block[60:92], calc_new_merkle)
    new_merkle = swap_endian(block[60:92])
    calc_new_merkle =swap_endian(calc_new_merkle)
    print('{:<24}'.format('new merkle:') + new_merkle.hex())
    print('{:<24}'.format('verify new merkle:') + 'hash(txn) = {}'.format(calc_new_merkle.hex()))

    # Calculate and display new block hash
    new_hash =swap_endian(hash(block[HEADER_SIZE:HEADER_SIZE + 80]))
    print('{:<24}'.format('new block hash:') + new_hash.hex())
    print('-' * 32)
    return block











def print_header(header, expected_cksum=None):
    """
       Parses and displays the contents of a Bitcoin message header, verifying the checksum if provided.

       Parameters:
       - header (bytes): The 24-byte Bitcoin message header.
         Contains:
           - Magic number: Identifies the Bitcoin network (Mainnet/Testnet).
           - Command: Specifies the type of message (e.g., 'version', 'ping').
           - Payload size: Length of the message payload in bytes.
           - Checksum: Used to validate the integrity of the payload.
       - expected_cksum (bytes): The expected checksum of the payload.
         If provided, this will be compared against the header's checksum.
       """

    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command


def print_block_message(payload):
    """
        Parses and displays the details of a Bitcoin block message payload.

        Parameters:
        - payload (bytes): The block message payload containing:
            - Block header: The first 80 bytes, which include:
                - Version (4 bytes): Indicates the block version.
                - Previous block hash (32 bytes): Links to the parent block.
                - Merkle root (32 bytes): Root hash of the transaction Merkle tree.
                - Epoch time (4 bytes): Timestamp of block creation (UNIX format).
                - Bits (4 bytes): Target difficulty for mining.
                - Nonce (4 bytes): Value used to solve the proof-of-work puzzle.
            - Transaction count: CompactSize encoding for the number of transactions.
            - Transactions: List of transactions in the block.

        Key Functionality:
        - Extracts and decodes the block header fields.
        - Decodes the transaction count using CompactSize encoding.
        - Calls `print_transaction` to display individual transaction details.
        - Logs parsed data for debugging or analysis.
        Dependencies:
        - `unmarshal_int` and `unmarshal_uint`: For decoding integers.
        - `swap_endian`: For reversing byte order in hashes.
        - `print_transaction`: For transaction parsing and display.
        """
    version, prev_block, merkle_root, epoch_time, bits, nonce = \
        payload[:4], payload[4:36], payload[36:68], payload[68:72], payload[72:76], payload[76:80]

    txn_count_bytes, txn_count =unmarshal_compactsize(payload[80:])
    txns = payload[80 + len(txn_count_bytes):]

    prefix = PREFIX * 2
    print('{}{:32} version: {}\n{}-'
          .format(prefix, version.hex(),unmarshal_int(version), prefix))
    prev_hash =swap_endian(prev_block)
    print('{}{:32}\n{}{:32} prev block hash\n{}-'
          .format(prefix, prev_hash.hex()[:32], prefix, prev_hash.hex()[32:], prefix))
    merkle_hash =swap_endian(merkle_root)
    print('{}{:32}\n{}{:32} merkle root hash\n{}-'
          .format(prefix, merkle_hash.hex()[:32], prefix, merkle_hash.hex()[32:], prefix))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} bits: {}'.format(prefix, bits.hex(),unmarshal_uint(bits)))
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(),unmarshal_uint(nonce)))
    print('{}{:32} transaction count: {}'.format(prefix, txn_count_bytes.hex(), txn_count))
    print_transaction(txns)


def print_transaction(txn_bytes):

    # Parse version and transaction input count bytes
    version = txn_bytes[:4]
    tx_in_count_bytes, tx_in_count =unmarshal_compactsize(txn_bytes[4:])
    i = 4 + len(tx_in_count_bytes)

    # Parse coinbase bytes
    cb_txn, cb_script_bytes_count = parse_coinbase(txn_bytes[i:], version)
    tx_in_list = [(cb_txn, cb_script_bytes_count)]
    i += len(b''.join(cb_txn))

    # Parse transaction input bytes
    for _ in range(1, tx_in_count):
        tx_in, script_bytes_count = parse_tx_in(txn_bytes[i:])
        tx_in_list.append((tx_in, script_bytes_count))
        i += len(b''.join(tx_in))

    # Parse transaction output count bytes
    tx_out_count_bytes, tx_out_count = unmarshal_compactsize(txn_bytes[i:])
    tx_out_list = []
    i += len(tx_out_count_bytes)

    # Parse transaction output bytes
    for _ in range(tx_out_count):
        tx_out, pk_script_bytes_count = parse_tx_out(txn_bytes[i:])
        tx_out_list.append((tx_out, pk_script_bytes_count))
        i += len(b''.join(tx_out))

    lock_time = txn_bytes[i:i+4]

    prefix = PREFIX * 2
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))

    print('\n{}Transaction Inputs:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} input txn count: {}'.format(prefix, tx_in_count_bytes.hex(), tx_in_count))
    print_transaction_inputs(tx_in_list)

    print('\n{}Transaction Outputs:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} output txn count: {}'.format(prefix, tx_out_count_bytes.hex(), tx_out_count))
    print_transaction_outputs(tx_out_list)

    print('{}{:32} lock time: {}'.format(prefix, lock_time.hex(), unmarshal_uint(lock_time)))
    if txn_bytes[i + 4:]:
        print('EXTRA: {}'.format(txn_bytes[i + 4:].hex()))


def print_transaction_inputs(tx_in_list):
    """
        Parses and displays the details of a Bitcoin transaction.

        Parameters:
        - txn_bytes (bytes): The raw transaction bytes, which include:
            - Version (4 bytes): Indicates the transaction version.
            - Input count: CompactSize encoding for the number of inputs.
            - Transaction inputs: Details for each input.
            - Output count: CompactSize encoding for the number of outputs.
            - Transaction outputs: Details for each output.
            - Lock time (4 bytes): Timestamp or block number for transaction finalization.

        Functionality:
        - Extracts and decodes transaction metadata and inputs/outputs.
        - Supports coinbase transactions by parsing the initial input differently.
        - Calls `print_transaction_inputs` and `print_transaction_outputs` to display input/output details"""

    prefix = PREFIX * 2
    for i, tx_in in enumerate(tx_in_list, start=1):
        print('\n{}Transaction {}{}:'.format(prefix, i, ' (Coinbase)' if i == 1 else ''))
        print(prefix + '*' * 32)
        hash, index, script_bytes, sig_script, seq = tx_in[0]
        script_bytes_count = tx_in[1]
        print('{}{:32}\n{}{:32} hash\n{}-'.format(prefix, hash.hex()[:32], prefix, hash.hex()[32:], prefix))
        print('{}{:32} index: {}'.format(prefix, index.hex(),unmarshal_uint(index)))
        print('{}{:32} script bytes: {}'.format(prefix, script_bytes.hex(), script_bytes_count))
        print('{}{:32} {}script'.format(prefix, sig_script.hex(), 'coinbase ' if i == 1 else ''))
        print('{}{:32} sequence number'.format(prefix, seq.hex()))


def print_transaction_outputs(tx_out_list):
    """
        Parses and displays the details of transaction outputs.

        Parameters:
        - tx_out_list (list): A list of transaction outputs, where each entry consists of:
            - A tuple of (value, pk_script_bytes, pk_script):
                - value (bytes): The output value in satoshis (8 bytes, little-endian).
                - pk_script_bytes (bytes): CompactSize-encoded length of the public key script.
                - pk_script (bytes): The public key script itself.
            - pk_script_bytes_count (int): Length of the public key script in bytes.

        Functionality:"""

    prefix = PREFIX * 2
    for i, tx_out in enumerate(tx_out_list, start=1):
        print('\n{}Transaction {}:'.format(prefix, i))
        print(prefix + '*' * 32)
        value, pk_script_bytes, pk_script = tx_out[0]
        pk_script_bytes_count = tx_out[1]
        sat= unmarshal_uint(value)
        btc = sat_to_btc(sat)
        print('{}{:32} value: {} sat = {} BTC'.format(prefix, value.hex(), sat, btc))
        print('{}{:32} public key script length: {}\n{}-'
              .format(prefix, pk_script_bytes.hex(), pk_script_bytes_count, prefix))
        for j in range(0, pk_script_bytes_count * 2, 32):
            print('{}{:32}{}' .format(prefix, pk_script.hex()[j:j + 32],
                                      ' public key script\n{}-'.format(prefix)
                                      if j + 32 > pk_script_bytes_count * 2 else ''))


def parse_coinbase(cb_bytes, version):
    """
        Parses the coinbase transaction from the given bytes.

        Parameters:
        - cb_bytes (bytes): The coinbase transaction bytes.
        - version (bytes): The transaction version to determine protocol-specific behavior.
"""

    hash_null = cb_bytes[:32]
    index = cb_bytes[32:36]
    script_bytes, script_bytes_count =unmarshal_compactsize(cb_bytes[36:])
    i = 36 + len(script_bytes)

    height = None
    # Version 1 doesn't require height parameter prior to block 227,836
    if unmarshal_uint(version) > 1:
        height = cb_bytes[i:i + 4]
        i += 4

    cb_script = cb_bytes[i:i + script_bytes_count]
    sequence = cb_bytes[i + script_bytes_count: i + script_bytes_count + 4]

    if height:
        return [hash_null, index, script_bytes, height, cb_script, sequence], script_bytes_count
    else:
        return [hash_null, index, script_bytes, cb_script, sequence], script_bytes_count


def parse_tx_out(tx_out_bytes):
    """
        Parses a transaction output from the provided byte sequence.

        Parameters:
        - tx_out_bytes (bytes): The bytes representing a transaction output."""

    value = tx_out_bytes[:8]
    pk_script_bytes, pk_script_bytes_count = unmarshal_compactsize(tx_out_bytes[8:])
    i = 8 + len(pk_script_bytes)
    pk_script = tx_out_bytes[i:i + pk_script_bytes_count]
    return [value, pk_script_bytes, pk_script], pk_script_bytes_count


def parse_tx_in(tx_in_bytes):
    """
        Parses a transaction input from the provided byte sequence.

        Parameters:
        - tx_in_bytes (bytes): The bytes representing a transaction input."""

    hash = tx_in_bytes[:32]
    index = tx_in_bytes[32:36]
    script_bytes, script_bytes_count =unmarshal_compactsize(tx_in_bytes[36:])
    i = 36 + len(script_bytes)
    sig_script = tx_in_bytes[i:i + script_bytes_count]
    sequence = tx_in_bytes[i + script_bytes_count:]
    return [hash, index, script_bytes, sig_script, sequence], script_bytes_count


def split_message(peer_msg_bytes):
    """
    Splits a peer message stream into individual Bitcoin protocol messages.

    Parameters:
    - peer_msg_bytes (bytes): Byte stream containing one or more serialized Bitcoin messages.

    Returns:
    - list: A list of byte segments, where each segment represents a single Bitcoin message."""

    msg_list = []
    while peer_msg_bytes:
        payload_size = unmarshal_uint(peer_msg_bytes[16:20])
        msg_size = HEADER_SIZE + payload_size
        msg_list.append(peer_msg_bytes[:msg_size])
        # Discard to move onto next message
        peer_msg_bytes = peer_msg_bytes[msg_size:]
    return msg_list


def get_last_block_hash(inv_bytes):
    """
      Extracts the last block hash from the inventory message bytes.

      Parameters:
      - inv_bytes (bytes): Byte sequence of inventory message.

      Returns:
      - bytes: The last 32 bytes representing the block hash.
      """

    return inv_bytes[len(inv_bytes) - 32:]


def update_current_height(block_list, curr_height):
    """
       Updates the current block height based on the last inventory message.

       Parameters:
       - block_list (list): List of blocks received.
       - curr_height (int): Current block height.

       Returns:
       - int: Updated block height.
       """

    return curr_height + (len(block_list[-1]) - 27) // 36



def get_peer_block_headers(input_hash, current_height):
    """
       Sends a `getblocks` message to the peer and retrieves inventory.

       Parameters:
       - input_hash (bytes): The starting block hash for the `getblocks` message.
       - current_height (int): Current height of the blockchain.

       Returns:
       - list: Headers of the last 500 blocks received.
       - int: Updated block height.
       """

    getblocks_bytes = build_message('getblocks', create_getblocks_payload(input_hash))
    peer_inv = exchange_messages(getblocks_bytes, expected_bytes=18027, height=current_height + 1)
    peer_inv_bytes = b''.join(peer_inv)
    last_500_headers = [peer_inv_bytes[i:i + 32] for i in range(31, len(peer_inv_bytes), 36)]
    current_height = update_current_height(peer_inv, current_height)
    return last_500_headers, current_height


def get_block_height_from_version(vsn_bytes):
    """
       Extracts the peer's blockchain height from the version message.

       Parameters:
       - vsn_bytes (bytes): Byte sequence of the version message.

       Returns:
       - int: Blockchain height of the peer.
       """

    return unmarshal_uint(vsn_bytes[-5:-1])




def block_modification_test(my_block, block_number, last_500_blocks, new_value):
    """
      Demonstrates the impact of altering a block's value (Bitcoin theft simulation).

      Parameters:
      - my_block (bytes): The block to be altered.
      - block_number (int): The block number being altered.
      - last_500_blocks (list): List of the last 500 blocks' headers.
      - new_value (float): New Bitcoin value to replace the original.

      Returns:
      - None
      """

    print('\nBitcoin thief experiment')
    print('*' * 64 + '\n')
    btcs = new_value
    sat = btc_to_sat(btcs)

    # Change block value, merkle hash, and update checksum
    thief_block = change_block_value(my_block, block_number, sat)
    thief_block = thief_block.replace(thief_block[20:HEADER_SIZE], calculate_checksum(thief_block[HEADER_SIZE:]))

    # Print fields of the new thief block
    end = HEADER_SIZE + 80
    thief_block_hash = swap_endian(hash(thief_block[HEADER_SIZE:end])).hex()
    print_message(thief_block, '*** TEST (value has changed) *** ')

    # Get the next block and verify it's prev block hash doesn't match the
    # new hash of the altered/thief block
    print('\nBlock # {} data: '.format(block_number + 1))
    next_block_hash = last_500_blocks[(block_number) % 500]
    getdata_msg = build_message('getdata', create_getdata_message(2, next_block_hash))
    next_block = exchange_messages(getdata_msg, wait=True)
    next_block = b''.join(next_block)
    prev_block_hash =swap_endian(next_block[28:60]).hex()
    print("\n\n\n--- Blockchain Validation Result ---\n")

    # Display the previous block hash stored in Block {block_number + 1}
    print(f"Block {block_number + 1} expects the following hash for its predecessor:")
    print(f"  Previous Block Hash: {prev_block_hash}\n")

    # Display the altered hash of Block {block_number}
    print(f"Block {block_number} has been modified. Its new hash is:")
    print(f"  Altered Hash: {thief_block_hash}\n")

    # Compare the hashes and show the result
    if prev_block_hash == thief_block_hash:
        print(">>> Comparison Result: MATCH")
        print(f"Block {block_number + 1} recognizes the modified Block {block_number} as its predecessor.")
        print("The chain remains valid.\n")
        print("Final Verdict: ACCEPTED ✅")
    else:
        print(">>> Comparison Result: NO MATCH")
        print(f"Block {block_number + 1} does NOT recognize the modified Block {block_number} as its predecessor.")
        print("This means the chain is broken and invalid.\n")
        print("Final Verdict: REJECTED ❌")

    print("\n------------------------------------\n")







def exchange_messages(bytes_to_send, expected_bytes=None, height=None, wait=False):
    """
       Sends a message to the peer and receives the response.

       Parameters:
       - bytes_to_send (bytes): Serialized message to be sent.
       - expected_bytes (int, optional): Expected size of the response in bytes.
       - height (int, optional): Block height associated with the message (for logging).
       - wait (bool, optional): Whether to wait for all available bytes.

       Returns:
       - list: List of received messages split into individual Bitcoin messages.
       """

    print_message(bytes_to_send, 'send', height=height)
    BTC_SOCK.settimeout(0.5)
    bytes_received = b''

    try:
        BTC_SOCK.sendall(bytes_to_send)

        if expected_bytes:
            # Message size is fixed: receive until byte sizes match
            while len(bytes_received) < expected_bytes:
                bytes_received += BTC_SOCK.recv(BUFFER_SIZE)
        elif wait:
            # Message size could vary: wait until timeout to receive all bytes
            while True:
                bytes_received += BTC_SOCK.recv(BUFFER_SIZE)

    except Exception as e:
        print('\nNo bytes left to receive from {}: {}'
              .format(BTC_PEER_ADDRESS, str(e)))

    finally:
        print('\n****** Received {} bytes from BTC node {} ******'
              .format(len(bytes_received), BTC_PEER_ADDRESS))
        peer_msg_list = split_message(bytes_received)
        for msg in peer_msg_list:
            print_message(msg, 'receive', height)
        return peer_msg_list








def main():
    """
     Main function to interact with the Bitcoin network.

     Usage:
     - python bitcoin_explorer.py BLOCK_NUMBER

     Steps:
     1. Connect to a Bitcoin node and perform a handshake.
     2. Retrieve the inventory up to the specified block number.
     3. Execute a Bitcoin theft experiment to demonstrate altered block behavior.

     Returns:
     - None
     """

    if len(sys.argv) != 2:
        print('Usage: bitcoin_explorer.py BLOCK_NUMBER')
        exit(1)

    # Block number from command line argument
    block_number = int(sys.argv[1])

    with BTC_SOCK:
        # Establish connection with Bitcoin node
        BTC_SOCK.connect(BTC_PEER_ADDRESS)

        # Send version -> receive version, verack
        version_bytes = build_message('version', version_message())
        peer_vsn_bytes = exchange_messages(version_bytes, expected_bytes=126)[0]
        peer_height = get_block_height_from_version(peer_vsn_bytes)

        # Send verack -> receive sendheaders, sendcmpct, ping, addr, feefilter
        verack_bytes = build_message('verack', EMPTY_STRING)
        exchange_messages(verack_bytes, expected_bytes=202)

        # Send ping -> receive pong
        ping_bytes = build_message('ping', ping_message())
        exchange_messages(ping_bytes, expected_bytes=32)

        # Check supplied block number against peer's blockchain height
        if block_number > peer_height:
            print('\nCould not retrieve block {}: max height is {}'.format(block_number, peer_height))
            exit(1)

        # Send getblocks (starting from genesis) -> receive inv
        block_hash = swap_endian(BLOCK_GENESIS)
        current_height = 0
        # Store last 500 blocks from inv messages
        last_500_blocks = []
        # Keep sending getblocks until inventory has the desired block number
        while current_height < block_number:
            last_500_blocks, current_height = get_peer_block_headers(block_hash, current_height)
            block_hash = last_500_blocks[-1]

        # Retrieve block, send getdata for the block -> receive block message
        my_block_hash = last_500_blocks[(block_number - 1) % 500]
        getdata_bytes = build_message('getdata', create_getdata_message(2, my_block_hash))
        msg_list = exchange_messages(getdata_bytes, height=block_number, wait=True)
        my_block = b''.join(msg_list)

        # Pick new reward value for the bitcoin
        block_modification_test(my_block, block_number, last_500_blocks, 4000)


if __name__ == '__main__':
    main()