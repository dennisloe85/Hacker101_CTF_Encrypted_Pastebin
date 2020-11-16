"""Useful functions for this CTF challenge"""


from math import ceil
import requests
import base64

def XOR_byte_list(a, b):
    """XOR two byte lists"""
    return "".join([ chr(ord(a_i) ^ ord(b_i)) for (a_i,b_i) in zip(a, b) ])

    
def evaluate_data(data, base_url):
    """Send data to the pastebin and retrieve response"""
    payload = { 'post': data }

    response = requests.get(base_url, params=payload)

    if response.status_code == 404:
        raise Exception("Error occurred! URL '{}' is not available ({}).".format(base_url, response.status_code) )
    
    return response


def print_blocks(blocks):
    """Pretty printing HEX blocks"""
    print("Cipher text blocks:")
    for i, block in enumerate(blocks):
        # @todo: Print related plaintext to each block
        print("Block[{}]: {} {}".format(i, str_to_hex(block), " <- IV" if (i==0) else ""))            
    print ("")


def unpad(data):
    """Remove padding bytes using PCKS#7"""
    num_padding_bytes = ord(data[-1])

    # Check if data is consistent with PCKS#7
    for i in range(len(data) - num_padding_bytes, len(data)):
        if ord(data[i]) is not num_padding_bytes:
            raise Exception("Error occured! Incorrect padding.")

    return data[:-num_padding_bytes]


def pad(data, block_size):
    """Add padding bytes using PCKS#7"""
    num_padding_bytes = block_size - len(data) % block_size

    # Full block of padding bytes is expected if data alreadyis multiple of block_size
    if num_padding_bytes == 0:
        num_padding_bytes += block_size

    return data + chr(num_padding_bytes) * num_padding_bytes


def str_to_int(val):
    """Nice formatting of integer numbers"""
    return " ".join("{:03}".format(ord(c)) for c in val) 


def str_to_hex(val):
    """Nice formatting of HEX pairs"""
    return " ".join("{:02x}".format(ord(c)) for c in val) 


def str_to_binary(val):
    """Nice formatting in binary octets"""    
    return " ".join("{:08b}".format(ord(c)) for c in val)     


def encode_data(data):
    """Encode data with base64 encoding and replacement"""

    # Encode with B64 
    b64e = lambda x: base64.encodestring(data)
    data_b64e = b64e(data)

    # Replace special keys in the input string
    return data_b64e.replace('=', '~').replace('/', '!').replace('+', '-').replace('\n', '') 


def decode_data(data):
    """Decode data with replacement and base64 encoding"""

    # Replace special keys in the input string
    data_replaced = data.replace('~', '=').replace('!', '/').replace('-', '+') 

    # Decode with B64 
    b64d = lambda x: base64.decodestring(data_replaced)
    return b64d(data_replaced)


def change_byte_at_index(data, index, byte):
    """Set given byte at given index"""
    
    if index >= len(data):
        raise Exception("Error occured! Input string is too short.")

    return data[:index] + chr(byte) + data[index+1:]


def split_into_blocks(data, block_size):
    """Split string into multiple blocks"""

    blocks = []

    for i in range( int(ceil( len(data) / float(block_size) )) ):
        cur_block = data[i * block_size : (i + 1) * block_size]
        blocks.append(cur_block)

    return blocks


def test_de_encoding():
    """Test decode and encode functionality"""

    data = "0WrV4QqDqUEgjpuCD4qWul9243BU0!M7HVLV31BSWeFrB4WSNvECLDO1XDbFboV1yZwlcKf0XA2EFACyNLnREYrCZl0rc86w5D4kDba-0qjbG40rDRovD-q0CUJl1BUiEUDCi9cqpRGLLk0bp8nn2V7eX5mZv7RnoxdIrFCtN5lKXBYv1XDI8rfFfpsNedLP-wYI6JllnDQAesiWY04IQA~~"
    dec_data = decode_data(data)
    enc_data = encode_data(dec_data)
    if enc_data != data:
        raise Exception("Error in encoding or decoding function.")


def test_un_padding():
    """Test decode and encode functionality"""

    block_size = 16
    data = "x" * (block_size / 2)
    pad_data = pad(data, block_size)
    unpadded_data = unpad(pad_data)
    if len(pad_data) == block_size and unpadded_data != data:
        raise Exception("Error in unpadding or padding  function.")