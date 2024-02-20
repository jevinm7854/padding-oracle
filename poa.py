from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as pkcs7_pad, unpad as pkcs7_unpad
import binascii


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    return zip(*[iter(iterable)] * n)


BYTE_ORDER: str = "little"
LENGTH_PREFIX_BYTES: int = 4
BLOCK_SIZE: int = 16

KEY: bytes = b"qwertyuiQWERTYUI"

"""
BONUS:
A function to pad `source_str` with padding length so that the resulting byte string is a multiple of `block_size`
We will add a prefix of the message length to this padding.
"""


def pad(source_str: bytes, block_size: int = 16):
    assert block_size < 2**8, f"Block size {block_size} is NOT less than {2**8}"
    # First add the length of the source string as a 4 byte little endian number
    res = bytearray(
        len(source_str).to_bytes(
            LENGTH_PREFIX_BYTES,
            byteorder=BYTE_ORDER,
        )
    )
    # Then, add the original source string
    res = res + bytearray(source_str)
    # Compute the padding element
    padding_length = block_size - len(res) % block_size
    print(padding_length)
    padding_element = padding_length.to_bytes(
        1,
        byteorder=BYTE_ORDER,
    )
    padding_string = padding_element * padding_length
    res = res + padding_string
    return bytes(res)


"""
BONUS:
A function to remove the padding elements from `padded_string` so that the resulting string is unpadded

The function returns False if the padding is incorrect
"""


def unpad(padded_string: bytes, block_size: int = 16):
    source_string_length = int.from_bytes(
        padded_string[:LENGTH_PREFIX_BYTES],
        byteorder=BYTE_ORDER,
    )
    if (source_string_length + LENGTH_PREFIX_BYTES) % block_size == 0:
        return padded_string[
            LENGTH_PREFIX_BYTES : LENGTH_PREFIX_BYTES + source_string_length
        ]
    padding_unit = 1

    # Check if the found padding matches the expected padding
    expected_padding = (
        block_size - (source_string_length + LENGTH_PREFIX_BYTES) % block_size
    )
    padding = int.from_bytes(
        padded_string[-padding_unit:],
        byteorder=BYTE_ORDER,
    )
    if padding != expected_padding:
        print(f"Mismatch: {expected_padding} {padding}")
        print(f"source length: {source_string_length}")
        print(f"Padding bytes: {padded_string[-4:]}")
        return False

    # Ensure all the padding elements are correct
    listed = list(padded_string)
    listed.reverse()
    grouped = list(grouper(listed, padding_unit))
    for element in grouped[:padding]:
        element = list(element)
        element.reverse()
        padding_element = int.from_bytes(
            element,
            byteorder=BYTE_ORDER,
        )
        if padding != padding_element:
            print("Padding mismatch")
            return False
    return padded_string[
        LENGTH_PREFIX_BYTES : LENGTH_PREFIX_BYTES + source_string_length
    ]


"""
A function to encrypt a message `msg` using key `key` and IV `iv`
"""


def encrypt(plain_text: bytes, key: bytes, iv: bytes):
    padded_msg = pkcs7_pad(plain_text, BLOCK_SIZE)
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    cipher = cryptor.encrypt(padded_msg)
    return cipher


"""
A function to decrypt the cipher `cipher` using the key `key` and IV `iv`
"""


def decrypt(cipher: bytes, key: bytes, iv: bytes):
    s = cipher
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(s)
    return plaintext


"""
`oracle` returns whether the `cipher` contains the correct padding.
NOTE: This is the padding oracle function.
"""


def oracle(cipher: bytes, iv: bytes) -> bool:
    decrypted = decrypt(cipher, KEY, iv)
    try:
        pkcs7_unpad(decrypted, BLOCK_SIZE)
        return True
    except ValueError:
        return False


"""
TODO: Demonstrate the padding oracle attack here!!!
"""


def padding_oracle_attack_exploiter(cipher, iv):

    cipher = bytearray(cipher)
    iv_old = bytearray(iv)

    plain_text = bytearray(b"\x00" * len(cipher))
    for block_no in range(len(cipher) // (16) - 1, 0, -1):

        current_block = cipher[16 * (block_no) :][:16]
        prev_block = cipher[16 * (block_no - 1) :][:16]
        block_ans_inter = bytearray(b"\x00" * 16)
        iv_new = bytearray(
            b"\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70"
        )
        for byte in range(16):
            loc = byte + 1
            for suff in range(byte):
                ind = -suff - 1
                iv_new[ind] = loc ^ block_ans_inter[ind]
            found = False
            for guess in range(256):
                iv_new[-loc] = guess
                ci = cipher[: 16 * (block_no - 1)] + iv_new + current_block
                # print(ci)
                res = oracle(ci, iv)
                if res == True:
                    found = True
                    block_ans_inter[-loc] = iv_new[-loc] ^ loc
                    ans_byte = (block_ans_inter[-loc]) ^ prev_block[-loc]
                    plain_text[(16 * block_no) + (16 - loc)] = ans_byte
            if found == False:
                print("Error: not found")
                exit()

    iv_new = bytearray(
        b"\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70"
    )
    plain_text_single = bytearray(b"\x00" * 16)
    block_ans_inter = bytearray(b"\x00" * 16)
    for byte in range(16):
        loc = byte + 1
        for suff in range(byte):
            ind = -suff - 1
            iv_new[ind] = loc ^ (block_ans_inter[ind])
        found = False
        for guess in range(256):
            iv_new[-loc] = guess
            res = oracle(cipher[:16], iv_new)
            if res == True:
                found = True
                block_ans_inter[-loc] = iv_new[-loc] ^ loc
                ans_byte = (block_ans_inter[-loc]) ^ iv_old[-loc]
                plain_text_single[-loc] = ans_byte
        if found == False:
            print("Error: Not found")
            exit()
    final_ans = plain_text_single + plain_text[16:]
    print("Using the implemented padding oracle exploit function : ", final_ans)


if __name__ == "__main__":
    iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # Test string
    p = b"This is cs528 padding oracle attack lab with hello world~~~!!"
    # p = b"Hello World! How are you doing? Today is a great Day"
    # p = b"abcd ef"
    cipher = encrypt(p, KEY, iv)
    hex_string = binascii.hexlify(cipher).decode("utf-8")
    dec = decrypt(cipher, KEY, iv)
    print("The input : ", p)
    print("After Encryption :  ", cipher)
    print("After Encryption (in hex) : ", hex_string)
    print("Using the provided decryption function : ", dec)
    padding_oracle_attack_exploiter(cipher, iv)
