from config import MASTER_KEY
from derive import derive_undiversified_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import CMAC
import io
import struct
import binascii
from lrp import LRP


cipher = AES.new(b'\x00'*16, AES.MODE_CBC, IV=b'\x00' * 16)

plaintext = cipher.encrypt(b'\xc7\x04\x95\x8c\xaa\\^\x80=\x00\x00')
print("plain text: ")
print(plaintext)
# print(binascii.hexlify(b'\xc7\x04\xde_\x1e\xac\xc0@=\x00\x00\xda\\\xf6\tA'))


class InvalidMessage(Exception):
    pass


class EncMode:
    AES = "AES"
    LRP = "LRP"


def get_encryption_mode(picc_enc_data: bytes):
    if len(picc_enc_data) == 16:
        return EncMode.AES

    if len(picc_enc_data) == 24:
        return EncMode.LRP

    raise InvalidMessage("Unsupported encryption mode.")


def reverse_decrypt_sun_message(picc_data_tag, uid, read_ctr_num, file_data, encryption_mode):
    # Reverse the decryption process based on encryption mode

    # mode = get_encryption_mode(picc_enc_data)
    encryption_mode = EncMode.AES
    if not file_data:
        file_data = ""
    if encryption_mode == EncMode.AES:
        picc_enc_data = reverse_aes_decryption(
            picc_data_tag, uid, read_ctr_num, file_data)
    elif encryption_mode == EncMode.LRP:
        picc_enc_data = reverse_lrp_decryption(
            picc_data_tag, uid, read_ctr_num, file_data)
    else:
        raise InvalidMessage("Invalid encryption mode.")

    print(picc_enc_data)
    # Convert picc_enc_data to hex representation
    # picc_data = picc_enc_data.hex()
    return binascii.hexlify(plaintext)


def reverse_aes_decryption(picc_data_tag, uid, read_ctr_num, file_data):
    # Implement reverse AES decryption logic
    # Example:
    # Construct plaintext from parameters (reverse of decrypt_sun_message)
    plaintext = construct_plaintext(
        picc_data_tag, uid, read_ctr_num, file_data)
    # print(plaintext, end="\n")
    print("Plain text unhexlify: ")
    print(pad(plaintext, AES.block_size))
    # plaintext = b'EF963FF7828658A599F3041510671E88'
    # Decrypt plaintext using the same key and IV used in decryption
    key = derive_undiversified_key(MASTER_KEY, 1)
    iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, IV=b'\x00' * 16)
    picc_enc_data = cipher.encrypt(
        pad(b'\xc7\x04\x95\x8c\xaa\\^\x80=\x00\x00', AES.block_size))
    return picc_enc_data


def reverse_lrp_decryption(picc_data_tag, uid, read_ctr_num, file_data):
    # Implement reverse LRP decryption logic
    # Example:
    # Construct plaintext from parameters (reverse of decrypt_sun_message)
    plaintext = construct_plaintext(
        picc_data_tag, uid, read_ctr_num, file_data)
    # Decrypt plaintext using the same key and parameters used in decryption
    key = b'\x00' * 16
    picc_rand = picc_enc_data[0:8]
    cipher = LRP(key, 0, picc_rand, pad=False)
    picc_enc_data = cipher.encrypt(plaintext)
    return picc_enc_data


def construct_plaintext(picc_data_tag, uid, read_ctr_num, file_data):
    # Construct plaintext from parameters
    # Example:
    # Construct plaintext in the format expected by decrypt_sun_message
    plaintext = io.BytesIO()
    plaintext.write(picc_data_tag)
    plaintext.write(uid)

    # Pack read_ctr_num as 3 bytes
    plaintext.write(struct.pack("<I", read_ctr_num))
    if file_data:
        plaintext.write(file_data)
    return plaintext.getvalue()


# Example usage:
encryption_mode = EncMode.AES
picc_data_tag = b'\xc7'
uid = b'\x04\x95\x8c\xaa\x5c\x5e\x80'
read_ctr_num = 61
file_data_utf8 = "xxxxxxxxxxxxxxxx"  # Your UTF-8 encoded file data
file_data = None

picc_data = reverse_decrypt_sun_message(
    picc_data_tag, uid, read_ctr_num, file_data, encryption_mode)
print("Reversed PICC Data:", picc_data)
