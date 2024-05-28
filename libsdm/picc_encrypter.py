from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import CMAC
import io
import binascii
from libsdm.lrp import LRP
import struct


class InvalidMessage(Exception):
    pass


class EncMode:
    AES = "AES"
    LRP = "LRP"


def reverse_decrypt_sun_message(picc_data_tag, uid, read_ctr_num, file_data, encryption_mode):
    # Reverse the decryption process based on encryption mode
    if encryption_mode == EncMode.AES:
        picc_enc_data = reverse_aes_decryption(
            picc_data_tag, uid, read_ctr_num, file_data)
    elif encryption_mode == EncMode.LRP:
        picc_enc_data = reverse_lrp_decryption(
            picc_data_tag, uid, read_ctr_num, file_data)
    else:
        raise InvalidMessage("Invalid encryption mode.")

    # Convert picc_enc_data to hex representation
    picc_data = picc_enc_data.hex()
    return picc_data


def reverse_aes_decryption(picc_data_tag, uid, read_ctr_num, file_data):
    # Implement reverse AES decryption logic
    # Example:
    # Construct plaintext from parameters (reverse of decrypt_sun_message)
    plaintext = construct_plaintext(
        picc_data_tag, uid, read_ctr_num, file_data)
    print(plaintext)
    # Decrypt plaintext using the same key and IV used in decryption
    key = b'Your_AES_Key_Here'
    iv = b'Your_AES_IV_Here'
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    picc_enc_data = cipher.encrypt(pad(plaintext, AES.block_size))
    return picc_enc_data


def reverse_lrp_decryption(picc_data_tag, uid, read_ctr_num, file_data):
    # Implement reverse LRP decryption logic
    # Example:
    # Construct plaintext from parameters (reverse of decrypt_sun_message)
    plaintext = construct_plaintext(
        picc_data_tag, uid, read_ctr_num, file_data)
    # Decrypt plaintext using the same key and parameters used in decryption
    key = b'Your_LRP_Key_Here'
    picc_rand = b'Your_PICC_Random_Value_Here'
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
    plaintext.write(struct.pack("<I", read_ctr_num)[:-1])
    if file_data:
        plaintext.write(file_data)
    return plaintext.getvalue()


# Example usage:
picc_data_tag = b'\xc7'
uid = b'\x04\xde\x5f\x1e\xac\xc0\x40'
read_ctr_num = 61
file_data = b'Your_File_Data_Here'
encryption_mode = EncMode.AES  # or EncMode.LRP

picc_data = reverse_decrypt_sun_message(
    picc_data_tag, uid, read_ctr_num, file_data, encryption_mode)
print("Reversed PICC Data:", picc_data)
