import struct

# Input parameters
picc_data_tag = b'\xc7'
uid = b'\x04\xde\x5f\x1e\xac\xc0\x40'
read_ctr_num = 61
file_data_hex = b""

# Convert read counter to 3 bytes
read_ctr_bytes = struct.pack("<I", read_ctr_num)[:3]

# Construct plaintext
plaintext = picc_data_tag + uid + read_ctr_bytes + file_data_hex

print("Constructed plaintext:", plaintext)
