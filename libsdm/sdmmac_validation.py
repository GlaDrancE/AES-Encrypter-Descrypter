# pylint: disable=invalid-name, line-too-long

"""
This code was implemented based on the examples provided in:
* AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
"""
import io
from enum import Enum
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

import libsdm.config as config
from libsdm.lrp import LRP


class EncMode(Enum):
    AES = 0
    LRP = 1


class ParamMode(Enum):
    SEPARATED = 0
    BULK = 1


class InvalidMessage(RuntimeError):
    pass


def calculate_sdmmac(param_mode: ParamMode,
                     sdm_file_read_key: bytes,
                     picc_data: bytes,
                     enc_file_data: Optional[bytes] = None,
                     mode: Optional[EncMode] = None) -> bytes:
    """
    Calculate SDMMAC for NTAG 424 DNA
    :param param_mode: Type of dynamic URL encoding (ParamMode)
    :param sdm_file_read_key: MAC calculation key (K_SDMFileReadKey)
    :param picc_data: [ UID ][ SDMReadCtr ]
    :param enc_file_data: SDMEncFileData (if used)
    :param mode: Encryption mode used by PICC - EncMode.AES (default) or EncMode.LRP
    :return: calculated SDMMAC (8 bytes)
    """
    if mode is None:
        mode = EncMode.AES

    input_buf = io.BytesIO()

    if enc_file_data:
        sdmmac_param_text = f"&{config.SDMMAC_PARAM}="

        if param_mode == ParamMode.BULK or not config.SDMMAC_PARAM:
            sdmmac_param_text = ""

        input_buf.write(enc_file_data.hex().upper().encode(
            'ascii') + sdmmac_param_text.encode('ascii'))

    if mode == EncMode.AES:
        sv2stream = io.BytesIO()
        sv2stream.write(b"\x3C\xC3\x00\x01\x00\x80")
        sv2stream.write(picc_data)

        while sv2stream.getbuffer().nbytes % AES.block_size != 0:
            # zero padding till the end of the block
            sv2stream.write(b"\x00")

        c2 = CMAC.new(sdm_file_read_key, ciphermod=AES)
        c2.update(sv2stream.getvalue())
        sdmmac = CMAC.new(c2.digest(), ciphermod=AES)
        sdmmac.update(input_buf.getvalue())
        mac_digest = sdmmac.digest()
    elif mode == EncMode.LRP:
        sv2stream = io.BytesIO()
        sv2stream.write(b"\x00\x01\x00\x80")
        sv2stream.write(picc_data)

        while (sv2stream.getbuffer().nbytes + 2) % AES.block_size != 0:
            # zero padding till the end of the block
            sv2stream.write(b"\x00")

        sv2stream.write(b"\x1E\xE1")
        sv = sv2stream.getvalue()

        lrp_master = LRP(sdm_file_read_key, 0)
        master_key = lrp_master.cmac(sv)

        lrp_session_macing = LRP(master_key, 0)
        mac_digest = lrp_session_macing.cmac(input_buf.getvalue())
    else:
        print("Here is your mode : ")
        print(mode)
        print(mode == EncMode.AES)
        print("Here is Type of your mode : ")
        print(type(mode) == type(EncMode.AES))
        print(type(mode))
        print(type(EncMode.AES))
        print("Here is your EncMode: ")
        print(EncMode.AES)
        raise InvalidMessage("Invalid encryption mode.")

    return bytes(bytearray([mac_digest[i] for i in range(16) if i % 2 == 1]))
