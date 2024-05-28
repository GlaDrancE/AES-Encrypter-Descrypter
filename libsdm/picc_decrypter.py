import argparse
import binascii
import io

from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.exceptions import BadRequest

from libsdm.config import (
    CTR_PARAM,
    ENC_FILE_DATA_PARAM,
    ENC_PICC_DATA_PARAM,
    REQUIRE_LRP,
    SDMMAC_PARAM,
    MASTER_KEY,
    UID_PARAM,
    DERIVE_MODE,
)

if DERIVE_MODE == "legacy":
    from libsdm.legacy_derive import derive_tag_key, derive_undiversified_key
elif DERIVE_MODE == "standard":
    from libsdm.derive import derive_tag_key, derive_undiversified_key
else:
    raise RuntimeError("Invalid DERIVE_MODE.")

from libsdm.sdm import (
    EncMode,
    InvalidMessage,
    ParamMode,
    decrypt_sun_message,
    # validate_plain_sun,
)

# This method parse the parameters from url, I've removed parameters like enc[enc_file_data] and cmac[sdmmac] because this is module of picc decrypter so we are only taking picc_data parameter


# def parse_parameters():
#     arg_e = request.args.get('e')
#     if arg_e:
#         param_mode = ParamMode.BULK

#         try:
#             e_b = binascii.unhexlify(arg_e)
#             print(e_b)
#         except binascii.Error:
#             raise BadRequest("Failed to decode parameters.") from None

#         e_buf = io.BytesIO(e_b)

#         if (len(e_b) - 8) % 16 == 0:
#             # using AES (16 byte PICCEncData)
#             file_len = len(e_b) - 16 - 8
#             enc_picc_data_b = e_buf.read(16)

#             if file_len > 0:
#                 enc_file_data_b = e_buf.read(file_len)
#             else:
#                 enc_file_data_b = None
#             sdmmac_b = e_buf.read(8)
#         elif (len(e_b) - 8) % 16 == 8:
#             # using LRP (24 byte PICCEncData)
#             file_len = len(e_b) - 24 - 8
#             enc_picc_data_b = e_buf.read(24)

#             if file_len > 0:
#                 enc_file_data_b = e_buf.read(file_len)
#             else:
#                 enc_file_data_b = None

#             sdmmac_b = e_buf.read(8)
#         else:

#             raise BadRequest("Incorrect length of the dynamic parameter.")
#     else:
#         param_mode = ParamMode.SEPARATED
#         enc_picc_data = request.args.get(ENC_PICC_DATA_PARAM)
#         enc_file_data = request.args.get(ENC_FILE_DATA_PARAM)
#         sdmmac = request.args.get(SDMMAC_PARAM)
#         if not enc_picc_data:
#             raise BadRequest(f"Parameter {ENC_PICC_DATA_PARAM} is required")

#         if not sdmmac:
#             raise BadRequest(f"Parameter {SDMMAC_PARAM} is required")

#         try:
#             enc_file_data_b = None
#             enc_picc_data_b = binascii.unhexlify(enc_picc_data)
#             sdmmac_b = binascii.unhexlify(sdmmac)
#             if enc_file_data:
#                 enc_file_data_b = binascii.unhexlify(enc_file_data)
#         except binascii.Error:
#             raise BadRequest("Failed to decode parameters.") from None

#     return param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b


# pylint:  disable=too-many-branches, too-many-statements, too-many-locals
def _internal_sdm(param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b, with_tt=False, force_json=False):
    """
    SUN decrypting/validating endpoint.
    """
    print(enc_picc_data_b)

    try:
        res = decrypt_sun_message(param_mode=param_mode,
                                  sdm_meta_read_key=derive_undiversified_key(
                                      MASTER_KEY, 1),
                                  sdm_file_read_key=lambda uid: derive_tag_key(
                                      MASTER_KEY, uid, 2),
                                  picc_enc_data=enc_picc_data_b,
                                  sdmmac=sdmmac_b,
                                  enc_file_data=enc_file_data_b)
    except InvalidMessage:
        # raise BadRequest("Invalid message (most probably wrong signature).") from InvalidMessage
        return jsonify({"message": "Something went wrong"})

    if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
        raise BadRequest("Invalid encryption mode, expected LRP.")

    picc_data_tag = res['picc_data_tag']
    uid = res['uid']
    read_ctr_num = res['read_ctr']
    file_data = res['file_data']
    encryption_mode = res['encryption_mode'].name

    file_data_utf8 = ""
    tt_status_api = ""
    tt_status = ""
    tt_color = ""

    if res['file_data']:
        if param_mode == ParamMode.BULK:
            file_data_len = file_data[2]
            file_data_unpacked = file_data[3:3 + file_data_len]
        else:
            file_data_unpacked = file_data

        file_data_utf8 = file_data_unpacked.decode('utf-8', 'ignore')

        if with_tt:
            tt_perm_status = file_data[0:1].decode('ascii', 'replace')
            tt_cur_status = file_data[1:2].decode('ascii', 'replace')

            if tt_perm_status == 'C' and tt_cur_status == 'C':
                tt_status_api = 'secure'
                tt_status = 'OK (not tampered)'
                tt_color = 'green'
            elif tt_perm_status == 'O' and tt_cur_status == 'C':
                tt_status_api = 'tampered_closed'
                tt_status = 'Tampered! (loop closed)'
                tt_color = 'red'
            elif tt_perm_status == 'O' and tt_cur_status == 'O':
                tt_status_api = 'tampered_open'
                tt_status = 'Tampered! (loop open)'
                tt_color = 'red'
            elif tt_perm_status == 'I' and tt_cur_status == 'I':
                tt_status_api = 'not_initialized'
                tt_status = 'Not initialized'
                tt_color = 'orange'
            elif tt_perm_status == 'N' and tt_cur_status == 'T':
                tt_status_api = 'not_supported'
                tt_status = 'Not supported by the tag'
                tt_color = 'orange'
            else:
                tt_status_api = 'unknown'
                tt_status = 'Unknown'
                tt_color = 'orange'

    if request.args.get("output") == "json" or force_json:
        return jsonify({
            "uid": uid.hex().upper(),
            "file_data": file_data.hex() if file_data else None,
            "read_ctr": read_ctr_num,
            "tt_status": tt_status_api,
            "enc_mode": encryption_mode
        })

    print(picc_data_tag)
    return jsonify({
        "uid": uid.hex().upper(),
        "file_data": file_data.hex() if file_data else None,
        "read_ctr": read_ctr_num,
        "picc_data_tag": binascii.hexlify(picc_data_tag).decode(),
        "enc_mode": encryption_mode
    })
