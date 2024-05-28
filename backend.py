from flask import Flask, request, jsonify, send_from_directory
from libsdm.picc_decrypter import (
    _internal_sdm
)
# from libsdm.picc_encrypter import encrypt_sun_message
from werkzeug.exceptions import BadRequest

import binascii
from libsdm.sdm import EncMode

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

app = Flask(__name__)


@app.route('/')
def home():
    return send_from_directory(".", "index.html")


@app.route('/decrypt', methods=['POST'])
def decrypt():
    # Assuming the form sends the necessary parameters in JSON format
    data = request.json

    # Extracting data from the JSON
    param_mode = EncMode.AES
    enc_picc_data = data["enc_picc_data"]
    enc_file_data = data["enc_file_data"]
    sdmmac = data["cmac"]

    if not enc_picc_data:
        raise BadRequest(f"picc data is required")

    if not sdmmac:
        raise BadRequest(f"cmac data is required")

    try:
        enc_file_data_b = None
        enc_picc_data_b = binascii.unhexlify(enc_picc_data)
        sdmmac_b = binascii.unhexlify(sdmmac)
        if enc_file_data:
            enc_file_data_b = binascii.unhexlify(enc_file_data)
    except binascii.Error:
        raise BadRequest("Failed to decode parameters.") from None

    # Similarly, extract other parameters

    try:
        decrypted_data = _internal_sdm(
            param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b, with_tt=False)
        return decrypted_data
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route("/encrypt", methods=['POST'])
def encrypt():
    data = request.json

    # Extracting data from it
    uid = data['uid']
    picc_data_tag = data['picc_data_tag']
    counter_value = data['counter_value']
    file_data = data['file_data']
    cmac = data['cmac']
    output = encrypt_sun_message(
        picc_data_tag=picc_data_tag,
        uid=uid,
        read_ctr=counter_value,
        file_data=file_data,
        sdm_meta_read_key=derive_undiversified_key(
            MASTER_KEY, 1),
        sdm_file_read_key=lambda uid: derive_tag_key(
            MASTER_KEY, uid, 2),

    )
    print(output)


if __name__ == '__main__':
    app.run(debug=True)
