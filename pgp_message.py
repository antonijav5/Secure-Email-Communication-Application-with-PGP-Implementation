import base64
import datetime

import elgamal.elgamal
from elgamal.elgamal import Elgamal

import keys_gen
from Crypto.Cipher import CAST
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Signature import DSS
from Crypto import Random
import zlib
from Crypto.Util.Padding import pad, unpad
import pgp_message

want = 0
toenc = 0
sess = 0


def send_message(message: str, enc_key_id: int, aut_key_id: int, algorithm: int, com: str, rad: str):
    addition = 0x0
    time = datetime.datetime.now()
    timestamp = str(time.timestamp()).split(".")
    timestamp = timestamp[0]
    time = time.strftime("%x %X")

    filename = "msg_" + timestamp + ".txt"

    message = message + "#*-*#" + timestamp + "#*-*#" + filename

    # Authentication
    if aut_key_id != 0:
        addition = addition | 0x1
        aut_key_id = str(aut_key_id)
        username = keys_gen.dict_key_id[aut_key_id]
        private_key = keys_gen.dict_private_key_ring.get((username, aut_key_id))[1]
        private_key = private_key.encode('utf-8')
        key = keys_gen.dict_public_key_ring.get((username, aut_key_id))[4]

        aut_algorithm_type = keys_gen.dict_public_key_ring.get((username, aut_key_id))[2]

        hash_sha1 = SHA1.new(message.encode('utf-8'))
        hash_message = hash_sha1.hexdigest()
        hash_digest = hash_message[0:4]

        if aut_algorithm_type == "RSA":
            encrypted_hash_message = PKCS1_PSS.new(key).sign(hash_sha1)
            aut_algorithm_id = "1"
        else:
            encrypted_hash_message = DSS.new(key, 'fips-186-3').sign(hash_sha1)
            aut_algorithm_id = "2"
        signature_time = datetime.datetime.now()
        signature_time = signature_time.strftime("%x %X")
        message = (message + "#*-*#" + encrypted_hash_message.hex() + "#*-*#" + hash_digest
                   + "#*-*#" + str(aut_key_id) + "#*-*#" + aut_algorithm_id + "#*-*#" + signature_time)

    if com != "off":
        addition = addition | 0x2
        message = zlib.compress(message.encode('utf-8'))
        message = message.hex()

    if enc_key_id != 0:
        addition = addition | 0x4
        enc_key_id = str(enc_key_id)
        username = keys_gen.dict_key_id[enc_key_id]
        public_key = keys_gen.dict_public_key_ring.get((username, enc_key_id))[4]
        public_key_algorithm = keys_gen.dict_public_key_ring.get((username, enc_key_id))[2]

        # AES
        if algorithm == 1:
            session_key = Random.get_random_bytes(16)

            cipher_aes = AES.new(session_key, AES.MODE_OPENPGP)
            message = cipher_aes.encrypt(message.encode('utf-8'))

            message = message.hex()
        # CAST
        else:
            session_key = Random.get_random_bytes(16)
            cipher_cast = CAST.new(session_key, CAST.MODE_OPENPGP)
            message = cipher_cast.encrypt(message.encode('utf-8'))

            message = message.hex()
        # Encrypt session key
        session_key = session_key.hex() + "#*-*#" + str(algorithm)
        if public_key_algorithm == "RSA":
            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted_session_key = cipher_rsa.encrypt(session_key.encode('utf-8')).hex()
        else:
            y = public_key.y
            g = public_key.g
            p = public_key.p
            elg_public_key = elgamal.elgamal.PublicKey(p, g, y)
            encrypted_session_key = Elgamal.encrypt(session_key.encode('utf-8'), elg_public_key)

        message = message + "#*-*#" + str(encrypted_session_key) + "#*-*#" + str(enc_key_id)
    if rad != "off":
        addition = addition | 0x8
        message = base64.b64encode(message.encode('utf-8')).hex()

    addition = str(bin(addition)[2:].zfill(4))
    message = message + "&" + addition
    return message, filename
