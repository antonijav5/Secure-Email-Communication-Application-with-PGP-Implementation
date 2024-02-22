import datetime
import tkinter.filedialog

from Crypto.PublicKey import DSA
from Crypto.Cipher import CAST
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.IO import PEM

import keys_io

dict_public_key_ring = {}
dict_private_key_ring = {}
dict_username = {}
dict_key_id = {}


def create_key_pair(username: str, mail: str, algorithm: int, size: int, password: str):
    password_hash = SHA1.new(password.encode('utf-8')).hexdigest()
    cast_key = password_hash[23:39]
    cast_key = cast_key.encode('utf-8')
    cast_cipher = CAST.new(cast_key, CAST.MODE_OPENPGP)

    time = datetime.datetime.now()
    time = time.strftime("%x %X")

    public_key_id = None

    if algorithm == 1:
        # RSA PART
        key = RSA.generate(size)
        modulus = key.n

        # Extract the last 64 bits (8 bytes) from the modulus
        public_key_id = str(modulus & ((1 << 64) - 1))
        algorithm = "RSA"
        privkey = str(key.d).encode('utf-8')

        privkey = cast_cipher.encrypt(privkey)
        privkey = privkey.hex()

        pubkey = str(key.n) + "," + str(key.e)

        dict_username[username] = public_key_id
        dict_key_id[public_key_id] = username
        dict_public_key_ring[(username, public_key_id)] = [pubkey, mail, algorithm, time, key]
        dict_private_key_ring[(username, public_key_id)] = [pubkey, privkey, algorithm, time]

        message = "RSA key pair created successfully\nKey ID: " + public_key_id
    else:
        key_pair = DSA.generate(size)
        public_key = key_pair.y
        private_key = str(key_pair.x).encode('utf-8')
        private_key = cast_cipher.encrypt(private_key)
        private_key = private_key.hex()

        public_key_id = public_key & 0xFFFFFFFFFFFFFFFF
        public_key_id = str(public_key_id)
        algorithm = "ElGamal/DSA"

        public_key = str(public_key)

        dict_username[username] = public_key_id
        dict_key_id[public_key_id] = username
        dict_public_key_ring[(username, public_key_id)] = [public_key, mail, algorithm, time, key_pair]
        dict_private_key_ring[(username, public_key_id)] = [public_key, private_key, algorithm, time]
        message = "ElGamal/DSA key pair created successfully\nKey ID: " + public_key_id

    return message


def create_random_keys():
    """
    for i in range(4):
         mail = "popara0" + str(i) + "@gmail.com"
         create_key_pair("djordje", mail, i % 2 + 1, 1024, "123")

    for i in range(4):
         mail = "vasiljevic0" + str(i) + "@gmail.com"
         create_key_pair("ant", mail, i % 2 + 1, 1024, "123")
    """
    for i in range(8):
        f = open("./KeyBox/key" + str(i + 1) + ".pem")
        l = f.read()
        keys_io.import_key(l, "private", "123")
        f.close()


def delete_key_pair(public_key_id: str):
    username = dict_key_id[public_key_id]
    dict_key_id.pop(public_key_id)
    dict_public_key_ring.pop((username, public_key_id))
    dict_private_key_ring.pop((username, public_key_id))
