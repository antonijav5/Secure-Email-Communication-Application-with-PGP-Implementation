import datetime
import tkinter.filedialog

import keys_gen
from Crypto.Cipher import CAST
from Crypto.Hash import SHA1
from Crypto.IO import PEM
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA


def export_key(key_id: int, type: str, passphrase: str, directory: str):
    key_id = str(key_id)
    message = "Export failed"
    if (type == "private"):
        username = keys_gen.dict_key_id[key_id]

        ring_element = keys_gen.dict_public_key_ring[(username, key_id)]
        public_key = ring_element[0]
        mail = ring_element[1]
        algorithm = ring_element[2]
        time = ring_element[3]
        key_pair = ring_element[4]

        if algorithm == "ElGamal/DSA":
            export = str(key_pair.x) + "\n" + public_key + "\n" + str(key_pair.g) + "\n" + str(key_pair.p) + "\n" + str(
                key_pair.q) + "\n" + username + "\n" + mail + "\n" + algorithm + "\n" + time

            export = export.encode('utf-8')

            export = PEM.encode(export, "DSA PRIVATE", passphrase.encode('utf-8')).encode('utf-8')

            filename = directory + "/" + username + "-" + key_id + ".pem"

            file = open(filename, "wb")
            file.write(export)
            file.close()

            message = "Key exported successfully as:\n" + filename
        else:
            export = str(key_pair.d) + "\n" + str(key_pair.e) + "\n" + str(key_pair.n) + "\n" + str(
                key_pair.p) + "\n" + str(key_pair.q) + "\n" + username + "\n" + mail + "\n" + algorithm + "\n" + time

            export = export.encode('utf-8')

            export = PEM.encode(export, "RSA PRIVATE", passphrase.encode('utf-8')).encode('utf-8')

            filename = directory + "/" + username + "-" + key_id + ".pem"

            file = open(filename, "wb")
            file.write(export)
            file.close()

            message = "Key exported successfully as:\n" + filename
    else:
        username = keys_gen.dict_key_id[key_id]

        ring_element = keys_gen.dict_public_key_ring[(username, key_id)]
        public_key = ring_element[0]
        mail = ring_element[1]
        algorithm = ring_element[2]
        time = ring_element[3]
        key_pair = ring_element[4]

        if algorithm == "ElGamal/DSA":
            export = "-" + "\n" + public_key + "\n" + str(key_pair.g) + "\n" + str(key_pair.p) + "\n" + str(
                key_pair.q) + "\n" + username + "\n" + mail + "\n" + algorithm + "\n" + time

            export = export.encode('utf-8')

            export = PEM.encode(export, "DSA PUBLIC").encode('utf-8')

            filename = directory + "/" + username + "-" + key_id + ".pem"

            file = open(filename, "wb")
            file.write(export)
            file.close()

            message = "Key exported successfully as:\n" + filename
        else:
            export = "-" + "\n" + str(key_pair.e) + "\n" + str(key_pair.n) + "\n" + str(
                key_pair.p) + "\n" + str(key_pair.q) + "\n" + username + "\n" + mail + "\n" + algorithm + "\n" + time

            export = export.encode('utf-8')

            export = PEM.encode(export, "RSA PUBLIC").encode('utf-8')

            filename = directory + "/" + username + "-" + key_id + ".pem"

            file = open(filename, "wb")
            file.write(export)
            file.close()
            message = "Key exported successfully as:\n" + filename

    return message


def import_key(import_key: str, type: str, password: str):
    message = "Import failed"
    public_key_id = ""
    if type == "private":
        import_key = PEM.decode(import_key, password.encode('utf-8'))

        password_hash = SHA1.new(password.encode('utf-8')).hexdigest()
        cast_key = password_hash[23:39]
        cast_key = cast_key.encode('utf-8')
        cast_cipher = CAST.new(cast_key, CAST.MODE_OPENPGP)
        if import_key[1] == "DSA PRIVATE":
            import_key = import_key[0].decode('utf-8').split('\n')
            x = import_key[0]
            y = import_key[1]
            g = import_key[2]
            p = import_key[3]
            q = import_key[4]
            username = import_key[5]
            mail = import_key[6]
            algorithm = import_key[7]
            time = import_key[8]

            public_key_id = str(int(y) & 0xFFFFFFFFFFFFFFFF)

            key_pair = DSA.construct((int(y), int(g), int(p), int(q), int(x)), True)

            private_key = x.encode('utf-8')
            private_key = cast_cipher.encrypt(private_key)
            private_key = private_key.hex()

            keys_gen.dict_public_key_ring[(username, public_key_id)] = [y, mail, algorithm, time, key_pair]
            keys_gen.dict_private_key_ring[(username, public_key_id)] = [y, private_key, algorithm, time]
            keys_gen.dict_key_id[public_key_id] = username
            keys_gen.dict_username[username] = public_key_id

            message = "DSA Private key imported successfully\nKey ID: " + public_key_id
        else:
            import_key = import_key[0].decode('utf-8').split('\n')
            d = import_key[0]
            e = import_key[1]
            n = import_key[2]
            p = import_key[3]
            q = import_key[4]
            username = import_key[5]
            mail = import_key[6]
            algorithm = import_key[7]
            time = import_key[8]

            public_key_id = str(int(n) & ((1 << 64) - 1))

            key_pair = RSA.construct((int(n), int(e), int(d), int(p), int(q)), True)
            private_key = d.encode('utf-8')
            private_key = cast_cipher.encrypt(private_key)
            private_key = private_key.hex()
            #added
            public_key_new = str(n) + "," + str(e)

            keys_gen.dict_public_key_ring[(username, public_key_id)] = [public_key_new, mail, algorithm, time, key_pair]
            keys_gen.dict_private_key_ring[(username, public_key_id)] = [public_key_new, private_key, algorithm, time]
            keys_gen.dict_key_id[public_key_id] = username
            keys_gen.dict_username[username] = public_key_id

            message = "RSA Private key imported successfully\nKey ID: " + public_key_id
    else:
        import_key = PEM.decode(import_key)
        if import_key[1] == "DSA PUBLIC":
            import_key = import_key[0].decode('utf-8').split('\n')
            y = import_key[1]
            g = import_key[2]
            p = import_key[3]
            q = import_key[4]
            username = import_key[5]
            mail = import_key[6]
            algorithm = import_key[7]
            time = import_key[8]

            public_key_id = str(int(y) & 0xFFFFFFFFFFFFFFFF)

            key_pair = DSA.construct((int(y), int(g), int(p), int(q)), True)

            keys_gen.dict_public_key_ring[(username, public_key_id)] = [y, mail, algorithm, time, key_pair]
            keys_gen.dict_key_id[public_key_id] = username
            keys_gen.dict_username[username] = public_key_id

            message = "DSA Public key imported successfully\nKey ID: " + public_key_id
        else:
            import_key = import_key[0].decode('utf-8').split('\n')
            e = import_key[1]
            n = import_key[2]
            p = import_key[3]
            q = import_key[4]
            username = import_key[5]
            mail = import_key[6]
            algorithm = import_key[7]
            time = import_key[8]

            public_key_id = str(int(n) & ((1 << 64) - 1))

            key_pair = RSA.construct((int(n), int(e)), True)

            #added
            public_key_new = str(n) + "," + str(e)
            keys_gen.dict_public_key_ring[(username, public_key_id)] = [public_key_new, mail, algorithm, time, key_pair]
            keys_gen.dict_key_id[public_key_id] = username
            keys_gen.dict_username[username] = public_key_id
            message = "RSA Public key imported successfully\nKey ID: " + public_key_id
    return message

def check_password(key_id: int, passphrase: str):
    key_id = str(key_id)
    username = keys_gen.dict_key_id[key_id]
    private_key = keys_gen.dict_private_key_ring[(username, key_id)][1]
    pk = bytes.fromhex(private_key)
    eiv = pk[:CAST.block_size + 2]
    ciphertext = pk[CAST.block_size + 2:]
    password_hash = SHA1.new(passphrase.encode('utf-8')).hexdigest()
    cast_key = password_hash[23:39]
    cast_key = cast_key.encode('utf-8')
    cast_cipher = CAST.new(cast_key, CAST.MODE_OPENPGP, eiv)
    try:
        decrypted_private_key = cast_cipher.decrypt(ciphertext).decode('utf-8')
        return ""
    except:
        return "Wrong password"


