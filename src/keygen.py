import sys
from Crypto.PublicKey import RSA


def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))


def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)


def save_keypair(keypair, privkeyfile):
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM'))


def load_keypair(privkeyfile):
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)


if __name__ == "__main__":
    pubkeyfile = "server_pubkey"
    privkeyfile = "privkey"
    print('Generating a new 2048-bit RSA key pair...')
    keypair = RSA.generate(2048)
    save_publickey(keypair.public_key(), pubkeyfile)
    # Save the entire key pair in privkeyfile
    save_keypair(keypair, privkeyfile)
    print('Done.')
