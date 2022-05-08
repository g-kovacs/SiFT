import sys
from Crypto.PublicKey import RSA
import getopt


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
    pubkeyfile = None
    privkeyfile = None
    key_len = 2048
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hl:', ['help', "length="])
    except getopt.GetoptError:
        print('Error: Unknown option detected.')
        print('Type "rsa_keygen.py -h" for help.')
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print("Generate RSA key pair.")
            print('Usage:')
            print('  rsa_keygen.py [-l <n>] <pubkeyfile> <privkeyfile>')
            print('  rsa_keygen.py [--length <n>] <pubkeyfile> <privkeyfile>')
            print('Default length is 2048 bits.')
            print(
                '  <pubkeyfile> will contain the public RSA key, <privkeyfile> will contain the keypair.')
            sys.exit(0)
        if opt in ('-l', '--length'):
            key_len = arg

    if len(args) < 2:
        print('Error: Key file names are missing.')
        print('Type "rsa_keygen.py -h" for help.')
        sys.exit(1)
    else:
        pubkeyfile = args[0]
        privkeyfile = args[1]

    print('Generating a new 2048-bit RSA key pair...')
    keypair = RSA.generate(2048)
    save_publickey(keypair.public_key(), pubkeyfile)
    # Save the entire key pair in privkeyfile
    save_keypair(keypair, privkeyfile)
    print('Done.')
