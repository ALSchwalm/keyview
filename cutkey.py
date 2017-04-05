"""CutKey

Usage:
  cutkey info <file>...
  cutkey graph <file>...
  cutkey (-h | --help)
  cutkey --version

Options:
  -h --help     Show this screen.
  --version     Show version.

"""

import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.backends
from cryptography.x509 import *
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec

import traceback
import OpenSSL
from docopt import docopt

def parse_objects_txt_file(path):
    file = open(path, "r")
    mapping = {}

    def expand_short_id(shorthand):
        for oid, short_and_long in mapping.items():
            if short_and_long[0].lower() == shorthand.lower():
                return oid

            #FIXME: hack to avoid implementing Cname and Alias rules
            elif shorthand.startswith("id-"):
                if short_and_long[0].lower() == shorthand[3:].lower():
                    return oid
        return None

    for line in file.readlines():
        if line.startswith("!") or line.startswith("#") or len(line.strip()) == 0:
            continue
        parts = [p.strip() for p in line.split(":")]
        id_short = parts[0]
        id_short_parts = id_short.split(" ")
        try:
            id = ".".join(str(int(p)) for p in id_short_parts)
        except:
            expanded = expand_short_id(id_short_parts[0])
            if expanded is None:
                # This can be caused by alias directives and such, if this becomes
                # a problem, they'll need to be implemented
                continue
            id = ".".join([expanded] + id_short_parts[1:])

        if len(parts) == 2:
            mapping[id] = [parts[1], ""]
        else:
            mapping[id] = [parts[1], parts[2]]
    return mapping

oid_map = parse_objects_txt_file("objects.txt")

def get_oid_name(oid):
    return oid_map[oid][1]

def display_large_number(num, indent="    "):
    hexnum = hex(num)[2:]
    if len(hexnum) % 2 != 0:
        hexnum = "0" + hexnum
    parts = [hexnum[i:i+2] for i in range(0, len(hexnum), 2)]

    for i in range(0, len(parts), 16):
        print(indent + ":".join(parts[i:i+16]))

def display_dsa_private_key(privkey):
    print("DSA Private-Key ({} bit)".format(privkey.key_size))
    priv_nums = privkey.private_numbers()
    pub_nums = priv_nums.public_numbers
    param_nums = pub_nums.parameter_numbers

    print("priv:")
    display_large_number(priv_nums.x)
    print("pub:")
    display_large_number(pub_nums.y)
    print("P:")
    display_large_number(param_nums.p)
    print("Q:")
    display_large_number(param_nums.q)
    print("G:")
    display_large_number(param_nums.g)

def display_rsa_private_key(privkey):
    print("RSA Private-Key ({} bit)".format(privkey.key_size))

    priv_nums = privkey.private_numbers()
    pub_nums = priv_nums.public_numbers

    print("modulus:")
    display_large_number(pub_nums.n)
    print("publicExponent: {} ({})".format(pub_nums.e, hex(pub_nums.e)))
    print("privateExponent:")
    display_large_number(priv_nums.d)
    print("prime1:")
    display_large_number(priv_nums.p)
    print("prime2:")
    display_large_number(priv_nums.q)

def display_private_key(privkey):
    if isinstance(privkey, rsa.RSAPrivateKey):
        display_rsa_private_key(privkey)
    else:
        display_dsa_private_key(privkey)

def display_rsa_public_key(pubkey, indent=""):
    print(indent + "RSA Public-Key ({} bit)".format(pubkey.key_size))

    pub_nums = pubkey.public_numbers()

    print(indent + "Modulus:")
    display_large_number(pub_nums.n, indent=indent+" "*4)
    print(indent + "Exponent: {} ({})".format(pub_nums.e, hex(pub_nums.e)))

def display_ec_public_key(pubkey, indent=""):
    print(indent + "Elliptic Curve Public-Key ({} bit)".format(pubkey.curve.key_size))
    pub_nums = pubkey.public_numbers()

    print(indent + "x:")
    display_large_number(pub_nums.x, indent=indent+" "*4)
    print(indent + "y:")
    display_large_number(pub_nums.y, indent=indent+" "*4)

    print(indent + "ASN1 OID: {}".format(pubkey.curve.name))

def display_dsa_public_key(pubkey, indent=""):
    print(indent + "DSA Public-Key ({} bit)".format(pubkey.key_size))
    pub_nums = pubkey.public_numbers()
    param_nums = pub_nums.parameter_numbers
    print(indent + "pub:")
    display_large_number(pub_nums.y, indent+" "*4)
    print(indent + "P:")
    display_large_number(param_nums.p, indent+" "*4)
    print(indent + "Q:")
    display_large_number(param_nums.q, indent+" "*4)
    print(indent + "G:")
    display_large_number(param_nums.g, indent+" "*4)

def display_public_key(pubkey, indent=""):
    if isinstance(pubkey, rsa.RSAPublicKey):
        display_rsa_public_key(pubkey, indent=indent)
    elif isinstance(pubkey, dsa.DSAPublicKey):
        display_dsa_public_key(pubkey, indent=indent)
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        display_ec_public_key(pubkey, indent=indent)
    else:
        raise ValueError("Unknown public key type")

def rdns_to_string(rdns):
    parts = []
    for attr in rdns:
        parts.append("{}={}".format(get_oid_name(attr.oid.dotted_string),
                                    attr.value))
    return ", ".join(parts)

def extension_description(extension):
    return get_oid_name(extension.oid.dotted_string)

def extended_key_usage_description(usage):
    return get_oid_name(usage.dotted_string)

def format_extension_value(value):
    if isinstance(value, ExtendedKeyUsage):
        return [", ".join(extended_key_usage_description(usage) for usage in value)]

    elif isinstance(value, KeyUsage):
        usages = []
        if value.digital_signature is True:
            usages.append("Digital Signature")
        if value.content_commitment is True:
            usages.append("Non Repudiation")
        if value.key_encipherment is True:
            usages.append("Key Encipherment")
        if value.data_encipherment is True:
            usages.append("Data Encipherment")
        if value.key_agreement is True:
            usages.append("Key Agreement")
            if value.encipher_only is True:
                usages.append("Encipher Only")
            if value.decipher_only is True:
                usages.append("Decipher Only")
        if value.key_cert_sign is True:
            usages.append("Certificate Sign")
        if value.crl_sign is True:
            usages.append("CRL Sign")
        return usages

    elif isinstance(value, SubjectAlternativeName):
        #TODO: Add 'DNS' prefix, etc.
        return [", ".join(name.value for name in value)]

    elif isinstance(value, AuthorityInformationAccess):
        descriptions = []
        for desc in value:
            descriptions.append("{} - {}".format(
                get_oid_name(desc.access_method.dotted_string),
                desc.access_location.value
            ))
        return descriptions
    elif isinstance(value, SubjectKeyIdentifier):
        return [":".join(["{:02X}".format(b) for b in value.digest])]

    elif isinstance(value, BasicConstraints):
        return ["CA:" + str(value.ca).upper()]

    elif isinstance(value, AuthorityKeyIdentifier):
        return ["keyid:" + ":".join("{:02X}".format(b) for b in value.key_identifier)]

    elif isinstance(value, CertificatePolicies):
        policies = []
        for policy in value:
            policies.append("Policy: {}".format(policy.policy_identifier.dotted_string))
        return policies

    elif isinstance(value, CRLDistributionPoints):
        points = []
        for point in value:
            if point.full_name is not None:
                points.append("Full Name:")
                for name in point.full_name:
                    points.append("  " + name.value)
            elif point.relative_name is not None:
                points.append("Relative Name:")
                points.append("  " + rdns_to_string(point.relative_name))
        return points

    raise ValueError("Unknown Value (This is a bug, please report it)")

def display_x509_cert(cert):
    print("X509 Certificate:")
    print("    Data:")
    print("        Version: {} (0x{})".format(cert.version.name.strip("v"), cert.version.value))
    print("        Serial Number:")
    display_large_number(cert.serial_number, indent=" "*12)

    #TODO: determine if there is a way to do this without accessing '_name' directly
    print("    Signature Algorithm: {}".format(cert.signature_algorithm_oid._name))

    print("        Issuer: {}".format(rdns_to_string(cert.issuer)))
    print("        Validity:")
    print("            Not Before: {}".format(cert.not_valid_before.strftime("%b %d %H:%M:%S %Y GMT")))
    print("            Not After : {}".format(cert.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT")))
    print("        Subject: {}".format(rdns_to_string(cert.subject)))
    print("        Subject Public Key Info:")
    display_public_key(cert.public_key(), indent=" "*12)
    print("        X509 Extensions:")

    for extension in cert.extensions:
        crit = " critical" if extension.critical is True else ""
        print(" "*12 + extension_description(extension) + ":" + crit)

        val = format_extension_value(extension.value)
        for row in val:
            print(" "*16 + row)

    print("    Signature:")
    sig_parts = ["{:02X}".format(b) for b in cert.signature]

    for i in range(0, len(sig_parts), 16):
        print(" "*8 + ":".join(sig_parts[i:i+16]))

def openssl_to_cryptography_cert(cert):
    backend = cryptography.hazmat.backends.default_backend()
    buff = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    return load_der_x509_certificate(buff, backend)


# This function was modified from this PR to the pyopenssl project
# https://github.com/pyca/pyopenssl/pull/367/files
def get_pkcs7_certificates(bundle):
    from OpenSSL._util import (
        ffi as _ffi,
        lib as _lib
    )
    from OpenSSL.crypto import X509

    certs = _ffi.NULL
    if bundle.type_is_signed():
        certs = bundle._pkcs7.d.sign.cert
    elif bundle.type_is_signedAndEnveloped():
        certs = bundle._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        pycert._x509 = _ffi.gc(_lib.X509_dup(_lib.sk_X509_value(certs, i)), _lib.X509_free)
        pycerts.append(pycert)
    if not pycerts:
        return tuple()
    return tuple(pycerts)


def display_pkcs7(bundle):
    certs = get_pkcs7_certificates(bundle)
    for cert in certs:
        display_x509_cert(openssl_to_cryptography_cert(cert))

def display_pkcs12(bundle):
    backend = cryptography.hazmat.backends.default_backend()
    ca_certs = bundle.get_ca_certificates()
    if ca_certs is not None:
        for i, ca_cert in enumerate(ca_certs):
            print("#######[ CA Certificate {} ]#######".format(i))
            display_x509_cert(openssl_to_cryptography_cert(ca_cert))

    cert = bundle.get_certificate()
    if cert is not None:
        print("#######[ Certificate ]#######")
        display_x509_cert(openssl_to_cryptography_cert(cert))

    pkey = bundle.get_privatekey()
    if pkey is not None:
        print("#######[ Private Key ]#######")
        pkey = pkey.to_cryptography_key()
        display_private_key(pkey)

def display_item_info(item, print_filename=False):
    if print_filename is True:
        print("#######[ {} ]#######".format(filename))

    if (isinstance(item, rsa.RSAPrivateKey) or
        isinstance(item, dsa.DSAPrivateKey) or
        isinstance(item, ec.EllipticCurvePrivateKey)):
        display_private_key(item)

    elif (isinstance(item, rsa.RSAPublicKey) or
          isinstance(item, dsa.DSAPublicKey) or
          isinstance(item, ec.EllipticCurvePublicKey)):
        display_public_key(item)

    elif isinstance(item, OpenSSL.crypto.PKCS12):
        display_pkcs12(item)

    elif isinstance(item, OpenSSL.crypto.PKCS7):
        display_pkcs7(item)

def load_file(filename):
    backend = cryptography.hazmat.backends.default_backend()
    buffer = open(filename, "rb").read()

    # PKCS#1/PKCS#8 private in DER
    try:
        return cryptography.hazmat.primitives.serialization.load_der_private_key(buffer, password=None, backend=backend)
    except:
        pass

    # PKCS#1/PKCS#8 private in PEM
    try:
        return cryptography.hazmat.primitives.serialization.load_pem_private_key(buffer, password=None, backend=backend)
    except:
        pass

    # PKCS#1/PKCS#8 public in DER
    try:
        return cryptography.hazmat.primitives.serialization.load_der_public_key(buffer, backend)
    except:
        pass

    # PKCS#1/PKCS#8 public in PEM
    try:
        return cryptography.hazmat.primitives.serialization.load_pem_public_key(buffer, backend)
    except:
        pass

    # X509 certificate in PEM
    try:
        return load_pem_x509_certificate(buffer, backend)
    except:
        pass

    # X509 certificate in DER
    try:
        return load_der_x509_certificate(buffer, backend)
    except:
        pass

    # PKCS7 certificate bundle in PEM
    try:
        return OpenSSL.crypto.load_pkcs7_data(OpenSSL.crypto.FILETYPE_PEM, buffer)
    except:
        pass

    # PKCS7 certificate bundle in DER
    try:
        return OpenSSL.crypto.load_pkcs7_data(OpenSSL.crypto.FILETYPE_ASN1, buffer)
    except:
        pass

    # PKCS12 bundle (binary)
    try:
        return OpenSSL.crypto.load_pkcs12(buffer)
    except:
        pass

    raise Exception("Unknown file type: {}".format(filename))


def display_info(args):
    for file in args["<file>"]:
        item = load_file(file)
        display_item_info(item, print_filename=len(args["<file>"]) > 1)

def find_cert_chains(item_mapping):
    certs = set([])
    for items in item_mapping.values():
        for item in items:
            if isinstance(item, Certificate):
                certs.add(item)

    def is_root(cert, certs):
        ''' A root is either self-signed or has no issuer in the given set
        '''
        if cert.issuer == cert.subject:
            return True
        for other in certs:
            if other.subject == cert.issuer:
                return False
        return True

    def get_children(parent, certs):
        children = {}
        for cert in certs:
            if cert.issuer == parent.subject:
                children[cert] = get_children(cert, certs)
        return children

    children = set([c for c in certs if not is_root(c, certs)])
    roots = {
        cert : get_children(cert, children) for cert in certs if is_root(cert, certs)
    }

    return roots

def display_graph(args):
    item_mapping = {}
    for file in args["<file>"]:
        item = load_file(file)
        item_mapping[file] = []

        if isinstance(item, OpenSSL.crypto.PKCS12):
            ca_certs = item.get_ca_certificates()
            if ca_certs is not None:
                for i, ca_cert in enumerate(ca_certs):
                    item_mapping[file].append(openssl_to_cryptography_cert(ca_cert))

            cert = item.get_certificate()
            if cert is not None:
                item_mapping[file].append(openssl_to_cryptography_cert(cert))

            pkey = item.get_privatekey()
            if pkey is not None:
                item_mapping[file].append(pkey.to_cryptography_key())
        elif isinstance(item, OpenSSL.crypto.PKCS7):
            for cert in get_pkcs7_certificates(item):
                item_mapping[file].append(openssl_to_cryptography_cert(cert))
        else:
            item_mapping[file] = [item]

    chains = find_cert_chains(item_mapping)
    from pprint import pprint
    pprint(chains)


def main():
    arguments = docopt(__doc__, version='CutKey')

    if arguments["info"] is True:
        display_info(arguments)
    elif arguments["graph"] is True:
        display_graph(arguments)

if __name__ == '__main__':
    main()
