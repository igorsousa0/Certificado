import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.base import Certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime


# Generate our key
def generate_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Write our key to disk for safe keeping
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    return key

def generate_certificate(key,list):
    con = sqlite3.connect('certificate.db')
    cur = con.cursor()
    subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, list['COUNTRY_NAME']),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, list['STATE_OR_PROVINCE_NAME']),
    x509.NameAttribute(NameOID.LOCALITY_NAME, list['LOCALITY_NAME']),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, list['ORGANIZATION_NAME']),
    x509.NameAttribute(NameOID.COMMON_NAME, list['COMMON_NAME']),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=500)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())
    # Write our certificate out to disk.
    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))  
    cur.execute("INSERT INTO certificate(serial_number,COUNTRY_NAME,STATE,LOCALITY_NAME,ORGANIZATION_NAME,COMMON_NAME) VALUES ('%s','%s','%s','%s','%s','%s' )" % (cert.serial_number,list['COUNTRY_NAME'],list['STATE_OR_PROVINCE_NAME'],list['LOCALITY_NAME'],list['ORGANIZATION_NAME'],list['COMMON_NAME']))

    get_certificate(cur)
    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.

def get_certificate(cur):
    for row in cur.execute('SELECT id,serial_number FROM certificate'):
        print(row)  

if __name__ == '__main__':
    list = {} 
    list['COUNTRY_NAME'] = input('COUNTRY_NAME: ')
    list['STATE_OR_PROVINCE_NAME'] = input('STATE_OR_PROVINCE_NAME: ')
    list['LOCALITY_NAME'] = input('LOCALITY_NAME: ')
    list['ORGANIZATION_NAME'] = input('ORGANIZATION_NAME: ')
    list['COMMON_NAME'] = input('COMMON_NAME: ')
    private_key = generate_key()
    certificate = generate_certificate(private_key,list)
    

    