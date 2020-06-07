
import hashlib
import jwt
import base64
import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode
from time import time
from Crypto.Cipher import DES
from Crypto import Random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def verifiy_sign_rsa(public_key , message , sign):

    with open(public_key) as f:
        pubkey = serialization.load_pem_public_key(
            f.read(), backend=default_backend())

    prehashed_msg = hashlib.sha256(message).hexdigest()
    decoded_sig = base64.b64decode(sign)


    try:
        pubkey.verify(
            decoded_sig,
            prehashed_msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
        sys.exit(0)
    except:
        return False

def sign_token(token):
    connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
    sql_select_Query = "select u.username,u.public_key,u.private_key from users_token as ut , users as u where u.username = ut.username AND token = '{0}'".format(token)
    cursor = connection.cursor()
    cursor.execute(sql_select_Query)
    records = cursor.fetchall()
    if cursor.rowcount > 0:
        return [True,records]
    else:
        return [False]

def get_all_messages(username):
    try:
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        sql_select_Query = "select * from messages Where receiver_username = '{0}'".format(username)
        cursor = connection.cursor()
        cursor.execute(sql_select_Query)
        records = cursor.fetchall()
        if cursor.rowcount > 0:
            return [True,records]
        else:
            return [False]

    except Error as e:
        return [False]



def DES_decrypt(cipher,key,iv):
    block_size = DES.block_size
    d = DES.new(key,DES.MODE_CBC,iv)
    return d.decrypt(cipher).decode('ascii')

def decrypt_with_rsa(encrypted,private_key):
    with open(private_key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message



token = raw_input("Token : ")

res = sign_token(token)
check = res[0]
if not check:
    print ("[-] Invalid Token")
    exit(0)

data = res[1]
for row in data:
    username = row[0]
    public_key = row[1]
    private_key = row[2]

data = get_all_messages(username)[1]
for row in data:
    sender = row[0]
    msg = row[1]
    Receiver = row[2]
    sender_public_key = row[3]
    

    

    msg = msg.split(".")
    sign = msg[5].decode("base64")
    msg_enc_with_des = msg[3].decode("base64")

    f = open("temp_sender_public_key.pem","w")
    f.write(sender_public_key)
    f.close()

    if not verifiy_sign_rsa("temp_sender_public_key.pem" , msg_enc_with_des , sign):
        print ("[-] Sign is Invalid")
        exit(0)
    
    sender = base64.b64decode(msg[4])

    iv = msg[1].decode("base64")

    key_enc_with_rsa = msg[2].decode("base64")

    f = open("temp_private_key.pem","w")
    f.write(private_key)
    f.close()

    key = decrypt_with_rsa(key_enc_with_rsa,"temp_private_key.pem")
    msg_enc_with_des = msg[3].decode("base64")
    msg = DES_decrypt(msg_enc_with_des,key,iv)
    print ("Receiver :",Receiver)
    print ("Sender : ",sender)
    print ("Message : ",msg)
    print ("[+] Valid Sign")
    print ("=======================================================")

