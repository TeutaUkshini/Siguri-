
import base64
import hashlib

import mysql.connector
from Crypto import Random
from Crypto.Cipher import DES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from mysql.connector import Error


def sign_with_rsa(message , private_key):
    with open(private_key) as f:
        privkey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    message = hashlib.sha256(message).hexdigest()

    sig = privkey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

    return base64.b64encode(sig)


def encrypt_with_rsa(message,public_key):
    with open(public_key, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )


    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

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

def pad_msg(msg):
    while len(msg) % 8 != 0:
        msg += "X"
    return msg


def DES_encrypt(msg,key,iv):
    block_size = DES.block_size 
    c = DES.new(key,DES.MODE_CBC,iv)
    encrypt_msg = c.encrypt(msg.encode('ascii'))
    return encrypt_msg

def DES_decrypt(cipher,key,iv):
    block_size = DES.block_size
    d = DES.new(key,DES.MODE_CBC,iv)
    return d.decrypt(cipher).decode('ascii')

def sign_token(token):
    try:
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

    except Error as e:
        return [False]

def get_public_key_of_sender(name):
    try:
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        sql_select_Query = "select public_key from users where username = '{0}'".format(name)
        cursor = connection.cursor()
        cursor.execute(sql_select_Query)
        records = cursor.fetchall()
        if cursor.rowcount > 0:
            return [True,records]
        else:
            return [False]

    except Error as e:
        return [False]

def check_user(username):
    
    try:
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        sql_select_Query = "select * from users_token where username = '{0}'".format(username)
        cursor = connection.cursor()
        cursor.execute(sql_select_Query)
        records = cursor.fetchall()
        if cursor.rowcount > 0:
            return True
        else:
            return False
    except Error as e:
        return False


def insert_msg_into_db(sender,msg,receiver,public_key):
    try:
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')

        mySql_insert_query = "INSERT INTO `messages`(`sender_username`, `message`, `receiver_username`, `sender_public_key`) VALUES ('{0}','{1}','{2}','{3}')".format(sender,msg,receiver,public_key)
        cursor = connection.cursor()
        cursor.execute(mySql_insert_query)
        connection.commit()
        cursor.close()
        if (connection.is_connected()):
            connection.close()
        return True
    except Error as e:
        return [False]



token = raw_input("Token : ")
data = sign_token(token)[1]
for row in data:
    sender_username = row[0]
    sender_public_key = row[1]
    sender_private_key = row[2]


f = open("temp_public_key.pem","w")
f.write(sender_public_key)
f.close()

receiver_name = raw_input("Enter Receiver name : ")
if not check_user(receiver_name):
    print ("[-] Receiver username is Not Found")
    exit(0)
message = raw_input("Enter Your Message : ")
message = pad_msg(message)

data  = get_public_key_of_sender(receiver_name)[1]
for row in data :
    receiver_public_key = row[0]

f = open("temp_recevier_public_key.pem","w")
f.write(receiver_public_key)
f.close()

f = open("temp_sender_private_key.pem","w")
f.write(sender_private_key)
f.close()

key = Random.new().read(8)
iv = Random.new().read(8)
msg_enc_with_des = DES_encrypt(message,key,iv)

cipher = receiver_name.encode("base64")
cipher = cipher + "." + iv.encode("base64") 
cipher = cipher + "." + base64.b64encode(encrypt_with_rsa(key,"temp_recevier_public_key.pem"))
cipher = cipher + "." + base64.b64encode(msg_enc_with_des)
cipher = cipher + "." + base64.b64encode(sender_username)
cipher = cipher + "." + base64.b64encode(sign_with_rsa(msg_enc_with_des,"temp_sender_private_key.pem"))

if(insert_msg_into_db(sender_username,cipher,receiver_name,sender_public_key)):
    print ("[+] Message Send Successfully")
else:
    print ("[-] Something Error")

