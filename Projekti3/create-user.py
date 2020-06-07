import mysql.connector
import hashlib
import base64
from mysql.connector import Error
from mysql.connector import errorcode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend



def verifiy_sign_rsa(public_key , message , sign):

    with open(pubkeyfile) as f:
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
    except InvalidSignature:
        return False

def generate_RSA(bits=2048):
    from Crypto.PublicKey import RSA 
    new_key = RSA.generate(bits, e=65537) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    return [private_key, public_key]


def check_user(username):
    
    try:
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        sql_select_Query = "select * from users where username = '{0}'".format(username)
        cursor = connection.cursor()
        cursor.execute(sql_select_Query)
        records = cursor.fetchall()
        if cursor.rowcount > 0:
            return True
        else:
            return False
        
        """
        for row in records:
            print("Id = ", row[0], )
            print("Name = ", row[1])
            print("Price  = ", row[2])
            print("Purchase date  = ", row[3], "\n")
        """

    except Error as e:
        return False


def Create_User(username , password , public , private):
    try:
        password = hashlib.sha512(password.encode("utf-8")).hexdigest() 
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        
        mySql_insert_query = """INSERT INTO users VALUES ("{0}", "{1}", "{2}", "{3}") """.format(username,password,public,private)

        cursor = connection.cursor()
        cursor.execute(mySql_insert_query)
        connection.commit()
        cursor.close()
        if (connection.is_connected()):
            connection.close()
        return True

    except mysql.connector.Error as error:
        return False


username = raw_input("Enter Username : ")
password = raw_input("Enter Password : ")
password2 = raw_input("Re-Type Password : ")

while password != password2:
    password = raw_input("Enter Password : ")
    password2 = raw_input("Re-Type Password : ")

RSA_Keys = generate_RSA(4096)
private = RSA_Keys[0]
public = RSA_Keys[1]

if not check_user(username):
    if Create_User(username,password,public,private):
        print ("[+] Successfully Regstired")
        print ("Username :",username)
        print ("Password :",password)
        f_public = open(username+"_public.pem","w")
        f_private = open(username+"_private.pem","w")
        f_public.write(public)
        f_private.write(private)
        f_public.close()
        f_private.close()
        print ("Public Key :",username+"_public.pem")
        print ("Private Key :",username+"_private.pem")
    else:
        print ("Something error")

else :
    print ("[-] Sorry , User Registerd Before")


verifiy_sign_rsa()