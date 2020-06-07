import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode
import hashlib
import jwt
from time import time
from datetime import datetime
def sign_token(token):
    try:
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        sql_select_Query = "select * from users_token where token = '{0}'".format(token)
        cursor = connection.cursor()
        cursor.execute(sql_select_Query)
        records = cursor.fetchall()
        if cursor.rowcount > 0:
            return [True,records]
        else:
            return [False]

    except Error as e:
        return [False]

def get_public_key_from_db(username,password):
    try:
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        sql_select_Query = "select * from users where username = '{0}' AND password = '{1}'".format(username,password)
        cursor = connection.cursor()
        cursor.execute(sql_select_Query)
        records = cursor.fetchall()
        if cursor.rowcount > 0:
            for row in records:
                return [True,row[2]]
        else:
            return [False]

    except Error as e:
        return [False]

token = raw_input("Token : ")
res = sign_token(token)
if res[0]:
    data = res[1]
    for row in data:
        username = row[0]
        password = row[1]
        sign = row[2] # token
        public = get_public_key_from_db(username,password)
        if public[0]:
            sign_data = jwt.decode(sign, public[1], algorithm='RS256')
            expr = sign_data['expr']
            if(expr > time()):
                print ("[+] user :",username)
                print ("[+] Token is Valid")
                datatime = datetime.fromtimestamp(expr)
                print ("[+] expire in :",datatime)
            else:
                print ("[-] Token is Expired")
                
        else:
            print ("[-] Something Error")
else:
    print ("[-] InValid Token")