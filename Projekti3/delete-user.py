# delete user by name 

import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode

def Delete_user(username,public,private):
    connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
    sql = "DELETE FROM `users` WHERE username = '{0}' AND public_key = '{1}' AND private_key = '{2}'".format(username,public,private)
    cursor = connection.cursor()
    cursor.execute(sql)
    connection.commit()
    if cursor.rowcount > 0:
        return True
    else:
        return False


username = raw_input("Enter Username : ")
pub = raw_input("Enter Path of public Key : ")
priv = raw_input("Enter Path of Private Key : ")

public = open(pub,"r").read()
private = open(priv,"r").read()
if Delete_user(username , public , private):
    print ("[+] Deleted Sucessfully if user in Database")
else :
    print ("[-] SomeThing Wrong")















