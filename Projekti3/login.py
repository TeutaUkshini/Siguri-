import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode
import hashlib
import jwt
from time import time


def create_token(username , password , private):

    data = {
        'username':username,
        'password':password,
        'expr': time() + 12000
    }
    token = jwt.encode(data, private, algorithm='RS256').decode('utf-8')
    return token


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


def login(username,password):
    
    try:
        password = hashlib.sha512(password.encode("utf-8")).hexdigest()
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        sql_select_Query = "select * from users where username = '{0}' AND password = '{1}'".format(username,password)
        cursor = connection.cursor()
        cursor.execute(sql_select_Query)
        records = cursor.fetchall()
        if cursor.rowcount > 0:
            return [True,records]
        else:
            return [False]

    except Error as e:
        return [False]


def insert_token(username,password,token):
    try:
        password = hashlib.sha512(password.encode("utf-8")).hexdigest()
        connection = mysql.connector.connect(host='localhost',
                                            database='project',
                                            user='root',
                                            password='')
        check = check_user(username)
        if check:
            sql_update_query = "Update users_token set token = '{2}' where username = '{0}' AND password = '{1}'".format(username,password,token)
            cursor = connection.cursor()
            cursor.execute(sql_update_query)
            connection.commit()
            cursor.close()
            if (connection.is_connected()):
                connection.close()
            return True
        else:
            mySql_insert_query = "insert into users_token VALUES('{0}','{1}','{2}')".format(username,password,token)
            cursor = connection.cursor()
            cursor.execute(mySql_insert_query)
            connection.commit()
            cursor.close()
            if (connection.is_connected()):
                connection.close()
            return True
    except Error as e:
        return [False]

username = raw_input("Enter Username : ")
password = raw_input("Enter Password : ")

res = login(username,password)
if res[0]:
    data = res[1]
    for row in data:
        private = row[3]
    
    token = create_token(username,password,private)
    if(insert_token(username,password,token)):
        print ("[+] Your Token is :",token)

else:
    print ("[-] Invalid Username or password")

