###########
# IMPORTS #
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import random
#---------#
###############################
# GENERATE RANDOM EMPLOYEE ID #
def randomEmployeeID():
    return random.randint(10000, 99999)
#################
# INITIALISE DB #
def startDatabase():
    conn = sqlite3.connect('database.sqlite3')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS employee (employeeID TEXT PRIMARY KEY, rsa_key BLOB)''')
    conn.commit()
    conn.close()
#############################
# INSERT KEY IN DB FUNCTION #
def insertKey_PUB(employeeID, rsa_key):
    conn = sqlite3.connect('database.sqlite3')
    c = conn.cursor()
    c.execute("INSERT INTO employee (employeeID, rsa_key) VALUES (?, ?)", (employeeID, rsa_key))
    conn.commit()
    conn.close()
##############################
# GENERATE KEY PAIR FUNCTION #
def generateKey(keyNumers):
    keys = []
    for _ in range(keyNumers):
        # PRIVATE KEY, PUBLIC EXPONENT AND SIZE OF KEY IN BITS
        key_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
        # PRIVATE KEY SERIAL
        pem_PRIV = key_PRIV.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        # PUBLIC KEY GEN
        key_PUB = key_PRIV.public_key()
        # PUBLIC KEY SERIAL
        pem_PUB = key_PUB.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        employerID = randomEmployeeID()
        keys.append((employerID, pem_PUB.decode('utf-8'), pem_PRIV.decode('utf-8')))
    return keys
###########################
# SAVE KEYS FILE FUNCTION #
def saveKeys(keys):
    for employeeID, _, pem_PRIV in keys:
        with open(f"KEY-{employeeID}.pem", "w") as file:
            file.write(pem_PRIV)

startDatabase()
#####################
# GENERATE KEY CALL #
keys = generateKey(1)

# PUB KEYS INTO DB
for employeeID, pem_PUB, pem_PRIV in keys:
    insertKey_PUB(employeeID, pem_PUB)
    saveKeys([(employeeID, pem_PUB, pem_PRIV)])
