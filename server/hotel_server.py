###########
# IMPORTS #
from os import path
import socket
import sqlite3
import ssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import base64
from datetime import *
import threading
#---------#

    

#######################
# INITIALISE DATABASE #
def setUpDatabase():
    # CONNECT DATABASE METHOD #
    connection = sqlite3.connect('database.sqlite3')
    cursor = connection.cursor()
    # QUERYS #
    cursor.execute('''CREATE TABLE IF NOT EXISTS employee (employeeID TEXT PRIMARY KEY, rsa_key BLOB)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS order_details (bed_number INTEGER, towel_number INTEGER, chair_number INTEGER, armch_number INTEGER, date DATE, employeeID INTEGER, FOREIGN KEY(employeeID) REFERENCES employee(employeeID))''')
    connection.commit()
    connection.close()
##############################
# ADD NEW LOG ENTRY FUNCTION #
def addEntryLog(msg):
    date = datetime.now().strftime('%m-%Y')
    log_path = "logs/" + date + '.log'
    date = datetime.now().strftime('%d/%m/%Y %H:%M')
    if not path.exists(log_path):
        with open(log_path, 'x') as l:
            l.write(msg + " día " + date)
    else:
        with open(log_path, 'a') as l:
            l.write("\n" + msg + " día " + date)
##########################################
# VERIFICATION OF THE SIGNATURE FUNCTION #
def signatureVerification(signature, pbk, msg, employeeID):
    public_key = load_pem_public_key(pbk.encode())
    signature = base64.b64decode(signature)
    try:
        public_key.verify(signature, msg.encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        addEntryLog(f"(-), El mensaje del usuario {employeeID} ha sido corrompido")
        return False
#################
# DoS DETECTION #
def checkMsg(bed_number, towel_number, chair_number, armch_number, employeeID):
    if bed_number <= 300 and towel_number <= 300 and chair_number <= 300 and armch_number <= 300:
        period = datetime.now() - timedelta(hours=44)
        connection = sqlite3.connect('database.sqlite3')
        cursor = connection.cursor()
        query = '''SELECT COUNT(*) FROM order_details WHERE employeeID = ? AND date >= ?'''
        cursor.execute(query, (employeeID, period))
        # Retrieve the first row of results #
        count = cursor.fetchone()[0]
        connection.close()
        if count <= 99999:
            return True
        else:
            addEntryLog(f"(-), Posible DoS, el usuario {employeeID} ha realizado demasiadas peticiones")
            return False
    else:
        addEntryLog(f"(-), El usuario {employeeID} ha solicitado demasiados objetos")
        return False
################################
# DETECT NON VERIFIED EMPLOYEE #
def detectNonVerifiedEmployee(employeeID, hashedMessage, message):
    res = False
    connection = sqlite3.connect('database.sqlite3')
    cursor = connection.cursor()
    cursor.execute("SELECT rsa_key FROM employee WHERE employeeID = ?", (employeeID,))
    # Retrieve the first row of results #
    result = cursor.fetchone()
    connection.close()
    if result != None:
        rsaKey = result[0]
        verified = signatureVerification(hashedMessage, rsaKey, message, employeeID)
        if verified:
            res = True
    else:
        addEntryLog(f"(-), Se ha recibido un mensaje de un usuario no verificado")
    return res
###################################
# DATA INSERTION INTO DB FUNCTION #
def insertData(bed_number, towel_number, chair_number, armch_number, employeeID):
    date = datetime.now()
    connection = sqlite3.connect('database.sqlite3')
    cursor = connection.cursor()
    cursor.execute("INSERT INTO order_details (bed_number, towel_number, chair_number, armch_number, date, employeeID) VALUES (?, ?, ?, ?, ?, ?)", (bed_number, towel_number, chair_number, armch_number, date, employeeID))
    connection.commit()
    connection.close()
#######################
# RUN SERVER FUNCTION #
def serverRun():
    # ERROR LOGS #
    invalidEmployeeData = "Datos del trabajador inválidos"
    toManyRequests = "Demasiadas peticiones u objetos solicitados"
    formatError = "Error en el formato del mensaje"
    #------------#
    port=7070
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # RESTRICTION OF TLS < 3 #
    context.options |= ssl.OP_NO_TLSv1_2
    context.options |= ssl.OP_NO_TLSv1_1
    context.options |= ssl.OP_NO_TLSv1
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile='server.crt', keyfile='server.key', password='insegus12')
    server_socket.bind(('192.168.1.32', port))
    server_socket.listen(5)
    secure_server_socket = context.wrap_socket(server_socket, server_side=True)
    print("Servidor activo. Esperando conexiones...")
    setUpDatabase()
    try:
        while True:
            (clientSocket, address) = secure_server_socket.accept()
            print(f"Se ha establecido la conexión con {address} .")
            try:
                signedData = clientSocket.recv(1024).decode('utf-8')
                parts = signedData.split('--|--')
                data = parts[0][2:]
                signature = parts[1][:-1]
                dt = data.split('-')
                try:
                    bed_number = int(dt[0]) if dt[0] != '' else 0
                    towel_number = int(dt[1]) if dt[0] != '' else 0
                    chair_number = int(dt[2]) if dt[0] != '' else 0
                    armch_number = int(dt[3]) if dt[0] != '' else 0
                    employeeID = dt[4] if dt[0] != '' else 0
                    if checkMsg(bed_number, towel_number, chair_number, armch_number, employeeID):
                        if detectNonVerifiedEmployee(employeeID, signature, data):
                            insertData(bed_number, towel_number, chair_number, armch_number, employeeID)
                            # VALID LOG ENTRY #
                            
                            addEntryLog("(+), El trabajador " + 
                                        employeeID + " ha solicitado: " + 
                                        str(bed_number) +" camas, " + 
                                        str(towel_number) + " mesas, " + 
                                        str(chair_number) + " sillas y " + 
                                        str(armch_number) + " sillones ")
                            
                            confirmation_message = f"¡El pedido se ha registrado correctamente para el trabajador {employeeID}!" 
                            clientSocket.send(confirmation_message.encode('utf-8'))
                        else:
                            clientSocket.send(invalidEmployeeData.encode('utf-8'))
                    else:
                        clientSocket.send(toManyRequests.encode('utf-8'))
                except ValueError:
                    clientSocket.send(formatError.encode('utf-8'))
            finally:
                clientSocket.close()

    except KeyboardInterrupt:
        server_socket.close()
        print("Apagando el servidor.")
########
# MAIN #
def main():
    # THREAD ACTIONS #
    server_thread = threading.Thread(target=serverRun)
    server_thread.start()
    server_thread.join()

if __name__ == '__main__':
    main()

 