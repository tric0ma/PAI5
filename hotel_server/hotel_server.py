###########
# IMPORTS #
import os
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
class SERVER:
    def __init__(self):
         pass

    #######################
    # INITIALISE DATABASE #
    def setUpDatabase(self):
            # CONNECT DATABASE METHOD #
            connection = sqlite3.connect('database.sqlite3')
            cursor = connection.cursor()
            # QUERYS #
            cursor.execute('''CREATE TABLE IF NOT EXISTS employee (employeeID TEXT PRIMARY KEY, rsa_key BLOB)''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS order_details (bed_number INTEGER, towel_number INTEGER, chair_number INTEGER, armch_number INTEGER, date DATE, employeeID INTEGER, FOREIGN KEY(employeeID) REFERENCES employee(employeeID))''')
            connection.commit()
            connection.close()

    from datetime import datetime, timedelta

    def generateKpi(self):
        results = []
        results_month_ago = []
        results_two_month_ago = []


        # Obtener la fecha actual
        datetime_now = datetime.now()

        last_month = datetime_now - timedelta(days=datetime_now.day)
        two_months_ago = last_month - timedelta(days=last_month.day)
        three_months_ago = two_months_ago - timedelta(days=two_months_ago.day)

        last_month = last_month.strftime("%Y-%m")
        two_months_ago = two_months_ago.strftime("%Y-%m")
        three_months_ago = three_months_ago.strftime("%Y-%m")

        with open("logs/"+last_month + ".log", "r") as l:
            for log in l:
                if log[0]=="E" :
                        results.append(1)
                else:
                    results.append(0)

        with open("logs/"+two_months_ago + ".log", "r") as l:
            for log in l:
                if log[0]=="E" :
                        results_month_ago.append(1)
                else:
                    results_month_ago.append(0)

        with open("logs/"+three_months_ago + ".log", "r") as l:
            for log in l:
                if log[0]=="E" :
                        results_two_month_ago.append(1)
                else:
                    results_two_month_ago.append(0)

        ratio_month = sum(results)/len(results)*100
        ratio_last_month = sum(results_month_ago)/len(results_month_ago)*100
        ratio_last_two_months = sum(results_two_month_ago)/len(results_two_month_ago)*100
        tendency = ""
        if (ratio_month == ratio_last_two_months and ratio_month == ratio_last_month):
            #TENDENCIA NULA
            tendency = "0"   
        if (ratio_month >= ratio_last_two_months and ratio_month >= ratio_last_month):
            #TENDENCIA POSITIVA
            tendency = "+"
        if (ratio_month < ratio_last_two_months or ratio_month < ratio_last_month):
            #TENDENCIA NEGATIVA
            tendency = "-"

        with open("kpi.log", "r") as kpi:
            if len(kpi.readlines()) <= 2:
                tendency = "0"

        with open("kpi.log", "a") as kpi:
            kpi.write(last_month + ", ratio: " + str(ratio_month) + ", tendency: " + tendency +"\n")


        ##############################
        # ADD NEW LOG ENTRY FUNCTION #
    def addEntryLog(self,msg):
            date = datetime.now().strftime('%Y-%m')
            log_path = "logs/" + date + '.log'
            date = datetime.now().strftime('%d/%m/%Y %H:%M')
            if not path.exists(log_path):
                self.generateKpi()
                with open(log_path, 'x') as l:
                    l.write(msg + ", timestamp: " + date)
            else:
                with open(log_path, 'a') as l:
                    l.write("\n" + msg + ", timestamp: " + date)
        ##########################################
        # VERIFICATION OF THE SIGNATURE FUNCTION #
    def signatureVerification(self,signature, pbk, msg, employeeID):
            public_key = load_pem_public_key(pbk.encode())
            signature = base64.b64decode(signature)
            try:
                public_key.verify(signature, msg.encode(), padding.PKCS1v15(), hashes.SHA256())
                return True
            except InvalidSignature:
                self.addEntryLog(f"FALLO, El mensaje del usuario {employeeID} ha sido corrompido")
                return False
        #################
        # DoS DETECTION #
    def checkMsg(self,bed_number, towel_number, chair_number, armch_number, employeeID):
            if bed_number <= 300 and towel_number <= 300 and chair_number <= 300 and armch_number <= 300:
                period = datetime.now() - timedelta(minutes=240)
                connection = sqlite3.connect('database.sqlite3')
                cursor = connection.cursor()
                query = '''SELECT COUNT(*) FROM order_details WHERE employeeID = ? AND date >= ?'''
                cursor.execute(query, (employeeID, period))
                # Retrieve the first row of results #
                count = cursor.fetchone()[0]
                connection.close()
                if count <= 3:
                    return True
                else:
                    self.addEntryLog("FALLO, Posible DoS, el usuario ha realizado demasiadas peticiones")
                    return False
            else:
                self.addEntryLog(f"FALLO, El usuario {employeeID} ha solicitado demasiados objetos")
                return False
        ################################
        # DETECT NON VERIFIED EMPLOYEE #
    def detectNonVerifiedEmployee(self,employeeID, hashedMessage, message):
            res = False
            connection = sqlite3.connect('database.sqlite3')
            cursor = connection.cursor()
            cursor.execute("SELECT rsa_key FROM employee WHERE employeeID = ?", (employeeID,))
            # Retrieve the first row of results #
            result = cursor.fetchone()
            connection.close()
            if result != None:
                rsaKey = result[0]
                verified = self.signatureVerification(hashedMessage, rsaKey, message, employeeID)
                if verified:
                    res = True
            else:
                self.addEntryLog(f"FALLO, Se ha recibido un mensaje de un usuario no verificado")
            return res
        ###################################
        # DATA INSERTION INTO DB FUNCTION #
    def insertData(self,bed_number, towel_number, chair_number, armch_number, employeeID):
            date = datetime.now()
            connection = sqlite3.connect('database.sqlite3')
            cursor = connection.cursor()
            cursor.execute("INSERT INTO order_details (bed_number, towel_number, chair_number, armch_number, date, employeeID) VALUES (?, ?, ?, ?, ?, ?)", (bed_number, towel_number, chair_number, armch_number, date, employeeID))
            connection.commit()
            connection.close()

        #######################
        # RUN SERVER FUNCTION #
    def serverRun(self):
        os.system('clear')
        with open('server_banner.txt', 'r') as b:
            for line in b:
                print(line.strip().replace('#', ''))
        # ERROR LOGS #
        formatError = "Error en el formato del mensaje"
        invalidEmployeeData = "Datos del trabajador inválidos"
        toManyRequests = "Demasiadas peticiones u objetos solicitados"
        #------------#
        port=7070
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # RESTRICTION OF TLS < 3 #
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certfile='server.crt', keyfile='server.key', password='insegus12')
        self.serverSocket.bind(('192.168.1.32', port))
        self.serverSocket.listen(5)
        self.SECServerSocket = context.wrap_socket(self.serverSocket, server_side=True)
        self.setUpDatabase()
        #try:
        while True:
            (clientSocket, address) = self.SECServerSocket.accept()
            print(f"Se ha establecido la conexión con {address}")
            try:
                signedData = clientSocket.recv(1024).decode('utf-8')
                parts = signedData.split('---')
                data = parts[0][2:]
                signature = parts[1][:-1]
                dt = data.split(' | ')
                try:
                    bed_number = int(dt[0]) if dt[0] != '' else 0
                    towel_number = int(dt[1]) if dt[0] != '' else 0
                    chair_number = int(dt[2]) if dt[0] != '' else 0
                    armch_number = int(dt[3]) if dt[0] != '' else 0
                    employeeID = dt[4] if dt[0] != '' else 0
                    if self.checkMsg(bed_number, towel_number, chair_number, armch_number, employeeID):
                        if self.detectNonVerifiedEmployee(employeeID, signature, data):
                            self.insertData(bed_number, towel_number, chair_number, armch_number, employeeID)
                            # VALID LOG ENTRY #                                        
                            self.addEntryLog("EXITO, El trabajador " + 
                                        employeeID + " ha solicitado: " + 
                                        str(bed_number) + " camas, " + 
                                        str(towel_number) + " mesas, " + 
                                        str(chair_number) + " sillas y " + 
                                        str(armch_number) + " sillones ")
                                        
                                # VALID BANNER FOR CLIENT #
                            validTransaction = f"¡El pedido se ha registrado correctamente!" 
                            clientSocket.send(validTransaction.encode('utf-8'))
                        else:
                            clientSocket.send(invalidEmployeeData.encode('utf-8'))
                    else:
                        clientSocket.send(toManyRequests.encode('utf-8'))
                except ValueError:
                    clientSocket.send(formatError.encode('utf-8'))
            finally:
                clientSocket.close()

################
# MAIN SECTION #
if __name__ == '__main__':
    # THREAD ACTIONS #
    server = SERVER()
    server_thread = threading.Thread(target=server.serverRun)
    server_thread.start()
    server_thread.join()

 