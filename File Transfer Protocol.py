#!/usr/bin/env python
# coding: utf-8

# In[1]:


import re #regex for password criteria checking
import getpass #password input box
import json
from pathlib import Path
import os.path
import os
import shutil
import hashlib
from Crypto.Cipher import AES
import sys
import ssl
import socket
from time import sleep
from multiprocessing import Process, Pipe, Lock, Queue
from socketserver import BaseRequestHandler, TCPServer
import base64


# In[2]:


own_ip = None

# The code below was taken from Fabrizio's demo posted to Github at
# https://github.com/fabrizio8/network-example

# This function initializes the IP address and stores it globally
def init_ip():
    global own_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    own_ip = s.getsockname()[0]
    s.close()
    
    
    

    
#######################################
#             TCP example             #
#######################################
class tcp_handler(BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        print("Echoing message from: {}".format(self.client_address[0]))
        print(self.data)
        self.request.sendall("ACK from server".encode())


def tcp_listener(port):
    host = "localhost"
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cntx.load_cert_chain('cert.pem', 'cert.pem')

    server = TCPServer((host, port), tcp_handler)
    server.socket = cntx.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except:
        print("listener shutting down")
        server.shutdown()


def tcp_client(port, data):
    host_ip = "127.0.0.1"

    # Initialize a TCP client socket using SOCK_STREAM
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cntx.load_verify_locations('cert.pem')
    cntx.load_cert_chain('cert.pem')

    s = cntx.wrap_socket(s, server_hostname='test.server')

    try:
        # Establish connection to TCP server and exchange data
        s.connect((host_ip, port))
        s.sendall(data.encode())
        # Read data from the TCP server and close the connection
        received = s.recv(1024)
    finally:
        s.close()

    print("Bytes Sent:     {}".format(data))
    print("Bytes Received: {}".format(received.decode()))


#######################################
#          Broadcast Example          #
#######################################
def broadcast_listener(socket):
    try:
        while True:
            data = socket.recvfrom(512)
            print(data)
    except KeyboardInterrupt:
        pass


def broadcast_sender(port, hashedEmail):
    count = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            msg = 'bcast_test: ' + str(count)
            count += 1
            s.sendto(msg.encode('ascii'), ('255.255.255.255', port))
            sleep(5)
    except KeyboardInterrupt:
        pass


#######################################
#               Driver                #
#######################################
def communication_manager(usersObj, hashedEmail, md5CheckSum, switch_ports=False):
    # find own ip
    init_ip()
    bcast_port = 1337 if switch_ports else 1338
    tcp_listen = 9990 if switch_ports else 9995
    tcp_port = 9995 if switch_ports else 9990

    # broadcast to other users that you exist
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.bind(('', bcast_port))

    parent_recv, child_trans = Pipe()
    child_recv, parent_trans = Pipe()
    
    broadcast_listener_worker = Process(target=broadcast_listener,
                                        name="broadcast_listener_worker",
                                        args=(broadcast_socket,))

    broadcast_sender_worker = Process(target=broadcast_sender,
                                      name="broadcast_sender_worker",
                                      args=(bcast_port, hashedEmail,))

    tcp_listener_worker = Process(target=tcp_listener,
                                  name="tcp_listener_worker",
                                  args=(tcp_listen,))

    procs = [
        broadcast_listener_worker,
        broadcast_sender_worker,
        tcp_listener_worker,
    ]
        
    try:
        for p in procs:
            print("Starting: {}".format(p.name))
            p.start()
        exit_shell = False # Exits the while loop when not False
        while (exit_shell == False):
            # 'shell' prefix for each line
            textInput = input('$secure_drop>')
            
            # Add command
            if(textInput == 'add'):
                # Check to verify user is correct
                print('Verify your identity: ')
                verifyLoginSuccess = False
                while(verifyLoginSuccess is False):
                    checkEmail = input('Your Email address: ')
                    checkPassword = input('Your Password: ')
                    verifyLoginSuccess = loginAuthentication(usersObj,checkEmail,checkPassword)
                
                # Check checksum for changes
                checkCheckSum(md5CheckSum)
                        
                # Adds users to the contact list for the logged in user
                print('\n--- Add Contact ---')
                contact_name = input('Enter Full Name: ')
                contact_email = input('Enter Email Address: ')
        
                encrypted_email = hashEmail(contact_email)
                # create the contact dict
                contact = {
                    "Email": encrypted_email,
                    "Name": contact_name
                }
                # add contact to user 
                usersObj.addContact(hashEmail(checkEmail), contact)
                
                # Update checksum
                md5CheckSum = getCheckSum()
                
                # was the contact properly stored?
                if(usersObj.doesContactExist(hashEmail(checkEmail), contact)):
                    print('Contact added to List')
                else:
                    print('Failed to add contact')
                    
            # List command
            elif(textInput == 'list'):
                # Check checksum for changes
                checkCheckSum(md5CheckSum)
                
                # Check to verify user is correct
                print('Verify your identity: ')
                verifyLoginSuccess = False
                checkEmail = ''
                checkPassword = ''
                while(verifyLoginSuccess is False):
                    checkEmail = input('Your Email address: ')
                    checkPassword = input('Your Password: ')
                    verifyLoginSuccess = loginAuthentication(usersObj,checkEmail,checkPassword)
                    
                # Check checksum for changes
                checkCheckSum(md5CheckSum)
                # the following in the main code from Fabrizio at https://github.com/fabrizio8/network-example
                # This should be used to find contacts, verify them, and find info for establishing
                # a connection to do the transfer
                #communication_manager()
                
                print('test list command')
                #contacts = usersObj.getContacts(checkEmail)
                #for k in contacts.keys():
                    #add code here to check if remote user is online and has added user to contacts
                 #   print(k)
                
            # Send command
            elif(textInput == 'send'):
                # Check checksum for changes
                checkCheckSum(md5CheckSum)
                
                # create a TCP socket for client (connection-oriented socket)
                clientSocket = socket(AF_INET, SOCK_STREAM)
                # connect the socket to the server
                clientSocket.connect((serverName,serverPort)) # these variables need to be set from the broadcast
                
                # Send the file 
                # open the file in read binary mode
                filename = input('What is the name of the file you would like to send: ')
                myfile = open(filename, "rb")
                # read the file in line by line with the while loop
                myline = myfile.readline()
                while myline:
                    # opened the file for sending
                    # print("the data is: ", myline) # this is for debugging
                    # send the line of data to the server and get the next line
                    clientSocket.send(myline)
                    myline = myfile.readline()
                # close the file
                myfile.close()
                
                # Receive the file
                # set a socket connection timeout
                connectionSocket.settimeout(5.0)
                # create the file and open for writing
                with open(filename, "wb") as f:
                    # print("file opened")
                    while True:
                        # print("in true")
                        try:
                            bytes_read = connectionSocket.recv(1024)
                        except error:
                            print("nothing read in, break")
                            break
                        print('data=%s', (bytes_read))
                
                        # write the contents to the file
                        f.write(bytes_read)
                    # print("quit while") # this line is for debugging
                    f.close()
                #print('test2')
            
            # Help command
            elif(textInput == 'help'):
                
            # Check checksum for changes
                checkCheckSum(md5CheckSum)
                        
                print('\t"add" -> Add a new contact \n\t\"list\" -> List all online contacts \n\t\"send\" -> Transfer file to contact \n\t\"exit\" -> Exit SecureDrop')
                
            # Exit command
            elif(textInput == 'exit'):
                # Check checksum for changes
                checkCheckSum(md5CheckSum)
                exit_shell= True
                
        print('Exiting Secure Drop')
        for p in procs:
            print("Terminating: {}".format(p.name))
            if p.is_alive():
                p.terminate()
                sleep(0.1)
            if not p.is_alive():
                print(p.join())
        
    except KeyboardInterrupt:
        for p in procs:
            print("Terminating: {}".format(p.name))
            if p.is_alive():
                p.terminate()
                sleep(0.1)
            if not p.is_alive():
                print(p.join())


# In[3]:


###########################################################
# Functions

# This function takes in an email and password, and returns true/false based on successful authentication
def loginAuthentication(usersObj, emailAddress, inputPassword):
    passwordHash = ' '
    
    # Check for @ symbol before period symbol
    intAtSymbol = emailAddress.find('@')
    intPeriodSymbol = emailAddress.find('.')
    if(intAtSymbol <0 or intPeriodSymbol < 0 or intAtSymbol > intPeriodSymbol):
        print('Not a valid email address')
        return False
    
    hashedEmail = hashEmail(emailAddress) 
    if(usersObj.isUserRegistered(hashedEmail)):
        passwordHash = hashPassword(inputPassword, usersObj.getPasswordHash(hashedEmail)[:32])
    else:
        print('user does not exist')
        return False
    

    
    #print('password hash')
    #print(usersObj.getPasswordHash(emailAddress)[32:])
    #print('password input hash')
    #print(passwordHash[32:])
    #print('is user registered')
    #print(usersObj.isUserRegistered(emailAddress))
    #print('do hashes equal?')
    #print(usersObj.getPasswordHash(emailAddress)[32:] in passwordHash)
    if(usersObj.isUserRegistered(hashedEmail) and usersObj.getPasswordHash(hashedEmail)[32:] in passwordHash):
        return True #exits while loop
    else:
        print('Incorrect email/password combination\n')
        return False #keeps running loop until true
        print('\n')

# Takes a password and returns a sha-256 hashvalue with a salt
def hashPassword(password, salt) :
    # SHA hashing
    hashResult = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200000) #200,000 iterations for SHA algorithm
    # Storing the hash and salt
    storage = salt + hashResult #[:32] is salt [32:] is key

    return storage

def hashEmail(email):
    hashResult = hashlib.pbkdf2_hmac('sha256', email.encode('utf-8'), bytes("email","utf-8"), 200000) #200,000 iterations for SHA algorithm
    return base64.b64encode(hashResult).decode('utf-8')
    
def encryptContact(plaintext):
    session_key = get_random_bytes(16)
    aes_cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext,tag = aes_cipher.encrypt_and_digest(plaintext)
    
    return [session_key, ciphertext, tag, aes_cipher.nonce]

def decryptContact(decryptArray, session_key):
    nonce = decryptArray[2]
    tag = decryptArray[1]
    ciphertext = decryptArray[0]
    
    aes_cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    plaintext = aes-cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext

#Returns MD5 Checksum to store and check against
def getCheckSum(): 
    if os.path.exists(Path(".SFTP_USERS.dat")):
        with open(".SFTP_USERS.dat","r") as f:
            data = f.read()
            return hashlib.md5(data.encode("utf-8")).hexdigest()
    else:
        #if the file doesnt exist
        return hashlib.md5("".encode("utf-8")).hexdigest()

#Throws an error if checksum is wrong
def checkCheckSum(good_checksum):
    with open(".SFTP_USERS.dat", "r") as f:
        data = f.read()
        newCheckSum = hashlib.md5(data.encode("utf-8")).hexdigest()
        if good_checksum != newCheckSum:
            print('hacked .SFTP_USERS.dat detected. Deleting file for safety.')
            f.close()
            os.remove(".SFTP_USERS.dat")
            sys.exit()

# New user generation, should generate a user and interface the file to save
def newUser():
    try_flag = True # used for password match checking

    fullName = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    while 1: # prompt the user until the passwords match
        if try_flag == False:
            # create junk values, user won't be created
            fullName = ""
            email = ""
            passWd = ""
            break
        passWd = input("Input Password: ")
        passWd_Check = input("Re-Enter Password: ")
        
        #validates the inputted email is of the proper format
        while 1:
            # Check for @ symbol before period symbol
            intAtSymbol = email.find('@')
            intPeriodSymbol = email.find('.')
            if(intAtSymbol <0 or intPeriodSymbol < 0 or intAtSymbol > intPeriodSymbol):
                
                print('Not a valid email address')
                email = input("Enter Email Address: ")
            else:
                break
        
        #checks if first input matches second input
        if passWd != passWd_Check:
            while 1: # prompt until accepted "try again?" answer
                try_again = input("Passwords do not match, try again? (y/n):")
                if (try_again == 'y' or try_again == 'Y'):
                    try_flag = True
                    break
                elif (try_again == 'n' or try_again == 'N'):
                    try_flag = False
                    break
                else: # invalid answer
                    print("User did not input y/n")
                
        else:
           # print("Passwords Match.")
            # Hashes the password using SHA-256
            # Use passWdHashed[32:] to get the key
            # Use passWdHashed[:32] to get the salt
            # 32 byte salt
            salt = os.urandom(32)
            passWdHashed = hashPassword(passWd, salt)
            
            #hashes the email before storing to user data for security
            emailHashed = hashEmail(email)
            break
    user = {
        "Name": fullName,
        "Email": emailHashed,
        "Password": passWdHashed
    }
    return user # return the user object to main to be saved


# In[4]:


# data object that stores the user's 
class UserData:
    userData_file_path = Path(".SFTP_USERS.dat")
    temp_data_file_path = Path(".SFTP_USERS.tmp")
    data = {}
    enc_data = {}
    data_fp = None
    temp_fp = None
    
    in_init_phase = True
    
    def __init__(self,filePath=userData_file_path,tempFile=temp_data_file_path):
        if os.path.exists(filePath) and os.path.getsize(filePath):
            self.loadData()
        else:
            with open(".SFTP_USERS.tmp", "a+") as tf:
                1==1
            with open(".SFTP_USERS.dat", "a+") as tf:
                1==1
            self.data = dict()
        in_init_phase = False
        return None
    
    def __del__(self):
        self.writeData()
        return None
    
    #returns a boolean if the object empty
    def isEmpty(self):
        return not(bool(self.data))
    
    #adds user data to JSON file. Gathers up all user info.
    def addUser(self, user):
        #print( user['Email'])
        self.data[user['Email']] = user
        self.data[user['Email']]['Password'] = base64.b64encode(user['Password']).decode('utf-8')
        self.data[user['Email']]['Contacts'] = {}
        #self.enc_data[user['Email']] = self.data[user['Email']]
        self.writeData()
    
    #returns boolean to check if the user is registered in the system
    def isUserRegistered(self, email):
        for k in self.data.keys():
            if k == email:
                return True
        return False
        
        #returns string version of password hash
    def getPasswordHash(self, email):
        return base64.b64decode(self.data[email]["Password"].encode('utf-8'))
    
    #returns the contacts dictionary from user
    def getContacts(self, email):
        if self.isUserRegistered(email):
            #self.decrpytContacts(email, self.getPasswordHash(email))
            return self.data[email]['Contacts']
        else:
            return {}
    
    #returns a boolean to check if the email address exists in contacts
    def doesContactExist(self, email, contact):
        if self.isUserRegistered(email) and contact['Email'] in self.data[email]['Contacts'].keys() and self.data[email]['Contacts'][contact['Email']] == contact['Name']:
            return True
        else:
            return False
    
    #adds contact to user data and writes to JSON
    def addContact(self, email, contact):
        if (self.isUserRegistered(email)):
            self.data[email]['Contacts'][contact['Email']] = contact['Name']
            self.writeData()
        else:
            print('user with specified email does not exist')
        return None
    
    #remves contact from user (unused)
    def removeContact(self, email, contact):
        if self.doesContactExist(email, contact):
            self.data[email]['Contacts'].remove(contact)
            #self.encryptContacts(email)
            self.writeData()
            return True
        else:
            return False
    
    #loads data from JSON
    def loadData(self):
        with open(".SFTP_USERS.dat","r") as f:
            try:
                self.data = json.load(f)
                return True
            except JSONDecodeError:           
                print('failed to load JSON file, is it empty?')
                self.data = dict()
                return False
    
    #writes user data to JSON file
    def writeData(self):
        write_successful = False
        print(json.dumps(self.data))
        while not write_successful:
            with open(".SFTP_USERS.tmp", "w") as tf:
                json.dump(self.data, tf)
            with open(".SFTP_USERS.tmp", "r") as tf:
                tmp_data = json.load(tf)
                write_successful = tmp_data == self.data
            if write_successful:
                print("data written to temp file")
        os.remove(self.userData_file_path)
        shutil.copy(self.temp_data_file_path, self.userData_file_path)
        return write_successful
    
    #unused function
    def decryptContacts(self, email, passwordHash):
        if self.data[email]['Password'] == passwordHash:
            self.data[email] = decryptContact(passwordHash, json.loads(self.enc_data[email]['Contacts']))
            return True
        else:
            return False
        
    #unused function
    def encryptContacts(self, email):
        self.enc_data[email]['Contacts'] = encryptContact(json.dumps(self.data[email]['Contacts']).encode('utf-8'), self.data[email]['Password'])
        return None


# In[ ]:


###########################################################
def main():
    
    # Start of main program
    # Initializes main checksum
    md5CheckSum = getCheckSum()
    
    #print("checksum after init:")
    #print(md5CheckSum)
    
    usersObj = UserData() #main user data in memory
    userList = not usersObj.isEmpty() # If there are no users in file 
    
    #If there are no users in file, create initial user in while loop
    while (userList == False):
        print('No users are registered with this client')
        firstUser= input('Would you like to register a new user now? (y/n): ')
                        
        if (firstUser == 'Y' or firstUser == 'y'):
            
            # create the new user
            user = newUser()
            if (user["Name"] == "" or user["Email"] == "" or user["Password"] == ""): # was a contact unable to be created
                print('You cannot use this system without a user registered')
            else:
                
                # Check checksum for changes
                # checkCheckSum(md5CheckSum)
                
                # Create new user
                usersObj.addUser(user)
            
                # Update checksum
                md5CheckSum = getCheckSum()
                #print("checksum after added:")
                #print(md5CheckSum)
                 
            userList = True #can be changed with user registration code (must not == False to exit loop)
        else:
            print('You cannot use this system without a user registered')

    print('\n$Welcome to Secure Drop!$ \n--- Login ---')

    checkCheckSum(md5CheckSum)

    loginSuccess = False # Exits the while loop when not False
    while (loginSuccess == False):
        emailAddress = input('Email Address:')
        inputPassword = input('Password:')
        
        # Check checksum for changes
        #print("checksum after login entered:")
        #print(getCheckSum())
        checkCheckSum(md5CheckSum)
                
         # Update the success variable       
        loginSuccess = loginAuthentication(usersObj, emailAddress, inputPassword) # Changes the boolean to True if successful
    print("Login was successful!")
    
    communication_manager(usersObj, hashEmail(emailAddress), md5CheckSum, len(sys.argv))
    
if __name__ == "__main__":
    main()

