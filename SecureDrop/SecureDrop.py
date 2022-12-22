import io, hashlib, hmac, os, secrets, sys, json, socket, time, socketserver, queue, ssl, getpass
from hashlib import pbkdf2_hmac
from getpass import getpass
from fabric import Connection
import multiprocessing as mp
from multiprocessing import Queue
from Crypto.Cipher import AES

# Team 13
# SecureDrop
# 12/13/2022

def addC(email): # Adds a contact to user's list, given user email
    conname = input("Enter Full Name: ")
    conemail = input("Enter Email Address: ")

    with open ('contacts.json', 'r+') as fc: #TODO: hash the contact info!!
        cr = json.load(fc)
        co = {
            "conname": conname,
            "conemail": conemail,
        }
        for index in range(len(cr["contacts"])):
            for key in cr["contacts"][index]:
                if key == email:
                    print(email)
                    cr["contacts"][index][key].append(co)
                    break
        fc.seek(0)
        json.dump(cr, fc, indent = 4)
    return

def listC(email): # Requests to see which contacts are online (must be added as contact back) and compiles list of said contact's info
    cctx = mp.get_context('spawn')
    ql = cctx.Queue()
    pp = cctx.Process(target=udprec, args=(ql,), daemon=1) # opens temp process for listening to replies to "list" broadcast
    pp.start()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    fmessage = f"Are you running SecureDrop? Respond with ip and username. I AM: {email}"#TODO: add broadcasters email
    message = fmessage.encode('utf-8')
    lis = 10
    myContacts = []
    with open ('contacts.json', 'r+') as fc: #TODO: create list of your contact emails
        cr = json.load(fc)
        for index in range(len(cr["contacts"])):
            for key in cr["contacts"][index]:
                if key == email:
                    for cindex in cr["contacts"][index][key]:
                        myContacts.append(cindex["conemail"])
                break
    print("My contacts that exist, not necessarily online: ", myContacts)
    while lis > 0:
        server.sendto(message, ('<broadcast>', 33445))
        time.sleep(0.2)
        lis -= 1
    i = 1
    j = 100 #TODO: or maybe just close process
    time.sleep(1)
    mylist = []
    while i == 1 and j > 0:
        j -= 1
        try:
            qdic = ql.get(True, 1)
        except queue.Empty:
            i = 0
        mylist.append(qdic)
    time.sleep(1)
    pp.terminate()
    time.sleep(2)#DO NOT REMOVE THIS!!!!!!!!
    pp.close()
    #O(n^2) algo to print those online:
    unique_list = []
    for index1 in mylist:
        if index1 not in unique_list:
            if type(index1) != type(unique_list):
                unique_list.append(index1)
    r = False
    returnlist = []
    for x in unique_list:
        if x["email:"] in myContacts:
            if r == False:
                print("We found some of your contacts online!")
                r = True

            print("Your friend", x["name:"], "is online at", x["email:"], "!")
            returnlist.append([x["host:"], x["port:"], x["name:"],x["email:"]])
            
    if r == False:
        print("No contacts found online!")            
    return returnlist
    
def sendC(email, looc): # Function for opening tcp connection with sslcontext and sending file
    targetemail = input("Who (email) do you want to send a file to?")
    #Get host name from email
    hostname = 'localhost'
    portnum = 33446
    name = "DEFAULT NAME"
    for index in looc:
        if index[3] == targetemail:
     #           hostname = "localhost"#index[0]
     #           portnum = 33446#index[1]
                 name = index[2]
    targetpathandfile = input("What do you want to send them? ex: /home/Desktop/file.zip... ")

    context = ssl._create_unverified_context()
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        print(hostname, portnum)
        s.connect((hostname, portnum))
        ssock = context.wrap_socket(s,server_hostname = hostname)

        print("Client has been assigned socket name", ssock.getsockname())
        string = f"Hi {name}, prepare for a file transfer!!!"
        ssock.send(bytes(string, "utf-8"))
        message=ssock.recv(1024)
        if message.decode('utf-8') == "GO AHEAD":
            print("They want the file!")
            with open(targetpathandfile, "rb") as f:
                ssock.sendfile(f)
        else:
            print("They didnt want the file... big sad")
        ssock.close()
    return

#cat /usr/local/etc/easy-rsa/vars
#easyrsa init-pki
#easyrsa build-ca
#easyrsa gen-req test nopass
#easyrsa sign-req server test

def Secure_Drop(name, email):
    print("Welcome to SecureDrop")
    print("Type \"help\" for Commands.\n")
    print("If you think the program is stalled, hit Enter")
    listofonlinecontacts = []
    ctx = mp.get_context('spawn')
    q = ctx.Queue() # never used
    portnum = int(input("Port for listening to list req's? Use 33445, but 8888 if you will be sender: "))
    p = ctx.Process(target=broadrespon, args=(portnum, q, name, email,), daemon=1) # Process for listening to "list" broadcasts
    p.start()  # Thread for listening to list requests
    
    ctxTCP = mp.get_context('spawn')
    #q = ctx.Queue()
    portnum2 = int(input("Port for listening to tcp req? use 33446 if you plan to be receiver, and 9999 otherwise: "))
    tcpServer = ctxTCP.Process(target=tcpRec, args=(portnum2, email,), daemon=1) # Process for listening for tcp requests for file transfer
    tcpServer.start()
    
    while True: #Main program loop
        command = input("SecureDrop $")
        if not command:
            print("No command read")
            continue
        elif command == "help":
            print("\"add\"  -> Add a new contact")
            print("\"list\" -> List all online contacts")
            print("\"send\" -> Transfer file to contact")
            print("\"exit\" -> Exit SecureDrop")

        elif command == "add":
            addC(email)
        elif command == "list":
            listofonlinecontacts = listC(email) # listofonlinecontacts is a list of online contact's info
        elif command == "send":
            sendC(email, listofonlinecontacts)
        elif command == "exit":
            quit("Have a nice day!")
        else:
            print("?")
        #if len(listofonlinecontacts) > 0:
        #    print("LoOC: ", listofonlinecontacts)
    quit() # never seen
    
class user: #Didnt actually have to be a class, but yolo
    def __init__(self):     # creates a user and places it in registry, adds space on contact json file
        self.name = input("Enter Full Name: ")
        self.email = input("Enter Email Address: ")
        #TODO: MAKE SURE EMAIL IS NOT ALREADY IN THE DATABASE
        password = getpass("Enter Password: ")
        #while len(password) < 8:
        password = getpass("Enter Password that is at least 8 characters: ")
        #passcheck = getpass("Re-enter Password: ")

        if password != passcheck:
            print("Error: passwords do not match!")
            user()
        print("Passwords match")
        
        with open ('contacts.json', 'r+') as fc:
            cr = json.load(fc)
            co = {
                self.email: [
                ]
            }
            cr["contacts"].append(co)
            fc.seek(0)
            json.dump(cr, fc, indent = 4)
        bytepass = bytes(password, 'utf-8')
        self.mysalt = secrets.token_bytes(16) # Storing salt
        s = bytes(self.mysalt)
        our_app_iters = 500_000
        self.dk = pbkdf2_hmac('sha256', bytepass, s*2, our_app_iters)
        b = bytes(self.dk)
        sa = bytearray(s)
        ba = bytearray(b) # some operations to make the hash json serializable
        sat = str(sa)
        bat = str(ba)
        x = {"name": self.name,"email": self.email,"saltinhex": sat,"hashinhex": bat}
        with open ('userinfo.json', 'r+') as fj:
            oldfile = json.load(fj)
            oldfile["users"].append(x)
            print(type(oldfile))
            fj.seek(0)
            json.dump(oldfile, fj, indent = 4)
        print("User Registered.\nExiting SecureDrop.")
        quit()
    def print_details(self):
        print("Name: " + self.name)
        print("Email: " + self.email)
        print("Hash: ", self.hash)

def verifyUser(uDict): # responsible for making sure user logging in uses correct password
    password = getpass("Enter Password: ")
    bytepass = bytes(password, 'utf-8')
    for key in uDict:
        if key == 'name':
            name = uDict[key]
        if key == 'email':
            email = uDict[key]
        if key == 'saltinhex':
            saltinhex = uDict[key]#saltinhex = base64.b64decode(uDict[key])
        if key == 'hashinhex':
            hashinhex = uDict[key]
    our_app_iters = 500_000
    cutsalt = saltinhex[12:len(saltinhex)-2]
    cuthash = hashinhex[12:len(hashinhex)-2]
    de = bytes(cutsalt, 'utf-8')
    dee = de.decode('unicode_escape').encode("raw_unicode_escape")
    inhash = pbkdf2_hmac('sha256', bytepass, dee*2, our_app_iters)
    time.sleep(0.1)
    if not hmac.compare_digest(inhash, bytes(cuthash, 'utf-8').decode('unicode_escape').encode("raw_unicode_escape")): #overflow vulnerable?
        quit("WRONG!!!!!")
    else:
        print("Correct password entered.")
        Secure_Drop(name, email)    #Begins secure drop

def loginUser(emailAddr, data): # calls verifyUser when a user match is found, begins SecureDrop
    for index in range(len(data["users"])):
        for key in data["users"][index]:
            if key == "email":
                if data["users"][index][key] == emailAddr:
                    verifyUser(data["users"][index])#which is each user row
    quit("User not found!")
    
def broadrespon(portnum, q, name, email): # Function that is always listening for "list" broadcast
    q.put([])
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP
    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    myContacts = []
    with open ('contacts.json', 'r+') as fc: #TODO: create list of your contact emails
        cr = json.load(fc)
        for index in range(len(cr["contacts"])):
            for key in cr["contacts"][index]:
                if key == email:
                    for cindex in cr["contacts"][index][key]:
                        myContacts.append(cindex["conemail"])
                break
    #print(myContacts)
    client.bind(("", portnum)) #TODO: THE LISTEN AND SEND PORTNUMS SHOULD BE CONSTANT, MADE VARIABLE SO I CAN RUN IT ON MY MACHINE
    while True:
        i = 1
        while i > 0:
            i -= 1
            data, addr = client.recvfrom(1024)
            if (data.decode('utf-8')[0:20] == 'Are you running Secu'):
                listsender = data.decode('utf-8')[64:]
                if listsender in myContacts:
                    dataR = {"BEGIN INFO host: ": socket.gethostbyname(socket.gethostname()), "port: ": portnum + 1, "name: ": name, "email: ": email}
                    dataJ = json.dumps(dataR).encode('utf-8')
                    responder.sendto(dataJ, (addr[0], 12345))
            #TODO: for security, make sure sent ip is same as observed
            #Also, take note of portnum + 1 for future tcp listen

        
def udprec(q):  # Function responsible for listening to replies to "list" broadcast
    q.put([])
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP
    print("Please wait 10 seconds while we check who is online...")
    start = time.time()
    client.bind(("", 12345)) #TODO: THE LISTEN AND SEND PORTNUMS SHOULD BE CONSTANT, MADE VARIABLE SO I CAN RUN IT ON MY MACHINE
    while time.time() < (start + 6):
        data, addr = client.recvfrom(1024)
        readUR = data.decode('utf-8')
        if (readUR[2:18] == "BEGIN INFO host:"):
            #print("RESPONSE IS BEING RECORDED")
            jx = json.loads(readUR)
            dic = {}
            for x, y in jx.items():
                if x == "BEGIN INFO host: ":
                    dic["host:"] = y
                elif x == "port: ":
                    dic["port:"] = y
                elif x == "name: ":
                    dic["name:"] = y
                elif x == "email: ":
                    dic["email:"] = y 
            q.put(dic)
            #TODO: for security, make sure sent ip is same as observed
            #Also, take note of portnum + 1 for future tcp listen
            
def tcpRec(portnum2, email):     # Function responsible for receiving file tranfers
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('test.pem', 'test.key')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "localhost"
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, portnum2))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        buffer = bytearray(2000)
        while True:
            print("Listening at ", ssock.getsockname())
            server, addr = ssock.accept()
            print("Accept connection from: ", addr)
            print("connection built from ", server.getsockname(), " and ", server.getpeername())
            message = server.recv(1024) #TODO: anything
            server.send(bytes("GO AHEAD", 'utf-8'))
            server.read(1500, buffer)
            print(buffer)
            server.close()
    #sock.close()
    

if __name__ == '__main__':
    data = {}
    if not os.path.isfile('userinfo.json'):
        with open('userinfo.json', 'a') as fnew:#Creates json files if not found
            fnew.write("{\n\"users\":[]\n}")
            print("New user info file created.")
    if not os.path.isfile('contacts.json'):
        with open('contacts.json', 'a') as fnew:
            fnew.write("{\n\"contacts\":[]\n}")
            print("New contacts file created.")
    with open ('userinfo.json', 'r+') as f:
        try:
            data = json.load(f)
        except:
            data["users"].append([])#Read users file
            f.seek(0)
            json.dump(data, f, indent = 4)
        print("\n\n")
        nousers = False
        if not data["users"]:
            print("No users are registered with this client.")
            nousers = True
        else:
            print("There are users registered with this client.")
        print("Do you want to register a new user (y/n)? ")
        yesIdo = input()
        try:
            if yesIdo[0] == 'y' or yesIdo[0] == 'Y':
                user()
            elif yesIdo[0] == 'n' or yesIdo[0] == 'N':
                if nousers == True:
                    quit("Ok well there are no users...\n")
                email = input("Enter Email Address: ")
                loginUser(email, data) # logs users in, begins SecureDrop
        except IndexError:
            quit("Bye!")
        quit("Ok sorry!\n")
        