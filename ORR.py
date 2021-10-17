from Crypto.Cipher import AES
import base64
import random


class Server():
    def __init__(self):
        self.Users = []
        self.Userskeys = []
        self.C = None
        self.data1 = None
        self.data2 = None
        self.data3 = None
        self.data4 = None
        self.data5 = None
        self.data6 = None
        self.data7 = None
        self.SecretKey = None
        self.MsgForUser1 = None #Buffor for Msg
        self.MsgForUser2 = None #Buffor for Msg

    def sesion_number(self):
        C = random.randint(1, 9)
        return C

    def User_list(self, A, B):
        self.Users.append(A.P)
        self.Users.append(B.P)

    def Generate_K(self):
        GENERATED_R = generateprime(16)
        return GENERATED_R

    def Get_User_K(self, A):
        self.Userskeys.append(A)
    #def

    def __del__(self):
        None


class User():
    def __init__(self):
        self.P = random.randint(2 ** (13 - 1), 2 ** 13)  # UserID
        self.R = random.randint(2 ** (16 - 1), 2 ** 16)  # Some random number (Nonce)
        self.C = None  # Index number
        self.K = None  # Server key for the user
        self.ctxt = None
        # Received data from the predecessor (something like buffor)
        self.data1 = None
        self.data2 = None
        self.data3 = None
        self.data4 = None
        self.RR = None
        self.SecretKey = None

    def __del__(self):
        None


def bitgenerator(Blength):
    p = random.getrandbits(Blength)
    p |= 2 ** (Blength - 1)
    p |= 1
    return p

def checkprime(number):
    if (number < 2):
        return False
    if (number == 2):
        return True
    for i in range(3, number, 2):
        if ((number % i) == 0):
            return False
    return True

def generateprime(Blength):
    fake = False
    while (not fake):
        number = bitgenerator(Blength)
        fake = checkprime(number)
    return number

def encrypt(data, key):
    cipher = AES.new(bin(key)[2:])  #Creating AES object with binary key
    length = 16 - (len(data) % 16)  # data padding
    data += chr(length) * length  # -||-
    ctxt = cipher.encrypt(base64.b32encode(data))  # encryption
    return ctxt

def decrypt(data, key):
    cipher = AES.new(bin(key)[2:])  #Creating AES object with binary key
    data = base64.b32decode(cipher.decrypt(data))  # deencryption
    data = data[:-ord(data[-1])]  # padding removal
    return data

def authorization(A, B):
    #Generating C for Users
    S.C = Server.sesion_number(S)
    A.C = S.C
    B.C = S.C
    # Step 0 Alice is preparing to send msg
    A.K = Server.Generate_K(S)
    Server.Get_User_K(S, A)
    A.ctxt = encrypt(str(A.R) + str(A.C) + str(A.P) + str(B.P), A.K)

    # Step1
    # A->B: C,P1,P2,Ea(Ra,C,P1,P2)
    B.data1 = A.ctxt #Bob has received Ea
    B.data3 = A.P #Bob has received  P1
    B.data4 = B.P #Bob has received  P2
    B.K = Server.Generate_K(S)
    Server.Get_User_K(S, B)
    B.ctxt = encrypt(str(B.R) + str(B.C) + str(B.P) + str(B.data3), B.K)

    # Step2
    # B->S: C,P1,P2,Ea,Eb(Rb,C,A,B)

    S.data1 = A.C #Server has received C
    S.data2 = A.ctxt #Server has received Ea
    S.data3 = B.ctxt #Server has received Eb
    S.data4 = decrypt(S.data2, A.K)
    S.data5 = decrypt(S.data3, B.K)

    if (S.C != S.data1): return False

    S.SecretKey = Server.Generate_K(S)

    del_lenght = len(str(A.C) + str(A.P) + str(B.P))
    S.data6 = S.data4[:len(S.data4) - del_lenght]
    S.MsgForUser1 = encrypt(str(A.R) + str(S.SecretKey), A.K)

    del_lenght = len(str(B.C) + str(B.P) + str(B.data3))
    S.data7 = S.data5[:len(S.data5) - del_lenght]
    S.MsgForUser2 = encrypt(str(B.R) + str(S.SecretKey), B.K)

    # Step3
    # S->B: C,Ea(Ra,K),Eb(Rb,K)
    B.data1 = S.data1 #Bob has received C
    if (B.data1 != B.C): return False
    B.data2 = S.MsgForUser1  # #Bob has received Ea
    B.data3 = S.MsgForUser2  # #Bob has received Eb
    B.data4 = decrypt(B.data3, B.K)
    del_lenght_B = len(str(B.R))
    B.RR = int(B.data4[:del_lenght_B])
    B.SecretKey = int(B.data4[del_lenght_B:])
    if (B.R != B.RR):
        False
    else:  print("Nonce is corretly. User B has received the key")

    # Step4
    # B->A: C,Ea(Ra,K)
    A.data1 = B.data1#Alice has received C
    if (A.data1 != A.C): return False
    A.data2 = B.data2 #Alice has received Ea
    A.data3 = decrypt(A.data2, A.K)
    del_lenght_A = len(str(A.R))
    A.RR = int(A.data3[:del_lenght_A])
    A.SecretKey = int(A.data3[del_lenght_A:])
    if (A.R != A.RR):
        return False
    else:
        print("Nonce is corretly. User A has received the key")
    print("authorization was successful")
    return True

S = Server()
A = User()
B = User()

print(authorization(A, B))








