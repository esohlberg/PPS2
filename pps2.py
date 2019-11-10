import urllib.request
from Crypto.Cipher import AES
import binascii
import base64
import random
import os
import zlib

################################################################################
# CS 284 Padding Utility Functions
################################################################################

# s is a bytearray to pad, k is blocklength
# you won't need to change the block length
def cmsc284pad(s,k=16):
    if k > 255:
        print("pkcs7pad: padding block length must be less than 256")
        return bytearray()
    n = k - (len(s) % k)
    if n == 0:
        n = k
    for i in range(1,n+1):
        s.extend([i])
    return s

# s is bytes to pad, k is blocklength
# you won't need to change the block length
def cmsc284padbytes(s,k=16):
    if k > 255:
        raise Exception("pkcs7pad: padding block length must be less than 256")
    n = k - (len(s) % k)
    if n == 0:
        n = k
    for i in range(1,n+1):
        s += chr(i).encode("utf-8")
    return s

# s is bytes to unpad, k is blocklength
# you won't need to change the block length
def cmsc284unpad(s,k=16):
    if not cmsc284checkpadding(s,k):
        print("cmsc284unpad: invalid padding")
        return b''
    n = s[len(s)-1]
    return s[:len(s)-n]

# checks padding on s and returns a boolean
# you won't need to change the block length
def cmsc284checkpadding(s,k=16):
    if(len(s) == 0):
       #print("Invalid padding: String zero length"%k) 
       return False
    if(len(s)%k != 0): 
       #print("Invalid padding: String is not multiple of %d bytes"%k) 
       return False
    n = s[len(s)-1]
    if n > k or n == 0:
       return False
    else: 
        for i in range(n):
            if s[len(s)-1-i] != (n-i):
                return False
    return True

################################################################################
# Function for querying the server
################################################################################

PPS2SERVER = "http://cryptoclass.cs.uchicago.edu/"
def make_query(task, cnetid, query):
    DEBUG = True
    if DEBUG:
        print("making a query")
        print("Task:", task)
        print("CNET ID:", cnetid)
        print("Query:", query)
    if (type(query) is bytearray) or (type(query) is bytes):
        url = PPS2SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query)) + "/"
    else:
        url = PPS2SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query.encode('utf-8'))) + "/"
    if DEBUG:
        print("Querying:", url)

    with urllib.request.urlopen(url) as response:
        raw_answer = response.read()
        answer = base64.urlsafe_b64decode(raw_answer)
        if DEBUG:
            print("Answer:", answer)
        return answer
    return None

def make_query_quiet(task, cnetid, query):
    DEBUG = True
    if (type(query) is bytearray) or (type(query) is bytes):
        url = PPS2SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query)) + "/"
    else:
        url = PPS2SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query.encode('utf-8'))) + "/"
    with urllib.request.urlopen(url) as response:
        raw_answer = response.read()
        answer = base64.urlsafe_b64decode(raw_answer)
        return answer
    return None


################################################################################
# Problem 1 SOLUTION
################################################################################

def problem1(cnetid):
    zerobyte = '\x00'
    querystring = ''
    for i in range(0, 30):
        querystring += zerobyte
    originalquerystring = querystring

    listofdicts = []
    for i in range(0, 20):
        listofdicts.append({})
    for z in range(0, 200):
        querystring = originalquerystring
        for i in range(0, 20):
            bytesstring = make_query('one', cnetid, querystring)
            querystring = querystring[0:-1]
            bytesaray = list(bytesstring)
            if bytesstring[30] in listofdicts[i]:
                listofdicts[i][bytesstring[30]] += 1
            else:
                listofdicts[i][bytesstring[30]] = 1

    answerbytes = []
    for i in range(0, 20):
        maxnum = 0
        maxbyte = None
        for key, value in listofdicts[i].items():
            if value > maxnum:
                maxnum = value
                maxbyte = key
        answerbytes.append(maxbyte)
    c = bytes(answerbytes)
    print(str(c, errors = 'replace'))
    return c


################################################################################
# Problem 2 SOLUTION
################################################################################

def problem2(cnetid):
    firstquery = make_query('twoa', cnetid, '')
    lastpiece = firstquery[-16:]

    secondquery = make_query('twob', cnetid, '1')
    firstpiece = secondquery[0:16]
    ciphertext = firstpiece + lastpiece

    result = make_query('twoc', cnetid, ciphertext)
    print(str(result, errors = 'replace'))
    return result


################################################################################
# Problem 3 SOLUTION
################################################################################

def problem3(cnetid):
    answerbytes = []
    zeroquery = b''
    for i in range(0, 47):
        zeroquery += b'\x00'
    bytesleft = 37
    queryquery = zeroquery
    while bytesleft:
        allbytecounter = 0
        savedblocks = {}
        realblock = make_query('three', cnetid, zeroquery)
        realblock = realblock[0:48]
        realbyte = None
        while allbytecounter < 256:
            currtestbyte = bytes([allbytecounter])
            freshquery = queryquery + currtestbyte
            forsavedblocks = make_query('three', cnetid, freshquery)
            if forsavedblocks[0:48] == realblock:
                realbyte = currtestbyte
                allbytecounter = 246
            allbytecounter += 1
        if not realbyte:
            return
        zeroquery = zeroquery[1:]
        queryquery = queryquery[1:]
        queryquery += realbyte
        answerbytes.append(realbyte)
        bytesleft -= 1
    answerbytestring = b''.join(answerbytes)
    print(str(answerbytestring, errors = 'replace'))
    return answerbytestring


################################################################################
# Problem 4 SOLUTION
################################################################################

def problem4(cnetid):
    zeroquery = b''
    for i in range(0, 32):
        zeroquery += b'\x00'
    secondquery = make_query('fourb', cnetid, zeroquery)
    p1 = secondquery[0:16]
    p2 = secondquery[16:]
    k =[]
    for i in range(0, 16):
        k.append(p1[i] ^ p2[i])
    
    cipher = AES.new(bytes(k), AES.MODE_ECB)
    
    padded = cmsc284padbytes(b'let me in please')
    print(cmsc284checkpadding(padded))

    encryptedanswer = b''

    firstAESInput = []
    for i in range(0, 16):
        firstAESInput.append(k[i] ^ padded[i])
    encryptedanswer += cipher.encrypt(bytes(firstAESInput))
    
    secondAESInput = []
    for i in range(0, 16):
        secondAESInput.append(firstAESInput[i] ^ padded[i + 16])
    encryptedanswer += cipher.encrypt(bytes(secondAESInput))

    secquery = make_query('fourb', cnetid, encryptedanswer)
    print(str(secquery, errors ='replace'))

    print(len(padded))
    thirdquery = make_query('fourc', cnetid, encryptedanswer)

    print(thirdquery)
    '''
    target16 = 'this is a test m'
    print(len(target16))
    firstquery = make_query('foura', cnetid, '+')
    firstquerylist = list(bytes(firstquery))
    print(len(firstquerylist))
    firstquerylist[len(firstquerylist) - 1] = 0
    print(firstquerylist)
    secondquery = make_query('fourb', cnetid, bytes(firstquerylist))
    '''
    return thirdquery


################################################################################
# Problem 5 SOLUTION
################################################################################

def problem5(cnetid):
    return b''

################################################################################
# Problem 6 SOLUTION
################################################################################

def problem6(cnetid):
    return b''


if __name__ == "__main__":
    # your driver code for testing here

    # example running AES; delete the code below here
    key = b'ABCDEFGHABCDEFGH'
    block1 = b'abcdefghabcdefgh'
    block2 = bytearray(b'abcdefghabcdefgh')

    # we declare the mode to be ECB but can just it or single-block calls to
    # AES
    cipher = AES.new(key, AES.MODE_ECB)
    print(cipher.encrypt(block1))

    # the following call with fail without the converting block2 to bytes the
    # call to AES. The AES implementation requires an immutable object and
    # bytearray is mutable. Same goes for key.
    print(cipher.encrypt(bytes(block2)))

    # test query, will hang if off campus
    # print(make_query('one','davidcash', ''))

    # bytearrays are mutable, which is handy
    print(block2)
    block2.extend([0])
    print(block2)
    block2.extend(block1)
    block2 = bytearray('abcdefghabcdefgh')
    print(block2)

