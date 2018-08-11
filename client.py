#!/usr/bin/env python
import socket
import sys
import math
from Crypto.Util.number import getPrime,isPrime
import random
import numpy as np
from Crypto.Hash import SHA
import pickle
import time
import struct

def modulo(a,b,c):
    x=1
    y=a
    while(b>0):
        if(b%2==1):
            x=(x*y)%c
        y=(y*y)%c
        b=b/2
    return x%c

def millerrabin(n,ite):
    if(n<2):
        return False
    if(n!=2 and n%2==0):
        return False
    d=n-1
    while(d%2==0):
        d=d/2
    for i in range(ite):
       a = random.randint(1,n-1)
       temp = d
    x = modulo(a,temp,n)
    while(temp!=n-1 and x!=1 and x!=n-1):
        x = (x*x)%n
        temp = temp*2
    if(x!=n-1 and temp%2==0):
        return False
    return True

def primeFactors(n,min_prime):
    temp=[]
    while n % 2 == 0:
        if 2 not in temp:
            if 2>=min_prime:
                temp.append(2)
        n = n / 2
    for i in range(3,int(math.sqrt(n))+1,2):
        while n % i== 0:
            if i not in temp:
                if i>=min_prime:
                    temp.append(i)
            n = n / i
    if n > 2:
        if n not in temp:
            if n>=min_prime:
                temp.append(n)
    if len(temp)>=1:
        return temp
    else:
        temp=[]
        return temp

def key_generation_phase(PUBKEY):
    max_prime=1000000
    it=4
    min_prime=10001
    while 1:
        p = np.random.randint(min_prime,max_prime)
        if millerrabin(p,it)==True:
            '''q = np.random.randint(min_prime,max_prime)
            if millerrabin(q,it)==True:
                if ((p-1)%q)==0:
                    break'''
            p_factors=primeFactors(p-1,min_prime)
            if len(p_factors)>=1:
                q = random.choice([i for i in p_factors if 1<i<p-1])
                break
    '''large_primes=[]
    for i in range(min_prime,max_prime):
        if millerrabin(i,it)==True:
            large_primes.append(i)
    while 1:

        p = random.choice([i for i in large_primes if min_prime<i<max_prime])
        p_factors=primeFactors(p-1)
        q = random.choice([i for i in p_factors if 1<i<p-1 and i>min_prime])
    '''
    while 1:

        g = np.random.randint(2,p-1)
        alpha = modulo(g,(p-1)/q,p)
        if alpha>1:
            break
    a = np.random.randint(1,q)
    y = modulo(alpha,a,p)
    PUBKEY.append(int(p))
    PUBKEY.append(int(q))
    PUBKEY.append(int(alpha))
    PUBKEY.append(int(y))
    #print PUBKEY,a
    return PUBKEY,int(a)

def signature_generation_phase(PUBKEY,a,m,SIGNEDMSG):
    m_decimal = int(m,2)
    print "Value of msg in decimal:- "
    print m_decimal
    print "\n"
    k = np.random.randint(1,PUBKEY[1])
    print "Value of k:- "
    print k
    print "\n"
    r = modulo(PUBKEY[2],k,PUBKEY[0])
    print "Value of r:- "
    print r
    print "\n"
    h = SHA.new()
    h.update(str(m)+str(r))
    e = h.hexdigest()
    print "Value of e:- "
    print e
    print "\n"
    e_decimal = int(h.hexdigest(),16)%PUBKEY[0]
    print "value of e in decimal:- "
    print e_decimal
    print "\n"
    s = ( ( ((a%PUBKEY[1]) * (e_decimal%PUBKEY[1]))%PUBKEY[1] ) + k%PUBKEY[1] )%PUBKEY[1]
    print "Value of s:- "
    print s
    print "\n"
    while 1:
        v = np.random.randint(1,PUBKEY[1])
        u = np.random.randint(1,PUBKEY[1])
        r_dash = ((r%PUBKEY[0]) * (modulo(PUBKEY[2],(PUBKEY[0]-2)*u,PUBKEY[0])) * (modulo(PUBKEY[3],v,PUBKEY[0])))%PUBKEY[0]
        s_dash = s-u
        h = SHA.new()
        h.update(str(m)+str(r_dash))
        e_dash = h.hexdigest()
        e_dash_decimal = int(h.hexdigest(),16)%PUBKEY[0]
        if (e_decimal-e_dash_decimal)==v:
            print e_decimal
            print e_dash_decimal
            print v
            break

    print "Value of u:- "
    print u
    print "\n"
    print "Value of s_prime:- "
    print s_dash
    print "\n"
    print "Value of v:- "
    print v
    print "\n"
    print "Value of r_prime:- "
    print r_dash
    print "\n"
    print "Value of e_prime:- "
    print e_dash
    print "\n"
    print "Value of e_prime in decimal:- "
    print e_dash_decimal
    print "\n"
    SIGNEDMSG.append(m)
    SIGNEDMSG.append((e_dash,s_dash))
    return SIGNEDMSG

def get_constants(prefix):
    """Create a dictionary mapping socket module constants to their names."""
    return dict( (getattr(socket, n), n)
                 for n in dir(socket)
                 if n.startswith(prefix)
                 )

def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

if __name__ == "__main__":
    #sock.close()
    Portnum = int(input("Enter the port:- "))
    families = get_constants('AF_')
    types = get_constants('SOCK_')
    protocols = get_constants('IPPROTO_')
    server_ip = sys.argv[1]
    #print server_ip
    try:
        sock = socket.create_connection((str(server_ip), Portnum))
    except socket.error:
        print "failed to connect to server"
        sys.exit()
    print "Socket connected to "+str(Portnum)+" on ip "+str(server_ip)
    create_socket_flag=0
    PUBKEY=[]
    PUBKEY,privateA = key_generation_phase(PUBKEY)
    print "\n"
    print "Value of p:- "
    print PUBKEY[0]
    print "\n"
    print "Value of q:- "
    print PUBKEY[1]
    print "\n"
    print "Value of alpha:- "
    print PUBKEY[2]
    print "\n"
    print "Private key of A:- "
    print privateA
    print "\n"
    print "Public key of A:- "
    print PUBKEY[3]
    print "\n"
    send_data=str(PUBKEY[0])
    for i in range(1,len(PUBKEY)):
        send_data+=" "+str(PUBKEY[i])
    #print send_data
    try:
        send_msg(sock,send_data)
    except socket.error:
        print "Unable to send public elements to B"
        sys.exit()
    print 'Public elements are send to B\n'
    while True:
        if create_socket_flag==1:
            try:
                sock = socket.create_connection((server_ip,Portnum))
            except socket.error:
                print "Failed to connect to server"
            print "Connection established"

        msg = raw_input("Enter the binary message to be signed:- ")
        print "\n"
        print "The input binary msg to be signed by A is:- "
        print msg
        print "\n"
        SIGNEDMSG=[]
        SIGNEDMSG = signature_generation_phase(PUBKEY,privateA,str(msg),SIGNEDMSG)
        print "Signed msg tuple to be sent to B is:- "
        print SIGNEDMSG
        print "\n"
        send_data=str(SIGNEDMSG[0])+" "+str(SIGNEDMSG[1][0])+" "+str(SIGNEDMSG[1][1])
        try:
            send_msg(sock,send_data)
        except socket.error:
            print "Unable to send signed msg to B"
            #sock.close()
            sys.exit()
        print "Signed msg is send to B\n"
        try:
            recv_data = recv_msg(sock)
        except socket.error:
            print "Unable to receive verification status from B"
            #sock.close()
            sys.exit()
        print "Received verification status from B\n"
        print "Verification status send by B is:- "
        print recv_data
        print "\n"
        if int(recv_data)==1:
            print "Signature is verified by B"
        elif int(recv_data)==0:
            print "Signature couldn't be verified by B"
        print "\n"
        sock.close()
        if create_socket_flag==0:
            create_socket_flag=1
