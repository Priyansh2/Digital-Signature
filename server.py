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

def signature_verification_phase(PUBKEY,SIGNEDMSG,VERSTATUS):
    m_decimal = int(SIGNEDMSG[0],2)
    print "Value of msg in decimal:- "
    print m_decimal
    print "\n"
    e_dash_decimal = int(SIGNEDMSG[1][0],16)%PUBKEY[0]
    print "value of e_prime in decimal:- "
    print e_dash_decimal
    print "\n"
    if SIGNEDMSG[1][1]>=0:
        s_dash=SIGNEDMSG[1][1]
    else:
        s_dash=(PUBKEY[0]-2)*(-1)*(SIGNEDMSG[1][1])
    r_star = (modulo(PUBKEY[2],s_dash,PUBKEY[0])*modulo(PUBKEY[3],e_dash_decimal*(PUBKEY[0]-2),PUBKEY[0]))%PUBKEY[0]
    print "Value of r* is:- "
    print r_star
    print "\n"
    h = SHA.new()
    h.update(str(SIGNEDMSG[0])+str(r_star))
    e_star = h.hexdigest()
    print "Value of e*:- "
    print e_star
    print "\n"
    e_star_decimal = int(h.hexdigest(),16)%PUBKEY[1]
    print "Value of e* in decimal:- "
    print e_star_decimal
    print "\n"
    if e_star==str(SIGNEDMSG[1][0]):
        VERSTATUS=1
    else:
        VERSTATUS=0
    return VERSTATUS

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
    accept_flag=1
    Portnum = int(input("Enter the port:- "))
    msg_flag=1
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print "Could not create socket"
        sys.exit()
    print "Socket is created"

    try:
        #host = socket.gethostname()
        host = '127.0.0.1'
    except socket.gaierror:
        print "Hostname could not be resolved"
        sys.exit()

    server_address = (host, Portnum)
    print 'starting up on %s port %s' % server_address
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as err:
        print err
        sys.exit()
    try:
        sock.bind(server_address)
    except socket.error:
        print "Binding of socket failed"
        sys.exit()
    print "Socket is binded"
    sock.listen(1)

    while True:
        print 'Waiting for incomming connection....'
        try:
            connection, client_address = sock.accept()
            #msg_flag=1
        except socket.error:
            print "Unable to accept the connection"
            sys.exit()
        if msg_flag==1:
            print 'Connection accepted from'+" "+str(client_address)
            msg_flag=0

        if accept_flag==1:
            accept_flag=0
            try:
                recv_data = recv_msg(connection)
                PUBKEY=[]
                temp = recv_data.split()
                for i in range(0,len(temp)):
                    PUBKEY.append(int(temp[i]))

            except socket.error:
                print "Unable to receive public elements from A"
                sys.exit()
            print "\n"
            print "Received public elements from A\n"
            print "Public key elements:- "
            print PUBKEY
            print "\n"
        try:
            recv_data = recv_msg(connection)
            SIGNEDMSG=[]
            temp=recv_data.split()
            SIGNEDMSG.append(str(temp[0]))
            SIGNEDMSG.append((temp[1],int(temp[2])))

        except socket.error:
            print "Unable to receive signed msg from A"
            sys.exit()
        print "Received signed msg from A\n"
        print "Message m in binary:- "
        print SIGNEDMSG[0]
        print "\n"
        print "Signed msg tuple:- "
        print SIGNEDMSG[1]
        print "\n"
        VERSTATUS=0
        VERSTATUS = signature_verification_phase(PUBKEY,SIGNEDMSG,VERSTATUS)
        print "Verification status to be sent:- "
        print VERSTATUS
        print "\n"
        try:
            send_data = send_msg(connection,str(VERSTATUS))
        except socket.error:
            print "Unable to send verification status to A"
            sys.exit()
        print "Verification status is send to A"
        print "\n"
        connection.close()

    sock.close()
