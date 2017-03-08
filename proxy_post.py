#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import urlparse
import sys
from thread import *

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 8000               # Arbitrary non-privileged port


def server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP socket
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(500)
    print "Serving at %s" % PORT
    while 1:
        try:
            conn, addr = s.accept()
            handle_connection(conn)
        except KeyboardInterrupt:
            print "Bye..."
            break


def getline(conn):
    line = ''
    while 1:
        buf = conn.recv(1)
        if buf == '\r':
            line += buf
            buf = conn.recv(1)
            if buf == '\n':
                line += buf
                return line
        # elif buf == '':
        #     return
        else:
            line += buf
            



def get_header(conn):

    headers = ''
    
    while 1:
        line = getline(conn)
        if line is None:
            break
        if line == '\r\n':
            break
        else:
            headers += line
    return headers


def get_postParm(conn):
    buffer = conn.recv(4096)
    return buffer
    
def parse_header(raw_headers):
    request_lines = raw_headers.split('\r\n')
    first_line = request_lines[0].split(' ')
    method = first_line[0]
    full_path = first_line[1]
    version = first_line[2]
    
    ind = full_path.find("http")
    http_full_path = full_path[ind:]
    # print "new full path :", http_full_path
    print "%s %s" % (method, full_path)
    (scm, netloc, path, params, query, fragment) \
        = urlparse.urlparse(http_full_path, 'http')
    i = netloc.find(':')
    if i >= 0:
        address = netloc[:i], int(netloc[i + 1:])
    else:
        address = netloc, 80
    print "address: ", address
    print "netloc: ", netloc
    return method, version, scm, address, path, params, query, fragment


def handle_connection(conn):

    req_headers = get_header(conn)
    
    print "RAW REQ_HEADER: ", req_headers
    
    if req_headers is None:
        return
    method, version, scm, address, path, params, query, fragment = \
        parse_header(req_headers)
    
    
    print "method: ", method
    print "version: ", version
    print "scm: ", scm
    print "address: ", address
    print "params: ", params
    print "query: ", query
    print "fragment: ", fragment
    
    
    #message, paramters, Content-Type, Host, Connection = get_postParm()
    pair = get_postParm(conn)
    
    
    path = urlparse.urlunparse(("", "", path, params, query, ""))
    print "path: ", path

    #print "PATH! ", httpPath

    req_headers = " ".join([method, path, version]) + "\r\n" +\
        "\r\n".join(req_headers.split('\r\n')[1:])
    
    #print "req_headers before! ", req_headers 
    

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    
    print "address! ", address
    try:
        soc.connect(address)
        print "Good connection!!"
    except socket.error, arg:
        conn.sendall("HTTP/1.1" + str(arg[0]) + " Fail\r\n\r\n")
        conn.close()
        soc.close()
    else: 
        print "req_headers:  ", req_headers
        
        """
        if req_headers.find('Connection') >= 0:
            req_headers = req_headers.replace('keep-alive', 'close')
        else:
            req_headers += req_headers + 'Connection: close\r\n'
        """
    

        req_headers += '\r\n'
        req_headers += pair
        req_headers +='Connection: close'
        
        soc.sendall(req_headers)

        data = ''
        while 1:
            try:
                buf = soc.recv(8129)
                data += buf
            except:
                buf = None
            finally:
                if not buf:
                    soc.close()
                    break
        print "DATA!", data

        conn.sendall(data)
        conn.close()
        
        
if __name__ == '__main__':
    server(HOST, PORT)
