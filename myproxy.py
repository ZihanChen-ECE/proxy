#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import urlparse
import sys
from thread import *

HOST = ''                
LOCALHOST = '127.0.0.1'
PORT = 8000             
MAX_BUFF = 4096
MAX_LISTEN = 500

def main_server(host, port):
    """
    Main function, work as the proxy server
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP socket
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(MAX_LISTEN)
    print "Serving at %s" % PORT
    # polling for connection from client
    while 1:
        try:
            conn, addr = s.accept()
            #handle_connection(conn)
            start_new_thread(handle_connection, (conn,))
        except KeyboardInterrupt:
            print "Bye..."
            break
    s.close()
                        
def getline(conn):
    """
    helper function
    """
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
    """
    This function create the raw header
    """
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
    """
    This function deals with key-value pair
    """
    buffer = conn.recv(MAX_BUFF)
    return buffer
    
    
def parse_header(raw_headers):
    """
    This function is preprocessing the raw header
    """
    request_lines = raw_headers.split('\r\n')
    first_line = request_lines[0].split(' ')
    method = first_line[0]
    full_path = first_line[1]
    version = first_line[2]
    
    ind = full_path.find("http")
    http_full_path = full_path[ind:]

    (scm, netloc, path, params, query, fragment) \
        = urlparse.urlparse(http_full_path, 'http')
    i = netloc.find(':')
    if i >= 0:
        address = netloc[:i], int(netloc[i + 1:])
    else:
        address = netloc, 80
    return method, version, scm, address, path, params, query, fragment            
           
            
def handle_connection(conn):
    """
    This function could deal with either get or post
    """
    
    # Parse the header for socket.sendall
    req_headers = get_header(conn)    
    
    if req_headers is None:
        return
    method, version, scm, address, path, params, query, fragment = \
        parse_header(req_headers)
    
    # deal with the key-value pair of post
    pair = ''
    if method == 'POST':
        pair = get_postParm(conn)
        
    path = urlparse.urlunparse(("", "", path, params, query, ""))

    req_headers = " ".join([method, path, version]) + "\r\n" +\
        "\r\n".join(req_headers.split('\r\n')[1:])

    # initial the TCP socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        soc.connect(address)
        print "Good TCP connection!!"
    except socket.error, arg:
        conn.sendall("HTTP/1.1" + str(arg[0]) + " Fail\r\n\r\n")
        conn.close()
        soc.close()
    else: 
        
        # complete the request header with k-v pair and connection:close
        req_headers += '\r\n'
        req_headers += pair
        req_headers +='Connection: close'
        # send the header and display the data to client
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
    
        conn.sendall(data)
        conn.close()
        
        
if __name__ == '__main__':
    main_server(HOST, PORT)