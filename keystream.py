#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Feb 24 02:49:10 2020

@author: Kash
"""

#pip install bitstring
import bitstring as bs

def next(x):
  x = (x & 1) << N+1 | x << 1 | x >> N-1
  y = 0
  for i in range(N):
    y |= RULE[(x >> i) & 7] << i
  return y

#Take in file and 32 byte key values
def extend_keystream(file, key):
    #Convert to bytes type to convert to int
    keybytes = key.tobytes()
    #Convert to int
    extkeystream = int.from_bytes(keybytes, 'little')
    for i in range(len(file)//N-1):
        extkeystream = next(extkeystream)
        #Append to keybytes (bytes type)
        keybytes += extkeystream.to_bytes(N_BYTES, 'little')
    return keybytes

def prevv(x):
  x = (x & 1) >> N+1 | x >> 1 | x << N-1
  y = 0
  for i in range(N):
    y |= RULE[(x >> i) & 7] << i
  return y

def rev_keystream(key):
    #Convert to bytes type to convert to int
    keybytes = key.tobytes()
    
    #Convert to int
    extkeystream = int.from_bytes(keybytes, 'little')
    keybytes = prevv(extkeystream)
    keybytes = keybytes.to_bytes(N_BYTES, 'little')
    return keybytes

RULE = [86 >> i & 1 for i in range(8)]
IRULE = [86 << i & 1 for i in range(8)]
N_BYTES = 32
N = 8 * N_BYTES

#Open files
fpt = bs.BitArray(filename='mssd.txt')
fen = bs.BitArray(filename='mssd.txt.enc')
fsc = bs.BitArray(filename='super_cipher.py.enc')
fgif = bs.BitArray(filename='hint.gif.enc')

#Derive key by fpt XOR fen
inikey = fpt ^ fen[0:len(fpt)]

#Decrypt fen by fen XOR inikey
dec = fen[0:len(inikey)] ^ inikey

#Write decrypted content from mssd.txt to mssddec.txt
f = open('mssddec.txt','wb')
dec.tofile(f)

#Decrypt py script partially
dsc = fsc[0:len(inikey)] ^ inikey

#Write partial python file based on initial key
fdsc = open('sc.py','wb')
dsc.tofile(fdsc)

#First 32 bytes of initial key
inikey2 = fpt[0:N] ^ fen[0:N]

#Generate key for full python file
newkey = extend_keystream(fsc, inikey2)
newkey = bs.BitArray(newkey)

#Decrypt py script fully
dscfull = fsc ^ newkey

#Write full python file
fdscfull = open('sc1.py','wb')
dscfull.tofile(fdscfull)

#Generate key for full gif file
newkey = extend_keystream(fgif, inikey2)
newkey = bs.BitArray(newkey)

#Decrypt gif fully
dgiffull = fgif ^ newkey

#Write full gif file
ffgif = open('hint.gif','wb')
dgiffull.tofile(ffgif)


curr = rev_keystream(inikey2)
print(curr)

