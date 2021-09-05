# -*- coding: utf-8 -*-
"""
Created on Sun May 24 00:28:17 2020

@author: Kashfun
"""

import hashlib as hl
import timeit
import optparse as op
from itertools import product
import string
import random

parser = op.OptionParser()

parser.add_option("-i", dest = "inputfile", help = "input file")
parser.add_option("-w", dest = "dictfile", help = "dictionary file")
parser.add_option("-o", dest = "outputfile", help = "output file")

(options, args) = parser.parse_args()

#parse each line in words5.txt into a list
dfile = options.dictfile
with open(dfile) as f1:
    lines = f1.read().splitlines()
    
#parse each line in 1004862-hash5.txt into a list
ifile = options.inputfile
with open(ifile) as f2:
    hash5 = f2.read().splitlines()

#output file
ofile = options.outputfile
f3 = open(ofile,"w+")

#hash all words in words5.txt
hashed = []
cracked = []
starttime = timeit.default_timer()
counter = 0
print("Dictionary attack in progress...")
f3.write("Dictionary attack\nHash = Cracked (plaintext)\n")
for i in range(len(lines)):
    hashed.append(hl.md5(lines[i].encode()).hexdigest())
    for n in range(len(hash5)):
        if hashed[i] == hash5[n]:
            cracked.append([hashed[i], i])
            counter += 1
            f3.write(hash5[n] + " = " + lines[i] + "\n")
endtime = timeit.default_timer()
print("Dictionary attack completed!")
print("Total number of hash values cracked: ", counter)
f3.write("\nTotal number of hash values cracked: " + str(counter))

print("Time taken for dictionary attack (s):", endtime - starttime)
f3.write("\nTime taken for dictionary attack (s):" + str(endtime - starttime))
f3.write("\n-----------------------------------------\n")

print("\n-----------------------------------------\n")

#brute-force attack
print("Generating list of combinations of lower alpha + digits of length 5 (lowerad)...")

#lower alpha + digits = lowerad, hash of lowerad = hashedlad
lowerad = []

for combo in product(string.ascii_lowercase + string.digits, repeat=5):
    lowerad.append(''.join(combo))
    
print("List of combinations generated.")

print("\n-----------------------------------------\n")

print("Brute-force attack in progress...")
f3.write("\nBrute-force attack\nHash = Cracked (plaintext)\n")
hashedlad = []
bfcracked = []
counter = 0
starttime = timeit.default_timer()
for j in range(len(lowerad)):
    hashedlad.append(hl.md5(lowerad[j].encode()).hexdigest())
    for m in range(len(hash5)):
        if hashedlad[j] == hash5[m]:
            bfcracked.append([hashedlad[j], j])
            counter += 1
            f3.write(hash5[m] + " = " + lowerad[j] + "\n")
            print("Current no. of hashes cracked: ", counter)
    if counter == 15:
        break
endtime = timeit.default_timer()
print("Brute-force attack completed!")
print("Total number of hash values cracked: ", counter)
f3.write("\nTotal number of hash values cracked: " + str(counter))

print("Time taken for brute-force attack (s):", endtime - starttime)
f3.write("\nTime taken for brute-force attack (s):" + str(endtime - starttime))

print("\nResults exported to " + ofile)

print("\n-----------------------------------------\n")

fpass6 = open("pass6.txt","w+")
fsalted6 = open("salted6.txt","w+")
hashedsalt = []
print("Salting in progress...")
for s in range(len(bfcracked)):
    newpass = str(bfcracked[s]) + random.choice(string.ascii_lowercase)
    bfcracked[s] = newpass
    fpass6.write(bfcracked[s] + "\n")
    hashedsalt.append(hl.md5(bfcracked[s].encode()).hexdigest())
    fsalted6.write(hashedsalt[s] + "\n")
print("Salting completed!")

fpass6.close()
fsalted6.close()

#close files
f1.close()
f2.close()
f3.close()
