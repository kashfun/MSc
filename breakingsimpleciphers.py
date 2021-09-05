#!/usr/bin/env python
# Skeleton for Security Tools Lab 1 - Simple ciphers
# Student ID: 1004862
# StudentName: Muhammad Kashfun Nazir Bin Mohd Ali

# IP: 10.1.1.10     Port: 5000
# run cmd as administrator for ping function to work

import binascii as b
import requests
import json
import hashlib
import argparse
# import collections used for substitution method
import collections as c
import os

# unused method
def xorString(s1,s2):
    """ 
        XOR two strings with each other, return result as string
    """
    rval = [ord(a) ^ ord(b) for a,b in zip(s1,s2)]
    return ''.join([chr(r) for r in rval])


def resolvePlainChallenge():
    """
        Solution of plain challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type': 'application/json'}

    r = requests.get(url + 'challenges/plain')
    data = r.json()
    print("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    a = data['challenge'][2:]
    s = bytearray.fromhex(a).decode()

    payload = {'cookie': data['cookie'], 'solution': s}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url + 'solutions/plain', headers=headers, data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)


def resolveCaesarChallenge():
    """
        Solution of caesar challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type' : 'application/json'}

    r = requests.get(url + 'challenges/caesar')
    data = r.json()
    print("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    s=data['challenge'][2:]
    s = b.unhexlify(s)
    
    # shift counter
    shift = 0
    
    # array for possible answers
    ans = []
    
    print("\nPerforming brute-force...")
    # extended ASCII has 256 characters
    for i in range(255):
        # declare solution variable
        solution = ''
        
        # shift by 1
        shift += 1
        
        for j in s:
            char = chr((j + shift) % 255)
            solution += char
        
        # append answer to array
        ans.append(solution)
        
        # set answer payload
        payload = { 'cookie' : data['cookie'], 'solution' : ans[i]}
        
        # send payload to server to check answer
        r = requests.post(url+'solutions/caesar', headers=headers,data=json.dumps(payload))
        
        # if answer is correct (response contains "correct..."), end loop
        if "correct..." in r.text:
            print('After %i attempts...' % i)
            break
    
    # moved payload and r into for loop
    #payload = { 'cookie' : data['cookie'], 'solution' : solution}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    #r = requests.post(url+'solutions/caesar', headers=headers,data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)

def resolvesubstitutionChallenge():
    """
        Solution of substitution challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type' : 'application/json'}

    r = requests.get(url + 'challenges/substitution')
    data = r.json()
    #print ("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    challenge = data['challenge'][2:]
    
    # break challenge string into separate hex characters
    hexlist = []
    pair = 2
    for i in range(pair, len(challenge)+pair,pair):
        hexlist.append(challenge[i-pair:i])
    
    # calculate the frequency
    freqCounter = c.Counter(hexlist)
    # sort by most frequent hex characters
    freq = freqCounter.most_common()
    
    # sorted list of most frequent hex characters
    sortedhexelements = []
    for i in range(len(freq)):
        sortedhexelements.append(freq[i][0])
        
    '''
    frequent characters using only lowercase letters and symbols [space] , \n . - ' ?
    sort by most frequent characters based on Google
    [space] is the most frequent character and e is most frequent letter
    try most frequent letters in English: e t a o h n i s r d l u w m c g f y p v k b j x z q
    add the symbols
    '''
    #freq_char = [" ","e","t","a","o","i","n","s","r","h","l","d","c","u","m","f","p","g","w","y","b","v","k","x","j","q","z",",","\n",".","-","\'","?"]
    
    '''
    looks like some characters are in place, but still gibberish.
    watching the lecture again, I noticed the story seems a bit like fiction
    so, next, I referenced most frequent letters in general fiction from http://letterfrequency.org/
    the letters are: e t a o h n i s r d l u w m c g f y p v k b j x z q
    '''
    #freq_char = [" ","e","t","a","o","h","n","i","s","r","d","l","u","w","m","c","g","f","y","p","v","k","b","j","x","z","q",",","\n",".","-","\'","?"]
    
    '''
    makes more sense now. first word is lrttle, which I assume should be little.
    I will shift the letters and symbols around to see what fits better through trial and error
    substitue letters with those that would make sense and shift those that don't further back
    '''
    #freq_char = [" ","e","t","a","o","h","n","r","s","i","d","l","u",",","\n","w","m","c","g","f","y","p",".","v","k","b","j","x","z","q","-","\'","?"]
    #freq_char = [" ","e","t","o","a","h","n","r","s","i","d","l","u",",","\n","w","m","c","g","y","f","p",".","v","k","b","j","q","-","\'","?","x","z"]
    #freq_char = [" ","e","t","o","a","h","r","n","d","i","s","l","u",",","\n","w","m","c","g","y","f","p",".","v","k","b","j","q","-","\'","?","x","z"]
    #freq_char = [" ","e","t","o","a","h","r","n","d","i","s","l","w","g","\n","u","m","c",",","y","f","p",".","b","v","k","j","q","-","\'","?","x","z"]
    #freq_char = [" ","e","t","o","a","h","r","n","d","i","s","l","w","g","\n",",","u","y","c","m","f","p",".","b","v","k","j","q","-","\'","?","x","z"]
    #freq_char = [" ","e","t","o","a","h","r","n","d","i","s","l","w","g","u",",","\n","y","c","m","f","p",".","b","v","k","j","q","-","\'","?","x","z"]
    #freq_char = [" ","e","t","o","a","h","r","n","d","i","s","l","w","g","u",",","\n","y","c","m","f","p",".","b","v","k","-","\'","j","q","?","x","z"]
    
    '''
    getting close. almost all characters look in place. there were some other trial and errors amongst above.
    below is the correct freq_char order
    FINALLY DONE! Took so much of my time!
    '''
    
    # characters sorted by frequency
    freq_char = [" ","e","t","o","a","h","r","n","d","i","s","l","w","g","u",",","\n","y","c","m","f","p",".","b","v","k","-","\'","j","?","q","x","z"]
    
    # create list of tuples of values to be replaced in this format: (existing,new)
    assignlist = []
    for i in range(len(sortedhexelements)):
        assignlist.append((sortedhexelements[i],freq_char[i]))
    
    # replace every hexlist elements with "new" characters
    newhexlist = []
    for i in range(len(hexlist)):
        for j in range(len(assignlist)):
            if assignlist[j][0] == hexlist[i]:
                newhexlist.append(assignlist[j][1])
    
    # join all elements in the list to form a string to return to server
    solution = (''.join(newhexlist))
    
    payload = { 'cookie' : data['cookie'], 'solution' : solution}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url+'solutions/substitution', headers=headers,data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)

def resolveotpChallenge():
    """
        Solution of otp challenge
    """
    url = "http://{}:{}/".format(IP, PORT)
    headers = {'Content-Type' : 'application/json'}

    r = requests.get(url + 'challenges/otp')
    data = r.json()
    #print ("[DEBUG] Obtained challenge ciphertext: %s with len %d" % (data['challenge'], len(data['challenge'])))

    # TODO: Add a solution here (conversion from hex to ascii will reveal that the result is in a human readable format)
    challenge = data['challenge'][2:]
    # convert hex to int
    challenge_int = int(challenge,16)
    
    # known text from lecture
    known_text = "Student ID 1000000 gets 0 points"
    # get hex value
    known_hex = b.hexlify(known_text.encode())
    # convert hex to int
    known_int = int(known_hex,16)
    
    # to get key, xor challenge int with known text int
    key = challenge_int ^ known_int
    
    # modify student id and points
    mod_text = "Student ID 1004862 gets 6 points"
    # get hex value
    mod_hex = b.hexlify(mod_text.encode())
    # convert hex to int
    mod_int = int(mod_hex,16)
    
    # xor modified int with key
    solution = key ^ mod_int
    # convert int to hex to submit to server
    solution = hex(solution)[2:]

    payload = { 'cookie' : data['cookie'], 'solution' : solution}
    print("[DEBUG] Submitted solution is:")
    print(json.dumps(payload, indent=4, separators=(',', ': ')))

    r = requests.post(url+'solutions/otp', headers=headers,data=json.dumps(payload))
    print("[DEBUG] Obtained response: %s" % r.text)

def parseArgs():               
    """ 
        Function for arguments parsing
    """
    aparser = argparse.ArgumentParser(description='Script demonstrates breaking of simple ciphers: Caesar, Substitution cipher, and OTP.', formatter_class = argparse.RawTextHelpFormatter) 
    aparser.add_argument('--port', required=True, metavar='PORT', help='Port of challenge/response server.')
    aparser.add_argument('--ip', required=True, metavar='PORT', help='Port of challenge/response server.')
    aparser.add_argument("--mode", required=True, choices = ['p', 'c', 's', 'o'], help="p => demonstrates hexadecimal encoding challenge.\
                         \nc => demonstrates breaking of the Caesar cipher.\
                         \ns => demonstrates breaking of the Substitution cipher.\
                         \no => demonstrates breaking of the OTP cipher.")
    args = aparser.parse_args()
    
    return args


def main():
    args = parseArgs()

    global IP
    IP = args.ip
    
    host = IP #example
    response = os.system("ping -n 1 " + host)
    
    #and then check the response...
    if response == 0:
      print(host, 'is up!')
    else:
      print(host, 'is down! Please enter valid IP.')
      exit()

    global PORT
    PORT = args.port

    if args.mode == "o":
        resolveotpChallenge()
    elif args.mode == "p":
        resolvePlainChallenge()
    elif args.mode == "c":
        resolveCaesarChallenge()
    elif args.mode == "s":
        resolvesubstitutionChallenge()

if __name__ == '__main__':
    main()