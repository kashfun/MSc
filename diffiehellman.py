#Q1
from __future__ import print_function
import random
import math

prime = []

def isPrime(x):
    if x % 2 == 0 and x > 2: 
        return False
    for i in range(3, int(math.sqrt(x)) + 1, 2):
        if x % i == 0:
            return False
    return True

def genPrime():
    counter = 1000
    min = 100
    max = 1000
    
    while counter != 0:
        x = random.randint(min,max)
        # Number of prime numbers you want. Here, I want 2 prime numbers.
        if len(prime) < 2:
            if isPrime(x) == True:
                prime.append(x)
        else:
            break
        counter = counter-1

def gcd(a,b):
    while b != 0:
        a, b = b, a % b
    return a

def primRoots(modulo):
    coprime_set = {num for num in range(1, modulo) if gcd(num, modulo) == 1}
    return [g for g in range(1, modulo) if coprime_set == {pow(g, powers, modulo)
            for powers in range(1, modulo)}]

# Basic implementation of Diffie Hellman
# Variables Used
# Alice and Bob agree on Prime numbers P and Base G and this is known publically
genPrime()
sharedPrime = int(prime[0])	# p, where p is a Prime number
sharedBase = int(primRoots(sharedPrime)[0])  	# g, where g is a primitive root mod. 5 is a primitive root modulo of 23
 
aliceSecret = random.randint(1,1000) 	# a, where a is a secret key for Alice (integer)
bobSecret = random.randint(1,1000)  	# b, where b is a secret key for Bob (integer)
 
# Variables used
print( "Shared variables:") # Publicly known to Bob/Alice
print( "Publicly Shared Prime: " , sharedPrime )
print( "Publicly Shared Base:  " , sharedBase )
 
# A to B : Alice Sends Bob A = g^a mod p
A = (sharedBase**aliceSecret) % sharedPrime
print( "\n  Alice Sends Over Public Channel: " , A )

# B to A:  Bob Sends Alice B = g^b mod p
B = (sharedBase ** bobSecret) % sharedPrime
print( "\n  Bob Sends Over Public Channel: " , B )
 
print( "\n------------\n" )
print( "Privately Calculated Shared Secret:" )
# Alice Computes Shared Secret: s = B^a mod p
aliceSharedSecret = (B ** aliceSecret) % sharedPrime
print( "Alice Shared Secret: ", aliceSharedSecret )
 
# Bob Computes Shared Secret: s = A^b mod p
bobSharedSecret = (A**bobSecret) % sharedPrime
print( "Bob Shared Secret: ", bobSharedSecret )
 
if aliceSharedSecret == bobSharedSecret:
  print ("Privately shared secrets for both Alice and Bob are the same!")
