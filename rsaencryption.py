#Q2
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
    min = 1
    max = 999
    
    while counter != 0:
        x = random.randint(min,max)
        # Number of prime numbers you want. Here, I want 2 prime numbers.
        if len(prime) < 2:
            if isPrime(x) == True:
                prime.append(x)
        else:
            break
        counter = counter-1

def gcd(a, b):
	while b:
		a, b = b, a%b
	return a

def modinv(a,m):
	g,x,y = egcd(a,m)
	if g != 1:
		return None
	else:
		return x%m

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def genKey(k):
        key = genPrime(k)
        return key
    
# pubKey = e
def encrypt(pubKey, msg, n):
    ctxt = (msg**pubKey) % n
    return ctxt

#privKey = d
def decrypt(privKey, ctxt, n):
    msg = (ctxt**privKey) % n
    return msg

genPrime()
p = prime[0]
q = prime[1]
n = p*q
phi = (p-1)*(q-1)
r = random.randint(2,100) # For efficiency 2 < e < 100
while True:
	if gcd(r, phi) == 1:
		break
	else:
		r += 1
e = r
d = modinv(e, phi)

# Message can only be in int
msg = int(input("Enter integer: "))

print("Message imput:", msg)
emsg = encrypt(e, msg, n)
print("Encrypted message:", emsg)
dmsg = decrypt(d, emsg, n)
print("Decrypted message:", dmsg)
 