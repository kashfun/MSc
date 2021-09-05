#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Nov 22 23:22:33 2019

@author: Kash
"""

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
    min = 100001
    max = 999999999
    
    while counter != 0:
        x = random.randint(min,max)
        # Number of prime numbers you want. Here, I want 2 prime numbers.
        if len(prime) < 2:
            if isPrime(x) == True:
                prime.append(x)
        else:
            break
        counter = counter-1
    
    print (str(prime)[1:-1])
    
genPrime()