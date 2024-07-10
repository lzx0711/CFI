#!/usr/bin/env python
# coding: utf-8

# CS532-35S Cryptography and Data Security: Dr. Sherif Hashem
# Implementation of PHOTON-80/20/16 Variant
# Written By: Joseph Killian, Brandon Horton

# # PHOTON-80/20/16

# The following program is based upon the description of the PHOTON lightweight hash function as described in the paper:
# [1] J. Guo, T. Peyrin, and A. Poschmann, “The photon family of lightweight hash functions,” in Annual Cryptology Conference. Springer, 2011, pp. 222–239.
# 
# This is the 80/20/16 variant, meaning that the hash output size is 80 bits, the bitrate is 20 bits, and the output bitrate is 16 bits. \
    # Some of the values of matrices were taken from the appendix of the above paper [1] and some were obtained form the reference implementation from the website \
        # that the authors of [1] provided: https://sites.google.com/site/photonhashfunction/home

# # Internal Permutation Functions

# In[1]:


import numpy as np


# In[2]:


"""
This set of functions comprises the 4 operations that are carried out in the sequence: AddConstants, SubCells, ShiftRows,
MixColumnsSerial over 12 rounds, and the internal permutation function itself. Also contained is a lookup table function
that carries out multiplication GF(2^4), with the irreducible polynomial: x^4 + x + 1

"""


# This function applies round specific constants to the first column of the state matrix, each element
# of the first column of the internal state is XORed with the constants corresponding to the round of
# of the permutation, and returns the internal state

def AddConstants(r,d):
    #Table of constants taken from appendix of reference [1] 
    # S' [i, 0] = S[i, 0]⊕RC(v)⊕ICd(i) 
    # S:Internal State, RC:Round Constant, IC:Internal Constant
    RoundConstants = [[ 1, 3, 7,14,13,11, 6,12, 9, 2, 5,10],
                      [ 0, 2, 6,15,12,10, 7,13, 8, 3, 4,11],
                      [ 2, 0, 4,13,14, 8, 5,15,10, 1, 6, 9],
                      [ 7, 5, 1, 8,11,13, 0,10,15, 4, 3,12],
                      [ 5, 7, 3,10, 9,15, 2, 8,13, 6, 1,14]]
    distinctInternalConstants = [0, 1, 3, 6, 4]
    for i in range(0,5):
        d[i][0] = (d[i][0])^(RoundConstants[i][r])
    for j in range(0,5):
        d[j][0] = (d[j][0])^(distinctInternalConstants[j])
    return(d)

# This function performs a left circular shift of row each i, by i positions, and returns the internal state

def ShiftRows(d):
    output = np.empty((5,5),dtype = int)
    n = 0
    for i in range (0,5):
        for j in range(0,5):
            output[i][j] = d[i][(j+n)%5] 
        n+=1
    return(output)

# This function applies a 4 bit S-Box to each cell of the internal state, this implementation uses
# the PRESENT Sbox for 4 bits as provided in the appendix by the authors of reference [1], as well
# as in their reference implementation in [5], and returns the internal state

def SubCells(d):
    output = np.empty((5,5),dtype = int)
    #sbox values taken form the sample implementation of provided by reference [5]
    sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
    for i in range(0,5):
        for j in range(0,5):
            output[i][j] = sbox[(d[i][j])]
    return(output)

# This function is a simple lookup table for performing polynomial multiplication GF(2^4) with
# an irreducible polynomial: x^4 + x + 1. This function is utilized in the following
# MixColumnsSerial Function


def polyMult(a,b):    
    polynomialMult = [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15],
                      [0, 2, 4, 6, 8,10,12,14, 3, 1, 7, 5,11, 9,15,13],
                      [0, 3, 6, 5,12,15,10, 9,11, 8,13,14, 7, 4, 1, 2],
                      [0, 4, 8,12, 3, 7,11,15, 6, 2,14,10, 5, 1,13, 9], 
                      [0, 5,10,15, 7, 2,13, 8,14,11, 4, 1, 9,12, 3, 6],
                      [0, 6,12,10,11,13, 7, 1, 5, 3, 9,15,14, 8, 2, 4],
                      [0, 7,14, 9,15, 8, 1, 6,13,10, 3, 4, 2, 5,12,11],
                      [0, 8, 3,11, 6,14, 5,13,12, 4,15, 7,10, 2, 9, 1],
                      [0, 9, 1, 8, 2,11, 3,10, 4,13, 5,12, 6,15, 7,14],
                      [0,10, 7,13,14, 4, 9, 3,15, 5, 8, 2, 1,11, 6,12],
                      [0,11, 5,14,10, 1,15, 4, 7,12, 2, 9,13, 6, 8, 3],
                      [0,12,11, 7, 5, 9,14, 2,10, 6, 1,13,15, 3, 4, 8],
                      [0,13, 9, 4, 1,12, 8, 5, 2,15,11, 6, 3,14,10, 7],
                      [0,14,15, 1,13, 3, 2,12, 9, 7, 6, 8, 4,10,11, 5],
                      [0,15,13, 2, 9, 6, 4,11, 1,14,12, 3, 8, 7, 5,10]]
    return(polynomialMult[a][b])

# For this function, each column is multiplied by the aMatrix to produce the mixed column, So the formula
# for the new column is column[i] = aMatrix * column[i]. The values for the matrix were taken from
# the appendix of reference [1]

i = 30%9

def MixColumnsSerial(d):
    #aMatrix taken from appendix of reference [1]
    # Zi: 1 2 9 9 2 
    # A^5
    aMatrix = [[ 1, 2, 9, 9, 2],
               [ 2, 5, 3, 8,13],
               [13,11,10,12, 1],
               [ 1,15, 2, 3,14],
               [14,14, 8, 5,12]]
    a = aMatrix
    output = np.empty((5,5),dtype = int)
    m = 0
    for k in range(0,5):
        for i in range(0,5):
            sum = 0
            for j in range(0,5):
                sum = sum ^ polyMult(a[i][j],d[j][0 + m])
            output[i][k] = sum
        m += 1
    return(output)

# This is the actual internal permutation function that applies each of these 4 functions in the sequence of: AddConstants,
# SubCells, ShiftRows, and MixColumnsSerial. Twelve rounds of these function are applied back to back as in all versions
# of PHOTON, and the function returns the state after the permutation

def Permutation(state):
    for i in range(0,12):
        state = AddConstants(i,state)
        state = SubCells(state)
        state = ShiftRows(state)
        state = MixColumnsSerial(state)
    return(state)


# # Domain Extension Algorithm Functions

# In[3]:


"""
This set of functions composes all that is needed for the domain extension algorithm of PHOTON-80/20/16. The
Algorithm itself first appends a '1' bit to the end of the message, and as many zeros as necessary such that
the length of the message is a multiple of the bitrate of 20. This message is then broken up into chunks of 20
bits each, then each of those chunks is XORed with the first 20 bits of the internal state. Then a permutation
is applied, and the next chunk is applied to the internal state matrix. This process continues until all of the
chunks of the message are applied to the state matrix. This completes the absorbing phase of the algorithm.
Then 16 bits are extracted from the first four cells of the first row of the state matrix, and a permutation
is applied. Then 16 bits are further extracted and the process repeats until a total of 80 bits of output are
reached. This completes the squeezing portion of the algorithm and produces the output of the hash.

"""

# This function pads the message by appending a '1' bit to the message and as many zeros as necessary such that,
# the message is a multiple of the bitrate 20, and returns the padded message

def padMessage(m):
    m += "1"
    while((len(m)%20) != 0):
        m += "0"
    return(m)

# This function splits the raw message into four bit chunks so that the binary representation of the message can
# be converted into integers, and returns a list of the 4 bit binary representation of each integer

def splitMessage(m):
    mblocks = []
    i = 0
    while(len(m)!=i):
        mblocks.append(m[i:i+4])
        i+=4
    return(mblocks)

# This function converts the list of integers from splitMessage into integers, and returns a list of integers

def binToInt(m):
    mInt = []
    for i in range(0,len(m)):
        sum = 0
        if(m[i][0] == "1"):
            sum += 8
        if(m[i][1] == "1"):
            sum += 4
        if(m[i][2] == "1"):
            sum += 2
        if(m[i][3] == "1"):
            sum += 1
        mInt.append(sum)
    return(mInt)

# This function takes in the list of integers from binToInt and chunks them in blocks of 5 to match the bitrate
# of 20, and returns this list of chunks

def chunkMessage(m):
    i = len(m)/5
    j = 0
    chunk = []
    while(j<i):
        chunk.append(m[(5*j):(5*j + 5)])
        j += 1
    return(chunk)

# This function takes a chunk of the padded message and XORs it with the first row of the internal state matrix,
# and returns that state after the chunk has been absorbed into the state

def absorb(chunk,state):
    for i in range(0,5):
        state[0][i] = (state[0][i]) ^ (chunk[i])
    return(state)

# This function squeezes out 16 bits of output from the first 4 cells of the first row of the internal state matrix,
# and returns the outputted bits, and the altered state matrix with the extracted bits

def squeeze(state):
    output = []
    for i in range(0,4):
        output.append(state[0][i])
        state[0][i] = 0
    return(output,state)

# This function converts the outputted integers from the squeeze function, and converts them back to binary to return
# the final hash output

def convertOutput(output):
    convert = ["0000", "0001", "0010", "0011","0100", "0101", "0110", "0111",
               "1000", "1001", "1010", "1011","1100", "1101", "1110", "1111"]
    convertedOutput = ""
    for i in range(0,4):
        j = ""
        n = output[i]
        j = convert[n]
        convertedOutput += j
    return(convertedOutput)


# # PHOTON-80/20/16 Lightweight Hash Function

# In[4]:


"""
This function combines the above Internal Permutation and Domain Extension Algorithm to produce the PHOTON-80/20/16
lightweight hash function. The Domain extension algorithm is carried out and the internal permutation is carried out
in-between each squeezing and absorbing phase. Then the final 80 bit output of the hash is returned
"""

def Photon_80_20_16(message, length):
    
    #initial state matrix taken from the appendix of reference [1] 
    state = [[ 0,  0,  0,  0,  0],
             [ 0,  0,  0,  0,  0],
             [ 0,  0,  0,  0,  0],
             [ 0,  0,  0,  0,  1],
             [ 4,  1,  4,  1,  0]]
    
    #Message is broken up into 20 bit chunks
    m = padMessage(message)
    
    m = splitMessage(m)
    
    m = binToInt(m)
    
    m = chunkMessage(m)
    
    #message is absorbed into the state matrix
    for i in range(0,len(m)):
        state = absorb(m[i],state)
        state = Permutation(state)
        
    #message is squeezed out into an output size of 80 bits
    intermediateOutput = []
    for i in range(0,5):
        output,state = squeeze(state)
        intermediateOutput.append(output)
        state = Permutation(state)
    
    #The output of the hash function is converted back to its binary bits
    finalOutput = ""
    cutted_output = ""
    # part_length = int(length)/4
    for i in range(0,5):
        finalOutput += convertOutput(intermediateOutput[i])
        # cutted = finalOutput[int(part_length):int(part_length)*2]
        # cutted_output += cutted
    cutted_output = finalOutput[:int(length)//2] + finalOutput[-int(length)//2:]
    

    return(cutted_output)


# # PHOTON-80/20/16 Examples

# Here are some various outputs of the hash function based on some different input messages

# In[5]:
'''

message1 = "101001010100001010111001010011110000001010101001001011001100000010010110100110101010000000000011110101010101"
hashValue1 = Photon_80_20_16(message1)
print("The hash value of the message is: ",hashValue1)


# In[6]:


message2 = "1"
hashValue2 = Photon_80_20_16(message2)
print("The hash value of the message is: ",hashValue2)


# In[7]:


message3 = "000000000"
hashValue3 = Photon_80_20_16(message3)
print("The hash value of the message is: ",hashValue3)


# In[8]:


message4 = "0"
hashValue4 = Photon_80_20_16(message4)
print("The hash value of the message is: ",hashValue4)


# In[9]:


message5 = "11111111111"
hashValue5 = Photon_80_20_16(message5)
print("The hash value of the message is: ",hashValue5)

'''