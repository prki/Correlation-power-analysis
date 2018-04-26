# -*- coding: utf-8 -*-
"""
@author: Marek Pikna
Correlation power analysis attack on AES-128.
Note: Depending on the traces which were taken, it is important to choose the
relevant part of the traces on which to attack in readTraces() function.
It is possible to attack on the entire power trace, but is nevertheless
quite ineffective.
"""

import matplotlib.pyplot as plt
import numpy as np
import struct
from joblib import Parallel, delayed
import multiprocessing

sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

corrKeyList = [0 for x in range(16)]


"""
Reads input plaintext. Plaintext is saved in hex numbers in strings, separated 
by whitespaces.
Returns a 2D list of inputs.
@param skipInput - amount of inputs which should be skipped
"""
def readInputs(fileIn, count, skipInput = None):
    lineInput = []
    inputs = []
    lineCnt = 0

    if skipInput != None:
        for _ in range(skipInput):
            next(fileIn)

    for line in fileIn:
        for word in line.split():
            lineInput.append(int(word, 16))
        inputs.append(lineInput.copy()) #list.copy() returns a shallow copy
        lineInput.clear()
        lineCnt = lineCnt + 1
        if lineCnt == count:
            break

    return inputs


"""
Reads traces. Traces are saved in a binary file, one right after the other.
Only the interesting part of the trace for the attack is read - the
start is skipped and so is the entire AES process (the attack targets
the first SubBytes operation)
@return a 2D list of traces.
@param count - count of traces to be read, depending on the amount of input
               read.
@param skipInput - amount of traces which should be skipped
"""
def readTraces(fileIn, count, skipInput = None):
    traceLength = 280000 #New traces, subject to change depending on traces
    start = 12000 #New traces, subject to change depending on traces
    length = 9000 #New traces, subject to change depending on traces
    traces = []
    traceInt = []

    if skipInput != None:
        fileIn.seek(traceLength * skipInput)

    for i in range(0, count):
        fileIn.seek(start, 1)
        for j in range(0, length):
            #struct unpack returns a one-item tuple in this case, cast to int
            traceInt.append(int(struct.unpack("B", fileIn.read(1))[0]))
        fileIn.seek(traceLength - (start + length), 1)
        traces.append(traceInt[:])
        traceInt.clear()

    return traces 


"""
Applies Gaussian noise to each trace. Mean and standard deviation
of the normal distribution are sent as parameters.
"""
def applyNoiseToTraces(traces, mean, stddev):
    traceLen = len(traces[0]) #length of a row - amount of samples to generate
    for i in range(len(traces)):
        samples = np.random.normal(mean, stddev, traceLen)
        traces[i] = np.add(traces[i], samples)

    print("Gaussian noise with mean:", mean, "and standard deviation:", stddev, "has been applied to traces.")


"""
Cuts bits off of the traces by AND-ing a mask with the trace
value.
"""
def applyMaskToTraces(traces, mask):
    traces = np.bitwise_and(traces, mask)
    print("The mask", bin(mask), "has been applied to the traces.")

    return traces


"""
Evaluates correlation coefficient between all rows.
Source: http://stackoverflow.com/questions/30143417/computing-the-correlation-coefficient-between-two-multi-dimensional-arrays
"""
def corr2_coeff(A,B):
    # Rowwise mean of input arrays & subtract from input arrays themeselves
    A_mA = A - A.mean(1)[:,None]
    B_mB = B - B.mean(1)[:,None]

    # Sum of squares across rows
    ssA = (A_mA**2).sum(1);
    ssB = (B_mB**2).sum(1);

    # Finally get corr coeff
    return np.dot(A_mA,B_mB.T)/np.sqrt(np.dot(ssA[:,None],ssB[None]))


"""
Generates a correlation matrix R checking correlation between the
hypothetical power consumption and the actual power traces.
"""
def genCorrMatrix(powerModelMat, traces):
    powerModelMatTr = np.transpose(powerModelMat)
    tracesTr = np.transpose(traces)

    return np.array(corr2_coeff(powerModelMatTr, tracesTr))


"""
Returns a matrix of hypothetical power consumption H based on the
Hamming distance model. Targeted spot is the first SubBytes operation,
thus checking the Hamming distance between the hypothetical intermediate
values before SubBytes and afterwards.
HD(v') = HW(v xor v')
"""
def genPowerMatHD(postSubBytes, preSubBytes):
    powerMatrix = np.bitwise_xor(postSubBytes, preSubBytes)

    for i in range(len(postSubBytes)):
        for j in range(len(postSubBytes[i])):
            powerMatrix[i][j] = bin(powerMatrix[i][j]).count("1")

    return powerMatrix


"""
Returns a matrix of hypothetical power consumption H based on the
Hamming weight model. Targeted spot are the results from the first
SubBytes operation.
"""
def genPowerMatHW(postSubBytes):
    powerMatrix = np.empty([len(postSubBytes), len(postSubBytes[0])])

    for i in range(len(postSubBytes)):
        for j in range(len(postSubBytes[i])):
            powerMatrix[i][j] = bin(postSubBytes[i][j]).count("1")

    return powerMatrix


"""
Finds partial guessing entropy of a specific run.
"""
def evalGuessEntropy(corrMatrix, corrKeyList, subkeyToFind, keyFound):
    probabilityList = []
    ge = -2
    corrKey = corrKeyList[subkeyToFind]

    for i in range(0, len(corrMatrix)):
        #find maximum of a row
        absArray = np.absolute(corrMatrix[i])
        maxval = max(absArray)
        tup = maxval, i
        probabilityList.append(tup[:])

    #sort probabilityList according to maxval
    probabilityList.sort(key=lambda tup:tup[0], reverse=True)

    #find index - PGE
    for i in range(0, len(probabilityList)):
        if probabilityList[i][1] == corrKey:
            ge = i 
            break
 
    return ge


"""
Function finding a subkey used in AES-128. Puts the subkey
into a keyList list at the correct position.
@param corrKeyList = None: For guessing entropy evaluation, correct
       key list is provided in order to evaluate it. Not needed
       otherwise.
"""
def findCorrKey(subkeyToFind, nptraces, count, inputs, foundKeyList, corrKeyList = None, PGEList = None):
    hypIntermVals = []
    keys = list(range(0, 256))
    i = subkeyToFind

    #step 1 - evaluate hypothetical intermediate values
    subBytMatrix = [[0 for x in range(256)] for x in range(count)]
    for j in range(0, count):
        arr = np.bitwise_xor(inputs[j][i], keys) #AddRoundKey
        hypIntermVals.append(arr)
        for k in arr:
            subBytMatrix[j][k] = sbox[arr[k]]

    #step 2 - create power model matrix - using the Hamming distance/Hamming weight model
    #powerModelMat = genPowerMatHD(subBytMatrix, hypIntermVals)
    powerModelMat = genPowerMatHW(subBytMatrix)

    #step 3 - generate correlation matrix
    correlationMatrix = np.absolute(genCorrMatrix(powerModelMat, nptraces))

    #step 4 - find the highest corr value in the matrix, add it to keyList
    index = np.argmax(correlationMatrix)
    corrKey = int(index / len(correlationMatrix[0])) #row - key hypothesis, find the row with highest correlation
    foundKeyList[subkeyToFind] = corrKey

    #step 5 - unnecessary, evaluate guessing entropy for this run (find position
    #         of the correct key)
    ge = -1
    if corrKeyList != None:
        ge = evalGuessEntropy(correlationMatrix, corrKeyList, subkeyToFind, corrKey)
        PGEList[subkeyToFind] = ge


"""
Appends the PGE result into fileName.
"""
def writePGEResult(fileName, PGEList):
    try:
        fileOut = open(fileName, "a")
    except IOError:
        print("Could not open PGE output file.")
        return -1

    for i in range(0, len(PGEList)):
        fileOut.write(str(PGEList[i]) + ' ')

    fileOut.write('\n')
    fileOut.close()

    return 0


"""
@param inputs - Plaintext inputs
@param traces - Power traces corresponding to plaintext inputs
@param count - Number of inputs/power traces.
"""
def CPAAttack(inputs, traces, count):
    nptrace = np.array(traces).astype(int)
    nptraces = nptrace[0:count, :]
    corrKeyList = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff] #Subject to change depending on the correct key list
    for i in range(0, count):
        nptraces[i] = nptraces[i] - np.mean(nptraces[i])

    manager = multiprocessing.Manager()
    foundKeyList = manager.list(range(16))
    PGEList = manager.list(range(16))
    Parallel(n_jobs=-1)(delayed(findCorrKey)(i, nptraces, count, inputs, foundKeyList, corrKeyList, PGEList) for i in range(16))

    print("Keys found from", count, "traces:")
    for i in range(16):
        print("Subkey", i, "=", foundKeyList[i], "hex:", hex(foundKeyList[i]), "partial guessing entropy:", PGEList[i])


    """PGE."""
    #writePGEResult("./PGE_results_cutbits/pge-30-400-4th-10000000.txt", PGEList) #UNCOMMENT TO LOG RESULTS


def main():
    #Read inputs
    try:
        fileInputs = open("../Measurements/4000/plaintext.txt", "r")
    except IOError:
        print("Could not open input file.")
        return 1;
    
    inputsCount = 400
    skipInputs = 0 #Change to choose a specific range of inputs/traces to read.
    inputs = readInputs(fileInputs, inputsCount, skipInputs)

    #Read traces
    try:
        fileTraces = open("../Measurements/4000/traces.bin", "rb")
    except IOError:
        print("Could not open traces file.")
        fileInputs.close()
        return 1;

    traces = readTraces(fileTraces, inputsCount, skipInputs)

    #applyNoiseToTraces(traces, 0, 20) #(UN)COMMENT TO REMOVE NOISE
    #traces = applyMaskToTraces(traces, 7) #(UN)COMMENT TO REMOVE MASK

    CPAAttack(inputs, traces, inputsCount)
    #for i in range(30, inputsCount+1): #Loops in order to create a file containing PGE of each run on a smaller part of traces.
    #    CPAAttack(inputs, traces, i)
 
    fileInputs.close()
    fileTraces.close()


if __name__ == "__main__":
    main()
