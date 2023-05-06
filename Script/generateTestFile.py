import os
import random

datasetFilePath = "Files/input/dataset/clean/"
testDirPath = "Files/input/Test/"
fileNameWithExtensionList = []
fileNameList = []

numSamples = 10
numRowsTest = [10,100,1000,10000]
numRowsFile=[]



for path in os.listdir(datasetFilePath):
    if os.path.isfile(os.path.join(datasetFilePath, path)):
        fileNameWithExtensionList.append(path)
        fileNameList.append(path.replace(".txt", ""))
        with open(datasetFilePath+path, 'r') as fp:
            numRowsFile.append((len(fp.readlines()))-2)

print(numRowsFile)
i=0
for fileName in fileNameWithExtensionList:
    print("Processing file: "+fileName+"\n")
    for numRows in numRowsTest:
        if numRows < numRowsFile[i]:
            for j in range(1,numSamples):
                lineStart = random.randint(1,numRowsFile[i]-numRows)
                lineEnd = lineStart+numRows
                with open(datasetFilePath+fileName, 'r') as fp:
                    lines = []
                    for k, line in enumerate(fp):
                        if k in range(lineStart,lineEnd):
                            lines.append(line.strip()+"\n")
                        elif k > lineEnd:
                            break
                    fout = open(testDirPath+fileNameList[i]+"/"+str(numRows)+"/test_"+fileNameList[i]+"_["+str(lineStart)+","+str(lineEnd)+"]"+"_"+str(j)+".txt","w")
                    fout.writelines(lines)
                    fout.close()
    i+=1
