import os
import matplotlib
matplotlib.use('TkAgg')

class Counter:
    count = 0
    value = 0

    def __init__(self, count, value):
        self.count = count
        self.value = value

    def toString(self):
        return "Value: " + str(self.value) + "\tCount: " + str(self.count)

    def incrementCount(self, value):
        self.count += value


class OccurenceInFile:
    nameFile = ""
    counts: []

    def __init__(self, nameFile, counts):
        self.nameFile = nameFile
        self.counts = counts

    def setCounts(self, counts):
        self.counts = counts


def getIndexCounter(listPresence, value):
    for i in range(0, len(listPresence)):
        if listPresence[i].value == value: return i

    return -1


occurenceInFiles = []

filesPath = []
reportFilePath = "Files/output/report"

for path, subdirs, files in os.walk(reportFilePath):
    for name in files:
        filesPath.append(os.path.join(path, name))

for file in filesPath:
    listPresence = []
    with open(file, "r") as fp:
        lines = fp.readlines()
        lines.pop(0)
        for line in lines:
            firstNum, secondNum, thirdNum = map(int, line.split(sep="\t"))
            index = getIndexCounter(listPresence, thirdNum)
            if (index != -1):
                listPresence[index].incrementCount(1)
            else:
                listPresence.append(Counter(1, thirdNum))
    occurenceInFiles.append(OccurenceInFile(file, listPresence))

numFrame = 0
deltaTot = 0

listValue = []
listCount = []

for item in occurenceInFiles:
    print(item.nameFile)
    for i in range(0, len(item.counts)):
        numFrame += item.counts[i].count
        deltaTot += item.counts[i].count * item.counts[i].value

        listValue.append(int(item.counts[i].value))

        print(item.counts[i].toString())

ritardoMedio = deltaTot / numFrame

print("\n\n")
print("NUMFRAME: " + str(numFrame))
print("DELTATOT: " + str(deltaTot))
print("RITARDMEDIO: " + str(ritardoMedio))


listValueNoDuplicates = list(set(listValue))
listValueNoDuplicates.sort()


for i in range(0,len(listValue)):
    listCount.append(0)

for item in occurenceInFiles:
    for i in range(0, len(item.counts)):
        index = listValueNoDuplicates.index(item.counts[i].value)
        listCount[index]+=item.counts[i].count

listPercentuali = []
for count in listCount:
    listPercentuali.append(count*100/numFrame)

print("VALUE\tCOUNT\t%")
for i in range(0,len(listValueNoDuplicates)):
    print(str(listValueNoDuplicates[i])+"\t\t"+str(listCount[i])+"\t\t"+str(listPercentuali[i]))
