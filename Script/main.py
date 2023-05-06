import os
import shutil
import signal
import subprocess
import time

def sendAndLogFrame(inputFileName):

    src_path = inputFileName
    dst_path = "./test.txt"
    shutil.copy(src_path, dst_path)

    outputFileCanplayerName = "frametimeToSend.txt"

    extension = ".log"
    candumpLogsFilePath = "Files/output/temp/candumpLog/"
    canplayerLogsFilePath = "Files/output/temp/canplayerLog/"

    currentTimestamp = time.time()
    candumpLogName = "candump_" + str(currentTimestamp)
    canplayerLogName = "canplayer_" + str(currentTimestamp)

    candumpLogFullPathFileName = candumpLogsFilePath + candumpLogName + extension
    canplayerLogFullPathFileName = canplayerLogsFilePath + canplayerLogName + extension

    processCandump = subprocess.Popen("candump -t d -L vcan0 > " + candumpLogFullPathFileName, stdout=subprocess.PIPE,
                                      shell=True, preexec_fn=os.setsid)
    os.system("./canplayer -r")
    time.sleep(1)
    processCandump.send_signal(signal.SIGINT)
    os.killpg(os.getpgid(processCandump.pid), signal.SIGTERM)

    shutil.move(outputFileCanplayerName, canplayerLogFullPathFileName)

    f1 = open(canplayerLogFullPathFileName, "r")
    f2 = open(candumpLogFullPathFileName, "r")

    framesTime = []
    realFrameTime = []

    for line in f1:
        framesTime.append(int(line))

    for line in f2:
        realFrameTime.append(int(line.split(")")[0][1:].replace(".", "")))

    f3 = open("Files/output/report/" + inputFileName.replace("Files/input/Test/","").split("t")[0]+ "report_te" + inputFileName.replace("Files/input/Test/","").split("te")[1], "w")

    f3.write("Frametime\t\t\tRealTime\t\t\tDifference\n")
    for i in range(0, len(framesTime)):
        difference = realFrameTime[i] - framesTime[i]
        f3.writelines(str(framesTime[i]) + "\t" + str(realFrameTime[i]) + "\t" + str(difference) + "\n")
    f1.close()
    f2.close()
    f3.close()

numFile = 0
rootdir = 'Files/input/Test/'
for file in os.listdir(rootdir):
    d = os.path.join(rootdir, file)
    if os.path.isdir(d):
        for file2 in os.listdir(d):
            d2 = os.path.join(d,file2)
            if os.path.isdir(d2):
                for path in os.listdir(d2):
                    if os.path.isfile(os.path.join(d2+"/", path)):
                        numFile+= 1

print("NUMFILE: "+str(numFile))

rootdir = 'Files/input/Test/'
i=0
for file in os.listdir(rootdir):
    d = os.path.join(rootdir, file)
    if os.path.isdir(d):
        for file2 in os.listdir(d):
            d2 = os.path.join(d,file2)
            if os.path.isdir(d2):
                for path in os.listdir(d2):
                    if os.path.isfile(os.path.join(d2+"/", path)):
                        i+=1
                        print("Processing: "+d2+"/" + path+"\t\t\t"+str(i)+"/"+str(numFile))
                        with open(d2+"/" + path, 'r') as fp:
                            sendAndLogFrame(d2+"/" + path)
