# Tool for the replication of datasets of CAN frames on virtual socket respecting the timescales 

## History
This project is my [thesis](/Thesis/Tesi_Brighenti_Patrik.pdf) that i've done to achieve my bachelor's degree at the [Università degli studi di Modena e Reggio Emilia](https://www.unimore.it/)

## Canplayer
A change has been made to the source code of Canplayer. A "-r" command line parameter has been added. By starting the program with this option, the replication of the dataset on the socket will be performed with particular precautions (with real time programming techniques).

## Scripts
The scripts take care of:

- generateTestFile.py: &emsp;Extract subdatasets from a dataset
- main.py:             &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;Carry out various simulations with "canplayer -r" on the previously extracted datasets logging the frames in transit with the Candump program
- analizeReport.py     &emsp;&emsp; Extrapolate statistical data on the simulations performed

## Dataset
The dataset with was tested the project is avaiable at this [link](https://ocslab.hksecurity.net/Dataset/CAN-intrusion-dataset).
The clean dataset is composed of 7 different CAN traces, including more than 8 million CAN messages corresponding to approximately 90 minutes of CAN traffic. 
The CAN traces are gathered in different driving sessions performed on different road types (urban, suburban, and highway), traffic conditions, weather conditions and geographical areas (plain, hill, and mountain), and by activating many different control commands. The CAN traces include ID, DLC, and payloads of each CAN data frame associated to its relative timestamp.

## Usage
In order to run this project, we have to:

1. Compile the program canplayer.c in the current directory
2. Setting up a virtual CAN Interface with the comands "ip link add dev vcan0 type vcan" & "ip link set up vcan0"
3. Run the scripts in order as they are list in the previous section.

## Documentation
An exhaustive description of the changes made, the methods of use and the results obtained is accessible by consulting the pdf of the thesis

