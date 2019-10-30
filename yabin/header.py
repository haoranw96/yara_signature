from os import listdir
import os

# list of malware families to be classified as
families = [f for f in listdir("../unpacked_binaries") if len([name for name in listdir("../unpacked_binaries/"+f)])>10]

fd = open("confusion_matrix.csv", 'w+')
line = " "
for family in families:
    line = line + ", "+ family
line = line+ ", no_family \n"
fd.write(line)
fd.close()