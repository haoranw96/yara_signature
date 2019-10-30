from os import listdir

# list of malware families to be classified as
families = [f for f in listdir("../unpacked_binaries")]

fd = open("confusion_matrix.csv", 'w+')
line = " "
for family in families:
    line = line + ", "+ family
line = line+ "\n"
fd.write(line)
fd.close()