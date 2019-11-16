from os import listdir

# list of malware families to be classified as
families = [f for f in listdir("/data/arsa/unpacked_binaries")  if len([name for name in listdir("/data/arsa/unpacked_binaries/"+f)])>=10]
families = sorted(families, key=str.casefold)

fd = open("accuracy.csv", 'w+')
line = " "
for family in families:
    line = line + ", predicted_"+ family
line = line+ ", no_predicted_family \n"
fd.write(line)
fd.close()
