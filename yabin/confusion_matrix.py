from os import listdir
import fnmatch

count = dict()		# count of malwares classified to different families
percentage = dict()		# percentage of malwares classified to different families
num_files = 0		# number of XXXXXXXXX malware files

# list of malware families to be classified as
families = [f for f in listdir("/data/arsa/unpacked_binaries_unipacker") if len([name for name in listdir("/data/arsa/unpacked_binaries_unipacker/"+f)])>=10]
families = sorted(families, key=str.casefold)

for f in families:
	count.update({f:0})
count.update({'no_family':0})

# open file of results of related samples for the malware family
try: 
	fd = open("result_XXXXXXXXX", "r")
except: 
	exit(0)
# votes for family of the test file by signatures
vote_family = dict()

for l in fd.readlines():
	if 'Found related samples:' in l:
		# use majority votes to determine malware family
		max_family = None
		max_vote = 0

		# find max vote family
		# print(vote_family)
		for k, v in vote_family.items():
			if v > max_vote:
				max_vote = v
				max_family = k

		# if a malware file has been voted
		if max_vote > 0:
			count[max_family] += 1
			num_files += 1

		# update vote_family with 0 for next the malware file
		for f in families:
			vote_family.update({f: 0})
		vote_family.update({'no_family': 0})
	elif 'No related samples found' in l:
		count['no_family'] += 1
	else:
		*other, signature = l.split()
		# find the family.rule file that contains the signature
		for file in listdir('.'):
			if fnmatch.fnmatch(file, '*.rule'):
				with open(file) as f:
					if 'global' not in file:
						if signature in f.read():
							family = file[:-5]
							try: 
								vote_family[family] += 1
							except: 
								vote_family['no_family'] += 1
							break
fd.close()

# determine family of the last malware file
# use majority votes to determine malware family
max_family = None
max_vote = 0

# find max vote family
# print(vote_family)
for k, v in vote_family.items():
	if v > max_vote:
		max_vote = v
		max_family = k

try:
	count[max_family] += 1
except:
	max_family = 'no_family'
num_files += 1

for k, v in count.items():
	percentage.update({k: round(v/num_files*1.0, 4)})

# append to confusion matrix csv
#fd = open("confusion_matrix.csv", 'a+')
#line = "actual_XXXXXXXXX"
#for value in count.values():
#        line = line + ", " + str(value)
#line = line+ "\n"
#fd.write(line)
#fd.close()

# append to true positive csv
fd = open("true_pos.csv", 'a+')
line = "XXXXXXXXX, "
line = line+ str(percentage["XXXXXXXXX"]*100) + "%, "+ str(num_files) +"\n"
fd.write(line)
fd.close()

# append to accuracy csv
#fd = open("accuracy.csv", 'a+')
#line = "actual_XXXXXXXXX"
#for value in percentage.values():
#        line = line + ", " + str(value)
#line = line+ "\n"
#fd.write(line)
#fd.close()
