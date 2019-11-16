#!/bin/bash 

# print header of confusion matrix
python3 header_accuracy.py
# iterate through each malware family
for f in /data/arsa/unpacked_binaries/*
do
  # get the name of family and number of files
  family=$(echo $f | awk -F '/' '{print $5}')
  num_file=$(($(ls $f | wc -l) + 0))
  # ignore malware families which have less than 10 samples
  if [ "$num_file" -ge 10 ]
  then
    # for each test file, search for samples related to this file
	  #for k in test_$family/*
	  #do
	  #  python2.7 yabin.py -s $k >> result_$family
	  #done

    # produce confusion matrix
    sed "s/XXXXXXXXX/$family/g" accuracy.py > accuracy_$family.py
    python3 accuracy_$family.py
    # rm $family.py
    # rm result_$family
    # rm -r test_$family
    # rm -r train_$family
  fi
done
