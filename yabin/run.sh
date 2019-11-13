#!/bin/bash 

# empty whitelist and malware database
python2.7 yabin.py -d
# rm global.rule
rm *.rule

# iterate through each malware folder
for f in /data/arsa/unpacked_binaries_unipacker/* 
do
  # get the name of family and number of files
  family=$(echo $f | awk -F '/' '{print $5}')
  num_file=$(($(ls $f | wc -l) + 0))

  # ignore malware families which have less than 10 samples
  if [ "$num_file" -ge 10 ]
  then
    echo $f has $num_file malware files
    # rm -r train_$family && rm -r test_$family
    mkdir train_$family && mkdir test_$family

    # split folder in to train files (80%) and test files (20%)
    num_train=`echo "$num_file*0.8" |bc | xargs printf "%.0f"`
	  echo $num_train train files
	  echo $((num_file - num_train)) test files
	  cd $f
	  # randomly sort the files and copy last 80% to train
	  cp  `ls |sort -R |tail -$num_train`  ~/yara_signature/yabin_2/train_$family
	  ls ~/yara_signature/yabin_2/train_$family >  ~/yara_signature/yabin_2/train.txt
	  # copy all the files not in train into test
	  rsync -ar --exclude-from='/home/haoran/yara_signature/yabin_2/train.txt' ./ ~/yara_signature/yabin_2/test_$family
	  cd ~/yara_signature/yabin_2

	  # generate yara signature
	  python2.7 yabin.py -y train_$family >> $family".rule"
	  # put the yara signature into malware database
	  python2.7 yabin.py -m train_$family
	  # cat $family".rule">>global.rule
  else
	  echo "ignore malware family $family"
  fi
done

# print header of confusion matrix
python3 header.py
# print header of accuracy matrix
python3 header_accuracy.py
# print header of true positive matrix 
echo "family, true positive percentage, number of testing samples" > true_pos.csv
# iterate through each malware family
for f in /data/arsa/unpacked_binaries_unipacker/*
do
  # get the name of family and number of files
  family=$(echo $f | awk -F '/' '{print $5}')
  num_file=$(($(ls $f | wc -l) + 0))
  # ignore malware families which have less than 10 samples
  if [ "$num_file" -ge 10 ]
  then
    # for each test file, search for samples related to this file
	  for k in test_$family/*
	  do
	    python2.7 yabin.py -s $k >> result_$family
	  done

    # produce confusion matrix
    sed "s/XXXXXXXXX/$family/g" confusion_matrix.py > $family.py
    python3 $family.py
    rm $family.py
    # rm result_$family
    # rm -r test_$family
    # rm -r train_$family
  fi
done
