#!/bin/bash 

for f in ../unpacked_binaries/* 
do 
    family=$(echo $f | awk -F '/' '{print $3}')
    num_file=$(($(ls -l $f | wc -l) + 0))

    # ignore malware families which have less than 10 samples
    if [ "$num_file" -gt 10 ]
    then 
	echo $f " has " $num_file " malware samples"
       	rm -r train && rm -r test
	mkdir train && mkdir test

	num_train=`echo "$num_file*0.8" |bc | xargs printf "%.0f"`
	echo $num_train
	cd $f
	cp  `ls |sort -R |tail -$num_train`  ../../yabin/train
	ls ../../yabin/train > ../../yabin/train.txt
	rsync -avrP --exclude-from='../../yabin/train.txt' ./ ../../yabin/test 
	cd ../../yabin
	python2.7 yabin.py -yh train >> $family".rule"
    else
	echo "ignore malware family $family"
    fi
done