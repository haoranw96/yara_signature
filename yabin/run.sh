#!/bin/bash 

rm global.rule
for f in ../unpacked_binaries/* 
do 
    family=$(echo $f | awk -F '/' '{print $3}')
    num_file=$(($(ls -l $f | wc -l) + 0))

    # ignore malware families which have less than 10 samples
    if [ "$num_file" -gt 10 ]
    then 
	echo $f " has " $num_file " malware samples"
       	rm -r train_$family && rm -r test_$family
	mkdir train_$family && mkdir test_$family

	num_train=`echo "$num_file*0.8" |bc | xargs printf "%.0f"`
	echo $num_train
	cd $f
	cp  `ls |sort -R |tail -$num_train`  ../../yabin/train_$family
	ls ../../yabin/train_$family > ../../yabin/train.txt
	rsync -avrP --exclude-from='../../yabin/train.txt' ./ ../../yabin/test_$family 
	cd ../../yabin
	python2.7 yabin.py -y train_$family >> $family".rule"
	python2.7 yabin.py -m train_$family
	cat $family".rule">>global.rule

	for k in test_$family/*
	do
	    python2.7 yabin.py -s $k > result
	done

    else
	echo "ignore malware family $family"
    fi
done