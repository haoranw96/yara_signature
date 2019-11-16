# yara_signature

This project uses Yabin from https://github.com/AlienVault-OTX/yabin to create signatures for executable code within malware.


## Clone Repo

```
$ git clone https://github.com/haoranw96/yara_signature.git
```

## Install dependency

```
$ pip3 install pefile
```

## To Run

```
# To run for data in /data/arsa/unpacked_binaries/ change directory to yabin
$ cd yabin
$ chmod +x run.sh
$ ./run.sh

# To run for data in  /data/arsa/unpacked_binaries_unipacker/ change directory to yabin_2
$ cd yabin_2
$ chmod +x run.sh
$ ./run.sh

# To run for code sections of /data/arsa/unpacked_binaries_unipacker/ change directory to yabin_code_section
$ cd yabin_code_section
$ chmod +x run.sh
$ ./run.sh
```

## Following files and folders are created: 
1. siganature/  
  This folder contains yara signatures for different families created from training malware samples. 

  Each file in this folder containing yara rule:


> rule tight__data_arsa_unpacked_binaries_waledac {  
> strings:  
>  $a_2 = { 558bec83ec0c894df46830314000ff15 }  
>  $a_3 = { 558bec51ff75086a00ff151430400050 }  
>  $a_4 = { 558beca11043400083e0017518a11043 }  
>  $a_5 = { 558bec83ec54566a4433f68d45ac5650 }  
>  $a_6 = { 558bec83ec205357ff750833db5333ff }  
> condition:  
>  any of them  
>}  

  Which are generated with hunt mechanism (https://github.com/AlienVault-OTX/yabin#hunt-for-code-re-use-amongst-malware) and can be used to identify similar samples of malware. 

2. result/  
  This folder contains matches of hashes from testing files and hashes from training files. 
  
  Each file in the folder are as following: 
  
  > Found related samples:  
  > 803723719a8b7a8544989103b49af1a2 matched via 558b0300940800a400fca0f3a600fc0d  
  > 1b0ed7d4d1fe05784d36f15798d0e3fb matched via 558b0300940800a400fca0f3a600fc0d  
  
  Which are generated with hunt mechanism (https://github.com/AlienVault-OTX/yabin#running-yabin)

3. true_pos.csv  
  This file contains accuracy of prediction for different families and the number of testing samples in the family. 
  
  family | true positive percentage | number of testing samples
  --------|-------------------------|------------------------------
  Family A | % of Family A gets predicted as Family A     |    Number of samples in family

4. confusion_matrix.csv  
  This file contains the confusion matrix of prediction.  
  
  &nbsp; | Family A                | Family B                    | ...  
  -------|-------------------------|-----------------------------|--------------------  
  Family A | number of Family A gets predicted as Family A | number of Family A gets predicted as Family B | ...  
  Family B | number of Family B gets predicted as Family A | number of Family B gets predicted as Family B | ...  
  ... | &nbsp; | &nbsp; |...
  
 5. accuracy.csv  
  This file contains the percentages of a family gets pecited as a family. 
 
  &nbsp; | Family A                | Family B                    | ...  
  -------|-------------------------|-----------------------------|--------------------  
  Family A | percentage of Family A gets predicted as Family A | percentage of Family A gets predicted as Family B | ...  
  Family B | percentage of Family B gets predicted as Family A | percentage of Family B gets predicted as Family B | ...  
  ... | &nbsp; | &nbsp; |...
