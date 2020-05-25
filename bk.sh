#!/bin/bash
#typically the first line of the bash scripts
BACKUPTIME=`date +%b-%d-%y` 
#get the current date
DESTINATION=/home/usr/path/backup-$BACKUPTIME.tar.gz 
#create a backup file using the current date in it's name
SOURCEFOLDER=/home/usr/path/data_folder 
#the folder that contains the files that we want to backup
tar -cpzf $DESTINATION $SOURCEFOLDER 
#create the backup
