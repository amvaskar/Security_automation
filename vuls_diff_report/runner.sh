#!/bin/bash

base_result_location="/home/ubuntu"
product_name=$1
report_type=".json"

cd $base_result_location
mkdir -p Recent_file
recent_file_folder="Recent_file"
recent_file=$base_result_location/$recent_file_folder/$product_name$report_type

mkdir -p Previous_file
previous_file_folder="Previous_file" 
previous_file=$base_result_location/$previous_file_folder/$product_name$report_type


#file_location="/home/ubuntu/workspace/Security_VulsScan_Logpoint/ansible_vuls/vuls_diff_report"
file_location=$2
cd $file_location

python comparejson.py -r $recent_file -p $previous_file -l $file_location -rf $recent_file_folder -pf $previous_file_folder --createJiraTicket no --email yes
