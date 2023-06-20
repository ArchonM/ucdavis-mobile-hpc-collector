#!/bin/bash

# test mode: 1 means on, 0 means off. other number or type will lead to error
test_mode=0

# Head Section

# Global variable and definitions. Change the variables to fit your needs.
# event_group='L1-icache-load-misses,dTLB-load-misses,iTLB-load-misses'
# event_group='L1-dcache-stores,branch-loads,L1-dcache-loads'
# event_group='L1-dcache-store-misses,branch-misses,cache-misses'
event_group='raw-br-retired,branch-load-misses,L1-dcache-load-misses'
# event_group='iTLB-loads,dTLB-loads,cache-references'
# Initialization and define comman folder path.
cd ./$(dirname $0)
work_path=$(pwd)
if [ $test_mode == 1 ]; then
    benign_folder_path=$work_path/testfiles/benign
    malware_folder_path=$work_path/testfiles/malware
    output_folder_path=$work_path/testfiles/output
elif [ $test_mode == 0 ]; then
    benign_folder_path=$work_path/app_lib/benign
    malware_folder_path=$work_path/app_lib/malware
    all_app_folder_path=$work_path/app_lib
    output_folder_path=$work_path/../output
else
    echo "test mode is not defined or out of range"
    echo "please use 1 or 0 only for test_mode (line 4)"
    exit 1
fi

# Functions Section

function user_check() {
    while true
    do
        read -r -p "Are these correct? [Y/n] " input
        case $input in
            [yY][eE][sS]|[yY])
                echo "Yes"
                break
                ;;
            [nN][oO]|[nN])
                echo "No"
                exit 1
                ;;
            *)
                echo "Invalid input..."
                ;;
        esac
    done
}

function path_detection() {
    if [[ ! -d "$1" ]]; then
        echo "$1 not found"
        echo "creating......"
        mkdir $1
    fi
    echo -e "\e[1;31m${1}\e[0m"
}

function print_x_axis() {  
    local Line= Title= Bytes= Xlength=  
  
    Title="$*"  
    Line='='  
  
    if [ -n "${Title}" ]; then  
        Bytes=$(echo "${Title}"|wc -c)  
    else  
        Bytes=1  
    fi  
  
    Xlength=$(( $(stty size|awk '{print $2}') - ${Bytes} ))  
    # printf '%s ' "${Title}"  
    printf "%${Xlength}s\n" "${Line}"|sed "s/ /${Line}/g"  
}

function list_files_test_mode() {
    files=$(ls $1)
    if [ ! -n "$files" ]
    then
        echo "None"
    else
        for filename in $files
        do
            echo -e "\e[1;31m$filename\e[0m"
        done
    fi
    print_x_axis
}

function check_environment() {
    if [ $test_mode == 1 ]; then
        echo -e "\e[1;31mTest mode enabled.\e[0m"
    fi

    echo "The current working path is: "
    echo -e "\e[1;31m${work_path}\e[0m"
    echo "The path to Benign Applications folder is: "
    # path_detection $benign_folder_path
    echo "The path to Malicious Applications folder is: "
    # path_detection $malware_folder_path
    echo "The path to the Output Folder is: "
    path_detection $output_folder_path
    # path_detection $output_folder_path/benign
    # path_detection $output_folder_path/malware

    user_check
    print_x_axis

    if [ $test_mode == 1 ]; then
        echo "Benign applications to be profiled (test mode):"
        list_files_test_mode $benign_folder_path
        echo "Malware applications to be profiled (test mode):"
        list_files_test_mode $malware_folder_path
    fi

    user_check
    print_x_axis
}

function cellphone_setup() {
    echo "Setting stay awake"
    adb shell settings put global stay_on_while_plugged_in 3
    print_x_axis
}

function simpleperf() {
    # the function of profile requires packagename($1) that is currently running
    # , the event_group($2), and the filename($3)
    adb shell "su -c '/data/local/tmp/simpleperf stat --app $1 -e $2 --duration\
     5  --interval 10 -o /data/local/tmp/${3}'"
}

function subfolder_profile() {
    subfolders=$(ls $1)
    echo $subfolders
    for subfolder in $subfolders
    do
        files=$(ls $1/$subfolder)
        for file in $files
        do
            filepath=$1/$subfolder/$file
            if test -f $filepath; then
                pkg=$(aapt dump badging $filepath|awk -F" " '/package/ {print $2}'|awk -F"'" '/name=/ {print $2}')
                act=$(aapt dump badging $filepath|awk -F" " '/launchable-activity/ {print $2}'|awk -F"'" '/name=/ {print $2}')
                # echo $filepath
                # echo $pkg/$act
                if [ -z $act ]; then
                    act=".LauncherActivity"
                fi
                adb install $filepath

                {
                    adb shell "su -c '/data/local/tmp/simpleperf stat --app $pkg -e $event_group --duration 30  --interval 1 -o /data/local/tmp/${file%.apk}'"
                }&
                {
                    sleep 1
                    # adb shell am start -n $pkg/$act
                    adb shell monkey -p $pkg -v 1 &
                    sleep 1
                    adb shell input tap 1000 2100
                    sleep 1
                    pid=$(adb shell pidof $pkg)
                    simpleperf_pid=$(adb shell pidof simpleperf)
                    if [ -z $pid ];then
                        adb shell su -c "kill ${simpleperf_pid}"
                    fi
                }&
                wait

                if ! test -d $output_folder_path/$subfolder;then
                    mkdir $output_folder_path/$subfolder
                fi
                if ! test -d ./app_lib_used/$subfolder;then
                    mkdir ./app_lib_used/$subfolder
                fi

                adb pull /data/local/tmp/${file%.apk} $output_folder_path/$subfolder/${file%.apk}
                adb shell rm /data/local/tmp/${file%.apk}
                if test -f $output_folder_path/$subfolder/${file%.apk};then
                    mv $filepath ./app_lib_used/$subfolder/$file
                fi
                adb uninstall $pkg
            else
                echo $filepath
                echo "Failed"
            fi
            
        done
    done
}

function profile() {
    subfolders=$(ls $1)
    for file in $subfolders
    do
        filepath=$1/$subfolder/$file
        if test -f $filepath; then
            pkg=$(aapt dump badging $filepath|awk -F" " '/package/ {print $2}'|awk -F"'" '/name=/ {print $2}')
            act=$(aapt dump badging $filepath|awk -F" " '/launchable-activity/ {print $2}'|awk -F"'" '/name=/ {print $2}')
            # echo $filepath
            # echo $pkg/$act
            if [ -z $act ]; then
                act=".LauncherActivity"
            fi
            adb install $filepath

            {
                adb shell "su -c '/data/local/tmp/simpleperf stat --app $pkg -e $event_group --duration 20  --interval 10 -o /data/local/tmp/${file%.apk}'"
            }&
            {
                sleep 1
                # adb shell am start -n $pkg/$act
                adb shell monkey -p $pkg -v 1 &
                sleep 1
                adb shell input tap 1000 2100
                sleep 1
                pid=$(adb shell pidof $pkg)
                simpleperf_pid=$(adb shell pidof simpleperf)
                if [ -z $pid ];then
                    adb shell su -c "kill ${simpleperf_pid}"
                fi
            }&
            wait

            if ! test -d $output_folder_path/$subfolder;then
                mkdir $output_folder_path/$subfolder
            fi
            if ! test -d ./app_lib_used/$subfolder;then
                mkdir ./app_lib_used/$subfolder
            fi

            adb pull /data/local/tmp/${file%.apk} $output_folder_path/$subfolder/${file%.apk}
            adb shell rm /data/local/tmp/${file%.apk}
            if test -f $output_folder_path/$subfolder/${file%.apk};then
                mv $filepath ./app_lib_used/$subfolder/$file
            fi
            adb uninstall $pkg
        else
            echo $filepath
            echo "Failed"
        fi
    done
}
# Body Section

# Check environment:
check_environment
# Set up cellphone:
cellphone_setup

subfolder_profile $all_app_folder_path
# subfolder_profile $malware_folder_path
