import os
import shutil
import pandas as pd
from collections import Counter


# Tools to verify each application has been fully profiled
benign_raw = [[], [], [], [], [], [], []]
malware_raw = [[], [], [], [], [], [], []]

# get benign package names which have been profiled


def get_benign_raw():
    folder_name = "./src/benign";
    for subdir, dirs, files in os.walk(folder_name):
        for file in files:
            if file != ".DS_Store":
                group_num = int(file[-2]);
                benign_raw[group_num].append(file.split('-')[0]);

# get malware packaged names which have been profiled


def get_malware_raw():
    folder_name = "./src/malware";
    for subdir, dirs, files in os.walk(folder_name):
        for file in files:
            if file != ".DS_Store":
                if file[-2].isdigit():
                    group_num = int(file[-2]);
                    malware_raw[group_num].append(file.split('-')[0]);
                else:
                    print("\n\nIrregular file:");
                    print(file);
                    print("\n\n");


def find_missing(raw_list):
    list_all = []
    for i in range(0, 7):
        diff = [element for element in raw_list[i] if element not in list_all];
        list_all.extend(diff);
    for i in range(0, 7):
        for element in list_all:
            if element not in raw_list[i]:
                print("event_group" + str(i) + " does not contain:");
                print(element);


# step 0: env set up
benign_dict = {}  # Contains package_name and file_name
malware_dict = {}

def set_up():
    folder_name = "./src/benign"
    for subdir, dirs, files in os.walk(folder_name):
        for file in files:
            if file != ".DS_Store":
                package_name = file.split('-')[0]
                if package_name in benign_dict.keys():
                    benign_dict[package_name].append(file);
                else:
                    benign_dict[package_name] = [file];

    folder_name = "./src/malware"
    for subdir, dirs, files in os.walk(folder_name):
        for file in files:
            if file != ".DS_Store":
                package_name = file.split('-')[0];
                if package_name in malware_dict.keys():
                    malware_dict[package_name].append(file);
                else:
                    malware_dict[package_name] = [file];


# step 1: combine raw data to one csv file
def raw_to_csv_benign(package_name):
    dfs = []
    for file in benign_dict[package_name]:
        file_name = "./src/benign/" + file
        events = []
        with open(file_name, 'r') as f:
            buf = f.readline()
            while buf:
                buf = buf.strip()
                buf = buf.replace(',', '')
                if buf.split(' ')[0].isdigit():
                    while buf.split(' ')[0].isdigit():
                        events.append(buf.split()[1])
                        buf = f.readline()
                        buf = buf.strip()
                        buf = buf.replace(',', '')
                    break
                buf = f.readline()
        dict_list = []
        with open(file_name, 'r') as f:
            buf = f.readline()
            while buf:
                buf = buf.strip()
                buf = buf.replace(',', '')
                if buf.split(' ')[0].isdigit():
                    dict_tmp = {}
                    while buf.split(' ')[0].isdigit():
                        dict_tmp[buf.split()[1]] = buf.split()[0]
                        buf = f.readline()
                        buf = buf.strip()
                        buf = buf.replace(',', '')
                    dict_list.append(dict_tmp)
                buf = f.readline()

        df_tmp = pd.DataFrame(dict_list, columns=events)
        dfs.append(df_tmp)

    row_num = len(dfs[0])
    for df in dfs:
        if len(df) < row_num:
            row_num = len(df)
    result = pd.concat([dfs[0].iloc[:row_num], dfs[1].iloc[:row_num],
                        dfs[2].iloc[:row_num], dfs[3].iloc[:row_num],
                        dfs[4].iloc[:row_num], dfs[5].iloc[:row_num],
                        dfs[6].iloc[:row_num]], axis=1)
    result['package_name'] = package_name;
    result['label'] = "benign";
    result_filename = "./output/single_csv/benign/" + package_name + ".csv";
    result.to_csv(result_filename, index=False)

def raw_to_csv_malware(package_name):
    dfs = []
    for file in malware_dict[package_name]:
        file_name = "./src/malware/" + file
        events = []
        with open(file_name, 'r') as f:
            buf = f.readline()
            while buf:
                buf = buf.strip()
                buf = buf.replace(',', '')
                if buf.split(' ')[0].isdigit():
                    while buf.split(' ')[0].isdigit():
                        events.append(buf.split()[1])
                        buf = f.readline()
                        buf = buf.strip()
                        buf = buf.replace(',', '')
                    break
                buf = f.readline()
        dict_list = []
        with open(file_name, 'r') as f:
            buf = f.readline()
            while buf:
                buf = buf.strip()
                buf = buf.replace(',', '')
                if buf.split(' ')[0].isdigit():
                    dict_tmp = {}
                    while buf.split(' ')[0].isdigit():
                        dict_tmp[buf.split()[1]] = buf.split()[0]
                        buf = f.readline()
                        buf = buf.strip()
                        buf = buf.replace(',', '')
                    dict_list.append(dict_tmp)
                buf = f.readline()

        df_tmp = pd.DataFrame(dict_list, columns=events)
        dfs.append(df_tmp)

    row_num = len(dfs[0])
    for df in dfs:
        if len(df) < row_num:
            row_num = len(df)
    result = pd.concat([dfs[0].iloc[:row_num], dfs[1].iloc[:row_num],
                        dfs[2].iloc[:row_num], dfs[3].iloc[:row_num],
                        dfs[4].iloc[:row_num], dfs[5].iloc[:row_num],
                        dfs[6].iloc[:row_num]], axis=1)
    result['package_name'] = package_name;
    result['label'] = "malware";
    result_filename = "./output/single_csv/malware/" + package_name + ".csv";
    result.to_csv(result_filename, index=False)

# step 2: distribute csv files
def split_csv_files():

    benign_list = [];
    malware_list = [];
    folder_name = "./output/single_csv/";
    benign_dir = folder_name + "benign";
    malware_dir = folder_name + "malware";

    for subdir, dirs, files in os.walk(benign_dir):
        for file in files:
            if file != ".DS_Store":
                benign_list.append(file);

    for subdir, dirs, files in os.walk(malware_dir):
        for file in files:
            if file != ".DS_Store":
                malware_list.append(file);

    print(os.getcwd());
    print(benign_list);
    print(malware_list);
    num_benign_training = int(len(benign_list) * 0.7);
    num_malware_training = int(len(malware_list) * 0.7);

    for i in range(0, num_benign_training):
        ori_file_name = "./output/single_csv/benign/" + benign_list[i];
        dest_file_name = "./output/benign_training/" + benign_list[i];
        shutil.copyfile(ori_file_name, dest_file_name);
    for i in range(num_benign_training, len(benign_list)):
        ori_file_name = "./output/single_csv/benign/" + benign_list[i];
        dest_file_name = "./output/benign_testing/" + benign_list[i];
        shutil.copyfile(ori_file_name, dest_file_name);

    for i in range(0, num_malware_training):
        ori_file_name = "./output/single_csv/malware/" + malware_list[i];
        dest_file_name = "./output/malware_training/" + malware_list[i];
        shutil.copyfile(ori_file_name, dest_file_name);
    for i in range(num_malware_training, len(malware_list)):
        ori_file_name = "./output/single_csv/malware/" + malware_list[i];
        dest_file_name = "./output/malware_testing/" + malware_list[i];
        shutil.copyfile(ori_file_name, dest_file_name);



# step 3: combine all csv files in one
def csv_combine_rows():
    folder_name = "./output/";
    benign_testing_dir = folder_name + "benign_testing/";
    benign_training_dir = folder_name + "benign_training/";
    malware_testing_dir = folder_name + "malware_testing/";
    malware_training_dir = folder_name + "malware_training/";

    dfs = [];
    for subdir, dirs, files in os.walk(benign_testing_dir):
        for file in files:
            if file != ".DS_Store": # this is not neccessary if not running on mac
                file_name = benign_testing_dir + file;
                df_tmp = pd.read_csv(file_name);
                dfs.append(df_tmp);
    result = pd.concat(dfs, axis=0);
    result.to_csv("./output/benign_testing.csv", index=False)

    dfs = [];
    for subdir, dirs, files in os.walk(benign_training_dir):
        for file in files:
            if file != ".DS_Store":
                file_name = benign_training_dir + file;
                df_tmp = pd.read_csv(file_name);
                dfs.append(df_tmp);
    result = pd.concat(dfs, axis=0);
    result.to_csv("./output/bening_training.csv", index=False)

    dfs = [];
    for subdir, dirs, files in os.walk(malware_testing_dir):
        for file in files:
            if file != ".DS_Store":
                file_name = malware_testing_dir + file;
                df_tmp = pd.read_csv(file_name);
                dfs.append(df_tmp);
    result = pd.concat(dfs, axis=0);
    result.to_csv("./output/malware_testing.csv", index=False)

    dfs = [];
    for subdir, dirs, files in os.walk(malware_training_dir):
        for file in files:
            if file != ".DS_Store":
                file_name = malware_training_dir + file;
                df_tmp = pd.read_csv(file_name);
                dfs.append(df_tmp);
    result = pd.concat(dfs, axis=0);
    result.to_csv("./output/malware_training.csv", index=False)

# def main():
    # # step 0: env set up
    # set_up();
    # # step 1: combine data from the same application
    # for key in benign_dict.keys():
    #     raw_to_csv_benign(key);
    # for key in malware_dict.keys():
    #     raw_to_csv_malware(key);
    # # step 2: split csv files, 30% for testing, 70% for training
    # split_csv_files();
    # # step 3: combine csv filess
    # csv_combine_rows();

# this main function is used to determine whether all applications have been
# completely profiled.
# def main():
#     get_benign_raw();
#     get_malware_raw();
#     print("BENIGN SECTION");
#     find_missing(benign_raw);
#     print("\n\nMALWARE SECTION");
#     find_missing(malware_raw);
#     for list in benign_raw:
#         dict_tmp = dict(Counter(list));
#         print([key for key,value in dict_tmp.items() if value > 1]);
#     for list in malware_raw:
#         dict_tmp = dict(Counter(list));
#         print([key for key,value in dict_tmp.items() if value > 1]);

if __name__ == "__main__":
    main();
