import os
import pandas as pd

# here to put the target interval:
# 1 for 10ms
# 10 for 100ms
# 100 for 1000ms
interval = 100;
# you will also need to edit line 49 for output path

def calc_increment(raw_file, result_file):
    raw_df = pd.read_csv(raw_file);
    raw_dict_list = raw_df.to_dict('records');
    initial_result_dict_list = [];
    initial_result_dict_list.append(raw_dict_list[0]);
    for index in range(0, len(raw_dict_list) - 1):
        dict_tmp = {};
        dict = raw_dict_list[index];
        for key in dict:
            if isinstance(dict[key], int):
                # print("int: "+str(dict[key]));
                dict_tmp[key] = raw_dict_list[index+1][key] - dict[key]
            else:
                # print("str: "+dict[key]);
                dict_tmp[key] = dict[key];
        initial_result_dict_list.append(dict_tmp);
        
    final_result_dict_list = [];
    for index in range(0, len(initial_result_dict_list), interval):
        dict_tmp = {};
        if (index + interval <= len(initial_result_dict_list)):
            dict_tmp = initial_result_dict_list[index]
            for sub_index in range(index + 1, index + interval):
                for key in initial_result_dict_list[sub_index]:
                    if isinstance(initial_result_dict_list[sub_index][key], int):
                        dict_tmp[key] = dict_tmp[key] + initial_result_dict_list[sub_index][key];
            final_result_dict_list.append(dict_tmp);
        
    if(len(final_result_dict_list) == 0):
        print("Warning: having empty file!");
        print(raw_file);
    
    result_df = pd.DataFrame(final_result_dict_list, columns=raw_df.columns.tolist());
    result_df.to_csv(result_file, index=False);
    # print(result_file);
    
def csv_combine_rows():
    folder_name = "./output/1000ms/";
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
    result.to_csv("./output/1000ms/benign_testing.csv", index=False)

    dfs = [];
    for subdir, dirs, files in os.walk(benign_training_dir):
        for file in files:
            if file != ".DS_Store":
                file_name = benign_training_dir + file;
                df_tmp = pd.read_csv(file_name);
                dfs.append(df_tmp);
    result = pd.concat(dfs, axis=0);
    result.to_csv("./output/1000ms/bening_training.csv", index=False)

    dfs = [];
    for subdir, dirs, files in os.walk(malware_testing_dir):
        for file in files:
            if file != ".DS_Store":
                file_name = malware_testing_dir + file;
                df_tmp = pd.read_csv(file_name);
                dfs.append(df_tmp);
    result = pd.concat(dfs, axis=0);
    result.to_csv("./output/1000ms/malware_testing.csv", index=False)
    
    dfs = [];
    for subdir, dirs, files in os.walk(malware_training_dir):
        for file in files:
            if file != ".DS_Store":
                file_name = malware_training_dir + file;
                df_tmp = pd.read_csv(file_name);
                dfs.append(df_tmp);
    result = pd.concat(dfs, axis=0);
    result.to_csv("./output/1000ms/malware_training.csv", index=False)
    
# def main():
#     folder_path = "./output/raw/";
#     result_path = "./output/1000ms/";
#     benign_testing_path = folder_path + "benign_testing/";
#     benign_training_path = folder_path + "benign_training/";
#     malware_testing_path = folder_path + "malware_testing/";
#     malware_training_path = folder_path + "malware_training/";
#     for subdir,dirs,files in os.walk(benign_testing_path):
#         for file in files:
#             if file != ".DS_Store":
#                 filename = benign_testing_path + file;
#                 result_file = result_path + "benign_testing/" + file;
#                 calc_increment(filename, result_file);
#             else:
#                 print(file);
#     for subdir,dirs,files in os.walk(benign_training_path):
#         for file in files:
#             if file != ".DS_Store":
#                 filename = benign_training_path + file;
#                 result_file = result_path + "benign_training/" + file;
#                 calc_increment(filename, result_file);
#             else:
#                 print(file);
#     for subdir,dirs,files in os.walk(malware_testing_path):
#         for file in files:
#             if file != ".DS_Store":
#                 filename = malware_testing_path + file;
#                 result_file = result_path + "malware_testing/" + file;
#                 calc_increment(filename, result_file);
#             else:
#                 print(file);
#     for subdir,dirs,files in os.walk(malware_training_path):
#         for file in files:
#             if file != ".DS_Store":
#                 filename = malware_training_path + file;
#                 result_file = result_path + "malware_training/" + file;
#                 calc_increment(filename, result_file);
#             else:
#                 print(file);
def main():
    csv_combine_rows();
        
if __name__ == "__main__":
    main();