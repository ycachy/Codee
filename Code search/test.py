# !/usr/bin/python3
import pymysql
import time
import numpy as np
import scipy.io as sio # 重新安装该库
import random
import os
from lshash import LSHash
DB_INFO = {'host':'127.0.0.1','port':3306,'DB':'YJ_TEST','TB':'test_new'}
folder = 'F:/Study/510/DocYJ/DataBase/'
mat_file = 'tensor_new.mat'
binary_file = 'functionname/binaryname_new.txt'
result_file = 'resultnew.txt'
select_result_folder = 'resultsnew/'
global result_save
global model_func_list
global Base_cg_list
global model

# 数据库操作类
class DB_Actor():
    # 初始化数据库连接，配置信息见全局变量
    def __init__(self):
        global DB_INFO
        self.conn = pymysql.Connect(host=DB_INFO['host'], port=DB_INFO['port'],\
                               user='root', passwd='jiang', db=DB_INFO['DB'], charset='utf8')
        self.cursor = self.conn.cursor()
        self.CreateTB(DB_INFO['TB'])

    # 创建表格
    def CreateTB(self,DBname):
        sql = "create table " + DBname + " (binary_name VARCHAR(100) NOT NULL,\
                                            function_name VARCHAR(100) NOT NULL,\
                                            feature VARCHAR(500) NOT NULL)"
        try:
            self.cursor.execute(sql)
            print('create db %s success.' %(DBname))
        except Exception as e:
            print(e)

    # 执行SQL语句
    def DoSql(self,SQL):
        try:
            self.cursor.execute(SQL)
            self.conn.commit()
            # print(SQL,'success')
        except Exception as e:
            print(e,SQL)
            self.conn.rollback()

    # 删除表格
    def DropTB(self,DBname):
        sql = "drop table " + DBname
        try:
            self.cursor.execute(sql)
            print('table:',DBname,'drop success')
        except Exception as e:
            print(e,sql)

    # 展示数据库数据
    def ShowDB(self,DBname):
        sql = "select * from " + DBname
        try:
            self.cursor.execute(sql)
            rows = self.cursor.fetchall()
            for row in rows:
                print(row)
        except Exception as e:
            print(e,sql)

    # 断开数据库连接
    def CutLink(self):
        self.cursor.close()
        self.conn.close()

# 数据分析与保存类op
class Date_Analysis():
    # 初始化数据精度，生成数据库实例
    def __init__(self):
        global DB_INFO
        self.accuracy = 6 # 设置精度小数位数
        self.table = DB_INFO['TB']
        self.DOSQL = DB_Actor()
        # self.DOSQL.CreateTB(self.table)

    # 数据分析主过程
    def MainAnalysis(self,binary_addr,mat_addr,folder):
        i = 0
        j = 0
        s_data = self.GetSourceMat(mat_addr)
        # write_file = open('log1.txt','a')
        matrix_shape = s_data.shape
        x_max = matrix_shape[0]
        y_max = matrix_shape[1]
        z_max = matrix_shape[2]
        try:
            binary_handle = open(binary_addr,'r')
            binary_contents = binary_handle.readlines()
            # 首先遍历所有的binary_name
            for each_binary in binary_contents:
                if i < y_max:
                    j = 0
                    binary_name = each_binary.split("'")[1]
                    func_addr = folder + 'functionname/' + binary_name + '.txt'
                    func_handle = open(func_addr,'r')
                    func_contents = func_handle.readlines()
                    # 然后遍历每个binary_name的所有function_name
                    for each_func in func_contents:
                        if j < z_max:
                            func_name = each_func.split(' ')[0]
                            ch_index = self.JudgeCharIndex(func_name)
                            func_name = func_name[ch_index:]
                            if self.JudgeNorZero(s_data[:,i,j]): # 全零
                                pass
                            else:
                                temp = self.DataAccuray(s_data[:,i,j])
                                str_data = temp.astype(str)
                                feature = "-".join(str_data)
                                print(binary_name,func_name,feature)
                                self.SaveData(binary_name,func_name,feature)
                                # write_file.write(binary_name+func_name+feature+'\n')
                            j=j+1
                        else:
                            break
                    i=i+1
                    func_handle.close()
                else:
                    break
            binary_handle.close()
        except Exception as e:
            print(e)
        print(i, j)
        # write_file.close()
        self.DOSQL.CutLink()

    def ResultAnalysis(self,res_addr,select_addr):
        '''
        result_handle = open(res_addr,'r')
        select_handle = open(select_addr,'a')
        result_contents = result_handle.readlines()
        for res in result_contents:
            feature_list = res.split(',')
            feature_array = self.ListStr2ArrayFloat(feature_list)
            temp = self.DataAccuray(feature_array)
            str_data = temp.astype(str)
            feature = "-".join(str_data)
            print(feature)
            exit()

            rows = self.DatafromFeature(feature)
            select_data = rows[0]
            select_handle.write(select_data+'\n')
            print(rows)
        result_handle.close()
        select_handle.close()
        '''
        feature = '0.008346-0.008392-0.005623-0.021094-0.004259-0.00653-4e-06-0.001683-0.00178-0.002022-0.001373-0.000187-0.005874-0.000901-0.003495'
        rows = self.DatafromFeature(feature)
        select_data = ''
        for row in rows:
            row_data = row[0] + ':' + row[1]
            select_data = select_data + row_data + '#'
        print(select_data)



    # 根据feature查询数据库 从0开始,num表示查询数量 注意limit是返回查询结果中的指定行数
    def DatafromFeature(self,feature,sta,num):
        res = []
        sql = "select * from " + self.table + " LIMIT " + str(sta) + ',' + str(num)
        self.DOSQL.cursor.execute(sql)
        rows = self.DOSQL.cursor.fetchall()
        for row in rows:
            # print(row)
            if row[2] == feature:
                res.append(row)
            else:
                pass
        return res

    # 字符串list转浮点数array
    def ListStr2ArrayFloat(self,data):
        for i in range(0,len(data)):
            data[i] = float(data[i])
        return np.array(data)

    # 修改数据精度np.array float类型
    def DataAccuray(self,data):
        i = 0
        for num in data:
            data[i] = round(num, self.accuracy)
            i = i + 1
        return data

    # 判断是否全零
    def JudgeNorZero(self,data):
        for num in data:
            if num > 0.0:
                return 0
        return 1

    # 找到字符串第一个字母的位置，用于裁剪字符串开头的破折号
    def JudgeCharIndex(self,s):
        i = 0
        for ch in s:
            if ch >= 'a' and ch <= 'z':
                return i
            elif ch >= 'A' and ch <= 'Z':
                return i
            else:
                i=i+1

    # 读取.mat文件
    def GetSourceMat(self,Mat_addr):
        m = sio.loadmat(Mat_addr)
        return m['FFE']

    # 保存数据库
    def SaveData(self,binary_name,fun_name,feature):
        sql = "insert into " + self.table + " (binary_name,function_name,feature) values('" + binary_name + "','" + fun_name + "','" + feature  + "')"
        self.DOSQL.DoSql(sql)

    # 确定保留小数
    def as_num(self,x):
        y = '{:.6f}'.format(x)
        return y

class LSHAnalysis():
    def __init__(self):
        self.DODB = DB_Actor()
        self.table = DB_INFO['TB']
        self.SelectDB = Date_Analysis()
        self.limit = 0.05
        pass


    # 获取前key个最近的feature 在limit误差范围内从base_cg中选择一个替换最后一个feature
    # 不返回下标，直接返回所有bianry:func结果
    def searchnew(self,test,key,limit,query):
        global result_save
        global model_func_list
        global Base_cg_list
        global model
        # testindex=list()
        base_cg = Base_cg_list[query]

        totaly = []
        cg_flag = 0
        last_min_dis = 100.0
        last_min_binary_fuc = ''
        last_min_position = 0

        need_key = key - len(result_save)

        #for testi in range(len(test)):
            #print
        #test[testi]
        testindex = list()

        print('len_model:',len(model))
        print('len_func_list:',len(model_func_list))
        print('len_result_save:',len(result_save))
        print('len_cg_binary:',len(base_cg))
        #y = []
        for modeli in range(len(model)):
            dis = np.linalg.norm(np.array(test) - np.array(model[modeli]))
            testindex.append({'index': modeli, 'dis': dis})
            #i = i + 1
        testindex.sort(key=lambda x: x['dis'], reverse=False)

        for x in testindex[0:need_key]:
            totaly.append(x['index'])
            result_save.append(model_func_list[x['index']])
        print('total_index:',totaly)

        #print(totaly)
        last_feature = model[totaly[need_key-1]]
        for cg in base_cg:
            feature_str = cg['feature']
            feature_str = feature_str.replace('e-','#')
            feature_list = feature_str.split('-')
            feature_float = self.liststr2float(feature_list)
            last_dis = np.linalg.norm(np.array(last_feature) - np.array(feature_float))
            if last_dis < last_min_dis and last_dis > 0.0:
                last_min_dis = last_dis
                last_min_binary_fuc = cg['binary']
                last_min_position = base_cg.index(cg)
        #print('last_min_dis:',last_min_dis)
        if last_min_dis <= limit and last_min_dis > 0.0:
            print('change:',result_save[key-1],'to',last_min_binary_fuc,last_min_dis,'\n')
            result_save[key-1] = last_min_binary_fuc
            del Base_cg_list[query][last_min_position]
            self.DelUsedData(totaly[0:-1])
            cg_flag = 1
        if not cg_flag:
            print('not change:',result_save[key-1],last_min_dis,'\n')
            self.DelUsedData(totaly)
        return result_save

    def DelUsedData(self,indexlist):
        global model_func_list
        global model
        pos = 0
        for del_index in range(len(indexlist)):
            del_num = indexlist[del_index]
            try:
                del model_func_list[del_num]
                model = np.delete(model, del_num, axis=0)
                pos = pos + 1
                for after_index in range(pos,len(indexlist)):
                    if indexlist[after_index] > del_num:
                        indexlist[after_index] = indexlist[after_index] - 1
                    else:
                        pass
                print('Success del_num:',del_num,'indexlist:',indexlist,'len(model_func_list):',len(model_func_list))
            except Exception as e:
                print(e)
                print('Error del_num:',del_num,'indexlist:',indexlist,'len(model_func_list):',len(model_func_list))


    def liststr2float(self,data):
        res = []
        for num in data:
            if num.find('#') != -1:
                num = num.replace('#','e-')
            res.append(float(num))
        return res

    # key表示获得相似feature的个数
    def Mainfunc(self,mat_addr,base,result_folder):
        global result_save
        global model_func_list
        global Base_cg_list
        global model
        # base数据的所有binary_func_name
        Total_binary_func = [] # binnary:funcution#
        SelectDB = Date_Analysis()
        #  np.set_printoptions(suppress=True, precision=6, threshold=8)
        s = sio.loadmat(mat_addr)
        svec = s['FFE']
        datalen = len(svec)
        n1, n2, n3 = np.shape(svec)
        #test_dict = {'core':[0,12],'curl':[48,60],'libgmp':[60,72],'busybox':[72,84],'openssl':[84,96],'sqlite':[96,108]}
        test_dict = {'busybox': [0, 12], 'core': [12, 60], 'curl': [60, 72], 'libgmp': [72, 84], 'openssl': [84, 96],
                     'sqlite': [96, 108]}
        # 对应与tensor_new

        compareDict = {'core_dir_arm_o0':16,'core_dir_arm_o1':17,'core_dir_arm_o2':18,'core_dir_arm_o3':19,
                       'curl_arm_o0':64,'curl_arm_o1':65,'curl_arm_o2':66,'curl_arm_o3':67,
                       'curl_mips_o0': 68, 'curl_mips_o1': 69, 'curl_mips_o2': 70, 'curl_mips_o3': 71,
                       'curl_x86_o0': 60, 'curl_x86_o1': 61, 'curl_x86_o2': 62, 'curl_x86_o3': 63,
                       'libgmp.so.10.3.2_arm_O0':76,'libgmp.so.10.3.2_arm_O1':77,
                       'libgmp.so.10.3.2_arm_O2':78,'libgmp.so.10.3.2_arm_O3':79,
                       'libgmp.so.10.3.2_X86_O0': 72, 'libgmp.so.10.3.2_X86_O1': 73,
                       'libgmp.so.10.3.2_X86_O2': 74, 'libgmp.so.10.3.2_X86_O3': 75,
                       'libgmp.so.10.3.2_mips_O0': 80, 'libgmp.so.10.3.2_mips_O1': 81,
                       'libgmp.so.10.3.2_mips_O2': 82, 'libgmp.so.10.3.2_mips_O3': 84,
                       'busybox_arm_o0':0,'busybox_arm_o1':1,'busybox_arm_o2':2,'busybox_arm_o3':3,
                       'busybox_mips_o0': 4, 'busybox_mips_o1': 5, 'busybox_mips_o2': 6, 'busybox_mips_o3': 7,
                       'busybox_x86_o0': 8, 'busybox_x86_o1': 9, 'busybox_x86_o2': 10, 'busybox_x86_o3': 11,
                       'openssl_arm_o0':84, 'openssl_arm_o1':85,'openssl_arm_o2':86,'openssl_arm_o3':87,
                       'sqlite_arm_o0':96,'sqlite_arm_o1':97, 'sqlite_arm_o2':98,'sqlite_arm_o3':99,
                       'sqlite_x86_o0': 104, 'sqlite_x86_o1': 105, 'sqlite_x86_o2': 106, 'sqlite_x86_o3': 107,
                       'sqlite_mips_o0': 100, 'sqlite_mips_o1': 101, 'sqlite_mips_o2': 102, 'sqlite_mips_o3': 103,
                       'core_dir_mips_o0': 20, 'core_dir_mips_o1': 21, 'core_dir_mips_o2': 22, 'core_dir_mips_o3': 23,
                       'core_dir_x86_o0': 12, 'core_dir_x86_o1': 13, 'core_dir_x86_o2': 14, 'core_dir_x86_o3': 15,
                       'openssl_mips_o0': 88, 'openssl_mips_o1': 89, 'openssl_mips_o2': 90, 'openssl_mips_o3': 91,
                       'openssl_x86_o0': 92, 'openssl_x86_o1': 93, 'openssl_x86_o2': 94, 'openssl_x86_o3': 95,
                       }

        FUNCTIONNUMBER={'coreutils_dir_X86_O0':290,
                        'coreutils_dir_X86_O1':239,
                        'coreutils_dir_X86_O2':291,
                        'coreutils_dir_X86_O3':255,
                        'coreutils_dir_arm_O0':451,
                        'coreutils_dir_arm_O1':368,
                        'coreutils_dir_arm_O2':377,
                        'coreutils_dir_arm_O3':334,
                        'coreutils_dir_mips_O0':306,
                        'coreutils_dir_mips_O1':247,
                        'coreutils_dir_mips_O2':242,
                        'coreutils_dir_mips_O3':244,
                        'coreutils_du_X86_O0':237,
                        'coreutils_du_X86_O1':182,
                        'coreutils_du_X86_O2':211,
                        'coreutils_du_X86_O3':176,
                        'coreutils_du_arm_O0':529,
                        'coreutils_du_arm_O1':393,
                        'coreutils_du_arm_O2':387,
                        'coreutils_du_arm_O3':329,
                        'coreutils_du_mips_O0':401,
                        'coreutils_du_mips_O1':288,
                        'coreutils_du_mips_O2':273,
                        'coreutils_du_mips_O3':248,
                        'coreutils_ls_X86_O0':290,
                        'coreutils_ls_X86_O1':239,
                        'coreutils_ls_X86_O2':291,
                        'coreutils_ls_X86_O3':255,
                        'coreutils_ls_arm_O0':451,
                        'coreutils_ls_arm_O1':368,
                        'coreutils_ls_arm_O2':377,
                        'coreutils_ls_arm_O3':334,
                        'coreutils_ls_mips_O0':306,
                        'coreutils_ls_mips_O1':247,
                        'coreutils_ls_mips_O2':242,
                        'coreutils_ls_mips_O3':244,
                        'coreutils_vdir_X86_O0':290,
                        'coreutils_vdir_X86_O1':239,
                        'coreutils_vdir_X86_O2':291,
                        'coreutils_vdir_X86_O3':255,
                        'coreutils_vdir_arm_O0':451,
                        'coreutils_vdir_arm_O1':368,
                        'coreutils_vdir_arm_O2':377,
                        'coreutils_vdir_arm_O3':334,
                        'coreutils_vdir_mips_O0':306,
                        'coreutils_vdir_mips_O1':247,
                        'coreutils_vdir_mips_O2':242,
                        'coreutils_vdir_mips_O3':244,
                        'curl_X86_O0':128,
                        'curl_X86_O1':102,
                        'curl_X86_O2':152,
                        'curl_X86_O3':134,
                        'curl_arm_O0':263,
                        'curl_arm_O1':223,
                        'curl_arm_O2':213,
                        'curl_arm_O3':209,
                        'curl_mips_O0':130,
                        'curl_mips_O1':107,
                        'curl_mips_O2':169,
                        'curl_mips_O3':186,
                        'libgmp.so.10.3.2_X86_O0': 621,
                        'libgmp.so.10.3.2_X86_O1': 568,
                        'libgmp.so.10.3.2_X86_O2': 591,
                        'libgmp.so.10.3.2_X86_O3': 571,
                        'libgmp.so.10.3.2_arm_O0':971,
                        'libgmp.so.10.3.2_arm_O1':876,
                        'libgmp.so.10.3.2_arm_O2':854,
                        'libgmp.so.10.3.2_arm_O3':844,
                        'libgmp.so.10.3.2_mips_O0':606,
                        'libgmp.so.10.3.2_mips_O1':551,
                        'libgmp.so.10.3.2_mips_O2':545,
                        'libgmp.so.10.3.2_mips_O3':544,
                        'busybox_arm_o0':3216,
                        'busybox_arm_o1':2128,
                        'busybox_arm_o2':2099,
                        'busybox_arm_o3':1730,
                        'busybox_mips_o0':2900,
                        'busybox_mips_o1':2243,
                        'busybox_mips_o2':1726,
                        'busybox_mips_o3':1381,
                        'busybox_x86_o0':3196,
                        'busybox_x86_o1':2390,
                        'busybox_x86_o2':2542,
                        'busybox_x86_o3':2045,
                        'openssl_arm_o0':1778,
                        'openssl_arm_o1':1692,
                        'openssl_arm_o2':1675,
                        'openssl_arm_o3':1658,
                        'openssl_mips_o0':414,
                        'openssl_mips_o1':333,
                        'openssl_mips_o2':333,
                        'openssl_mips_o3':324,
                        'openssl_x86_o0':414,
                        'openssl_x86_o1':322,
                        'openssl_x86_o2':350,
                        'openssl_x86_o3':333,
                        'sqlite_arm_o0':2876,
                        'sqlite_arm_o1':2058,
                        'sqlite_arm_o2':1972,
                        'sqlite_arm_o3':1805,
                        'sqlite_mips_o0':2701,
                        'sqlite_mips_o1':1936,
                        'sqlite_mips_o2':1830,
                        'sqlite_mips_o3':1705,
                        'sqlite_x86_o0':2693,
                        'sqlite_x86_o1':1931,
                        'sqlite_x86_o2':1967,
                        'sqlite_x86_o3':1772,
                                                }

        FUNCTIONNAME = []
        func_name = open(binary_file,'r')
        func_contents = func_name.readlines()
        for func_content in func_contents:
            FUNCTIONNAME.append(func_content.strip("'").strip('\n').split("'")[0])
        print(FUNCTIONNAME)



        data = np.zeros((n1, 30000))
        test=np.zeros((n1,3500))
        m = 0

        #curl在binary_new.txt中最开始的binary
        Test_BIN_name = 'openssl_arm_o0'
        #curl在binary_new.txt中下一类最开始的binary
        Test_END_name = 'sqlite_arm_o0'
        # 开始位置
        Test_s = self.GetSqlStart(FUNCTIONNUMBER,FUNCTIONNAME,Test_BIN_name)
        # 结束位置
        Test_n = self.GetSqlStart(FUNCTIONNUMBER,FUNCTIONNAME,Test_END_name)
        # 确定数据库范围
        Test_s_n = [Test_s,Test_n-Test_s]
        print(Test_s_n)


        for i in range(test_dict['openssl'][0],test_dict['openssl'][1]):
            for j in range(n3):
                if svec[:, i, j].all() != 0:
                    data[:, m] = svec[:, i, j]
                    m = m + 1

        dataves = np.transpose(data)
        lsh_model = LSHash(7, n1)
        model = np.zeros((m, n1))


        for jj in range(m):
        # for jj in range(87212):
            lsh_model.index(dataves[jj, :])
            model[jj, :] = dataves[jj, :]

        model_back = model.copy() # 保存model



        testindex = list(set(np.random.randint(0, m, size=base)))  # SIZE IS THE NUMBER OF TEST FUNCTIONS

        test = np.zeros((len(testindex), n1))

        for i in range(len(testindex)):
            test[i, :] = dataves[testindex[i], :]
        # output = open(result_folder + 'result_key' + str(key) + '_base' + str(base) + '.txt', 'w')
#        testindex=mm
        ##############################################################################


        timee = open(result_folder + 'openssl_time.txt', 'a')
        target_list = [] #待测试的feature列表
        M_list = []
        Base_cg_list = []
        result_save = []# 逐步保存不同key的值

        for queryi in range(len(testindex)):
            target = test[queryi, :]
            temp_target = SelectDB.DataAccuray(target)
            str_target = temp_target.astype(str)
            feature_target = "-".join(str_target)
            print(feature_target)
            rows = SelectDB.DatafromFeature(feature_target,Test_s_n[0],Test_s_n[1])
            target_data = self.Row2Str(rows)
            target_list.append(target_data)
            GetData = self.GetGlobalM(rows[0][1],Test_s_n[0],Test_s_n[1],target_data)
            Global_M = GetData[0]
            Base_cg = GetData[1]
            M_list.append(Global_M)
            Base_cg_list.append(Base_cg)
        print('Global_M Base_cg_list get success\n')
        #print('M_list:',M_list)
        #print('Base_cg_list:',Base_cg_list)

        #model_func_list = ['test']*len(model)
        model_func_list = self.GetFuncListFromFeature(model, Test_s_n[0],Test_s_n[1])
        model_func_list_back = model_func_list.copy()
        print('target_list get success\n')


        Totaltime = 0.0
        Feature_Func_Cache = dict()
        # 记录feature与func的对应关系，避免重复查数据库feature:func
        # SelectDB = Date_Analysis()
        for queryi in range(len(testindex)):
            flag_over = 0
            result_save = []
            model_func_list = model_func_list_back.copy()
            model = model_back.copy()


            keylist = [i for i in range(5, 2001, 5)]
            #keylist = [i for i in range(5, 21, 5)]
            #keylist=[5]
            target_data = target_list[queryi].split('#')[0]
            output = open(result_folder + 'openssl_result_base' + str(base) + \
                          '_No' + str(queryi) + '.txt', 'w')
            output.write('Target:' + target_data + '\n')
            print(target_data + '\n')
            for key in keylist:
                if flag_over == 0:
                    msg = 'Key:' + str(key) + ' Base:' + str(base) + \
                          ' No:' + str(queryi) + ' M:' + str(M_list[queryi])
                    print(msg + '\n')
                    output.write(msg + '\n')
                    if test[queryi, :].all() != 0:
                        starttime = time.time()
                        self.searchnew(test[queryi, :], key,self.limit,queryi)
                        # Atemp = lsh_model.query(test[queryi, :], key, 'euclidean')
                        endtime = time.time()
                        Totaltime = Totaltime + endtime - starttime

                        for i in range(0,key):
                            if i < len(result_save):
                                try:
                                    flag_over = 0
                                    select_data = result_save[i]
                                except Exception as e:
                                    print(e)
                                    select_data = 'null:null#'
                            else:
                                print('AtempLen:',len(result_save),' ','key:',key ,'\n')
                                select_data = 'null:null#'
                                flag_over = 1
                            output.write(select_data + '\n')
                            print(select_data + '\n')
                else:
                    break

                msg = 'Key:' + str(key) + ' Base:' + str(base) + \
                      ' No:' + str(queryi) + ' Time:' + str(float(Totaltime/base)) + '\n'
                timee.write(msg)
                print(msg)
            output.close()
        timee.close()

    def Row2Str(self,rows):
        data = ''
        for row in rows:
            # row_data = row[0] + ':' + row[1] + ':' + row[2]
            row_data = row[0] + ':' + row[1]
            data = data + row_data + '#'
        return data

    def Row2Dict(self,row):
        res = {'binary_name':row[0],'function_name':row[1]}
        return res


    # 清除空格
    def ClearStr(self,data):
        res = ''
        for ch in data:
            if ch != '_':
                res = res + ch
            else:
                pass
        return res

    # 比较两字符串是否相似
    def CompareStr(self,target,test):
        target = self.ClearStr(target)
        test = self.ClearStr(test)
        n = len(target)-3
        for i in range(0,n):
            temp = target[i:i+5]
            if test.find(temp) != -1:
                return 1
        return 0

    # 获取当前M的值sour是所有base里的数据，字符串，target是要判断的数据
    def GetGlobalM(self,func,sta,num,target):
        target_str = target.split('#')
        target_binary = []
        for data in target_str:
            if data:
                bin = data.split(':')[0]
                target_binary.append(bin)
        res = []
        base_cg = []
        m = 0
        sql = "select * from " + self.table + " LIMIT " + str(sta) + ',' + str(num)
        self.DODB.cursor.execute(sql)
        rows = self.DODB.cursor.fetchall()
        for row in rows:
            if row[1] == func:
                m = m + 1
                # 只记录非自身的相同func
                if row[0] not in target_binary:
                    row_data = row[0] + ':' + row[1] + '#'
                    base_cg.append({'binary':row_data,'feature':row[2]})
            else:
                pass
        res.append(m)
        res.append(base_cg)
        return res

    # funcnum DICT   funcname LIST   target STR
    def GetSqlStart(self,funcnum,funcname,target):
        n = funcname.index(target)
        sta = 0
        for i in range(0,n):
            temp = funcnum[funcname[i]]
            sta = sta + temp
        return sta

    def GetFuncListFromFeature(self,featurelist,sta,num):
        target_list = []
        # 获取test的所有funcname
        for queryi in range(len(featurelist)):
            target = featurelist[queryi, :]
            print(target)
            if target.all() != 0:
                temp_target = self.SelectDB.DataAccuray(target)
                str_target = temp_target.astype(str)
                feature_target = "-".join(str_target)
                rows = self.SelectDB.DatafromFeature(feature_target,sta,num)
                target_funcname = self.Row2Str(rows)
                target_list.append(target_funcname)
        return target_list





if __name__ == "__main__":
    # DODB = DB_Actor()
    # DOAnalysis = Date_Analysis()
    # keylist = [i for i in range(1,200)]

    # s = '0.086363-0.035784-0.022083-0.002909-0.005622-0.004817-0.000327-0.002584-0.000147-0.000138-5.7e-05-0.001568-0.007419-9.4e-05-0.003508'
    # new_s = s.replace('e-','#')
    # print(new_s)
    # exit()


    base = 3000
    DOlsh = LSHAnalysis()
    DOlsh.Mainfunc(folder+mat_file,base,folder+select_result_folder)
    
    # func_list = ['v2i_POLICY_MAPPINGS','genrsa_main','priv_decode_gost','prompt_info',\
    #              'ssl3_get_message']
    # output = open(folder+select_result_folder + 'funcsearch.txt', 'w')
    # 创建数据库
    # create database YJ_TEST;
    # 查询某条记录
    # for func in func_list:
    #     sql = "select * from test_new where function_name = " + "'" + func + "'"
    #     print(sql)
    #     # 查询记录数
    #     # sql = "select * from test where binary_name='busybox_X86_O3'"
    #     DODB.cursor.execute(sql)
    #     rows = DODB.cursor.fetchall()
    #     print(func, ':')
    #     output.write('Target:' + func + '\n')
    #     for row in rows:
    #         print(row)
    #         output.write('search:' + row[0] + ':' + row[2] + '\n')
    #     print('\n')

    # 清空数据库表格
    # DODB.DropTB(DB_INFO['TB'])

    # 数据分析并保存数据库
    # DOAnalysis.MainAnalysis(folder+binary_file,folder+mat_file,folder)

    # 根据feature查询数据库
    # DOAnalysis.ResultAnalysis(folder+result_file,folder+select_result_file)

    # str与float转换
    # x = float('0.1234')
    # y = str(x)
    # print(type(x),type(y))

    # array与list转换
    # a = list()
    # b = np.array(a)
    # c = b.tolist()


    # 展示数据库数据
    # DODB.ShowDB(DB_INFO['TB'])

    # 断开数据库连接
    # DODB.CutLink()
