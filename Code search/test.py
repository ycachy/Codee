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
mat_file = 'tensor.mat'
binary_file = 'functionname/binaryname_new.txt'
result_file = 'result.txt'
select_result_folder = 'result/'

# 数据库操作类
class DB_Actor():
    # 初始化数据库连接，配置信息见全局变量
    def __init__(self):
        global DB_INFO
        self.conn = pymysql.Connect(host=DB_INFO['host'], port=DB_INFO['port'],\
                               user='root', passwd='yangjia', db=DB_INFO['DB'], charset='utf8')
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

# 数据分析与保存类
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



    # 根据feature查询数据库
    def DatafromFeature(self,feature):
        sql = "select * from " + self.table + " where feature='" + feature + "'"
        self.DOSQL.cursor.execute(sql)
        rows = self.DOSQL.cursor.fetchall()
        return rows

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
        return m['X']

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
        pass

    # key表示获得相似feature的个数
    def Mainfunc(self,mat_addr,base,result_folder):
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
        compareDict = {'core_arm_o0':4,'core_arm_o1':5,'core_arm_o2':6,'core_arm_o3':7,
                       'curl_arm_o0':52,'curl_arm_o1':53,'curl_arm_o2':54,'curl_arm_o3':55,
                       'libgmp.so.10.3.2_arm_O0':64,'libgmp.so.10.3.2_arm_O1':65,
                       'libgmp.so.10.3.2_arm_O2':66,'libgmp.so.10.3.2_arm_O3':67,
                       'busybox_arm_o0':73,'busybox_arm_o1':74,'busybox_arm_o2':75,'busybox_arm_o3':76,
                       'openssl_arm_o0':84, 'openssl_arm_o1':85,'openssl_arm_o2':86,'openssl_arm_o3':87,
                       'sqlite_arm_o0':96,'sqlite_arm_o1':97, 'sqlite_arm_o2':98,'sqlite_arm_o3':99,

        'core_x86_o0': 0, 'core_x86_o1': 1, 'core_x86_o2': 2, 'core_x86_o3': 3,
        'curl_x86_o0': 48, 'curl_x86_o1': 49, 'curl_x86_o2': 50, 'curl_x86_o3': 51,
        'libgmp.so.10.3.2_x86_O0': 60, 'libgmp.so.10.3.2_x86_O1': 61,
        'libgmp.so.10.3.2_x86_O2': 62, 'libgmp.so.10.3.2_x86_O3': 63,
        'busybox_x86_o0': 80, 'busybox_x86_o1': 81, 'busybox_x86_o2': 82, 'busybox_x86_o3': 83,
        'openssl_x86_o0': 92, 'openssl_x86_o1': 93, 'openssl_x86_o2': 94, 'openssl_x86_o3': 95,
        'sqlite_x86_o0': 104, 'sqlite_x86_o1': 105, 'sqlite_x86_o2': 106, 'sqlite_x86_o3': 107,}
#         FUNCTIONNUMBER={'coreutils_dir_X86_O0':290,'coreutils_dir_X86_O1':239,
#                         'coreutils_dir_X86_O2':291,'coreutils_dir_X86_O3':255,
#                         'coreutils_dir_arm_O0':451,'coreutils_dir_arm_O1':368,'coreutils_dir_arm_O3':334,'coreutilsr_mips_O0':306,
#                         'coreutils_dir_mips_O1':247,'coreutils_dir_mips_O2':242,'coreutils_dir_mips_O3':244,'coreutils_du_X86_O0':237,'coreutils_du_X86_O1':182,
# 'coreutils_du_X86_O2':211,'coreutils_du_X86_O3':176,'coreutils_du_arm_O0':529,'coreutils_du_arm_O1':393,
# 'coreutils_du_arm_O2':387,
# 'coreutils_du_arm_O3':329,
# 'coreutils_du_mips_O0':401,
# 'coreutils_du_mips_O1':288,
# 'coreutils_du_mips_O2':273,
# 'coreutils_du_mips_O3':248,
# 'coreutils_ls_X86_O0':290,
# 'coreutils_ls_X86_O1':239,
# 'coreutils_ls_X86_O2':291,
# 'coreutils_ls_X86_O3':255,
# 'coreutils_ls_arm_O0':451,
# 'coreutils_ls_arm_O1':368,
# 'coreutils_ls_arm_O2':377,
# 'coreutils_ls_arm_O3':334,
# 'coreutils_ls_mips_O0':306,
# 'coreutils_ls_mips_O1':247,
# 'coreutils_ls_mips_O2':242,
# 'coreutils_ls_mips_O3':244,
# 'coreutils_vdir_X86_O0':290,
# 'coreutils_vdir_X86_O1':239,
# 'coreutils_vdir_X86_O2':291,
# 'coreutils_vdir_X86_O3':255,
# 'coreutils_vdir_arm_O0':451,
# 'coreutils_vdir_arm_O1':368,
# 'coreutils_vdir_arm_O2':377,
# 'coreutils_vdir_arm_O3':334,
# 'coreutils_vdir_mips_O0':306,
# 'coreutils_vdir_mips_O1':247,
# 'coreutils_vdir_mips_O2':242,
# 'coreutils_vdir_mips_O3':244,
# 'curl_X86_O0':128,
# 'curl_X86_O1':102,
# 'curl_X86_O2':152,
# 'curl_X86_O3':134,
# 'curl_arm_O0':263,
# 'curl_arm_O1':223,
# 'curl_arm_O2':213,
# 'curl_arm_O3':209,
# 'curl_mips_O0':130,
# 'curl_mips_O1':107,
# 'curl_mips_O2':169,
# 'curl_mips_O3':186,
# 'libgmp.so.10.3.2_X86_O0': 621,
# 'libgmp.so.10.3.2_X86__O1': 568,
# 'libgmp.so.10.3.2_X86__O2': 591,
# 'libgmp.so.10.3.2_X86__O3': 571,
# 'libgmp.so.10.3.2_arm_O0':971,
# 'libgmp.so.10.3.2_arm_O1':876,
# 'libgmp.so.10.3.2_arm_O2':854,
# 'libgmp.so.10.3.2_arm_O3':844,
# 'libgmp.so.10.3.2_mips_O0':606,
# 'libgmp.so.10.3.2_mips_O1':551,
# 'libgmp.so.10.3.2_mips_O2':545,
# 'libgmp.so.10.3.2_mipsO3':544,
# 'busybox_arm_o0':3216,
# 'busybox_arm_o1':2128,
# 'busybox_arm_o2':2099,
# 'busybox_arm_o3':1730,
# 'busybox_mips_o0':2900,
# 'busybox_mips_o1':2243,
# 'busybox_mips_o2':1726,
# 'busybox_mips_o3':1381,
# 'busybox_x86_o0':3196,
# 'busybox_x86_o1':2390,
# 'busybox_x86_o2':2542,
# 'busybox_x86_o3':2045,
# 'openssl_arm_o0':1778,
# 'openssl_arm_o1':1692,
# 'openssl_arm_o2':1675,
# 'openssl_arm_o3':1658,
# 'openssl_mips_o0':414,
# 'openssl_mips_o1':333,
# 'openssl_mips_o2':333,
# 'openssl_mips_o3':324,
# 'openssl_x86_o0':414,
# 'openssl_x86_o1':322,
# 'openssl_x86_o2':350,
# 'openssl_x86_o3':333,
# 'sqlite_arm_o0':2876,
# 'sqlite_arm_o1':2058,
# 'sqlite_arm_o2':1972,
# 'sqlite_arm_o3':1805,
# 'sqlite_mips_o0':2701,
# 'sqlite_mips_o1':1936,
# 'sqlite_mips_o2':1830,
# 'sqlite_mips_o3':1705,
# 'sqlite_x86_o0':2693,
# 'sqlite_x86_o1':1931,
# 'sqlite_x86_o2':1967,
# 'sqlite_x86_o3':1772,
#                         }


        data = np.zeros((n1, 30000))
        test=np.zeros((n1,3500))
        m = 0
        imodel=compareDict['core_arm_o0']
        itest=compareDict['core_arm_o3']
        for i in range(test_dict['core'][0],test_dict['core'][1]):
            for j in range(n3):
                if svec[:, i, j].all() != 0:
                    data[:, m] = svec[:, i, j]
                    m = m + 1

        dataves = np.transpose(data)


        #testves = np.transpose(test)


######## 两对比  两
        # for j in range(n3):
        #     if svec[:, imodel, j].all() != 0:
        #         data[:, m] = svec[:, imodel, j]
        #         m = m + 1
        #     if svec[:, itest, j].all() != 0:
        #         test[:, mm] = svec[:, itest, j]
        #         mm = mm + 1
        #dataves = np.transpose(data)
        #testves=np.transpose(test)
        # modelindex = list(set(np.random.randint(0, m, size=10000)))

    #    output_total = open(result_folder + 'result_total.txt', 'w')


        lsh_model = LSHash(7, n1)

        for jj in range(m):
        # for jj in range(87212):
            lsh_model.index(dataves[jj, :])



        testindex = list(set(np.random.randint(0, m, size=base)))  # SIZE IS THE NUMBER OF TEST FUNCTIONS

        test = np.zeros((len(testindex), n1))

        for i in range(len(testindex)):
            test[i, :] = dataves[testindex[i], :]
        # output = open(result_folder + 'result_key' + str(key) + '_base' + str(base) + '.txt', 'w')
#        testindex=mm
        ##############################################################################


        timee = open(result_folder + 'time.txt', 'a')
        target_list = []
        M_list = []

        for queryi in range(len(testindex)):
            target = test[queryi, :]
            temp_target = SelectDB.DataAccuray(target)
            str_target = temp_target.astype(str)
            feature_target = "-".join(str_target)
            rows = SelectDB.DatafromFeature(feature_target)
            target_data = self.Row2Str(rows)
            target_list.append(target_data)


            Global_M = self.GetGlobalM(rows[0][1])
            M_list.append(Global_M)


        print('Global_M get success\n')


        Totaltime = 0.0
        # SelectDB = Date_Analysis()
        for queryi in range(len(testindex)):
            flag_over = 0
            keylist = [i for i in range(1, 10001, 5)]
            #keylist=[5]
            target_data = target_list[queryi].split('#')[0]
            output = open(result_folder + 'coreutils_result_base' + str(base) + \
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
                        Atemp = lsh_model.query(test[queryi, :], key, 'euclidean')
                        endtime = time.time()
                        Totaltime = Totaltime + endtime - starttime

                        for i in range(0,key):
                            if i < len(Atemp):
                                try:
                                    flag_over = 0
                                    feature_str = str(Atemp[i]).split(')')[0].split('(')[2]
                                    feature_list = feature_str.split(',')
                                    feature_array = SelectDB.ListStr2ArrayFloat(feature_list)
                                    temp = SelectDB.DataAccuray(feature_array)
                                    str_data = temp.astype(str)
                                    feature = "-".join(str_data)
                                    rows = SelectDB.DatafromFeature(feature)
                                    select_data = self.Row2Str(rows)
                                except Exception as e:
                                    print(e)
                                    print(str(Atemp[i]))
                                    select_data = 'null:null#'
                            else:
                                print('AtempLen:',len(Atemp),' ','key:',key ,'\n')
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
    def GetGlobalM(self,func):
      #  m = 0
        sql = "select * from test where function_name = " + "'" + func + "'"
        # 查询记录数
        # sql = "select * from test where binary_name='busybox_X86_O3'"
        self.DODB.cursor.execute(sql)
        rows = self.DODB.cursor.fetchall()

        return len(rows)





if __name__ == "__main__":
    # DODB = DB_Actor()
    # DOAnalysis = Date_Analysis()
    # keylist = [i for i in range(1,200)]

    base = 1
    DOlsh = LSHAnalysis()

    DOlsh.Mainfunc(folder+mat_file,base,folder+select_result_folder)

    # 创建数据库
    # create database YJ_TEST;
    # 查询某条记录
    # sql = "select * from test where function_name = 'fts3EvalStartReaders'"
    # 查询记录数
    # sql = "select * from test where binary_name='busybox_X86_O3'"
    # DODB.cursor.execute(sql)
    # rows = DODB.cursor.fetchall()
    # for row in rows:
    #     print(row)

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
