
import numpy as np
import scipy.io
import os
import json
#import util
path='node/'
files= os.listdir(path)
s = []
for file in files:
    if not os.path.isdir(file):
        f = open(path+file)
        tt=f.readlines()
        fline=len(tt)
        #print(fline)
        a=int(fline)
        ii=0  
        #print a
        network=np.zeros([a-1,60])
        #print network
        j=tt[0].split(':')[0]
        if a>2:
            #print(file)
            for line in tt[1:fline]:


                print ii
                #print line
                edge=[]
                #res=json.dumps(line)
                line=line.replace('\'','"').replace('L','')
                #res = json.dumps(line)
                dict=json.loads(line)
                #print dict['v']
                #linetemp=dict.values()
                #tempconnectnode_len = len(linetemp)
                #tempconnectnode = line.strip('\n').strip('}').strip(']').split(',')
                #print(tempconnectnode)
                tempconnectnode_len=len(dict['v'])
                aaa=dict['v'][2:int(tempconnectnode_len)]
                aaalen=len(aaa)
               # print aaa
                if tempconnectnode_len>1:
                    for tempite in range(6):
                     #   print(tempconnectnode[int(tempite)+1])
                        #if aaa[int(tempite)+1] !=' []':
                      #  print aaa[tempite]
                        network[ii][tempite]=aaa[tempite]
                    bbb=aaa[aaalen-1]
                    bbblen=len(bbb)
                    #####print network[i][7]
                    ######print bbblen
                    if bbblen<=54:
                        for jj in range(bbblen):
                            network[ii][int(jj+6)] = int(bbb[int(jj)])
                    else:
                        for jj in range(54):
                            network[ii][int(jj + 6)] = int(bbb[int(jj)])
                ii=ii+1

            print network
                #print network[i]


        #j=j+1
            scipy.io.savemat('att/'+str(file)+'.mat', mdict={'network': network})
            




         




