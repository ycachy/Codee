
import numpy
import scipy.io
import os
path='edge/'

files= os.listdir(path)
s = []
for file in files:
    if not os.path.isdir(file):
        f = open(path+file)
        tt=f.readlines()
        fline=len(tt)
        #print(fline)
        a=int(fline)
        network=numpy.zeros((a-1,a-1))
        j=tt[0].split(':')[0]
        if a>2:
            i=0
            for line in tt[1:fline]:
                #print(line)
                
                edge=[]
                tempconnectnode = line.strip('{').strip('}').strip('\n').split(',')
                tempconnectnode_len=len(tempconnectnode)
                #if tempconnectnode_len==0:
                 #   network[i]={0}
               # if tempconnectnode_len==1:
                #    network[i][int(tempedge)]=tempconnectnode.split(':')[0]
                #if tempconnectnode_len>=1:
                    
                print(tempconnectnode)       
                if  tempconnectnode !='':
                    for tempite in tempconnectnode:
                        edge.append(tempite.split(':')[0])
                        print(edge)
                    if edge !='':
                        for tempedge in edge:
                        # print(tempedge)
                            if tempedge !='':
                                network[i][int(tempedge)]=1
                i=i+1

        #j=j+1
            scipy.io.savemat('network/'+str(file)+'.mat', mdict={'network': network})





         




