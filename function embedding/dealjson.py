import json
from os import listdir
import os
import scipy.io
import numpy as np
pathjson= 'outputDir/Dataset/'
#pathedge='outputDir/Dataset/'
pathfilename='outputDir/functionname/'
binaryfiles=os.listdir(pathjson)
bl={}
for binaryfile in binaryfiles:
    frameworkfiles=os.listdir(pathjson+binaryfile+'/')
    for frameworkfile in frameworkfiles:
        pathedge=pathjson+binaryfile+'/'+frameworkfile+'/edge/'
        pathnodejson=pathjson+binaryfile+'/'+frameworkfile+'/nodejson/'
        files = os.listdir(pathnodejson)
        for file in files:           
            filename=open(pathfilename+file.split('.j')[0]+'.txt', 'a')
            functionname=[]
            functionid=0 
            with open(pathnodejson+file,'r') as fp:
                #print file
                json_data = json.load(fp)
                for func in json_data:
                    blockid=[]
                    blockembedding=[]
                    functionname.append(func) 
                    functionid=functionid+1
                    filename.write(func)
                    filename.write("\n")   
                    for bb in json_data[func]:
                        embed= json_data[func][bb]
                        #print (func, bb)
                        blockid.append(int(bb))
                        embedtemp=[]
                        for ei in range(len(embed)):
                            embedtemp.append(float(embed[ei]))
                        blockembedding.append(embedtemp)
                    blocklen=len(blockid)
                    #print blockembedding
                    edges=os.listdir(pathedge)
                    for edgename in edges:
                        if file.split('.')[0] in edgename:
                            edge=open(pathedge+edgename,'r')
                            edgeff=edge.readlines()
                            edgemat=np.zeros((blocklen,blocklen))
                            for i in range(len(edgeff)):
                                edgeffi=edgeff[i].split(' ',1)
                                if (int(edgeffi[0]) in blockid) and (int(edgeffi[1].strip("\n")) in blockid):
                                    edgemat[blockid.index(int(edgeffi[0]))][blockid.index(int(edgeffi[1].strip("\n")))]=1
                    #print edgemat
                    #print blockid
                    networkpath='network/'+binaryfile+'/'+frameworkfile+'/'+file.split('.j')[0]+'/'
                    attpath='att/'+binaryfile+'/'+frameworkfile+'/'+file.split('.j')[0]+'/'
                    isExists=os.path.exists(networkpath)
                    if not isExists:
                        os.makedirs(networkpath) 
                    isExists=os.path.exists(attpath)
                    if not isExists:
                        os.makedirs(attpath) 
                    scipy.io.savemat(networkpath+func+'.mat', mdict={'edgemat': edgemat})
                    scipy.io.savemat(attpath+func+'.mat', mdict={'blockembedding': blockembedding})
                functionlen=len(functionname)
                bl[file]=functionlen
            filename.close()
            print(bl)
       
