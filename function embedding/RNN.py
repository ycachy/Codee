import numpy as np
import scipy.io as sio
from FEfun import FEfun
import time
import os




#import util
path='network/'
files= os.listdir(path)
s = []
for file in files:
    if not os.path.isdir(file):
        print(file)
        #mat_contents = sio.loadmat('BlogCatalog.mat')
        lambd = 0.05  # the regularization parameter
        rho = 5  # the penalty parameter

        

        
        d = 1  # the dimension of the embedding representation
        #G = mat_contents["Network"]
        #f = open(path+file)
        GG=sio.loadmat(path+file)
        G=GG["network"]
        #print(G)
        G_name=os.path.basename(path+file)
        A_name='node'+G_name[4:]
        AA=sio.loadmat('att/'+A_name)
        A=AA["network"]
        #print(A)
       # label_name='graph_'+G_name[6:]
     #   AA=sio.loadmat('opensslarm/att/'+A_name)
      #A#=AA["network"]
     #   LL=sio.loadmat('opensslarm/label/'+label_name)
      #  Label=LL["network"]
       # label_name='label'+G_name[7:]
#G = mat_contents["Network"
#print(G)
##A = mat_contents["Attributes"]
#print(A)
#L#abel = mat_contents["Label"]
#print(Label)
#del mat_contents
        n = G.shape[0]
        Indices = np.random.randint(25, size=n)+1  

        Group1 = []
        Group2 = []
        [Group1.append(x) for x in range(0, n) if Indices[x] <= 20]  #
        [Group2.append(x) for x in range(0, n) if Indices[x] >= 21]  #
        n1 = len(Group1)  # num of nodes in training group
        n2 = len(Group2)  # num of nodes in test group
        CombG = G[Group1+Group2,:][:,Group1+Group2]
        CombA = A[Group1+Group2,:]
        print(CombG.shape)
        print(CombA.shape)
        start_time = time.time()
        FE = FEfun(CombG, CombA, d, lambd, rho)
        print(FE)
        print("time elapsed: {:.2f}s".format(time.time() - start_time))

        embedding_name='emdedding'+G_name[4:]
        
        sio.savemat('embeddd/'+embedding_name, {"FE": FE})

