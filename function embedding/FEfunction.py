def FEfunction(Wei,Attri,d,*varargs):
    import numpy as np
    from scipy import sparse
    from scipy.sparse import csc_matrix
    from scipy.sparse.linalg import svds
    from math import ceil
    '''################# Parameters #################'''
    global affi, sa, H, Z
    maxiter = 20  # Max num of iteration
    [n, m] = Attri.shape  # n = Total num of nodes, m = attribute category num
    #print min(A.shape)
    A=Attri
    #print A
    Net = sparse.lil_matrix(Wei)
    Net.setdiag(np.zeros(n))
    Net = csc_matrix(Net)
    Attri = csc_matrix(Attri)
    #print Net
    #print Attri
    lambd = 1  # Initial regularization parameter
    rho = 5  # Initial penalty parameter
    splitnum = 1  # number of pieces we split the SA for limited cachemin(10 * d, n)[0:d]
    #print varargs[3]
    if len(varargs) >= 4 and varargs[3] == 'Att':
        sumcol = np.arange(m)
        np.random.shuffle(sumcol)
        H = svds(Attri[:, sumcol[0:min(10 * d, m)]], d)[2]
    else:

        sumcol = Net.sum(0)
        #print sumcol.shape
        if max(sumcol.shape)>1:
            Atemp = np.zeros((n, 2*d))
            H = np.zeros((n, d))
            if 2*d>m:
                Atemp[:,0:m]=A
            else:
                Atemp=A[:,0:2*d]
            if n<d:
                H=np.zeros((n,d))
                #H[:,0:n-1]= svds(Attri, n-1)[0]
                H[:,0:n-1] = svds(Attri,min(d,n)-1)[0]
            else:
                H=svds(Atemp,min(d,n))[0][:,0:d]
            #H = np.zeros((n, d))
            #H = svds(Net[:, sorted(range(n), key=lambda k: sumcol[0, k], reverse=True)][0:d], min(10 * d, n))[0]


            #print
        else:
           # print np.sum(A),A.shape[0]
            #A[:, 0]=np.sum(A)
            H=np.zeros((n,d))
            if d>m:
                H[:,0:m]=A
            else:
                H[:,0]=np.sum(A)
           # print H
        #print min(Attri[:, 0:2*d].shape)
       # H = np.linalg.svd(Attri[:, 0:2*d])[0]
    if len(varargs) > 0:
        lambd = varargs[0]
        rho = varargs[1]
        if len(varargs) >= 3:
            maxiter = varargs[2]
            if len(varargs) >=5:
                splitnum = varargs[4]
    block = min(int(ceil(float(n) / splitnum)), 7575)  # Treat at least each 7575 nodes as a block
    splitnum = int(ceil(float(n) / block))
    with np.errstate(divide='ignore'):  # inf will be ignored
        Attri = Attri.transpose() * sparse.diags(np.ravel(np.power(Attri.power(2).sum(1), -0.5)))
    #H=np.ones((n, d))
    Z = H.copy()
    affi = -1  # Index for affinity matrix sa
    U = np.zeros((n, d))
    nexidx = np.split(Net.indices, Net.indptr[1:-1])
    Net = np.split(Net.data, Net.indptr[1:-1])
    #print Z
    #print H
    '''################# Update functions #################'''
    def updateH():
        global affi, sa, H
        xtx = np.dot(Z.transpose(), Z) * 2 + rho * np.eye(d)
        for blocki in range(splitnum):  # Split nodes into different Blocks
            indexblock = block * blocki  # Index for splitting blocks
            if affi != blocki:
                sa = Attri[:, range(indexblock, indexblock + min(n - indexblock, block))].transpose() * Attri
                affi = blocki
            sums = sa.dot(Z) * 2
            for i in range(indexblock, indexblock + min(n - indexblock, block)):
                #print nexidx[i]
                neighbor = Z[nexidx[i], :]  # the set of adjacent nodes of node i
                #print neighbor.shape
                for j in range(1):
                    normi_j = np.linalg.norm( neighbor-H[i, :], axis=1)
                    #print normi_j.shape
                    #print normi_j
                    #print neighbor * np.transpose(Z[i, :])
                    #print np.dot(neighbor, Z[i, :])
                    nzidx = normi_j != 0   # Non-equal Index
                    (Zm, Zn) = np.shape(Z)
                    #print Zm,Zn
                    Exp = [0] * Zm
                    HExp=[0]*Zm
                    for kk in range(Zm):
                        Exp[kk] = np.exp(np.dot(Z[kk, :], H[i, :]))
                        HExp[kk]=Z[kk, :]*Exp[kk]
                    #if np.any(nzidx):
                        #normij = float(np.dot(H, Exp)) / sum(Exp)
                        #normi_j = lambd * Net[i][nzidx] * normij
                    #print nzidx
                    if np.any(nzidx):
                        #normij = np.exp(np.dot(neighbor[nzidx], H[i, :]))
                        #print 'npdot:',np.dot(Z, Exp)
                        #print np.sum(ZExp,axis=1)
                        normij = np.sum(HExp,axis=1) / sum(Exp)
                       #
                    #  print np.transpose(np.mat(normij)),Net[i][nzidx]
                        normi_j = np.sum(np.dot(np.transpose(np.mat(normij)),np.mat(lambd * Net[i][nzidx])),axis=1)
                        #normi_j = np.transpose(normi_j) - lambd * Net[i][nzidx] * neighbor[nzidx, :]
                        normi_j = normi_j[0]
                        #H[i, :] = np.linalg.solve(xtx + normi_j.sum() * np.eye(d), sums[i - indexblock, :] + (
                         #   neighbor[nzidx, :] * normi_j.reshape((-1, 1))).sum(0) + rho * (
                         #                            Z[i, :] - U[i, :]))
                        H[i, :] = np.linalg.solve(xtx, sums[i - indexblock, :] - (neighbor[nzidx,:]*(lambd*Net[i][nzidx]).reshape((-1,1))).sum(0)+(
                             normi_j.reshape((-1, 1))).sum(0) + rho * (
                                                      Z[i, :] - U[i, :]))
                    else:
                        H[i, :] = np.linalg.solve(xtx, sums[i - indexblock, :] + rho * (
                            Z[i, :] - U[i, :]))
                        #normi_j = lambd * Net[i][nzidx] / normij
                        #normi_j = normi_j[0]
                        #H[i, :] = np.linalg.solve(xtx + normi_j.sum() * np.eye(d), sums[i - indexblock, :] + (
                         #   neighbor[nzidx, :] * normi_j.reshape((-1, 1))).sum(0) + rho * (
                         #                             Z[i, :] - U[i, :]))
    def updateZ():
        global affi, sa, Z
        xtx = np.dot(H.transpose(), H) * 2 + rho * np.eye(d)
        for blocki in range(splitnum):  # Split nodes into different Blocks
            indexblock = block * blocki  # Index for splitting blocks
            if affi != blocki:
                sa = Attri[:, range(indexblock, indexblock + min(n - indexblock, block))].transpose() * Attri
                affi = blocki
            sums = sa.dot(H) * 2
            for i in range(indexblock, indexblock + min(n - indexblock, block)):
                neighbor = H[nexidx[i], :]  # the set of adjacent nodes of node i
                for j in range(1):
                    normi_j = np.linalg.norm(neighbor - Z[i, :], axis=1)  # norm of h_i^k-z_j^k
                    #normij = 1 + np.exp(np.dot(neighbor, Z[i, :]))
                    nzidx = normi_j != 0  # Non-equal Index
                    (Hm, Hn)=np.shape(H)
                    #print Hm
                    Exp=[0]*Hm
                    #for kk in range(Hm):
                    #    Exp[kk]=np.exp(np.dot(H[kk,:], Z[i, :]))
                    ZExp = [0] * Hm
                    for kk in range(Hm):
                        Exp[kk] = np.exp(np.dot(H[kk, :], Z[i, :]))
                        ZExp[kk] = H[kk, :] * Exp[kk]

                    if np.any(nzidx):
                        #print Exp
                        normij = np.sum(ZExp,axis=1)/sum(Exp)
                        normi_j = np.sum(np.dot(np.transpose(np.mat(normij)), np.mat(lambd * Net[i][nzidx])), axis=1)
                       # normi_j=np.transpose(normi_j)-lambd*Net[i][nzidx]*neighbor[nzidx,:]
                        normi_j = normi_j[0]
                        #Z[i, :] = np.linalg.solve(xtx + normi_j.sum() * np.eye(d), sums[i - indexblock, :] + (
                         #   neighbor[nzidx, :] * normi_j.reshape((-1, 1))).sum(0) + rho * (H[i, :] + U[i, :]))
                        Z[i, :] = np.linalg.solve(xtx, sums[i - indexblock, :] -(neighbor[nzidx,:]*(lambd*Net[i][nzidx]).reshape((-1,1))).sum(0)+ (
                            normi_j.reshape((-1, 1))).sum(0) + rho * (
                                                      H[i, :] + U[i, :]))
                    else:
                        Z[i, :] = np.linalg.solve(xtx, sums[i - indexblock, :] + rho * (
                            H[i, :] + U[i, :]))
                        #normi_j = lambd * Net[i][nzidx] / normij
                       # normi_j = normi_j[0]
                        # Z[i, :] = np.linalg.solve(xtx + normi_j.sum() * np.eye(d), sums[i - indexblock, :] + (
                        #   neighbor[nzidx, :] * normi_j.reshape((-1, 1))).sum(0) + rho * (H[i, :] + U[i, :]))
                        #Z[i, :] = np.linalg.solve(xtx, sums[i - indexblock, :] + (
                           # neighbor[nzidx, :] * normi_j.reshape((-1, 1))).sum(0) + rho * (
                            #                          H[i, :] + U[i, :]))
    '''################# First update H #################'''
    updateH()
    '''################# Iterations #################'''
    for iternum in range(maxiter - 1):
        updateZ()
        U = U + H - Z
        updateH()
    return H
