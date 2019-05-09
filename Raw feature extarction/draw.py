from raw_graphs import *
import cPickle as pickle
import networkx as nx
import matplotlib.pyplot as plt
import datetime

# input the program.ida that is extracted by ida pro
file_name = 'G:\ida_out\busybox_O0_X86.ida'

data = pickle.load(open(file_name, 'r'))
graphs = data.raw_graph_list
folder = file_name + '_graphs_' + datetime.datetime.now().strftime('%H_%M_%S')
os.mkdir(folder)
os.mkdir(folder + '/node')
os.mkdir(folder + '/edge')
os.mkdir(folder + '/adj')
#doc_node = open('nodeopenssl.txt', 'w')
#doc_edge = open('edgeopenssl.txt', 'w')
#doc_adj = open('adjopenssl.txt', 'w')
for i in  range(len(graphs)):
    print(i)
    #if i % 100 == 0:
    #    print(i)
    doc_node = open(folder + '/node/nodeopenssl'+str(i)+'.txt', 'w')
    doc_edge = open(folder + '/edge/edgeopenssl'+str(i)+'.txt', 'w')
    doc_adj = open(folder + '/adj/adjopenssl'+str(i)+'.txt', 'w')
    g = graphs[i].g
    ### node
    print('graph_' + str(i) + '(node):')
    doc_node.write('graph_' + str(i) + ':(node)\n')
    for j in range(len(g.node)):
        print(g.node[j])
        doc_node.write(str(g.node[j]) + '\n')
    ### edge
    print('graph_' + str(i) + '(edge):')
    doc_edge.write('graph_' + str(i) + ':(edge)\n')
    for k in range(len(g.edge)):
        print(g.edge[k])
        doc_edge.write(str(g.edge[k]) + '\n')
    ### adj
    print('graph_' + str(i) + '(adj):')
    doc_adj.write('graph_' + str(i) + ':(adj)\n')
    for l in range(len(g.adj)):
        print(g.adj[l])
        doc_adj.write(str(g.adj[l]) + '\n')
    doc_node.close()
    doc_edge.close()
    doc_adj.close()
   # plt.cla()
   # nx.draw(g)
   # pic_save_name = folder + '/graphs/' + file_name + ".%05d.png" % i;
   # plt.savefig(pic_save_name)
