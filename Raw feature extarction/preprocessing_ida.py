from func import *
from raw_graphs import *
from idc import *
import os
import argparse
import time

def parse_command():
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument("--path", type=str, help="The directory where to store the generated .ida file")
	args = parser.parse_args()
	return args

  
if __name__ == '__main__':

	args = parse_command()
	path =  'C:/Users/YJ/Desktop/ida_output/'
	print path
	analysis_flags = idc.GetShortPrm(idc.INF_START_AF)
	analysis_flags &= ~idc.AF_IMMOFF
	# turn off "automatically make offset" heuristic
	idc.SetShortPrm(idc.INF_START_AF, analysis_flags)
	idaapi.autoWait()
	starttime=time.time()
	cfgs = get_func_cfgs_c(FirstSeg())

	#for cfg in cfgs.raw_graph_list:
	#   adjacencymatrix = AdjacencyMatrix(cfg.g.edges(),len(cfg.old_g))
     
	endtime=time.time()
	binary_name = idc.GetInputFile() + '.ida'
	fullpath = os.path.join(path, binary_name)
	pickle.dump(cfgs, open(fullpath,'w'))
	print binary_name
	#idc.Exit(0)
