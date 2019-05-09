
from idautils import *
from idaapi import *
from idc import *
import networkx as nx
import cfg_constructor as cfg
import cPickle as pickle
import pdb
from raw_graphs import *
#from discovRe_feature.discovRe import *
from discovRe import *
#import wingdbstub
#wingdbstub.Ensure()
def gt_funcNames(ea):
	funcs = []
	plt_func, plt_data = processpltSegs()
	for funcea in Functions(SegStart(ea)):
			funcname = get_unified_funcname(funcea)
			if funcname in plt_func:
				print funcname
				continue
			funcs.append(funcname)
	return funcs

def get_funcs(ea):
	funcs = {}
		# Get current ea
		# Loop from start to end in the current segment
	plt_func, plt_data = processpltSegs()
	for funcea in Functions(SegStart(ea)):
		funcname = get_unified_funcname(funcea)
		if funcname in plt_func:
			continue
		func = get_func(funcea)
		blocks = FlowChart(func)
		funcs[funcname] = []
		for bl in blocks:
				start = bl.startEA
				end = bl.endEA
				funcs[funcname].append((start, end))
	return funcs

# used for the callgraph generation.
def get_func_namesWithoutE(ea):
	funcs = {}
	plt_func, plt_data = processpltSegs()
	for funcea in Functions(SegStart(ea)):
			funcname = get_unified_funcname(funcea)
			if 'close' in funcname:
				print funcea
			if funcname in plt_func:
				print funcname
				continue
			funcs[funcname] = funcea
	return funcs

# used for the callgraph generation.
def get_func_names(ea):
	funcs = {}
	for funcea in Functions(SegStart(ea)):
			funcname = get_unified_funcname(funcea)
			funcs[funcname] = funcea
	return funcs

def get_func_bases(ea):
		funcs = {}
		plt_func, plt_data = processpltSegs()
		for funcea in Functions(SegStart(ea)):
				funcname = get_unified_funcname(funcea)
				if funcname in plt_func:
					continue
				funcs[funcea] = funcname
		return funcs

def get_func_range(ea):
		funcs = {}
		for funcea in Functions(SegStart(ea)):
				funcname = get_unified_funcname(funcea)
		func = get_func(funcea)
		funcs[funcname] = (func.startEA, func.endEA)
		return funcs

def get_unified_funcname(ea):
	funcname = GetFunctionName(ea)
	if len(funcname) > 0:
		if '.' == funcname[0]:
			funcname = funcname[1:]
	return funcname

def get_func_sequences(ea):
	funcs_bodylist = {}
	funcs = get_funcs(ea)
	for funcname in funcs:
		if funcname not in funcs_bodylist:
			funcs_bodylist[funcname] = []
		for start, end in funcs[funcname]:
			inst_addr = start
			while inst_addr <= end:
				opcode = GetMnem(inst_addr)
				funcs_bodylist[funcname].append(opcode)
				inst_addr = NextHead(inst_addr)
	return funcs_bodylist

def get_func_cfgs_c(ea):
	binary_name = idc.GetInputFile()
	raw_cfgs = raw_graphs(binary_name)
	externs_eas, ea_externs = processpltSegs()
	i = 0
	for funcea in Functions(SegStart(ea)):
		funcname = get_unified_funcname(funcea)
		print funcname
		func = get_func(funcea)
		print i
		i += 1
		icfg = cfg.getCfg(func, externs_eas, ea_externs)
		func_f = get_discoverRe_feature(func, icfg[0])
		raw_g = raw_graph(funcname, icfg, func_f)
		raw_cfgs.append(raw_g)
			
	return raw_cfgs

def get_func_cfgs_ctest(ea):
	binary_name = idc.GetInputFile()
	raw_cfgs = raw_graphs(binary_name)
	externs_eas, ea_externs = processpltSegs()
	i = 0
	diffs = {}
	for funcea in Functions(SegStart(ea)):
		funcname = get_unified_funcname(funcea)
		func = get_func(funcea)
		print i
		i += 1
		icfg, old_cfg = cfg.getCfg(func, externs_eas, ea_externs)
		diffs[funcname] = (icfg, old_cfg)
		#raw_g = raw_graph(funcname, icfg)
		#raw_cfgs.append(raw_g)
			
	return diffs

def get_func_cfgs(ea):
	func_cfglist = {}
	i = 0
	for funcea in Functions(SegStart(ea)):
		funcname = get_unified_funcname(funcea)
		func = get_func(funcea)
		print i
		i += 1
		try:
			icfg = cfg.getCfg(func)
			func_cfglist[funcname] = icfg
		except:
			pass
			
	return func_cfglist

def get_func_cfg_sequences(func_cfglist):
	func_cfg_seqlist = {}
	for funcname in func_cfglist:
		func_cfg_seqlist[funcname] = {}
		cfg = func_cfglist[funcname][0]
		for start, end in cfg:
			codesq = get_sequences(start, end)
			func_cfg_seqlist[funcname][(start,end)] = codesq

	return func_cfg_seqlist


def get_sequences(start, end):
	seq = []
	inst_addr = start
	while inst_addr <= end:
		opcode = GetMnem(inst_addr)
		seq.append(opcode)
		inst_addr = NextHead(inst_addr)
	return seq

def get_stack_arg(func_addr):
	print func_addr
	args = []
	stack = GetFrame(func_addr)
	if not stack:
			return []
	firstM = GetFirstMember(stack)
	lastM = GetLastMember(stack)
	i = firstM
	while i <=lastM:
		mName = GetMemberName(stack,i)
		mSize = GetMemberSize(stack,i)
		if mSize:
				i = i + mSize
		else:
				i = i+4
		if mName not in args and mName and ' s' not in mName and ' r' not in mName:
			args.append(mName)
	return args

		#pickle.dump(funcs, open('C:/Documents and Settings/Administrator/Desktop/funcs','w'))

def processExternalSegs():
	funcdata = {}
	datafunc = {}
	for n in xrange(idaapi.get_segm_qty()):
		seg = idaapi.getnseg(n)
		ea = seg.startEA
		segtype = idc.GetSegmentAttr(ea, idc.SEGATTR_TYPE)
		if segtype in [idc.SEG_XTRN]:
			start = idc.SegStart(ea)
			end = idc.SegEnd(ea)
			cur = start
			while cur <= end:
				name = get_unified_funcname(cur)
				funcdata[name] = hex(cur)
				cur = NextHead(cur)
	return funcdata

def processpltSegs():
	funcdata = {}
	datafunc = {}
	for n in xrange(idaapi.get_segm_qty()):
		seg = idaapi.getnseg(n)
		ea = seg.startEA
		segname = SegName(ea)
		if segname in ['.plt', 'extern', '.MIPS.stubs']:
			start = seg.startEA
			end = seg.endEA
			cur = start
			while cur < end:
				name = get_unified_funcname(cur)
				funcdata[name] = hex(cur)
				datafunc[cur]= name
				cur = NextHead(cur)
	return funcdata, datafunc

		
def processDataSegs():
	funcdata = {}
	datafunc = {}
	for n in xrange(idaapi.get_segm_qty()):
		seg = idaapi.getnseg(n)
		ea = seg.startEA
		segtype = idc.GetSegmentAttr(ea, idc.SEGATTR_TYPE)
		if segtype in [idc.SEG_DATA, idc.SEG_BSS]:
			start = idc.SegStart(ea)
			end = idc.SegEnd(ea)
			cur = start
			while cur <= end:
				refs = [v for v in DataRefsTo(cur)]
				for fea in refs:
					name = get_unified_funcname(fea)
					if len(name)== 0:
						continue
					if name not in funcdata:
						funcdata[name] = [cur]
					else:
						funcdata[name].append(cur)
					if cur not in datafunc:
						datafunc[cur] = [name]
					else:
						datafunc[cur].append(name)
				cur = NextHead(cur)
	return funcdata, datafunc

def obtainDataRefs(callgraph):
	datarefs = {}
	funcdata, datafunc = processDataSegs()
	for node in callgraph:
		if node in funcdata:
			datas = funcdata[node]
			for dd in datas:
				refs = datafunc[dd]
				refs = list(set(refs))
				if node in datarefs:
					print refs
					datarefs[node] += refs
					datarefs[node] = list(set(datarefs[node]))
				else:
					datarefs[node] = refs
	return datarefs


