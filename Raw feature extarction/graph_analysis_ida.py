#coding=utf-8
from idautils import *
from idaapi import *
from idc import *

def getfunc_consts(func):
	strings = []
	consts = []
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	for bl in blocks:
		strs, conts = getBBconsts(bl)
		strings += strs
		consts += conts
	return strings, consts
	

def getConst(ea, offset):
	strings = []
	consts = []
	optype1 = GetOpType(ea, offset)
	if optype1 == idaapi.o_imm:
		imm_value = GetOperandValue(ea, offset)
		if 0<= imm_value <= 10:
			consts.append(imm_value)
		else:
			if idaapi.isLoaded(imm_value) and idaapi.getseg(imm_value):
				str_value = GetString(imm_value)
				if str_value is None:
					str_value = GetString(imm_value+0x40000)
					if str_value is None:
						consts.append(imm_value)
					else:
						re = all(40 <= ord(c) < 128 for c in str_value)
						if re:
							strings.append(str_value)
						else:
							consts.append(imm_value)
				else:
					re = all(40 <= ord(c) < 128 for c in str_value)
					if re:
						strings.append(str_value)
					else:
						consts.append(imm_value)
			else:
				consts.append(imm_value)
	return strings, consts

def getBBconsts(bl):
	strings = []
	consts = []
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in ['la','jalr','call', 'jal']:
			inst_addr = NextHead(inst_addr)
			continue
		strings_src, consts_src = getConst(inst_addr, 0)
		strings_dst, consts_dst = getConst(inst_addr, 1)
		strings += strings_src
		strings += strings_dst
		consts += consts_src
		consts += consts_dst
		try:
			strings_dst, consts_dst = getConst(inst_addr, 2)
			consts += consts_dst
			strings += strings_dst
		except:
			pass

		inst_addr = NextHead(inst_addr)
	return strings, consts

def getFuncCalls(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	sumcalls = 0
	for bl in blocks:
		callnum = calCalls(bl)
		sumcalls += callnum
	return sumcalls

def getcodesquence(bl):
	sequence=[]
	#print("EEEEEEEEEEEEEEEEEEEEEEEE")
	#x86_AI = {'add':1, 'sub':1, 'div':1, 'imul':1, 'idiv':1, 'mul':1, 'shl':1, 'dec':1, 'inc':1}
	#mips_AI = {'add':1, 'addu':1, 'addi':1, 'addiu':1, 'mult':1, 'multu':1, 'div':1, 'divu':1}
	#x86_TI = {'jmp': 1, 'jz': 1, 'jnz': 1, 'js': 1, 'je': 1, 'jne': 1, 'jg': 1, 'jle': 1, 'jge': 1, 'ja': 1, 'jnc': 1,
			#  'call': 1}
	#mips_TI = {'beq': 1, 'bne': 1, 'bgtz': 1, "bltz": 1, "bgez": 1, "blez": 1, 'j': 1, 'jal': 1, 'jr': 1, 'jalr': 1}
	#arm_TI = {'MVN': 1, "MOV": 1}
	# in each opcode, there are three lines, one is the arm, one is the x86, and the other is mips.
	GDTI={'MVN':1, "MOV":1,'LDR':2,'LDRB':2,'LDRH':2,'STR':3,'STRB':3,'STRH':3,'LDM':2,'STM':3,'SWP':3,'SWPB':3,
		  'mov':1,'movsx':1,'movzx':1,'push':4,'pop':5,'pusha':4,'pope':5,'pushed':4,'popad':5,'bswap':3,'xlat':7,'mvn':1,'popf':5,'pushd':4,'popd':5,'movs':1,'lods':2,'stos':3, 'movss':1,'movsd':1,'movaps':8, 'movapd':8,'movups':9,'movupd':9,
'movlps':10, 'movlpd':10,'movhps':11, 'movhpd':11, 'movlhps':12	,'movhlps':13,	'mosldup':14, 'movshdup':15,'movddup':16, 'movmskps':17, 'movmskpd':17,'shufps':18, 'shufpd':18,'movdqa':12	,'movdpu':13,	'movq2dq':14	,'movdq2q':15,	
'unpcklps':19, 'unpcklpd':19,	'insertps':4,'extractps':5,
'unpckhps':20, 'unpckhpd':20,
		  'lui':1,'lw':1,'sw':3}
	IOPTI={'in':1,'out':2,}
	DATI={'lea':1,'lds':1,'les':1,'lfs':1,'lgs':1}
	FTI={'lahf':1,'sahf':2,}
	ADO={'add':1,'adc':1,'inc':2,'aaa':3,'daa':3,'sub':4,'sbb':4,'dec':5,'nec':5,'xadd':1,'tst':6,'tea':6,'cmp':7,'xchg':7,'cmps':7, 'cmpxchg':7, 'addps':1,'subps':4,'mulps':8,'divps':11,'addss':1,'addsd':1,'subss':4,'subsd':4,'mulss':8,'mulsd':8,'divss':9, 'divsd':9,'sqrtss':10,'sqrtsd':10,'maxss':11,'maxsd':11,'minss':12,'minsd':12,'roundss':13,'roundsd':13,'rcpss':14,'rsqrt':15, 'cmpss':7,'smpsd':7,'comiss':16,'comisd':16,'ucomiss':17,'ucomisd':17,'addps':1,'addpd':1,'subps':4,'subpd':4,'mulps':8,'mulpd':8,'divps':9, 'divpd':9,'sqrtps':10,'sqrtpd':10,'maxps':11,'maxpd':11,'minps':12,'minpd':12,'roundps':13,'roundpd':13,'rcpps':14,'rsqrtps':15,'addsubps':18, 'addsubpd':18,'pmulld':8,'pmuldq':8,'pmaxub':19,'pmaxuw':19,'pmaxud':19,'pminsb':12,'pminsd':12,'pminsw':12,'pminub':20,'pminud':20,'pminuw':20,',pmaxsb':11,'pmaxsw':11,'pmaxsd':11,'dpps':21, 'dppd':21, 'roundps':13, 'roundpd':13,'haddps':22, 'haddpd':22,	'hsubpd':23, 'hsubpd':23,'cmpps':7,'pcmpeqd':7,'pcmpeqw':7,'pcmpeqb':7,'pcmpeqq':7,'pcmpgtb':7,'pcmpgtw':7,'pcmpgtd':7,'pcmpgtq':7,'cmppd':7,'ADD':1, 'ADC':1,'SUB':4,'C':4,'R':5,'RSC':5,'TEQ':6,'TST':6,'CMP':7,'MUL':8,'MLA':8,'SMULL':8,'SMLAL':8,'UMULL':8,'UMLAL':8,'aas':3,'das':3,'mul':8,'imul':8,'aam':3,'div':9,'idiv':9,'aad':1, 'add':1,'addu':1,'sub':4,'subu':4,'addi':1,'addiu':1}
	LDO={'and':1,'or':2,'xor':3,'not':4,'test':5,'shl':6,'sal':6,'shr':6,'sar':6,'rol':7,'ror':7,'rcl':7,'rcr':7,
		 'orr':7,'eor':7,'bic':8,'cwd':9,'cwde':9,'cdq':9,'cbw':9, 'cvtsi2ss':10,'cvrsi2sd':10,'cvtss2si':11,'cvtsd2si':11,'cvttss2si':12,'cvttsd2si':12,'cvtss2sd':13,'cvtsd2ss':14,'cvtpi2ps':10, 'cvpi2pd':10,'cvtps2pi':11,'cvtpd2pi':11,'cvttps2pi':12,'cvttpd2pi':12,'cvtps2pd':13,'cvtpd2ps':14,'andps':1, 'andpd':1,	'andnps':15, 'andnpd':15,'orps':2,'orpd':2,	'xorps':3,	'xorpd':3,'pslldq':6,'psrldq':6,'and':1,'or':2,'xor':2,'nor':2,'andi':3,'ori':2,'xori':2,'AND':1,'ORR':2,'EOR':2,'BIC':8,'LSL':3,'LSR':3}
	SI={'scas':1,'rep':2,'repe':2,'repen':2,'repc':2,'repnc':2,'pcmpestri':3,	
'pcmpestrm':3,	
'pcmpistri':4,	
'pcmpistrm':4}
	UBI={'jump':1,'call':2,'ret':2,
		 'j':1,'jal':1,'jr':1}
	CBI={'ja':1,'jnz':1,'jnbe':2,'jae':2,'jnb':2,'jb':3,'jbe':3,'jg':4,'jge':4,'jl':5,'jle':5,'je':1,'jne':2,'jc':6,'jnc':6,'jno':6,'jnp':6,'jns':6,'jo':7,'jp':7,'js':7,
		 'slt':1,'sltu':1,'sll':1,'srl':2,'sra':2,'sllv':1,'srlv':2,'srav':2,"beq":3, "bne":3,'slti':1,'sltiu':1,
		 #"beqz":1 "bgez":4, "b":5, "bnez":6, "bgtz":7, "bltz":8, "blez":9, "bgt":10, "bge":11, "blt":12, "ble":13, "bgtu":14, "bgeu":15, "bltu":16, "bleu":17,
		 "B":1, "BAL":1, "BNE":1, "BEQ":1, "BPL":2, "BMI":2, "BCC":3, "BLO":5, "BCS":3, "BHS":4, "BVC":6, "BVS":6, "BGT":7, "BGE":7, "BLT":5, "BLE":5, "BHI":4 ,"BLS":5,'BL':5,'BLX':5}
	LCI={'loop':1,'loope':1,'loopne':1,'jcxz':2,'jecxz':2}
	II={'int':1,'into':1,'iret':2,
		'SWI':1,'BKPT':2,}
	PCI={'hlt':1,'wait':2,'esc':3,'lock':4,'nop':5,'stc':6,'clc':7,'cmc':7,'std':8,'cld':7,'sti':8,'cli':7,'ldmxcsr':9,	
'stmxcsr':10,	'fxsave':11,	'fxrstor':12,	'crc32':13,
		 'CDP':1,'LDC':2,'STC':3,'MCR':4,'MRC':4,'MRS':4,'MSR':4}
	PI={'dw':1,'proc':2,'ends':3,'segment':4,'assume':5,'end':3,
		'GBLA':1,'GBLL':1,'GBLS':1,'LCLA':2,'LCLL':2,'LCLS':2,'SETA':3,'SETL':3,'SETS':3,'RLIST':4,'DCB':5,'DCW':5,'DCD':5,'DCFD':5,
		'DCFS':5,'DCQ':5,'SPACE':6,'MAP':7,'FILED':8}
	opcodenum=0
	#blocks=[(v.startEA, v.endEA) for v in FlowChart(func)]

	start = bl[0]
	end = bl[1]

	inst_addr = start
	while inst_addr < end:

		opcode = GetMnem(inst_addr)

		if opcode in GDTI:
			opcodenum=GDTI.get(opcode)
			sequence.append(1)
		if opcode in IOPTI:
			opcodenum=IOPTI.get(opcode)
			sequence.append(2)
		if opcode in DATI:
			opcodenum=DATI.get(opcode)
			sequence.append(3)
		if opcode in PI:
			opcodenum=PI.get(opcode)
			sequence.append(4)
		if opcode in FTI:
			opcodenum=FTI.get(opcode)
			sequence.append(5)
		if opcode in ADO:
			opcodenum=ADO.get(opcode)
			sequence.append(6)
		if opcode in LDO:
			opcodenum=LDO.get(opcode)
			sequence.append(7)
		if opcode in SI:
			opcodenum=SI.get(opcode)
			sequence.append(8)
		if opcode in UBI:
			opcodenum=UBI.get(opcode)
			sequence.append(9)
		if opcode in CBI:
			opcodenum=CBI.get(opcode)
			sequence.append(10)
		if opcode in LCI:
			opcodenum=LCI.get(opcode)
			sequence.append(11)
		if opcode in II:
			opcodenum=II.get(opcode)
			sequence.append(12)
		if opcode in PCI:

			opcodenum=PCI.get(opcode)
			#print("CCCCCCCCCCCCCCCCCCCC")
			sequence.append(13)

		sequence.append(opcodenum)
		print sequence
		inst_addr = NextHead(inst_addr)
	return sequence


def getLogicInsts(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	sumcalls = 0
	for bl in blocks:
		callnum = calLogicInstructions(bl)
		sumcalls += callnum
	return sumcalls

def getTransferInsts(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	sumcalls = 0
	for bl in blocks:
		callnum = calTransferIns(bl)
		sumcalls += callnum
	return sumcalls

def getIntrs(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	sumcalls = 0
	for bl in blocks:
		callnum = calInsts(bl)
		sumcalls += callnum
	return sumcalls	


	
	
def getLocalVariables(func):
	args_num = get_stackVariables(func.startEA)
	return args_num

def getBasicBlocks(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	return len(blocks)

def getIncommingCalls(func):
	refs = CodeRefsTo(func.startEA, 0)
	re = len([v for v in refs])
	return re


def get_stackVariables(func_addr):
	#print func_addr
	args = []
	stack = GetFrame(func_addr)
	if not stack:
			return 0
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
		if mName not in args and mName and 'var_' in mName:
			args.append(mName)
	return len(args)



def calArithmeticIns(bl):
	x86_AI = {'add':1, 'sub':1, 'div':1, 'imul':1, 'idiv':1, 'mul':1, 'shl':1, 'dec':1, 'inc':1}
	mips_AI = {'add':1, 'addu':1, 'addi':1, 'addiu':1, 'mult':1, 'multu':1, 'div':1, 'divu':1}
  arm_AI={'ADD':1, 'ADC':1,'SUB':1,'MUL':1,'MLA':1,'SMULL':1,'SMLAL':1,'UMULL':1,'UMLAL':1}
	calls = {}
	calls.update(x86_AI)
	calls.update(mips_AI)
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in calls:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calCalls(bl):
	calls = {'call':1, 'jal':1, 'jalr':1}
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in calls:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calInsts(bl):
	start = bl[0]
	end = bl[1]
	ea = start
	num = 0
	while ea < end:
		num += 1
		ea = NextHead(ea)
	return num

def calLogicInstructions(bl):
	x86_LI = {'and':1, 'andn':1, 'andnpd':1, 'andpd':1, 'andps':1, 'andnps':1, 'test':1, 'xor':1, 'xorpd':1, 'pslld':1,'and':1,'or':1,'xor':1,'not':1,'test':1,'shl':1,'sal':1,'shr':,1'sar':1,'rol':1,'ror':1,'rcl':1,'rcr':1,
		 'orr':7,'eor':1,'bic':1,'cwd':1,'cwde':1,'cdq':1,'cbw':1, 'cvtsi2ss':1,'cvrsi2sd':1,'cvtss2si':1,'cvtsd2si':1,'cvttss2si':1,'cvttsd2si':1,'cvtss2sd':1,'cvtsd2ss':1,'cvtpi2ps':1, 'cvpi2pd':1,'cvtps2pi':1,'cvtpd2pi':1,'cvttps2pi':1,'cvttpd2pi':1,'cvtps2pd':1,'cvtpd2ps':1}
	mips_LI = {'and':1, 'andi':1, 'or':1, 'ori':1, 'xor':1, 'nor':1, 'slt':1, 'slti':1, 'sltu':1,'andps':1, 'andpd':1,	'andnps':1, 'andnpd':1,'orps':1,'orpd':1,	'xorps':1,	'xorpd':1,'pslldq':1,'psrldq':1,'and':1,'or':1,'xor':1,'nor':1,'andi':1,'ori':1,'xori':1}
  arm_LI={'AND':1,'ORR':1,'EOR':1,'BIC':1,'LSL':1,'LSR':1}
	calls = {}
	calls.update(x86_LI)
	calls.update(mips_LI)
  calls.update(arm_LI)
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in calls:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calSconstants(bl):
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in calls:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num


def calNconstants(bl):
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		optype1 = GetOpType(inst_addr, 0)
		optype2 = GetOpType(inst_addr, 1)
		if optype1 == 5 or optype2 == 5:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def retrieveExterns(bl, ea_externs):
	externs = []
	start = bl[0]
	end = bl[1]
	inst_addr = start
	while inst_addr < end:
		refs = CodeRefsFrom(inst_addr, 1)
		try:
			ea = [v for v in refs if v in ea_externs][0]
			externs.append(ea_externs[ea])
		except:
			pass
		inst_addr = NextHead(inst_addr)
	return externs

def calTransferIns(bl):
	x86_TI = {'jmp':1, 'jz':1, 'jnz':1, 'js':1, 'je':1, 'jne':1, 'jg':1, 'jle':1, 'jge':1, 'ja':1, 'jnc':1, 'call':1}
	mips_TI = {'beq':1, 'bne':1, 'bgtz':1, "bltz":1, "bgez":1, "blez":1, 'j':1, 'jal':1, 'jr':1, 'jalr':1}
	arm_TI = {'MVN':1, "MOV":1}
	calls = {}
	calls.update(x86_TI)
	calls.update(mips_TI)
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		re = [v for v in calls if opcode in v]
		if len(re) > 0:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num
