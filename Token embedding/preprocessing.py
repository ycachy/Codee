# encoding: utf-8
from operator import index
import angr
import os
import ntpath
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import json


edgeFolderName = "edge/"

# this list contains all the opcode in the two binaries
opcode_list = []


edgeListFileName = "edgeList"
funcListFileName = "funcList"
stringBidFileName = "string_bid"
nodelistFileName = "nodelist"
blockEmbeddingFileName = "features"
externFuncNameBlockMappingFileName = "externFuncNameBlockMappingList"
per_block_neighbors_bids_list_fileName = "per_block_neighbors_bids"
non_code_block_ids_FileName = "non_code_block_ids_File"
# this dictionary stores the predecessors and successors of nodes
# per_block_neighbors_bids[block_id] = [[predecessors],[successors]]
per_block_neighbors_bids = {}

# blocks that have no code
non_code_block_ids = []

# register list
register_list_8_byte = [
    'rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9', 'r10',
    'r11', 'r12', 'r13', 'r14', 'r15'
]

register_list_4_byte = [
    'eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'esp', 'ebp', 'r8d', 'r9d',
    'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'
]

register_list_2_byte = [
    'ax', 'cx', 'dx', 'bx', 'si', 'di', 'sp', 'bp', 'r8w', 'r9w', 'r10w',
    'r11w', 'r12w', 'r13w', 'r14w', 'r15w'
]

register_list_1_byte = [
    'al', 'cl', 'dl', 'bl', 'sil', 'dil', 'spl', 'bpl', 'r8b', 'r9b', 'r10b',
    'r11b', 'r12b', 'r13b', 'r14b', 'r15b'
]


def makeDir(outputDir, *args) -> str:
    
    tempDir = outputDir
    for dirPath in args:
        tempDir = tempDir + dirPath + "/"
    if not os.path.exists(os.path.dirname(tempDir)):
        print(os.path.exists(tempDir))
        os.makedirs(tempDir)
    return tempDir


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def angrGraphGen_binaryList(filePathList):
    progList = []
    for filePath in filePathList:
        progList.append(
            angr.Project(filePath, load_options={'auto_load_libs': False}))

    print("Analyzing the binaries to generate CFGs...")
    cfgList = []
    cgList = []
    for prog in progList:
        cfgTemp = prog.analyses.CFGFast()
        cfgList.append(cfgTemp)
        cgList.append(cfgTemp.functions.callgraph)
    print("CFGs Generated!")
    
    nodeLists = []
    edgeLists = []
    for cfg in cfgList:
        nodelistTemp = list(cfg.graph.nodes)
        nodeLists.append(nodelistTemp)
        edgelistTemp = list(cfg.graph.edges)
        edgeLists.append(edgelistTemp)
    return cfgList, nodeLists, edgeLists


def angrGraphGen(filepath1, filepath2):
  
    print(filepath1)
    prog1 = angr.Project(filepath1, load_options={'auto_load_libs': False})
    prog2 = angr.Project(filepath2, load_options={'auto_load_libs': False})

    print("Analyzing the binaries to generate CFGs...")
    cfg1 = prog1.analyses.CFGFast()
    cg1 = cfg1.functions.callgraph
    print("First binary done")
    cfg2 = prog2.analyses.CFGFast()
    cg2 = cfg2.functions.callgraph  # CFG 调用图 call图
    print("CFGs Generated!")

    nodelist1 = list(cfg1.graph.nodes)
    edgelist1 = list(cfg1.graph.edges)

    nodelist2 = list(cfg2.graph.nodes)
    edgelist2 = list(cfg2.graph.edges)
    print("edgeList:", type(edgelist2[0]))

    return cfg1, cg1, nodelist1, edgelist1, cfg2, cg2, nodelist2, edgelist2


def nodeDicGen_nodeLists(nodeLists):
    nodeDicts = []
    j = 0
    nodeSum = 0
    for nodelist in nodeLists:
        nodeDictTemp = {}
        for i in range(len(nodelist)):
            nodeDictTemp[nodelist[i]] = j
            j += 1
        nodeDicts.append(nodeDictTemp)
        nodeSum += len(nodeDictTemp)

    print("The {} binaries have total of {} nodes.".format(
        len(nodeLists), nodeSum))
    return nodeDicts


def nodeDicGen(nodelist1, nodelist2):
    # generate node dictionary for the two input binaries
   
    nodeDic1 = {}
    nodeDic2 = {}

    for i in range(len(nodelist1)):
        nodeDic1[nodelist1[i]] = i

    for i in range(len(nodelist2)):
        j = i + len(nodelist1)
        nodeDic2[nodelist2[i]] = j

    print("The two binaries have total of {} nodes.".format(
        len(nodeDic1) + len(nodeDic2)))
    return nodeDic1, nodeDic2


def instrTypeDicGen(nodelist1, nodelist2):
    # count type of instruction for feature vector generation

    mneList = []

    for node in nodelist1:
        if node.block is None:
            continue
        for insn in node.block.capstone.insns:
            mne = insn.mnemonic
            if mne not in mneList:
                mneList.append(mne)

    for node in nodelist2:
        if node.block is None:
            continue
        for insn in node.block.capstone.insns:
            mne = insn.mnemonic
            if mne not in mneList:
                mneList.append(mne)

    mneDic = {}
    for i in range(len(mneList)):
        mneDic[mneList[i]] = i
    print("there are total of {} types of instructions in the two binaries".
          format(len(mneList)))
    return mneList, mneDic


def offsetStrMappingGen_Lists(cfgList, binaryList):
    # count type of constants for feature vector generation
    
    offsetStrMapping = {}
    externFuncNamesList = []

    for i in range(len(cfgList)):
        externFuncNameTemp = []
        for func in cfgList[i].functions.values():
            if func.binary_name == binaryList[i]:
                for offset, strRef in func.string_references(vex_only=True):
                    offset = str(offset)
                    if offset not in offsetStrMapping:
                        offsetStrMapping[offset] = ''.join(strRef.split())
            elif func.binary_name not in externFuncNameTemp:
                externFuncNameTemp.append(func.name)
        externFuncNamesList.append(externFuncNameTemp)

    print("there are total of {} types of strings in binaries".format(
        len(offsetStrMapping)))
    return offsetStrMapping, externFuncNamesList


def offsetStrMappingGen(cfg1, cfg2, binary1, binary2, mneList):
    # count type of constants for feature vector generation

    # offsetStrMapping[offset] = strRef.strip()
    
    offsetStrMapping = {}

    # lists that store all the non-binary functions in bin1 and 2
    
    externFuncNamesBin1 = []
    externFuncNamesBin2 = []

    for func in cfg1.functions.values():
        if func.binary_name == binary1:
            for offset, strRef in func.string_references(vex_only=True):
              
                offset = str(offset)
                # offset = str(hex(offset))[:-1]
                if offset not in offsetStrMapping:
                    offsetStrMapping[offset] = ''.join(strRef.split())
        elif func.binary_name not in externFuncNamesBin1:
            externFuncNamesBin1.append(func.name)

    for func in cfg2.functions.values():
        if func.binary_name == binary2:
            for offset, strRef in func.string_references(vex_only=True):
                offset = str(offset)
                # offset = str(hex(offset))[:-1] #[:-1] is to remove the L from say "0x420200L"
                if offset not in offsetStrMapping:
                    offsetStrMapping[offset] = ''.join(strRef.split())
        elif func.binary_name not in externFuncNamesBin2:
            externFuncNamesBin2.append(func.name)
    # constDic = {}
    # i = len(mneList)
    # for key in offsetStrMapping.values():
    #     print('{}: {}'.format(i,key))
    #     constDic[key] = i
    #     i = i + 1

    print("there are total of {} types of strings in the two binaries".format(
        len(offsetStrMapping)))
    return offsetStrMapping, externFuncNamesBin1, externFuncNamesBin2


def externBlocksAndFuncsToBeMerged_Lists_blockEmbedding_gen(
        cfgList, nodeLists,  binaryList, nodeDicts,
        externFuncNamesList, string_bid_List):
    
    externFuncNameBlockMappingList = []
    nodeSum = 0
    for i in range(len(cfgList)):
        externFuncNameBlockMappingTemp = {}
        for func in cfgList[i].functions.values():
            binName = func.binary_name
            funcName = func.name
            blockList = list(func.blocks) 
            if (binName == binaryList[i]) and (funcName in externFuncNamesList[i]) and (
                    len(blockList) == 1):
                for node in nodeLists[i]:
                    if (node.block
                            is not None) and (node.block.addr == blockList[0].addr):  
                        externFuncNameBlockMappingTemp[funcName] = nodeDicts[i][node] - nodeSum
        externFuncNameBlockMappingList.append(externFuncNameBlockMappingTemp)
        nodeSum += len(nodeLists[i])
    return externFuncNameBlockMappingList


def externBlocksAndFuncsToBeMerged_blockEmbedding_Pair(externFuncNameBlockMappingBin1, externFuncNameBlockMappingBin2, string_bid1, string_bid2):
    toBeMergedBlocks = {}
    toBeMergedBlocksReverse = {}
    for funcName in externFuncNameBlockMappingBin1:
        if funcName in externFuncNameBlockMappingBin2:
            blockBin1 = externFuncNameBlockMappingBin1[
                funcName] 
            blockBin2 = externFuncNameBlockMappingBin2[
                funcName] 
            toBeMergedBlocks[blockBin1] = blockBin2
            toBeMergedBlocksReverse[blockBin2] = blockBin1

    for opstr in string_bid1:
        if opstr in string_bid2 and len(opstr) > 5:
            bid1 = string_bid1[opstr]
            bid2 = string_bid2[opstr]

            if bid1 in toBeMergedBlocks and bid2 != toBeMergedBlocks[bid1]:
                print("wierd!", bid1, toBeMergedBlocks[bid1], bid2)
            else:
                toBeMergedBlocks[bid1] = bid2
                toBeMergedBlocksReverse[bid2] = bid1
    return toBeMergedBlocks, toBeMergedBlocksReverse


# This func extracts the blocks that represent the same external function from both binary 1 and 2.

# For example, from libc.so
# Somehow angr will create a block in binary 1 and 2 if they call an external function
def externBlocksAndFuncsToBeMerged(cfg1, cfg2, nodelist1, nodelist2, binary1,
                                   binary2, nodeDic1, nodeDic2,
                                   externFuncNamesBin1, externFuncNamesBin2,
                                   string_bid1, string_bid2):
    # toBeMerged[node1_id] = node2_id
    toBeMergedBlocks = {}
    toBeMergedBlocksReverse = {}

    # toBeMergedFuncs[func1_addr] = func2_addr
    toBeMergedFuncs = {}
    toBeMergedFuncsReverse = {}

    externFuncNameBlockMappingBin1 = {}
    externFuncNameBlockMappingBin2 = {}
    funcNameAddrMappingBin1 = {}
    funcNameAddrMappingBin2 = {}

    for func in cfg1.functions.values():
        binName = func.binary_name
        funcName = func.name
        funcAddr = func.addr
        blockList = list(func.blocks) 
        if (binName == binary1) and (funcName in externFuncNamesBin1) and (
                len(blockList) == 1):
            for node in nodelist1:
                if (node.block
                        is not None) and (node.block.addr  
                                          == blockList[0].addr):
                    externFuncNameBlockMappingBin1[funcName] = nodeDic1[node]
                    funcNameAddrMappingBin1[funcName] = funcAddr

    for func in cfg2.functions.values():
        binName = func.binary_name
        funcName = func.name
        funcAddr = func.addr
        blockList = list(func.blocks)
        if (binName == binary2) and (funcName in externFuncNamesBin2) and (
                len(blockList) == 1):
            for node in nodelist2:
                if (node.block is not None) and (node.block.addr
                                                 == blockList[0].addr):
                    externFuncNameBlockMappingBin2[funcName] = nodeDic2[node]
                    funcNameAddrMappingBin2[funcName] = funcAddr

  
    for funcName in externFuncNameBlockMappingBin1:
        if funcName in externFuncNameBlockMappingBin2:
            blockBin1 = externFuncNameBlockMappingBin1[
                funcName]  
            blockBin2 = externFuncNameBlockMappingBin2[
                funcName] 
            toBeMergedBlocks[blockBin1] = blockBin2
            toBeMergedBlocksReverse[blockBin2] = blockBin1

            func1Addr = funcNameAddrMappingBin1[funcName]
            func2Addr = funcNameAddrMappingBin2[funcName]
            toBeMergedFuncs[func1Addr] = func2Addr
            toBeMergedFuncsReverse[func2Addr] = func1Addr
    
    # now we also consider string as an indicator for merging
    for opstr in string_bid1:
        if opstr in string_bid2 and len(opstr) > 5:
            bid1 = string_bid1[opstr]
            bid2 = string_bid2[opstr]

            if bid1 in toBeMergedBlocks and bid2 != toBeMergedBlocks[bid1]:
                print("wierd!", bid1, toBeMergedBlocks[bid1], bid2)
            else:
                toBeMergedBlocks[bid1] = bid2

    print("TOBEMEGERED size: ", len(toBeMergedBlocks), "\n", toBeMergedBlocks,
          "\n")
    #print("to be merged funcs: ", toBeMergedFuncs)
    return toBeMergedBlocks, toBeMergedBlocksReverse, toBeMergedFuncs, toBeMergedFuncsReverse


def normalization(opstr, offsetStrMapping):
    optoken = ''

    opstrNum = ""
    if opstr.startswith("0x") or opstr.startswith("0X"):
        try:
            opstrNum = str(int(opstr, 16))
        except:
            optoken = str(opstr)

    # normalize ptr
    if "ptr" in opstr:
        optoken = 'ptr'
        # nodeToIndex.write("ptr\n")
    # substitude offset with strings
    elif opstrNum in offsetStrMapping:
        optoken = offsetStrMapping[opstrNum]
        # nodeToIndex.write("str\n")
        # nodeToIndex.write(offsetStrMapping[opstr] + "\n")
    elif opstr.startswith("0x") or opstr.startswith("-0x") or opstr.replace(
            '.', '', 1).replace('-', '', 1).isdigit():
        optoken = 'imme'
        # nodeToIndex.write("IMME\n")
    elif opstr in register_list_1_byte:
        optoken = 'reg1'
    elif opstr in register_list_2_byte:
        optoken = 'reg2'
    elif opstr in register_list_4_byte:
        optoken = 'reg4'
    elif opstr in register_list_8_byte:
        optoken = 'reg8'
    else:
        optoken = str(opstr)
        # nodeToIndex.write(opstr + "\n")
    return optoken


def nodeIndexToCodeGen_Lists(nodelists, nodeDicts, offsetStrMapping,
                             outputDir):
    # this dictionary stores the string to block id mapping
    # string_bid[string] = bid
    string_bid_List = []
    
    blockIdxToTokens = {}
   
    blockIdxToOpcodeNum = {}
 
    blockIdxToOpcodeCounts = {}
    insToBlockCounts = {}
    
    with open(outputDir + 'nodeIndexToCode', 'w') as nodeToIndex:
        nodelist_str = ''
        for nodelist in nodelists:
            nodelist_str = nodelist_str + ' ' + str(len(nodelist))
        nodeToIndex.write(nodelist_str + '\n')  # write #nodes in both binaries
        nodeSum = 0
        per_block_neighbors_bids_list = []
        non_code_block_ids_list = []
        for i in range(len(nodelists)):
            per_block_neighbors_bids_temp = {}
            non_code_block_ids_temp = []
            string_bid_temp = {}
            for node in nodelists[i]:
                # extract predecessors and successors
                preds = node.predecessors
                succs = node.successors
                preds_ids = []
                succs_ids = []

                for pred in preds:
                    preds_ids.append(nodeDicts[i][pred])
                for succ in succs:
                    succs_ids.append(nodeDicts[i][succ])
                neighbors = [preds_ids, succs_ids]
                per_block_neighbors_bids[nodeDicts[i][node]] = neighbors

                preds_ids_temp = []
                succs_ids_temp = []
                for pred in preds:
                    preds_ids_temp.append(nodeDicts[i][pred] - nodeSum)
                for succ in succs:
                    succs_ids_temp.append(nodeDicts[i][succ] - nodeSum)
                neighbors_temp = [preds_ids_temp, succs_ids_temp]
                per_block_neighbors_bids_temp[nodeDicts[i][node] - nodeSum] = neighbors_temp
                
                if node.block is None:
                    non_code_block_ids.append(nodeDicts[i][node])
                    non_code_block_ids_temp.append(nodeDicts[i][node] - nodeSum)
                    blockIdxToTokens[str(nodeDicts[i][node])] = []
                    blockIdxToOpcodeCounts[str(nodeDicts[i][node])] = {}
                    blockIdxToOpcodeNum[str(nodeDicts[i][node])] = 0
                    continue

                tokens = []
                opcodeCounts = {}
                nodeToIndex.write(str(nodeDicts[i][node]) + ':\n')
                nodeToIndex.write(str(node.block.capstone.insns) + "\n\n")

                countedInsns = []
                numInsns = 0
                for insn in node.block.capstone.insns:
                    numInsns = numInsns + 1

                    if insn.mnemonic not in opcode_list:
                        opcode_list.append(insn.mnemonic)

                    if insn.mnemonic not in countedInsns:
                        if insn.mnemonic not in insToBlockCounts:
                            insToBlockCounts[insn.mnemonic] = 1
                        else:
                            insToBlockCounts[insn.mnemonic] = insToBlockCounts[
                                insn.mnemonic] + 1
                        countedInsns.append(insn.mnemonic)

                    if insn.mnemonic not in opcodeCounts:
                        opcodeCounts[insn.mnemonic] = 1
                    else:
                        opcodeCounts[
                            insn.mnemonic] = opcodeCounts[insn.mnemonic] + 1

                    tokens.append(str(insn.mnemonic))
                    opStrs = insn.op_str.split(", ")
                    for opstr in opStrs:
                        optoken = normalization(opstr, offsetStrMapping)
                        if optoken != '':
                            tokens.append(optoken)
                        
                        opstrNum = ""
                        if opstr.startswith("0x") or opstr.startswith("0X"):
                            try:
                                opstrNum = str(int(opstr, 16))
                            except:
                                opstrNum = ""
                        if opstrNum in offsetStrMapping:
                            string_bid_temp[
                                offsetStrMapping[opstrNum]] = nodeDicts[i][node] - nodeSum
                blockIdxToTokens[str(nodeDicts[i][node])] = tokens
                blockIdxToOpcodeCounts[str(nodeDicts[i][node])] = opcodeCounts
                blockIdxToOpcodeNum[str(nodeDicts[i][node])] = numInsns
            non_code_block_ids_list.append(non_code_block_ids_temp)
            per_block_neighbors_bids_list.append(per_block_neighbors_bids_temp)
            nodeSum += len(nodelists[i])
            string_bid_List.append(string_bid_temp)

    return blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, string_bid_List, per_block_neighbors_bids_list, non_code_block_ids_list


def nodeIndexToCodeGen(nodelist1, nodelist2, nodeDic1, nodeDic2,
                       offsetStrMapping, outputDir):
    # this dictionary stores the string to block id mapping
    # string_bid[string] = bid
    string_bid1 = {}
    string_bid2 = {}

    # stores the index of block to its tokens
    # blockIdxToTokens[id] = token list of that block
    blockIdxToTokens = {}

    # used to calculate TF part of the TF-IDF
    # it stores # of instructions per block
  
    blockIdxToOpcodeNum = {}

    # it stores # of instruction appears in one block
   
    blockIdxToOpcodeCounts = {}

    # calculate IDF part of the information. It stores # of blocks that contain each instruction
    insToBlockCounts = {}

    # store the node index to code mapping for reference
   
    with open(outputDir + 'nodeIndexToCode', 'w') as nodeToIndex:
        nodeToIndex.write(
            str(len(nodelist1)) + ' ' + str(len(nodelist2)) +
            '\n')  # write #nodes in both binaries

        for node in nodelist1:

            # extract predecessors and successors
            preds = node.predecessors
            succs = node.successors
            preds_ids = []
            succs_ids = []

            for pred in preds:
                preds_ids.append(nodeDic1[pred])
            for succ in succs:
                succs_ids.append(nodeDic1[succ])
            neighbors = [preds_ids, succs_ids]
            per_block_neighbors_bids[nodeDic1[node]] = neighbors

            # go through each instruction to extract token information
            if node.block is None:
                non_code_block_ids.append(nodeDic1[node])
                blockIdxToTokens[str(nodeDic1[node])] = []
                blockIdxToOpcodeCounts[str(nodeDic1[node])] = {}
                blockIdxToOpcodeNum[str(nodeDic1[node])] = 0
                #blockIdxToInstructions[str(nodeDic1[node])] = []
                continue
            tokens = []
            opcodeCounts = {}
            nodeToIndex.write(str(nodeDic1[node]) + ':\n')
            nodeToIndex.write(str(node.block.capstone.insns) + "\n\n")

            # stores the instructions that have been counted for at least once in this block
  
            countedInsns = []
            numInsns = 0
            for insn in node.block.capstone.insns:
                numInsns = numInsns + 1

                if insn.mnemonic not in opcode_list:
                    opcode_list.append(insn.mnemonic)

                if insn.mnemonic not in countedInsns:
                    if insn.mnemonic not in insToBlockCounts:
                        insToBlockCounts[insn.mnemonic] = 1
                    else:
                        insToBlockCounts[insn.mnemonic] = insToBlockCounts[
                            insn.mnemonic] + 1
                    countedInsns.append(insn.mnemonic)

                if insn.mnemonic not in opcodeCounts:
                    opcodeCounts[insn.mnemonic] = 1
                else:
                    opcodeCounts[
                        insn.mnemonic] = opcodeCounts[insn.mnemonic] + 1

                tokens.append(str(insn.mnemonic))
                opStrs = insn.op_str.split(", ")
                for opstr in opStrs:
                    optoken = normalization(opstr, offsetStrMapping)
                    if optoken != '':
                        tokens.append(optoken)

                    opstrNum = ""
                    if opstr.startswith("0x") or opstr.startswith("0X"):
                        try:
                            opstrNum = str(int(opstr, 16))
                        except:
                            opstrNum = ""
                    if opstrNum in offsetStrMapping:
                        string_bid1[
                            offsetStrMapping[opstrNum]] = nodeDic1[node]

            # nodeToIndex.write("\ttoken:" + str(tokens) + "\n\n")
            blockIdxToTokens[str(nodeDic1[node])] = tokens
            blockIdxToOpcodeCounts[str(nodeDic1[node])] = opcodeCounts
            blockIdxToOpcodeNum[str(nodeDic1[node])] = numInsns

            #blockIdxToInstructions[str(nodeDic1[node])] = insns
            # nodeToIndex.write("\n\n")

        for node in nodelist2:

            # extract predecessors and successors
            preds = node.predecessors
            succs = node.successors
            preds_ids = []
            succs_ids = []

            for pred in preds:
                preds_ids.append(nodeDic2[pred])
            for succ in succs:
                succs_ids.append(nodeDic2[succ])
            neighbors = [preds_ids, succs_ids]
            per_block_neighbors_bids[nodeDic2[node]] = neighbors

            # go through each instruction to extract token information
            if node.block is None:
                non_code_block_ids.append(nodeDic2[node])
                blockIdxToTokens[str(nodeDic2[node])] = []
                blockIdxToOpcodeCounts[str(nodeDic2[node])] = {}
                blockIdxToOpcodeNum[str(nodeDic2[node])] = 0
                continue

            tokens = []
            opcodeCounts = {}
            nodeToIndex.write(str(nodeDic2[node]) + ':\n')
            nodeToIndex.write(str(node.block.capstone.insns) + "\n\n")

            countedInsns = []
            numInsns = 0
            for insn in node.block.capstone.insns:
                numInsns = numInsns + 1

                if insn.mnemonic not in opcode_list:
                    opcode_list.append(insn.mnemonic)

                if insn.mnemonic not in countedInsns:
                    if insn.mnemonic not in insToBlockCounts:
                        insToBlockCounts[insn.mnemonic] = 1
                    else:
                        insToBlockCounts[insn.mnemonic] = insToBlockCounts[
                            insn.mnemonic] + 1
                    countedInsns.append(insn.mnemonic)

                if insn.mnemonic not in opcodeCounts:
                    opcodeCounts[insn.mnemonic] = 1
                else:
                    opcodeCounts[
                        insn.mnemonic] = opcodeCounts[insn.mnemonic] + 1

                tokens.append(str(insn.mnemonic))
                opStrs = insn.op_str.split(", ")
                for opstr in opStrs:
                    optoken = normalization(opstr, offsetStrMapping)
                    if optoken != '':
                        tokens.append(optoken)

                    opstrNum = ""
                    if opstr.startswith("0x") or opstr.startswith("0X"):
                        opstrNum = str(int(opstr, 16))
                    if opstrNum in offsetStrMapping:
                        string_bid2[
                            offsetStrMapping[opstrNum]] = nodeDic2[node]

            # nodeToIndex.write("\ttoken" + str(tokens) + "\n\n")
            blockIdxToTokens[str(nodeDic2[node])] = tokens
            blockIdxToOpcodeCounts[str(nodeDic2[node])] = opcodeCounts
            blockIdxToOpcodeNum[str(nodeDic2[node])] = numInsns
            # nodeToIndex.write("\n\n")

    return blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, string_bid1, string_bid2


def functionIndexToCodeGen(cfg1, cg1, nodelist1, nodeDic1, cfg2, cg2,
                           nodelist2, nodeDic2, binary1, binary2, outputDir):
    # store function addresses
    funclist1 = []
    funclist2 = []
    with open(outputDir + 'functionIndexToCode', 'w') as f:
        f.write(
            str(len(list(cg1.nodes))) + ' ' + str(len(list(cg2.nodes))) +
            '\n')  # write #nodes in both binaries
        for idx, func in enumerate(list(cg1.nodes)):
            function = cfg1.functions.function(func)

            funclist1.append(function.addr)
            f.write(str(idx) + ':' + '\n')

            f.write('Bin1 ' + function.name + ' ' + hex(function.addr) + ' ' +
                    function.binary_name + '\n')
            for block in function.blocks:
                for node in nodelist1:
                    if (node.block is not None) and (node.block.addr
                                                     == block.addr):
                        f.write(str(nodeDic1[node]) + ' ')
            f.write('\n')

        for idx, func in enumerate(list(cg2.nodes)):
            function = cfg2.functions.function(func)

            funclist2.append(function.addr)
            f.write(str(idx + len(cg1.nodes)) + ':' + '\n')
            f.write('Bin2 ' + function.name + ' ' + hex(function.addr) + ' ' +
                    function.binary_name + '\n')
            for block in function.blocks:
                for node in nodelist2:
                    if (node.block is not None) and (node.block.addr
                                                     == block.addr):
                        f.write(str(nodeDic2[node]) + ' ')
            f.write('\n')
    return funclist1, funclist2


def edgeListGen_blockEmbedding_pair(edgeList1, edgeList2, nodelist1Len, nodelist2Len, toBeMergedBlocks, toBeMergedBlocksReverse, outputDir, fileNameList):
    with open(outputDir + 'edgelist_merged_tadw', 'w') as edgelistFile:
        with open(outputDir + 'edgelist_merged_tadw_2', 'w') as f:
            for (src, tgt) in edgeList1:
                edgelistFile.write(str(src) + " " + str(tgt) + "\n")
            for (src, tgt) in edgeList2:
                new_src_id = src
                new_tgt_id = tgt
                if src in toBeMergedBlocksReverse:
                    new_src_id = toBeMergedBlocksReverse[src]
                if tgt in toBeMergedBlocksReverse:
                    new_tgt_id = toBeMergedBlocksReverse[tgt]
                edgelistFile.write(str(new_src_id) + " " + str(new_tgt_id) + "\n")
                f.write(str(new_src_id) + " " + str(new_tgt_id) + "\n")
    


def edgeListGen_onlyEdgeList(edgeLists, nodeDicts, outputDir, fileNameList):
    global edgeFolderName
   
    with open(outputDir + 'edgelist', 'w') as edgelistFile:
        for i in range(len(edgeLists)):
            for (src, tgt) in edgeLists[i]:
                edgelistFile.write(
                    str(nodeDicts[i][src]) + " " + str(nodeDicts[i][tgt]) +
                    "\n")
    fileName = "-".join(fileNameList)
    with open(outputDir + edgeFolderName + fileName + '-edge.txt',
              'w') as edgelistFile:
        for i in range(len(edgeLists)):
            for (src, tgt) in edgeLists[i]:
                edgelistFile.write(
                    str(nodeDicts[i][src]) + " " + str(nodeDicts[i][tgt]) +
                    "\n")


def infoLoad_blockEmbedding_Pair(fileNameList, inputDir):
    global non_code_block_ids
    global per_block_neighbors_bids
    info1Path = makeDir(inputDir, fileNameList[0])
    info2Path = makeDir(inputDir, fileNameList[1])
    with open(info1Path + nodelistFileName, "r") as f:
        nodelist1Len = int(f.readlines()[0])

    with open(info2Path + nodelistFileName, "r") as f:
        nodelist2Len = int(f.readlines()[0])
    
    # funcNameBlockListMappingBin
    funcNameBlockListMappingBin1 = {}
    with open(info1Path + funcListFileName) as f:
        funcNameBlockListMappingBin1 = json.load(f)

    funcNameBlockListMappingBin2 = {}
    with open(info2Path + funcListFileName) as f:
        funcNameBlockListMappingBin2 = json.load(f)
    
 
    for funcname in funcNameBlockListMappingBin2.keys():
        blockList = funcNameBlockListMappingBin2[funcname]
        blockList2 = [x+nodelist1Len for x in blockList]
        funcNameBlockListMappingBin2[funcname] = blockList2

    # externFuncNameBlockMappingBin
    externFuncNameBlockMappingBin1 = {}
    with open(info1Path+externFuncNameBlockMappingFileName, 'r') as f:
        if os.path.getsize(info1Path+externFuncNameBlockMappingFileName):
            externFuncNameBlockMappingBin1 = json.load(f)

    externFuncNameBlockMappingBin2 = {}
    with open(info2Path+externFuncNameBlockMappingFileName, 'r') as f:
        if os.path.getsize(info2Path+externFuncNameBlockMappingFileName):
            externFuncNameBlockMappingBin2 = json.load(f)

    for funcName in externFuncNameBlockMappingBin2.keys():
        nodeId = externFuncNameBlockMappingBin2[funcName] + nodelist1Len
        externFuncNameBlockMappingBin2[funcName] = nodeId

    # edgeList
    edgeList1 = []
    with open(info1Path+edgeListFileName, 'r') as f:
        for line in f.readlines():
            src, tgt = line.split()
            src = int(src)
            tgt = int(tgt)
            edgeList1.append((src, tgt))
    
    edgeList2 = []
    with open(info2Path+edgeListFileName, 'r') as f:
        for line in f.readlines():
            src, tgt = line.split()
            src = int(src)
            tgt = int(tgt)
            edgeList2.append((src + nodelist1Len, tgt + nodelist1Len))

    # string_bid
    string_bid1 = {}
    with open(info1Path+stringBidFileName, 'r') as f:
        if os.path.getsize(info1Path+stringBidFileName):
            string_bid1 = json.load(f)

    string_bid2 = {}
    with open(info2Path+stringBidFileName, 'r') as f:
        if os.path.getsize(info2Path+stringBidFileName):
            string_bid2 = json.load(f)

    for key in string_bid2.keys():
        nodeId = string_bid2[key]
        string_bid2[key] = nodeId + nodelist1Len

    # embedding
    blockEmbedding = {}
    with open(info1Path+blockEmbeddingFileName, 'r') as f:
        for line in f.readlines():
            lineList = line.split()
            counter = lineList[0]
            value = lineList[1:]
            blockEmbedding[counter] = value
    with open(info2Path+blockEmbeddingFileName, 'r') as f:
        for line in f.readlines():
            lineList = line.split()
            counter = str(int(lineList[0]) + nodelist1Len)
            value = lineList[1:]
            blockEmbedding[counter] = value

    #per_block_neighbors_bids_list_fileName
    per_block_neighbors_bids_bin1 = {}
    with open(info1Path+per_block_neighbors_bids_list_fileName, 'r') as f:
        per_block_neighbors_bids_bin1 = json.load(f)
        for key in per_block_neighbors_bids_bin1:
            per_block_neighbors_bids[int(key)] = per_block_neighbors_bids_bin1[key]
    
    per_block_neighbors_bids_bin2_temp = {}
    with open(info2Path+per_block_neighbors_bids_list_fileName, 'r') as f:
        per_block_neighbors_bids_bin2_temp = json.load(f)

    per_block_neighbors_bids_bin2 = {}
    for key in per_block_neighbors_bids_bin2_temp.keys():
        neighbors = per_block_neighbors_bids_bin2_temp[key]
        preds_ids, succs_ids = neighbors
        for pred in preds_ids:
            pred += nodelist1Len
        for succs in succs_ids:
            succs += nodelist1Len
        neighbors_new = [preds_ids, succs_ids]
        per_block_neighbors_bids_bin2[int(key) + nodelist1Len] = neighbors_new
    per_block_neighbors_bids.update(per_block_neighbors_bids_bin2)

    # non_code_block_ids_list
    with open(info1Path + non_code_block_ids_FileName, 'r') as f:
        non_code_block_ids = json.load(f)
    
    with open(info2Path + non_code_block_ids_FileName, 'r') as f:
        non_code_block_ids_bin2 = json.load(f)
    for ids in non_code_block_ids_bin2:
        non_code_block_ids.append(ids + nodelist1Len)
    
    return nodelist1Len, nodelist2Len, funcNameBlockListMappingBin1, funcNameBlockListMappingBin2, externFuncNameBlockMappingBin1, externFuncNameBlockMappingBin2, edgeList1, edgeList2, string_bid1, string_bid2, blockEmbedding



def infoSave_blockEmbedding_Gen(funcIndexMappingList, blockListOfFuncList, string_bid_List, externFuncNameBlockMappingList, nodeDicts, edgeLists, per_block_neighbors_bids_list, non_code_block_ids_list, fileNameList, outputDir):
  
    nodeSum = 0
    for i in range(len(fileNameList)):
        dirPath = makeDir(outputDir, fileNameList[i])
        funcJson = {}
        for func, fid in funcIndexMappingList[i].items():
            blockListOfFunc = blockListOfFuncList[i]
            blockList = blockListOfFunc[fid]
            blockListSave = [x-nodeSum for x in blockList]
            funcJson[func.name] = blockListSave
        
        with open(dirPath+funcListFileName, 'w') as f:
            json.dump(funcJson, f)
        
        string_bid = string_bid_List[i]
        with open(dirPath+stringBidFileName, 'w') as f:
            json.dump(string_bid, f)
        
        edgeList = edgeLists[i]
        with open(dirPath + edgeListFileName, 'w') as f:
            for (src, tgt) in edgeList:
                f.write(str(nodeDicts[i][src] - nodeSum) + " " + str(nodeDicts[i][tgt] - nodeSum) + "\n")
        
        with open(dirPath + nodelistFileName, "w") as f:
            f.write(str(len(nodeDicts[i])))

        with open(dirPath + externFuncNameBlockMappingFileName, 'w') as f:
            json.dump(externFuncNameBlockMappingList[i], f)

        with open(dirPath + per_block_neighbors_bids_list_fileName, 'w') as f:
            json.dump(per_block_neighbors_bids_list[i], f)

        with open(dirPath + non_code_block_ids_FileName, 'w') as f:
            json.dump(non_code_block_ids_list[i], f)

        nodeSum += len(nodeDicts[i])


# This function generates super CFG edge list. We also replace external function blocks in binary 2 from block in binary 1

def edgeListGen(edgelist1, nodeDic1, edgelist2, nodeDic2, toBeMerged,
                toBeMergedReverse, outputDir):
    with open(outputDir + 'edgelist_merged_tadw', 'w') as edgelistFile:
        for (src, tgt) in edgelist1:
            edgelistFile.write(
                str(nodeDic1[src]) + " " + str(nodeDic1[tgt]) + "\n")
        for (src, tgt) in edgelist2:
            src_id = nodeDic2[src]
            tgt_id = nodeDic2[tgt]

            new_src_id = src_id
            new_tgt_id = tgt_id

            if src_id in toBeMergedReverse:
                new_src_id = toBeMergedReverse[src_id]
            if tgt_id in toBeMergedReverse:
                new_tgt_id = toBeMergedReverse[tgt_id]

            edgelistFile.write(str(new_src_id) + " " + str(new_tgt_id) + "\n")

    with open(outputDir + 'edgelist', 'w') as edgelistFile:
        for (src, tgt) in edgelist1:
            edgelistFile.write(
                str(nodeDic1[src]) + " " + str(nodeDic1[tgt]) + "\n")
        for (src, tgt) in edgelist2:
            edgelistFile.write(
                str(nodeDic2[src]) + " " + str(nodeDic2[tgt]) + "\n")


def funcedgeListGen(cg1, funclist1, cg2, funclist2, toBeMergedFuncsReverse,
                    outputDir):
    with open(outputDir + 'func_edgelist', "w") as f:
        for edge in list(cg1.edges):
            f.write(
                str(funclist1.index(edge[0])) + ' ' +
                str(funclist1.index(edge[1])) + '\n')
        for edge in list(cg2.edges):
            src_addr = edge[0]
            tgt_addr = edge[1]

            src_id = funclist2.index(src_addr) + len(cg1.nodes)
            tgt_id = funclist2.index(tgt_addr) + len(cg1.nodes)

            new_src_id = src_id
            new_tgt_id = tgt_id

            if src_addr in toBeMergedFuncsReverse:
                new_src_id = funclist1.index(toBeMergedFuncsReverse[src_addr])
            if tgt_addr in toBeMergedFuncsReverse:
                new_tgt_id = funclist1.index(toBeMergedFuncsReverse[tgt_addr])

            f.write(str(new_src_id) + ' ' + str(new_tgt_id) + '\n')


# not used. we now generate node features from asm2vec
def nodeFeaturesGen(nodelist1, nodelist2, mneList, mneDic, constDic,
                    offsetStrMapping, outputDir):
    # generate feature vector file for the two input binaries
    with open(outputDir + 'features', 'w') as feaVecFile:
        for i in range(len(nodelist1)):
            node = nodelist1[i]
            feaVec = []
            for _ in range(len(mneList) + len(offsetStrMapping)):
                feaVec.append(0)
            if node.block is not None:
                for const in node.block.vex.constants:
                    if str(const) != 'nan':
                        offset = str(const.value)  #hex(int(const.value))
                    if offset in offsetStrMapping:
                        c = offsetStrMapping.get(offset)
                        pos = constDic[c]
                        feaVec[pos] += 1

                for insn in node.block.capstone.insns:
                    mne = insn.mnemonic
                    pos = mneDic[mne]
                    feaVec[pos] += 1

            # index as the first element and then output all the features
            feaVecFile.write(str(i) + " ")
            for k in range(len(feaVec)):
                feaVecFile.write(str(feaVec[k]) + " ")
            feaVecFile.write("\n")

        for i in range(len(nodelist2)):
            node = nodelist2[i]
            feaVec = []
            for x in range(len(mneList) + len(offsetStrMapping)):
                feaVec.append(0)
            if node.block is not None:
                for const in node.block.vex.constants:
                    if str(const) != 'nan':
                        offset = str(const.value)  #hex(int(const.value))
                    if offset in offsetStrMapping:
                        c = offsetStrMapping.get(offset)
                        pos = constDic[c]
                        feaVec[pos] += 1

                for insn in node.block.capstone.insns:
                    mne = insn.mnemonic
                    pos = mneDic[mne]
                    feaVec[pos] += 1
            j = i + len(nodelist1)
            feaVecFile.write(str(j) + " ")
            for k in range(len(feaVec)):
                feaVecFile.write(str(feaVec[k]) + " ")
            feaVecFile.write("\n")


def funcBlockGen_Lists_blockEmbedding_Gen(cfgList, nodeLists, externFuncNamesList, nodeDicts):
    funcIndexMappingList = []
    funcIndexMappingReverseList = []
    blockListOfFuncList = []
    blockFuncNameMappingList = []
    nodeSum = 0
    for i in range(len(cfgList)):
        funcIndex = 0
        funcIndexMappingTemp = {}
        funcIndexMappingReverseTemp = {}
        blockListOfFuncTemp = []
        blockFuncNameMappingTemp = {}
        for func in cfgList[i].functions.values():
            funcName = func.name
            if funcName in externFuncNamesList[i]:
                continue
            if funcName.find('sub_') == 0:
                continue
            if funcName.find('$d') == 0:
                continue
            funcIndexMappingTemp[func] = funcIndex
            funcIndexMappingReverseTemp[funcIndex] = func
            funcAddr = func.addr
            blockList = []
            blockListOfFunc = list(func.blocks)
            for block in blockListOfFunc:
                for node in nodeLists[i]:
                    if (node.block is not None) and (node.block.addr
                                                     == block.addr):
                        blockList.append(nodeDicts[i][node] - nodeSum)
                        blockFuncNameMappingTemp[nodeDicts[i][node] - nodeSum] = funcName
            blockListOfFuncTemp.append(blockList)
            funcIndex += 1
        funcIndexMappingList.append(funcIndexMappingTemp)
        funcIndexMappingReverseList.append(funcIndexMappingReverseTemp)
        blockListOfFuncList.append(blockListOfFuncTemp)
        blockFuncNameMappingList.append(blockFuncNameMappingTemp)
    return funcIndexMappingList, funcIndexMappingReverseList, blockListOfFuncList, blockFuncNameMappingList


def funcBlockGen_Lists(cfgList, nodeLists, externFuncNamesList, nodeDicts):
    funcIndexMappingList = []
    funcIndexMappingReverseList = []
    blockListOfFuncList = []
    blockFuncNameMappingList = []
    nodeSum = 0
    for i in range(len(cfgList)):
        funcIndex = 0
        funcIndexMappingTemp = {}
        funcIndexMappingReverseTemp = {}
        blockListOfFuncTemp = []
        blockFuncNameMappingTemp = {}
        for func in cfgList[i].functions.values():
            funcName = func.name
            if funcName in externFuncNamesList[i]:
                continue
            if funcName.find('sub_') == 0:
                continue
            if funcName.find('$d') == 0:
                continue
            funcIndexMappingTemp[func] = funcIndex
            funcIndexMappingReverseTemp[funcIndex] = func
            funcAddr = func.addr
            blockList = []
            blockListOfFunc = list(func.blocks)
            for block in blockListOfFunc:
                for node in nodeLists[i]:
                    if (node.block is not None) and (node.block.addr
                                                     == block.addr):
                        blockList.append(nodeDicts[i][node])
                        blockFuncNameMappingTemp[nodeDicts[i][node]] = funcName
            blockListOfFuncTemp.append(blockList)
            funcIndex += 1
        funcIndexMappingList.append(funcIndexMappingTemp)
        funcIndexMappingReverseList.append(funcIndexMappingReverseTemp)
        blockListOfFuncList.append(blockListOfFuncTemp)
        blockFuncNameMappingList.append(blockFuncNameMappingTemp)
    return funcIndexMappingList, funcIndexMappingReverseList, blockListOfFuncList, blockFuncNameMappingList


def funcBlockGen(cfg1, cfg2, nodelist1, nodelist2, externFuncNamesBin1,
                 externFuncNamesBin2, nodeDic1, nodeDic2):
    funcIndexMappingBin1 = {}
    funcIndexMappingBin2 = {}
    # funcIndexMappingBin1[func] = index  it is index of func in blockListOfFunc in binary1
    funcIndexMappingReverseBin1 = {}
    funcIndexMappingReverseBin2 = {}
    # funcToIndexDictReverse[index] = func
    blockListOfFuncBin1 = []
    blockListOfFuncBin2 = []
    blockFuncNameMappingBin1 = {}
    blockFuncNameMappingBin2 = {}
    # blockListOfFunc[index] means No.index Func
    # blockListOfFunc[index][index2] means No.index2 block's index in nodelist of No.index Func

    funcIndex = 0
    funcNameList1 = []
    for func in cfg1.functions.values():
        funcName = func.name
        if funcName in externFuncNamesBin1:
            continue
        if funcName.find('sub_') == 0:  
            continue
        if funcName.find('$d') == 0:
            continue
        funcNameList1.append(funcName)
        funcIndexMappingBin1[func] = funcIndex
        funcIndexMappingReverseBin1[funcIndex] = func
        funcAddr = func.addr
        blockList = []
        '''for i in range(len(nodelist1)):
            if nodelist1[i].function_address == funcAddr:
                blockList.append(i)
        '''
        blockListOfFunc = list(func.blocks)
        for block in blockListOfFunc:
            for node in nodelist1:
                if (node.block is not None) and (node.block.addr
                                                 == block.addr):
                    blockList.append(nodeDic1[node])
                    blockFuncNameMappingBin1[nodeDic1[node]] = funcName
        blockListOfFuncBin1.append(blockList)
        funcIndex += 1

    funcIndex = 0
    funcNameList2 = []
    for func in cfg2.functions.values():
        funcName = func.name
        if funcName in externFuncNamesBin2:
            continue
        if funcName.find('sub_') == 0: 
            continue
        if funcName.find('$d') == 0:
            continue
        funcNameList2.append(funcName)
        funcIndexMappingBin2[func] = funcIndex
        funcIndexMappingReverseBin2[funcIndex] = func
        funcAddr = func.addr
        blockList = []
        '''
        for i in range(len(nodelist2)):
            if nodelist2[i].function_address == funcAddr:
                blockList.append(
                    i + len(nodelist1))  
        '''
        blockListOfFunc = list(func.blocks)
        for block in blockListOfFunc:
            for node in nodelist2:
                if (node.block is not None) and (node.block.addr
                                                 == block.addr):
                    blockList.append(nodeDic2[node])
                    blockFuncNameMappingBin2[nodeDic2[node]] = funcName
        blockListOfFuncBin2.append(blockList)
        funcIndex += 1

    for funcName in funcNameList1:
        if funcName not in funcNameList2:
            print("bin1 函数不在bin2中:", funcName)
    for funcName in funcNameList2:
        if funcName not in funcNameList1:
            print("bin2 函数不在bin1中:", funcName)
   
    delete_funcName1 = []
    delete_funcName2 = []
    # print(len(funcIndexMappingBin1), " ", len(blockListOfFuncBin1))
  
    for funcName in funcNameList1:
        if funcName not in funcNameList2:
            delete_funcName1.append(funcName)
    for funcName in delete_funcName1:
       
        delete_index = funcNameList1.index(funcName)
        # blockListOfFuncBin1.pop(delete_index)
        if delete_index in funcIndexMappingReverseBin1.keys():
            func = funcIndexMappingReverseBin1.pop(delete_index)
            funcIndexMappingBin1.pop(func)

    # print(len(funcIndexMappingBin1), " ", len(blockListOfFuncBin1))
    for funcName in funcNameList2:
        if funcName not in funcNameList1:
            delete_funcName2.append(funcName)
    for funcName in delete_funcName2:
      
        delete_index = funcNameList2.index(funcName)
        # blockListOfFuncBin2.pop(delete_index)
        if delete_index in funcIndexMappingReverseBin2.keys():
            func = funcIndexMappingReverseBin2.pop(delete_index)
            funcIndexMappingBin2.pop(func)
    '''
    for func1, func1Id in funcIndexMappingBin1.items():
        print("func1Id", func1Id)
        blockList1 = blockListOfFuncBin1[func1Id]
    for func2, func2Id in funcIndexMappingBin2.items():
        print("func2Id", func2Id)
        blockList2 = blockListOfFuncBin2[func2Id]
    '''
    ''' test:
    print("extrnal test function：")
    print("bin1 extrnal function:")
    for funcName in externFuncNamesBin1:
        print(funcName, end="  ")
    print(" ")
    print("bin2 extrnal function：")
    for funcName in externFuncNamesBin2:
        print(funcName, end="  ")
    print(" ")
    for funcName in externFuncNamesBin1:
        if funcName not in externFuncNamesBin2:
            print("bin1 extrnal function not in bin2:", funcName, "   ")
    
    funcNameList1 = []
    funcNameList2 = []
    index = 0
    print("bin1 bin2 bb_test:", len(funcIndexMappingBin1), len(funcIndexMappingBin2))
    for func1, func1Id in funcIndexMappingBin1.items():
        funcNameList1.append(func1.name)
        for func2, func2Id in funcIndexMappingBin2.items():
            if func2.name not in funcNameList2:
                funcNameList2.append(func2.name)
            if func1.name == func2.name:
                blockList1 = blockListOfFuncBin1[func1Id]
                blockList2 = blockListOfFuncBin2[func2Id]
                if len(blockList1) != len(blockList2):
                    print("same_number:", func1.name, "  ", len(blockList1), "  ", func2.name, "  ", len(blockList2))
                else:
                    index += 1
                    print("different_number：", func1.name, len(blockList1), len(blockList2), " ", index)
    print(" ")
    print("bin1 bin2 function test ", len(funcNameList1), len(funcNameList2), type(funcNameList1), type(funcNameList1[0]))
    for funcName in funcNameList1:
        if funcName not in funcNameList2:
            print("bin1 函数不在bin2中:", funcName)
    print("funcIndexSize:", len(funcIndexMappingBin1)+len(funcIndexMappingBin2))
    for func in funcIndexMappingBin2.keys():
        print(func.name, funcIndexMappingBin2[func])
    for blockList in blockListOfFuncBin2:
        for block in blockList:
            print(block)
    '''
    return funcIndexMappingBin1, funcIndexMappingBin2, funcIndexMappingReverseBin1, funcIndexMappingReverseBin2, blockListOfFuncBin1, blockListOfFuncBin2, blockFuncNameMappingBin1, blockFuncNameMappingBin2


# preprocessing the two binaries with Angr.
def preprocessing(filepath1, filepath2, outputDir):
    binary1 = path_leaf(filepath1)
    binary2 = path_leaf(filepath2)

    if not os.path.exists(outputDir):
        os.makedirs(outputDir)

    cfg1, cg1, nodelist1, edgelist1, cfg2, cg2, nodelist2, edgelist2 = angrGraphGen(
        filepath1, filepath2)
   
    nodeDic1, nodeDic2 = nodeDicGen(nodelist1, nodelist2)

    # funcToIndexDict funcToIndexDictReverse blockListOfFunc
    # nodeDict1[nodelist1[i]] = i nodeDict2[nodelist2[i]] = len(nodelist1) + i
    #for node in nodelist1:
    #    print("node.addr:{}, node.size:{}, node.function_address:{}, node.block_id:{}, node.byte_string:{}, node._name:{}, node._hash:{}, node.simprocedure_name:{}".format(node.addr, node.size, node.function_address, node.block_id, node.byte_string, node._name, node._hash, node.simprocedure_name))
    # nodelist[i] = i
    # nodeDict[nodelist[i]] = i
   
    mneList, _ = instrTypeDicGen(nodelist1, nodelist2)

    # print("\t extracing strings...")
    offsetStrMapping, externFuncNamesBin1, externFuncNamesBin2 = offsetStrMappingGen(
        cfg1, cfg2, binary1, binary2, mneList)

    funcIndexMappingBin1, funcIndexMappingBin2, funcIndexMappingReverseBin1, funcIndexMappingReverseBin2, blockListOfFuncBin1, blockListOfFuncBin2, blockFuncNameMappingBin1, blockFuncNameMappingBin2 = funcBlockGen(
        cfg1, cfg2, nodelist1, nodelist2, externFuncNamesBin1,
        externFuncNamesBin2, nodeDic1, nodeDic2)

    print("\tprocessing instructions...")
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, string_bid1, string_bid2 = nodeIndexToCodeGen(
        nodelist1, nodelist2, nodeDic1, nodeDic2, offsetStrMapping, outputDir)

  
    toBeMergedBlocks, toBeMergedBlocksReverse, toBeMergedFuncs, toBeMergedFuncsReverse = externBlocksAndFuncsToBeMerged(
        cfg1, cfg2, nodelist1, nodelist2, binary1, binary2, nodeDic1, nodeDic2,
        externFuncNamesBin1, externFuncNamesBin2, string_bid1, string_bid2)

    # print("\t processing functions...")
    # funclist1, funclist2 = functionIndexToCodeGen(cfg1, cg1, nodelist1, nodeDic1, cfg2, cg2, nodelist2, nodeDic2, binary1, binary2, outputDir)

   
    print("\tgenerating CFGs...")
    edgeListGen(edgelist1, nodeDic1, edgelist2, nodeDic2, toBeMergedBlocks,
                toBeMergedBlocksReverse, outputDir)

    # print("\t generating call graphs...")
    # funcedgeListGen(cg1, funclist1, cg2, funclist2, toBeMergedFuncsReverse, outputDir)

    print("Preprocessing all done. Enjoy!!")
    return blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, nodeDic1, nodeDic2, binary1, binary2, nodelist1, nodelist2, toBeMergedBlocks


def preprocessing_blockEmbedding_Pair(filePathList, fileNameList, outputDir, inputDir):
 
    binaryList = []
    for filePath in filePathList:
        binaryList.append(path_leaf(filePath))

    nodelist1Len, nodelist2Len, funcNameBlockListMappingBin1, funcNameBlockListMappingBin2, externFuncNameBlockMappingBin1, externFuncNameBlockMappingBin2, edgeList1, edgeList2, string_bid1, string_bid2, blockEmbedding = infoLoad_blockEmbedding_Pair(fileNameList, inputDir)
    toBeMergedBlocks, toBeMergedBlocksReverse = externBlocksAndFuncsToBeMerged_blockEmbedding_Pair(externFuncNameBlockMappingBin1, externFuncNameBlockMappingBin2, string_bid1, string_bid2)
    edgeListGen_blockEmbedding_pair(edgeList1, edgeList2, nodelist1Len, nodelist2Len, toBeMergedBlocks, toBeMergedBlocksReverse, outputDir, fileNameList)
    return toBeMergedBlocks, blockEmbedding, nodelist1Len, funcNameBlockListMappingBin1, funcNameBlockListMappingBin2


def preprocessing_blockEmbedding_Gen(filePathList, outputDir, fileNameList):
  
    binaryList = []
    for filePath in filePathList:
        binaryList.append(path_leaf(filePath))
    cfgList, nodeLists, edgeLists = angrGraphGen_binaryList(filePathList)
    nodeDicts = nodeDicGen_nodeLists(nodeLists)
    
    offsetStrMapping, externFuncNamesList = offsetStrMappingGen_Lists(
        cfgList, binaryList)
   
    funcIndexMappingList, funcIndexMappingReverseList, blockListOfFuncList, blockFuncNameMappingList = funcBlockGen_Lists_blockEmbedding_Gen(
        cfgList, nodeLists, externFuncNamesList, nodeDicts)

    print("\tprocessing instructions...")
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, string_bid_List, per_block_neighbors_bids_list, non_code_block_ids_list = nodeIndexToCodeGen_Lists(
        nodeLists, nodeDicts, offsetStrMapping, outputDir)

    externFuncNameBlockMappingList = externBlocksAndFuncsToBeMerged_Lists_blockEmbedding_gen(
        cfgList, nodeLists,  binaryList, nodeDicts,
        externFuncNamesList, string_bid_List)
    print("\tgenerating CFGs...")
  
    edgeListGen_onlyEdgeList(edgeLists, nodeDicts,  outputDir, fileNameList)
    infoSave_blockEmbedding_Gen(funcIndexMappingList, blockListOfFuncList, string_bid_List, externFuncNameBlockMappingList, nodeDicts, edgeLists, per_block_neighbors_bids_list, non_code_block_ids_list, fileNameList, outputDir)
    print("Preprocessing all done. Enjoy!!")
    return blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, funcIndexMappingList, blockListOfFuncList, nodeLists



def preprocessing_multiInput(filePathList, outputDir, fileNameList):
    binaryList = []
    for filePath in filePathList:
        binaryList.append(path_leaf(filePath))

    if not os.path.exists(outputDir):
        os.makedirs(outputDir)

    cfgList, nodeLists, edgeLists = angrGraphGen_binaryList(filePathList)

    nodeDicts = nodeDicGen_nodeLists(nodeLists)
 
    offsetStrMapping, externFuncNamesList = offsetStrMappingGen_Lists(
        cfgList, binaryList)
   
    funcIndexMappingList, funcIndexMappingReverseList, blockListOfFuncList, blockFuncNameMappingList = funcBlockGen_Lists(
        cfgList, nodeLists, externFuncNamesList, nodeDicts)

    print("\tprocessing instructions...")
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, string_bid_List, per_block_neighbors_bids_list, non_code_block_ids_list = nodeIndexToCodeGen_Lists(
        nodeLists, nodeDicts, offsetStrMapping, outputDir)

    print("\tgenerating CFGs...")
   
    edgeListGen_onlyEdgeList(edgeLists, nodeDicts, outputDir, fileNameList)
    print("Preprocessing all done. Enjoy!!")
    return blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, funcIndexMappingList, blockListOfFuncList


# preprocessing the two binaries with Angr.
def preprocessing_GatherFunc_In_blockEmbedding(filepath1, filepath2,
                                               outputDir):
    binary1 = path_leaf(filepath1)
    binary2 = path_leaf(filepath2)

    if not os.path.exists(outputDir):
        os.makedirs(outputDir)

    cfg1, cg1, nodelist1, edgelist1, cfg2, cg2, nodelist2, edgelist2 = angrGraphGen(
        filepath1, filepath2)
    
    nodeDic1, nodeDic2 = nodeDicGen(nodelist1, nodelist2)

    # funcToIndexDict funcToIndexDictReverse blockListOfFunc
    # nodeDict1[nodelist1[i]] = i nodeDict2[nodelist2[i]] = len(nodelist1) + i
    #for node in nodelist1:
    #    print("node.addr:{}, node.size:{}, node.function_address:{}, node.block_id:{}, node.byte_string:{}, node._name:{}, node._hash:{}, node.simprocedure_name:{}".format(node.addr, node.size, node.function_address, node.block_id, node.byte_string, node._name, node._hash, node.simprocedure_name))
    # nodelist[i] = i
    # nodeDict[nodelist[i]] = i
    
    mneList, _ = instrTypeDicGen(nodelist1, nodelist2)

    # print("\t extracing strings...")
    offsetStrMapping, externFuncNamesBin1, externFuncNamesBin2 = offsetStrMappingGen(
        cfg1, cfg2, binary1, binary2, mneList)

    funcIndexMappingBin1, funcIndexMappingBin2, funcIndexMappingReverseBin1, funcIndexMappingReverseBin2, blockListOfFuncBin1, blockListOfFuncBin2, blockFuncNameMappingBin1, blockFuncNameMappingBin2 = funcBlockGen(
        cfg1, cfg2, nodelist1, nodelist2, externFuncNamesBin1,
        externFuncNamesBin2, nodeDic1, nodeDic2)

 
    print("\tprocessing instructions...")
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, string_bid1, string_bid2 = nodeIndexToCodeGen(
        nodelist1, nodelist2, nodeDic1, nodeDic2, offsetStrMapping, outputDir)

    
    toBeMergedBlocks, toBeMergedBlocksReverse, toBeMergedFuncs, toBeMergedFuncsReverse = externBlocksAndFuncsToBeMerged(
        cfg1, cfg2, nodelist1, nodelist2, binary1, binary2, nodeDic1, nodeDic2,
        externFuncNamesBin1, externFuncNamesBin2, string_bid1, string_bid2)

    # print("\t processing functions...")
    # funclist1, funclist2 = functionIndexToCodeGen(cfg1, cg1, nodelist1, nodeDic1, cfg2, cg2, nodelist2, nodeDic2, binary1, binary2, outputDir)

    
    print("\tgenerating CFGs...")
    edgeListGen(edgelist1, nodeDic1, edgelist2, nodeDic2, toBeMergedBlocks,
                toBeMergedBlocksReverse, outputDir)

    # print("\t generating call graphs...")
    # funcedgeListGen(cg1, funclist1, cg2, funclist2, toBeMergedFuncsReverse, outputDir)

    print("Preprocessing all done. Enjoy!!")
    return blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, nodeDic1, nodeDic2, binary1, binary2, nodelist1, nodelist2, toBeMergedBlocks, blockListOfFuncBin1, blockListOfFuncBin2, funcIndexMappingReverseBin1, funcIndexMappingReverseBin2, funcIndexMappingBin1, funcIndexMappingBin2, blockFuncNameMappingBin1, blockFuncNameMappingBin2
