# encoding: utf-8
import os
import collections
import ntpath
import math

from shutil import copyfile
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

import matching_driver
import featureGen
import preprocessing
from deepwalk import deepwalk

import tensorflow as tf
import numpy as np

import jsonlines
import json
from random import shuffle
from preprocessing import preprocessing_blockEmbedding_Pair
from preprocessing import makeDir
from preprocessing import edgeFolderName
from preprocessing import blockEmbeddingFileName

import random
import time
# this list contains all the indices of the opcode in opcode_list
opcode_idx_list = []

roc_point_output = 'func_pair_roc_output.jsonl'

# boundaryIdx = -1
jsonFolderName = "nodejson/"


def makeOutputDir(outputDir):
    if not os.path.exists(outputDir + jsonFolderName):
        os.makedirs(outputDir + jsonFolderName)
    if not os.path.exists(outputDir + edgeFolderName):
        os.makedirs(outputDir + edgeFolderName)


# blockIdxToTokens: blockIdxToTokens[block index] = token list
# return dictionary: index to token, reversed_dictionary: token to index
def vocBuild(blockIdxToTokens):
    global opcode_idx_list
    vocabulary = []
    reversed_dictionary = dict()
    count = [['UNK'], -1]
    index = 0
    for idx in blockIdxToTokens:
        for token in blockIdxToTokens[idx]:
            vocabulary.append(token)
            if token not in reversed_dictionary:
                reversed_dictionary[token] = index
                if token in preprocessing.opcode_list and index not in opcode_idx_list:
                    opcode_idx_list.append(index)
                    # print("token:", token, " has idx: ", str(index))
                index = index + 1

    dictionary = dict(
        zip(reversed_dictionary.values(), reversed_dictionary.keys()))
    count.extend(collections.Counter(vocabulary).most_common(1000 - 1))
    print('20 most common tokens: ', count[:20])

    del vocabulary

    return dictionary, reversed_dictionary


# generate article for word2vec. put all random walks together into one article.

# we put a tag between blocks
def articlesGen(walks, blockIdxToTokens, reversed_dictionary):
    # stores all the articles, each article itself is a list
  
    article = []

    # stores all the block boundary indice. blockBoundaryIndices[i] is a list to store indices for articles[i].
    # each item stores the index for the last token in the block
    blockBoundaryIdx = []
    #instruction token
    for walk in walks:
        # one random walk is served as one article
        for idx in walk:
            if idx in blockIdxToTokens:
                tokens = blockIdxToTokens[idx]
                for token in tokens:
                    article.append(reversed_dictionary[token])
            blockBoundaryIdx.append(len(article) - 1)
            # aritcle.append(boundaryIdx)


    insnStartingIndices = []
   
    indexToCurrentInsnsStart = {}
    # blockEnd + 1 so that we can traverse to blockEnd
    # go through the current block to retrive instruction starting indices
  
    for i in range(0, len(article)):
        if article[i] in opcode_idx_list:
            insnStartingIndices.append(i)
        indexToCurrentInsnsStart[i] = len(insnStartingIndices) - 1

    # for counter, value in enumerate(insnStartingIndices):
    #     if data_index == value:
    #         currentInsnStart = counter
    #         break
    #     elif data_index < value:
    #         currentInsnStart = counter - 1
    #         break

    return article, blockBoundaryIdx, insnStartingIndices, indexToCurrentInsnsStart


# adopt TF-IDF method during block embedding calculation

def cal_block_embeddings(blockIdxToTokens, blockIdxToOpcodeNum,
                         blockIdxToOpcodeCounts, insToBlockCounts,
                         tokenEmbeddings, reversed_dictionary):
    block_embeddings = {}
    totalBlockNum = len(blockIdxToOpcodeCounts)

    for bid in blockIdxToTokens:
        tokenlist = blockIdxToTokens[bid]
        opcodeCounts = blockIdxToOpcodeCounts[bid]
        opcodeNum = blockIdxToOpcodeNum[bid]

        opcodeEmbeddings = []
        operandEmbeddings = []

        if len(tokenlist) != 0:
            for token in tokenlist:
                tokenid = reversed_dictionary[token]

                tokenEmbedding = tokenEmbeddings[tokenid]

                if tokenid in opcode_idx_list:  
                    # here we multiple the embedding with its TF-IDF weight if the token is an opcode
                    if token in opcodeCounts.keys():
                        tf_weight = opcodeCounts[token] / opcodeNum
                    else:
                        tf_weight = 1 / opcodeNum
                    if token in insToBlockCounts.keys():
                        x = totalBlockNum / insToBlockCounts[token]
                    else:
                        x = totalBlockNum / 1
                    idf_weight = math.log(x)
                    tf_idf_weight = tf_weight * idf_weight
                    # print("tf-idf: ", token, opcodeCounts[token], opcodeNum, totalBlockNum, insToBlockCounts[token], tf_weight, idf_weight)

                    opcodeEmbeddings.append(tokenEmbedding * tf_idf_weight)
                else:  
                    operandEmbeddings.append(tokenEmbedding)

            opcodeEmbeddings = np.array(opcodeEmbeddings)
            operandEmbeddings = np.array(operandEmbeddings)

            opcode_embed = opcodeEmbeddings.sum(0)
            operand_embed = operandEmbeddings.sum(0)
        # set feature vector for null block node to be zeros
        else:
            embedding_size = 64
            opcode_embed = np.zeros(embedding_size)
            operand_embed = np.zeros(embedding_size)
        # if no operand, give zeros
        if operand_embed.size == 1:
            operand_embed = np.zeros(len(opcode_embed))

        block_embed = np.concatenate((opcode_embed, operand_embed), axis=0)
        block_embeddings[bid] = block_embed
        # print("bid", bid, "block embedding:", block_embed)

    return block_embeddings




def feature_vec_file_gen(feature_file, block_embeddings):
    with open(feature_file, 'w') as feaVecFile:

        for counter in block_embeddings:
            value = block_embeddings[counter]
            # index as the first element and then output all the features
            feaVecFile.write(str(counter) + " ")
            for k in range(len(value)):
                feaVecFile.write(str(value[k]) + " ")
            feaVecFile.write("\n")


def block_embedding_multiInput_output(block_embeddings, funcIndexMappingList,
                                      blockListOfFuncList, filePathList,
                                      outputDir, fileNameList):
    jsonData = {}
    for i in range(len(fileNameList)):
        #

        funcIndexMapping = funcIndexMappingList[i]
        blockListOfFunc = blockListOfFuncList[i]
        for func, funcId in funcIndexMapping.items():
            funcDict = {}
            #f.write(func.name+"\n")
            blockList = blockListOfFunc[funcId]
            for bid in blockList:
                embedding_List = []
                embedding = block_embeddings[str(bid)]
                #f.write(str(bid) + " ")
                for k in range(len(embedding)):
                    embedding_List.append(str(embedding[k]))
                funcDict[bid] = embedding_List
            jsonData[func.name] = funcDict
        with open(outputDir + jsonFolderName + fileNameList[i] + ".json", 'w') as f:
            json.dump(jsonData, f)


def copyEverythingOver_blockEmbedding_Pair(src_dir, dst_dir):
    node_features = 'features'
    cfg_edgelist = 'edgelist_merged_tadw'
    copyfile(src_dir + node_features, dst_dir + node_features)
    copyfile(src_dir + cfg_edgelist, dst_dir + 'edgelist')


def copyEverythingOver(src_dir, dst_dir):
    # ground_truth = 'addrMapping'
    node_features = 'features'
    cfg_edgelist = 'edgelist_merged_tadw'
    #func_edgelist = 'func_edgelist'
    #functionInfo = 'functionIndexToCode'
    nodeInfo = 'nodeIndexToCode'

    #copyfile('/home/yueduan/yueduan/groundTruthCollection/output/' + ground_truth, dst_dir + ground_truth)
    # copyfile(src_dir + ground_truth, dst_dir + ground_truth)
    copyfile(src_dir + node_features, dst_dir + node_features)
    copyfile(src_dir + cfg_edgelist, dst_dir + 'edgelist')
    #copyfile(src_dir + func_edgelist, dst_dir + func_edgelist)
    #copyfile(src_dir + functionInfo, dst_dir + functionInfo)
    copyfile(src_dir + nodeInfo, dst_dir + nodeInfo)

    #Yue: use feature as embedding
    # copyfile(src_dir + node_features, 'vec_all')


def blockEmbedding_save_blockEmbedding_Gen(block_embeddings, nodeLists, outputDir, fileNameList):
    blockEmbeddingList = list(block_embeddings)
    nodeSum = 0
    for i in range(len(fileNameList)):
        curblockEmbeddingList = blockEmbeddingList[nodeSum: nodeSum+len(nodeLists[i])]
        dirPath = makeDir(outputDir, fileNameList[i])
        print(dirPath)
        with open(dirPath+blockEmbeddingFileName, 'w') as f:
            for j in range(len(curblockEmbeddingList)):
                counter = curblockEmbeddingList[j]
                value = block_embeddings[counter]
                counter = int(counter)
                counter -= nodeSum
                f.write(str(counter) + " ")
                for k in range(len(value)):
                    f.write(str(value[k]) + " ")
                f.write("\n")
        nodeSum += len(nodeLists[i])
        


def get_func_embeddings(block_embeddings, blockListOfFuncBin1,
                        blockListOfFunBin2):
    func_embeddings = {}

    for blockList in blockListOfFuncBin1:
        single_Func_embedding = None
        for i in range(len(blockList)):
            if single_Func_embedding is None:
                single_Func_embedding = block_embeddings[str(blockList[i])]
            else:
                single_Func_embedding += block_embeddings[str(blockList[i])]
        func_embeddings[str(len(func_embeddings))] = single_Func_embedding

    for blockList in blockListOfFunBin2:
        single_Func_embedding = None
        for i in range(len(blockList)):
            if single_Func_embedding is None:
                single_Func_embedding = block_embeddings[str(blockList[i])]
            else:
                single_Func_embedding += block_embeddings[str(blockList[i])]
        func_embeddings[str(len(func_embeddings))] = single_Func_embedding

    return func_embeddings


def gen_match_inputs_blockEmbedding(funcNameBlockListMappingBin1, funcNameBlockListMappingBin2, isShuffle="True", selectPercentage=0.5):

    
    random.seed(time.time())
    inputs_func_list = []
    label_func_list = []
    for func1Name in funcNameBlockListMappingBin1.keys():
        for func2Name in funcNameBlockListMappingBin2.keys():
            if func1Name == func2Name:
                inputs_func_list.append(func1Name)

    inputs_func_list = random.sample(inputs_func_list, int(len(inputs_func_list) * selectPercentage))  # int(len(inputs_func_list) * selectPercentage
    for funcName in inputs_func_list:
        label_func_list.append(funcName)
    if isShuffle:
        inputs_func_list.extend(inputs_func_list)
        label_func_list_temp = label_func_list.copy()
        shuffle(label_func_list_temp)
        label_func_list.extend(label_func_list_temp)
    return inputs_func_list, label_func_list


def gen_match_inputs(matched_pairs,
                     funcIndexMappingBin1,
                     funcIndexMappingBin2,
                     blockListOfFuncBin1,
                     blockListOfFuncBin2,
                     isShuffle="True"):

    block_match_Dict = {}
    for pair in matched_pairs:
        bid1, bid2 = pair
        block_match_Dict[int(bid1)] = int(bid2)
  
    inputs_func_list = []
    label_func_list = []
    for func1, func1Id in funcIndexMappingBin1.items():
        for func2, func2Id in funcIndexMappingBin2.items():
            if func2.name == func1.name:
                inputs_func_list.append((func1.name, func1Id))
                label_func_list.append((func2.name, func2Id))
    if isShuffle:
        inputs_func_list.extend(inputs_func_list)
        label_func_list_temp = label_func_list.copy()
        shuffle(label_func_list_temp)
        label_func_list.extend(label_func_list_temp)
    #print("inputs_func_list_num ?= lable_func_list:{}".format(len(lable_func_list)==len(inputs_func_list)))
    #for i in range(len(inputs_func_list)):
    #print(inputs_func_list[i], lable_func_list[i])
    return inputs_func_list, label_func_list, block_match_Dict


def caculate_roc_for_function_match_blockEmbedding(matched_pairs, funcNameBlockListMappingBin1, funcNameBlockListMappingBin2, fileNameList, outputDir):
    block_match_Dict = {}
    for pair in matched_pairs:
        bid1, bid2 = pair
        block_match_Dict[int(bid1)] = int(bid2)

    threshold_x = 0.1
    epochs = 200
    stat_for_roc_bool_index_dict = {
        (True, True): 0,
        (True, False): 1,
        (False, True): 2,
        (False, False): 3
    }
    stat_for_roc_name_list = ['TP', 'FN', 'FP', 'TN']

    jsonDict = {}
    jsonDict['binary1'] = fileNameList[0]
    jsonDict['binary2'] = fileNameList[1]
    jsonDict['threshold_x_init'] = threshold_x
    point_list = []
    same_name = 0
    match_same_name = 0
    outputPath = makeDir(outputDir, "blockEmbeddingJsons")
    with open(outputPath+"info.txt", 'w') as f:
        for epoch in range(epochs):
            inputs_func_list, label_func_list = gen_match_inputs_blockEmbedding(funcNameBlockListMappingBin1, funcNameBlockListMappingBin2)

            stat_for_roc_list = [0, 0, 0, 0]  
            for i in range(len(inputs_func_list)):
                func1Name = inputs_func_list[i]
                func2Name = label_func_list[i]
                f.write(func1Name + " " + func2Name+"\n")
                f.write("blockList1:\n")
                blockList1 = funcNameBlockListMappingBin1[func1Name]
                blockList2 = funcNameBlockListMappingBin2[func2Name]
                for block in blockList1:
                    f.write(str(block)+" ")
                f.write("\nblockList2\n")
                for block in blockList2:
                    f.write(str(block)+" ")
                f.write("\n")
                min_block_count = min(len(blockList1), len(blockList2))
                threshold_min_block_count = 1  # max(1, int(math.ceil(min_block_count *threshold_x)))
                matched_block_count = 0
                for bid1 in blockList1:
                    if bid1 in block_match_Dict.keys():
                        bid2 = block_match_Dict[bid1]
                        f.write("("+str(bid1)+" "+str(bid2)+") ")
                        if bid2 in blockList2:
                            matched_block_count += 1
                f.write("\n"+str(matched_block_count)+"\n")
                actual_Positive = False  
                predict_Positive = False  
                if matched_block_count >= threshold_min_block_count:  
                    predict_Positive = True
                    if func1Name == func2Name:
                        match_same_name += 1
                else:
                    predict_Positive = False

                if func1Name == func2Name:
                    actual_Positive = True
                    same_name += 1
                else:
                    actual_Positive = False
                stat_for_roc_list[stat_for_roc_bool_index_dict[(
                    actual_Positive, predict_Positive)]] += 1
            TP = stat_for_roc_list[stat_for_roc_name_list.index('TP')]
            FP = stat_for_roc_list[stat_for_roc_name_list.index('FP')]
            TN = stat_for_roc_list[stat_for_roc_name_list.index('TN')]
            FN = stat_for_roc_list[stat_for_roc_name_list.index('FN')]
            point_list.append(((TP, FP, TN, FN), len(inputs_func_list)))
    jsonDict['points'] = point_list
    outputPath = makeDir(outputDir, "blockEmbeddingJsons")
    with open(outputPath + fileNameList[0]+"-"+fileNameList[1]+".json", "w") as f:
        json.dump(jsonDict, f)


def caculate_roc_for_function_match(block_match_Dict, inputs_func_list,
                                    lable_func_list, blockListOfFuncBin1,
                                    blockListOfFuncBin2, outputDir, binary1,
                                    binary2):
    print("caculate_roc_for_function_match")
    threshold_x = 0  
    threshold_x_increase_step = 0.05
    # sta_for_roc_dict[(actual, predict)]
    stat_for_roc_bool_index_dict = {
        (True, True): 0,
        (True, False): 1,
        (False, True): 2,
        (False, False): 3
    }
    stat_for_roc_name_list = ['TP', 'FN', 'FP', 'TN']
    
    jsonDict = {}
    jsonDict['binary1'] = binary1
    jsonDict['binary2'] = binary2
    jsonDict['threshold_x_init'] = threshold_x
    jsonDict['threshold_x_increase_step'] = threshold_x_increase_step
    point_list = []
    same_name = 0
    match_same_name = 0
    for epoch in range(int(1 / threshold_x_increase_step)):
        # stat_for_roc_list[0] = TP, 1 = FN, 2 = FP, 3 = TN
        stat_for_roc_list = [0, 0, 0, 0]  
        for i in range(len(inputs_func_list)):
            func1Name, func1Id = inputs_func_list[i]
            func2Name, func2Id = lable_func_list[i]
            actual_Positive = False  
            predict_Positive = False  
            #print("---------------------------------------------")
            blockList1 = blockListOfFuncBin1[func1Id]
            blockList2 = blockListOfFuncBin2[func2Id]
            min_block_count = min(len(blockList1),
                                  len(blockList2))  
          
            threshold_min_block_count = max(
                1, int(math.ceil(min_block_count *
                                 threshold_x))) 
            
            matched_block_count = 0
            for bid1 in blockList1:
                if bid1 in block_match_Dict.keys():
                    bid2 = block_match_Dict[bid1]
                    if bid2 in blockList2:
                        matched_block_count += 1
            
            if matched_block_count >= threshold_min_block_count: 
                predict_Positive = True
                if func1Name == func2Name:
                    match_same_name += 1
                  
                if func1Name != func2Name:
                    pass
                  
            else:
                predict_Positive = False

            if func1Name == func2Name:
                actual_Positive = True
                same_name += 1
            else:
                actual_Positive = False

            
            stat_for_roc_list[stat_for_roc_bool_index_dict[(
                actual_Positive, predict_Positive)]] += 1

        TP = stat_for_roc_list[stat_for_roc_name_list.index('TP')]
        FP = stat_for_roc_list[stat_for_roc_name_list.index('FP')]
        TN = stat_for_roc_list[stat_for_roc_name_list.index('TN')]
        FN = stat_for_roc_list[stat_for_roc_name_list.index('FN')]
        #FPR = FP / (FP + TN)
        #TPR = TP / (TP + FN)
        point_list.append((TP, FP, TN, FN))
        threshold_x += threshold_x_increase_step
        '''
        print("threshold:", threshold_x)
        for i in range(len(stat_for_roc_list)):
            print("{}:{}  ".format(stat_for_roc_name_list[i],
                                   stat_for_roc_list[i]))
        '''
    jsonDict['points'] = point_list
    with open(outputDir+"jsons/"+binary1+"-"+binary2+".json", "a") as f:
        json.dump(jsonDict, f)
    #print("jsonlines:", jsonDict)
    #with jsonlines.open(roc_point_output, mode='a') as writer:
        #writer.write(jsonDict)
    print("number_same_name_function:", same_name)
    print("matched_function：", match_same_name)


def compare_binary_experiment(matched_pairs, funcIndexMappingBin1,
                              funcIndexMappingBin2, blockListOfFuncBin1,
                              blockListOfFuncBin2):

    block_match_Dict = {}
    for pair in matched_pairs:
        bid1, bid2 = pair
        block_match_Dict[int(bid1)] = int(bid2)
    threshold_x = 0.1
    threshold_x_increase_step = 0.1
    same_name_func = 0
    match_same_name = 0
    wrong_match_same_name = 0
    for func1, func1Id in funcIndexMappingBin1.items():
        for func2, func2Id in funcIndexMappingBin2.items():
            blockList1 = blockListOfFuncBin1[func1Id]
            blockList2 = blockListOfFuncBin2[func2Id]
            min_block_count = min(len(blockList1),
                                  len(blockList2))  
         
            threshold_min_block_count = int(
                math.ceil(min_block_count *
                          threshold_x))  
        
            matched_block_count = 0
            for bid1 in blockList1:
                if bid1 in block_match_Dict.keys():
                    bid2 = block_match_Dict[bid1]
                    if bid2 in blockList2:
                        matched_block_count += 1
       
            if matched_block_count >= threshold_min_block_count:  
                if func1.name == func2.name:
                    # Inmodel_Num
                    match_same_name += 1
                else:
                    wrong_match_same_name += 1

            if func1.name == func2.name:
                same_name_func += 1
    return match_same_name, same_name_func, wrong_match_same_name, threshold_x


def experiment_output(Inmodel_Num, Inmodel_Total, wrong_Inmodel_Num,
                      threshold_x, Key, Test_NUM, Model_NUM, filepath1,
                      filepath2):
    output_str = "{}----->{} Res:{:.4} Inmodel_NUM:{} Inmodel_Total:{} Test_NUM:{} Model_NUM:{} Wrong_Inmodel_Num:{} Threshold_x:{} Key:{}\n"
    bin1_name = os.path.basename(filepath1)
    bin2_name = os.path.basename(filepath2)
    Res = Inmodel_Num / min(Test_NUM, Model_NUM)
    output_str = output_str.format(bin1_name, bin2_name, Res, Inmodel_Num,
                                   Inmodel_Total, Test_NUM, Model_NUM,
                                   wrong_Inmodel_Num, threshold_x, Key)
    with open("experiment_output.txt", "a") as f:
        f.write(output_str)


def getFileNameList(pathList):
    fileNameList = []
    for filePath in pathList:
        tempName = ""
        path, fname = os.path.split(filePath)
        if path.find("arm") != -1:
            tempName += "arm-"
        elif path.find("mips") != -1:
            tempName += "mips-"
        elif path.find("x86") != -1:
            tempName += "x86-"

        if path.find("clang") != -1:
            tempName += "clang-"
        elif path.find("gcc") != -1:
            tempName += "gcc-"
        
        if path.find("O0") != -1:
            tempName += "O0-"
        elif path.find("O1") != -1:
            tempName += "O1-"
        elif path.find("O2") != -1:
            tempName += "O2-"
        elif path.find("O3") != -1:
            tempName += "O3-"
        tempName += fname
        fileNameList.append(tempName)
    return fileNameList


def main_DeepbinDiff_multiInput():
    # example:
    # python3 src/deepbindiff.py --input1 input/ls_6.4 --input2 input/ls_8.30 --outputDir output/

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            conflict_handler='resolve')
    parser.add_argument('--inputDir',
                        required=False,
                        help='Input bin file Dir')
    parser.add_argument(
        '--inputList', required=False, help='Input bin file Dir'
    )  
    parser.add_argument('--outputDir',
                        required=True,
                        help='Specify the output directory')

    args = parser.parse_args()
  
    fileDirPath = args.inputDir
    # filepath2 = args.input2
    outputDir = args.outputDir
    if outputDir.endswith('/') is False:
        outputDir = outputDir + '/'

    makeOutputDir(outputDir) 
    inputList = args.inputList
    filePathList = []  

    if fileDirPath is not None:
      
        for root, dirs, files in os.walk(fileDirPath):
            for name in files:
                filePathList.append(os.path.join(fileDirPath, name))
    else:  
        inputList = inputList.replace(",", " ")
        filePathList = inputList.split()

    fileNameList = getFileNameList(filePathList)  
    EDGELIST_FILE = outputDir + "edgelist"
    # step 1: perform preprocessing for the two binaries
    # blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, _, _, bin1_name, bin2_name, toBeMergedBlocks = preprocessing.preprocessing_multiInput(filePathList, outputDir)
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, funcIndexMappingList, blockListOfFuncList = preprocessing.preprocessing_multiInput(
        filePathList, outputDir, fileNameList)

    dictionary, reversed_dictionary = vocBuild(blockIdxToTokens)

  
    walks = deepwalk.randomWalksGen(EDGELIST_FILE, blockIdxToTokens)


    article, blockBoundaryIndex, insnStartingIndices, indexToCurrentInsnsStart = articlesGen(
        walks, blockIdxToTokens, reversed_dictionary)


    tokenEmbeddings = featureGen.tokenEmbeddingGeneration_skipgram(
        article, blockBoundaryIndex, insnStartingIndices,
        indexToCurrentInsnsStart, dictionary, reversed_dictionary,
        opcode_idx_list)
    print(tokenEmbeddings)
  
    block_embeddings = cal_block_embeddings(blockIdxToTokens,
                                            blockIdxToOpcodeNum,
                                            blockIdxToOpcodeCounts,
                                            insToBlockCounts, tokenEmbeddings,
                                            reversed_dictionary)

    block_embedding_multiInput_output(block_embeddings, funcIndexMappingList,
                                      blockListOfFuncList, filePathList,
                                      outputDir, fileNameList)


def main_DeepbinDiff_func_match():
    # example:
    # python3 src/deepbindiff.py --input1 input/ls_6.4 --input2 input/ls_8.30 --outputDir output/

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')

    parser.add_argument('--input2', required=True, help='Input bin file 2')

    parser.add_argument('--outputDir',
                        required=True,
                        help='Specify the output directory')
    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    outputDir = args.outputDir

    if outputDir.endswith('/') is False:
        outputDir = outputDir + '/'

    EDGELIST_FILE = outputDir + "edgelist"

    # step 1: perform preprocessing for the two binaries
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, _, _, bin1_name, bin2_name, nodelist1, nodelist2, toBeMergedBlocks, blockListOfFuncBin1, blockListOfFuncBin2, funcIndexMappingReverseBin1, funcIndexMappingReverseBin2 = preprocessing.preprocessing(
        filepath1, filepath2, outputDir)

    #step 2: vocabulary buildup
  
    dictionary, reversed_dictionary = vocBuild(blockIdxToTokens)

    # step 3: generate random walks, each walk contains certain blocks

    walks = deepwalk.randomWalksGen(EDGELIST_FILE, blockIdxToTokens)

    # step 4: generate articles based on random walks

    article, blockBoundaryIndex, insnStartingIndices, indexToCurrentInsnsStart = articlesGen(
        walks, blockIdxToTokens, reversed_dictionary)

    # step 5: token embedding generation
  
    tokenEmbeddings = featureGen.tokenEmbeddingGeneration(
        article, blockBoundaryIndex, insnStartingIndices,
        indexToCurrentInsnsStart, dictionary, reversed_dictionary,
        opcode_idx_list)

    # step 6: calculate feature vector for blocks
  
    # block 的feature
    block_embeddings = cal_block_embeddings(blockIdxToTokens,
                                            blockIdxToOpcodeNum,
                                            blockIdxToOpcodeCounts,
                                            insToBlockCounts, tokenEmbeddings,
                                            reversed_dictionary)
    # func_embeddings = get_func_embeddings(block_embeddings, blockListOfFuncBin1, blockListOfFuncBin2)

    feature_vec_file_gen(outputDir + 'features', block_embeddings)

    copyEverythingOver(outputDir, 'data/DeepBD/')

    # step 7: TADW for block embedding generation & block matching
    matched_pairs = matching_driver.pre_match_Func(bin1_name, bin2_name,
                                                   blockListOfFuncBin1,
                                                   blockListOfFuncBin2)

    for pair in matched_pairs:
        fid1, fid2 = pair
        func1 = funcIndexMappingReverseBin1[fid1]
        if fid2 != -1:
            func2 = funcIndexMappingReverseBin2[fid2]
            print("func1:{}, func2:{}".format(func1.name, func2.name))
        else:
            print("func1:{}, none ".format(func1.name))


def main_DeepbinDiff_blockEmbedding_Pair():
   
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')

    parser.add_argument('--input2', required=True, help='Input bin file 2')

    parser.add_argument('--outputDir',
                        required=True,
                        help='Specify the output directory')
    parser.add_argument('--inputDir', required=True, help='Folder of input file in')
    args = parser.parse_args()
    filepathList = []
    filepathList.append(args.input1)
    filepathList.append(args.input2)
    outputDir = args.outputDir
    inputDir = args.inputDir
    fileNameList = getFileNameList(filepathList)

    if inputDir.endswith('/') is False:
        inputDir = inputDir + '/'

    if outputDir.endswith('/') is False:
        outputDir = outputDir + '/'

    outputDir = makeDir(outputDir, "preMatchingResult")
    EDGELIST_FILE = outputDir + "edgelist"
    
    toBeMergedBlocks, block_embeddings, nodelist1Len, funcNameBlockListMappingBin1, funcNameBlockListMappingBin2 = preprocessing_blockEmbedding_Pair(filepathList, fileNameList, outputDir, inputDir)
    feature_vec_file_gen(outputDir + 'features', block_embeddings)
    copyEverythingOver_blockEmbedding_Pair(outputDir, 'data/DeepBD/')
    matched_pairs, bb_matching_pair = matching_driver.pre_matching_blockEmbedding_Pair(toBeMergedBlocks, nodelist1Len)
    bb_matching_pair_replace = []
    for bid1, bid2 in bb_matching_pair:
        bid1 = int(bid1)
        bid2 = int(bid2)
        bid2 += nodelist1Len
        bb_matching_pair_replace.append((bid1, bid2))
    matched_pairs.extend(bb_matching_pair_replace)

    caculate_roc_for_function_match_blockEmbedding(matched_pairs, funcNameBlockListMappingBin1, funcNameBlockListMappingBin2, fileNameList, outputDir)



def main_DeepbinDiff_blockEmbedding_Gen():

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            conflict_handler='resolve')
    parser.add_argument('--inputDir',
                        required=False,
                        help='Input bin file Dir')
    parser.add_argument(
        '--inputList', required=False, help='Input bin file Dir'
    )  
    parser.add_argument('--outputDir',
                        required=True,
                        help='Specify the output directory')

    args = parser.parse_args()
   
    fileDirPath = args.inputDir
 
    outputDir = args.outputDir
    if outputDir.endswith('/') is False:
        outputDir = outputDir + '/'

    makeOutputDir(outputDir) 
    inputList = args.inputList
    filePathList = [] 
    if fileDirPath is not None:
        
        for root, dirs, files in os.walk(fileDirPath):
            for name in files:
                filePathList.append(os.path.join(fileDirPath, name))
    else: 
        inputList = inputList.replace(",", " ")
        filePathList = inputList.split()
    for filePath in filePathList:
        print(filePath)
    
    fileNameList = getFileNameList((filePathList))  
    EDGELIST_FILE = outputDir + "edgelist"
    
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, funcIndexMappingList, blockListOfFuncList, nodeLists = preprocessing.preprocessing_blockEmbedding_Gen(
        filePathList, outputDir, fileNameList)

    dictionary, reversed_dictionary = vocBuild(blockIdxToTokens)

   
    walks = deepwalk.randomWalksGen(EDGELIST_FILE, blockIdxToTokens)

    article, blockBoundaryIndex, insnStartingIndices, indexToCurrentInsnsStart = articlesGen(
        walks, blockIdxToTokens, reversed_dictionary)

  
    tokenEmbeddings = featureGen.tokenEmbeddingGeneration(
        article, blockBoundaryIndex, insnStartingIndices,
        indexToCurrentInsnsStart, dictionary, reversed_dictionary,
        opcode_idx_list)
    print(tokenEmbeddings)
  
    block_embeddings = cal_block_embeddings(blockIdxToTokens,
                                            blockIdxToOpcodeNum,
                                            blockIdxToOpcodeCounts,
                                            insToBlockCounts, tokenEmbeddings,
                                            reversed_dictionary)

    blockEmbedding_save_blockEmbedding_Gen(block_embeddings, nodeLists, outputDir, fileNameList)
 
def main_DeepbinDiff_FuncPair_ROC():
    # example:
    # python3 src/deepbindiff.py --input1 input/ls_6.4 --input2 input/ls_8.30 --outputDir output/
    
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')

    parser.add_argument('--input2', required=True, help='Input bin file 2')

    parser.add_argument('--outputDir',
                        required=True,
                        help='Specify the output directory')
    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    outputDir = args.outputDir

    if outputDir.endswith('/') is False:
        outputDir = outputDir + '/'
    EDGELIST_FILE = outputDir + "edgelist"

    fileList = []
    fileList.append(filepath1)
    fileList.append(filepath2)
    fileNameList = getFileNameList(fileList)

    # step 1: perform preprocessing for the two binaries
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, _, _, bin1_name, bin2_name, nodelist1, nodelist2, toBeMergedBlocks, blockListOfFuncBin1, blockListOfFuncBin2, funcIndexMappingReverseBin1, funcIndexMappingReverseBin2, funcIndexMappingBin1, funcIndexMappingBin2, blockFuncNameMappingBin1, blockFuncNameMappingBin2 = preprocessing.preprocessing_GatherFunc_In_blockEmbedding(
        filepath1, filepath2, outputDir)

    #step 2: vocabulary buildup
   
    dictionary, reversed_dictionary = vocBuild(blockIdxToTokens)

    # step 3: generate random walks, each walk contains certain blocks
  
    walks = deepwalk.randomWalksGen(EDGELIST_FILE, blockIdxToTokens)

    # step 4: generate articles based on random walks

    article, blockBoundaryIndex, insnStartingIndices, indexToCurrentInsnsStart = articlesGen(
        walks, blockIdxToTokens, reversed_dictionary)

    # step 5: token embedding generation
 
    tokenEmbeddings = featureGen.tokenEmbeddingGeneration(
        article, blockBoundaryIndex, insnStartingIndices,
        indexToCurrentInsnsStart, dictionary, reversed_dictionary,
        opcode_idx_list)

    # step 6: calculate feature vector for blocks
  
    # block 的feature
    block_embeddings = cal_block_embeddings(blockIdxToTokens,
                                            blockIdxToOpcodeNum,
                                            blockIdxToOpcodeCounts,
                                            insToBlockCounts, tokenEmbeddings,
                                            reversed_dictionary)
    # func_embeddings = get_func_embeddings(block_embeddings, blockListOfFuncBin1, blockListOfFuncBin2)

    feature_vec_file_gen(outputDir + 'features', block_embeddings)
 
    copyEverythingOver(outputDir, 'data/DeepBD/')

    # step 7: TADW for block embedding generation & block matching
    matched_pairs, bb_matching_pair = matching_driver.pre_matching(
        bin1_name, bin2_name, toBeMergedBlocks)
   
    bb_matching_pair_replace = []
    for bid1, bid2 in bb_matching_pair:
        bid1 = int(bid1)
        bid2 = int(bid2)
        bid2 += len(nodelist1)
        bb_matching_pair_replace.append((bid1, bid2))
    matched_pairs.extend(bb_matching_pair_replace)

    inputs_func_list, lable_func_list, block_match_Dict = gen_match_inputs(
        matched_pairs, funcIndexMappingBin1, funcIndexMappingBin2,
        blockListOfFuncBin1, blockListOfFuncBin2)
    caculate_roc_for_function_match(block_match_Dict, inputs_func_list,
                                    lable_func_list, blockListOfFuncBin1,
                                    blockListOfFuncBin2, outputDir, fileNameList[0],
                                    fileNameList[1])



def main_DeepbinDiff_Comparative_Experiment():
 

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')

    parser.add_argument('--input2', required=True, help='Input bin file 2')

    parser.add_argument('--outputDir',
                        required=True,
                        help='Specify the output directory')
    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    outputDir = args.outputDir

    if outputDir.endswith('/') is False:
        outputDir = outputDir + '/'

    EDGELIST_FILE = outputDir + "edgelist"

    # step 1: perform preprocessing for the two binaries
    blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, _, _, bin1_name, bin2_name, nodelist1, nodelist2, toBeMergedBlocks, blockListOfFuncBin1, blockListOfFuncBin2, funcIndexMappingReverseBin1, funcIndexMappingReverseBin2, funcIndexMappingBin1, funcIndexMappingBin2, blockFuncNameMappingBin1, blockFuncNameMappingBin2 = preprocessing.preprocessing_GatherFunc_In_blockEmbedding(
        filepath1, filepath2, outputDir)

    #step 2: vocabulary buildup

    dictionary, reversed_dictionary = vocBuild(blockIdxToTokens)

    # step 3: generate random walks, each walk contains certain blocks
 
    walks = deepwalk.randomWalksGen(EDGELIST_FILE, blockIdxToTokens)

    # step 4: generate articles based on random walks

    article, blockBoundaryIndex, insnStartingIndices, indexToCurrentInsnsStart = articlesGen(
        walks, blockIdxToTokens, reversed_dictionary)

    # step 5: token embedding generation

    tokenEmbeddings = featureGen.tokenEmbeddingGeneration(
        article, blockBoundaryIndex, insnStartingIndices,
        indexToCurrentInsnsStart, dictionary, reversed_dictionary,
        opcode_idx_list)

    # step 6: calculate feature vector for blocks

    # block 的feature
    block_embeddings = cal_block_embeddings(blockIdxToTokens,
                                            blockIdxToOpcodeNum,
                                            blockIdxToOpcodeCounts,
                                            insToBlockCounts, tokenEmbeddings,
                                            reversed_dictionary)
    # func_embeddings = get_func_embeddings(block_embeddings, blockListOfFuncBin1, blockListOfFuncBin2)

    feature_vec_file_gen(outputDir + 'features', block_embeddings)
  
    copyEverythingOver(outputDir, 'data/DeepBD/')
    for k in (1, 5, 10, 20):
        # step 7: TADW for block embedding generation & block matching
        matched_pairs, bb_matching_pair = matching_driver.pre_matching(
            bin1_name, bin2_name, toBeMergedBlocks, k)
       
        bb_matching_pair_replace = []
        for bid1, bid2 in bb_matching_pair:
            bid1 = int(bid1)
            bid2 = int(bid2)
            bid2 += len(nodelist1)
            bb_matching_pair_replace.append((bid1, bid2))
        matched_pairs.extend(bb_matching_pair_replace)

      
        Inmodel_Num, Inmodel_Total, wrong_Inmodel_Num, threshold_x = compare_binary_experiment(
            matched_pairs, funcIndexMappingBin1, funcIndexMappingBin2,
            blockListOfFuncBin1, blockListOfFuncBin2)
        experiment_output(Inmodel_Num, Inmodel_Total, wrong_Inmodel_Num,
                          threshold_x, k, len(blockListOfFuncBin1),
                          len(blockListOfFuncBin2), filepath1, filepath2)




if __name__ == "__main__":
    main_DeepbinDiff_blockEmbedding_Gen()

