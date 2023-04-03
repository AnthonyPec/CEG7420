# Retrieves and displays the summary counts for instructions used within
# a function.
# This is a simple script to enumerate functions in a binary. It reports the name, the entry address, the minimal address, the maximal address, and the number of parameters.
# @category: CEG7420.Demo
# @author: Anthony Pecoraro

# Use the Python json library
import io, json
from ghidra.app.decompiler import *
import re

# Import some of the Ghidra classes we will be using
from ghidra.util.task import ConsoleTaskMonitor


def check(inDict, key, token, line):

    reg = re.compile(token)
    # if token in line:
    #     print("math")
    # if bool(re.findall(reg,line)) == True:
    m = re.findall(reg,line)

    for i in m:
        if key == "string":
            if "string" in inDict:
                inDict[key].append(i)
            else:
                inDict[key] = [i]
        else:
            if word in inDict:
                inDict[key] += 1
            else:
                inDict[key] = 1

# def checkString():

# Used to create labels for training machine learning model.
function_keywords =["malloc","get","read","load","error","fetch","close","test","init","destroy"
,"clean","cache","check","create","copy","process","transform","fill","convert","write","update","display"
"validate","main","make","set","flush","add","free","gen","compare","copy","send","build","search","validate"]

missedFunctions = []

library_functions = ['gets(.*)','strcpy(.*)','scanf(.*)','printf(.*)','malloc(.*)','while(.*)',
'fprintf(.*)','fputs(.*)','fflush(.*)','abort(.*)','memcpy(.*)','vfprintf(.*)','feof(.*)','putchar(.*)'
'strerror(.*)','memset(.*)','setjmp(.*)','if (.*)','if (.* == 0)','if (.* != 0)','if (.* < .*)','for (.*)',
'if (.* < \d*)']
# other_keywords = ['case','break','char','double','.*\+','return 0','int']\
other_keywords = ['case','break','return 0','int','goto','return;','.*\+','.*\-','char *','double','= .*\+'
'.*\+ 0x.*']

#got this regex off stackoverflow to find strings
# strings_keywords = ['(?:\/\/.+\n|\/\*.+\*\/)|(\".+\"|\'.+\')']
strings_keywords = ['"([^"]*)"']


# Initialize an empty dict for the "all functions" report
fn_report = {}

myDecomp = DecompInterface()
myDecomp.openProgram(currentProgram)




# "void","typedef","sizeof","register","enum","if","long","==","+","-","float",
# "do","for","goto","break","static","const","struct","free","switch","fflush"]

# the Program.getFunctionManager() provides an interface to navigate the functions
# that Ghidra has found within the program. The getFunctions() method will provide
# an iterator that allows you to walk through the list forward (True) or
# backward (False).
# for testing to make script not run as long
count = 0
for fn in getCurrentProgram().getFunctionManager().getFunctions(True):


    # thunk functions wont have definitions so skip those
    if fn.isThunk():
        continue
    decomp_results = myDecomp.decompileFunction(fn,60,monitor)

    if decomp_results and decomp_results.getDecompiledFunction():
        c_string = decomp_results.getDecompiledFunction().getC()
       
        params = fn.getParameters()
        name = fn.getName()
        # print(c_string)
        # print(c_string)
        c_string = c_string.strip();
        li = list(c_string.split("\n"))

        # Get the earliest instruction defined within the function, to start our exploration
        # instr = getInstructionAt(fn.getBody().getMinAddress())

        # If it is defined, then we assume this is a navigable function and create an entry
        # for it in fn_report
        # if instr:
        fn_report[fn.getName()] = {}

        for word in function_keywords:
            if word in fn.getName().lower():
                fn_report[fn.getName()]["label"] = word
                break

        if "label" not in fn_report[fn.getName()]:
            missedFunctions.append(fn.getName())

        fn_sig = decomp_results.getDecompiledFunction().getSignature()
        returnType = fn_sig.split(" ")[0]
        params_string = fn_sig.split("(")[-1]
        params = params_string.split(",")


        fn_report[name]["return"] = returnType
        counter = 1
        for i in params:
            fn_report[fn.getName()]["param"+str(counter)]= i.split(" ")[0]
            counter = counter +1

      
        # fn_report[name]["code"] = c_string
        # print(c_string)
        for line in li:
            if line not in fn_sig:
                for word in library_functions:
                    check(fn_report[fn.getName()], word, word, line)
                    # reg = re.compile(word)
                    # # reg = "({})".format(word)
                    # if re.search(reg,line):
                    #     if word in fn_report[fn.getName()]:
                    #         fn_report[fn.getName()][word] += 1
                    #     else:
                    #         fn_report[fn.getName()][word] = 1

                for word in other_keywords:
                    check(fn_report[fn.getName()], word, word, line)
                    # reg = re.compile(word)
                    # # reg = "({})".format(word)
                    # if re.search(reg,line):
                    #     m = re.search(reg,line)
                    #     for i in m.groups():
                    #         if word in fn_report[fn.getName()]:
                    #             fn_report[fn.getName()][i] += 1
                    #         else:
                    #             fn_report[fn.getName()][i] = 1   
                for word in strings_keywords:
                      check(fn_report[fn.getName()], "string", word, line)
                # for word in other_keywords:
                #     reg = re.compile(word)
                #     # reg = "({})".format(word)
                #     if re.search(reg,line):
                #         m = re.search(reg,line)
                #         for i in m.groups():
                #             if word in fn_report[fn.getName()]:
                #                 fn_report[fn.getName()][i] += 1
                #             else:
                #                 fn_report[fn.getName()][i] = 1


        #limit number of functions we process to avoid heap overflow
        count = count +1
        if count > 500:
            break;
        # This code is largely the same as the GetFunctionInstructions.py code, with the change
        # that it uses the functions provided from the aforementioned iterator, rather than the
        # function from the cursor position
        # while instr and instr.getMinAddress() <= fn.getBody().getMaxAddress():
        #     if fn.getBody().contains(instr.getMinAddress()):
        #         opcode = instr.getMnemonicString()

        #         if opcode in fn_report[fn.getName()]:
        #             fn_report[fn.getName()][opcode] += 1
        #         else:
        #             fn_report[fn.getName()][opcode] = 1

        #     instr = instr.getNext()

# Original source file
file = fn.getProgram().getExecutablePath().split("/")[-1]
# remove file extension
file = file.split(".")[0]
file = file+".json"
print(file)

with io.open("/home/vboxuser/CEG7420/TrainingData/"+file,"w+",encoding='utf-8') as f:
    f.write(json.dumps(fn_report, ensure_ascii=False,indent=2))

print("Done count: "+ str(count))
# The below is useful if you want to print raw JSON for machine-machine handling
#print(json.dumps(fn_report))
print(missedFunctions)