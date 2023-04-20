import os
import sys

binaries_list = []
binaries_name = []
directory = "../Downloads/Binaries"

op = "-import"

if len(sys.argv) > 2:
    if sys.argv[1] == "-process":
        op = "-process"

for filename in os.listdir(directory):
    path = os.path.join(directory, filename)
    if os.path.isdir(path):
        for i in os.listdir(path):
            binaries_list.append(os.path.join(path, i))
            binaries_name.append(i)

headless = "../ghidra_10.2.2_PUBLIC_20221115/ghidra_10.2.2_PUBLIC/support/analyzeHeadless"

project_path = "../"
project = "../test2.gpr "
postScript = "CreateJson.py"

for i in binaries_name:
    cmd = "{0} {1} {2} {3} {4} -postScript {5}".format(headless, project_path, project,op, i, postScript)
    # cmd = "{0} {1} {2} -import {3} -postScript {4}".format(headless,project_path,project,i,postScript)
    os.system(cmd)
