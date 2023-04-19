import os
import subprocess

binaries_list =[]
binaries_name =[]
directory= "../Downloads/Binaries"
for filename in os.listdir(directory):
	path = os.path.join(directory,filename)
	if os.path.isdir(path):
		for i in os.listdir(path):
			binaries_list.append(os.path.join(path,i))
			binaries_name.append(i)


# print(binaries_list)
		# for i in :
		# 	print(i)

headless = "../ghidra_10.2.2_PUBLIC_20221115/ghidra_10.2.2_PUBLIC/support/analyzeHeadless"

project_path = "../"
project = "../test2.gpr "
postScript="CreateJson.py"


# cmd = "{0} {1} {2} -process {3} -postScript {4}".format(headless,project_path,project,binaries_name[1],postScript)
for i in binaries_name:
	cmd = "{0} {1} {2} -process {3} -postScript {4}".format(headless,project_path,project,i,postScript)

	# cmd = "{0} {1} {2} -import {3} -postScript {4}".format(headless,project_path,project,i,postScript)
	# cmd = "{0} {1} {2} -process {3} -postScript {4}".format(headless,project_path,project,i,postScript)

# print(cmd)
	os.system(cmd)
# os.system("headless project_path project binaries_list[0]")
# -import ~/Downloads/crackme0x05 -postScript ~/ghidraScripts/CreateJson.py 

# ./analyzeHeadless ~/ test2.gpr -process crackme0x05 -postScript ~/ghidraScripts/CreateJson.py 