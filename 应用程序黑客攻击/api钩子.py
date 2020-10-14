import utils,sys
import pydbg
from pydbg.defines import *

dbg=pydbg()
isProcess=False

orgPattern="love"
repPattern="hate"
processName="notepad.exe"

def replaceString(dbg,args):
	buffer=dbg.read_process_memory(args[1],args[2])

	if orgPattern in buffer:
		print("[APIHooking] Before: %s"%buffer)
		buffer=buffer.replace(orgPattern,repPattern)
		replace=dbg.write_process_memory(args[1],buffer)
		print("[APIHooking] After:%s"% dbg.read_process_memory(args[1],args[2]))
	return DBG_CONTINUE

for(pid,name) in dbg.enumerate_processes():
	if name.lower()==processName:
		isProcess=True
		hooks=utils.hooks_container()
		dbg.attach(pid)
		print("Saves a process handle in self.h_process of pid[%d]"%pid)

		hookAddress=dbg.func_resolve_debuggee("kernel32.dll","WriteFile")

		if hookAddress:
			hooks.add(dbg,hookAddress,5,replaceString,None)
			print("sets a breakpoint at the designated address: 0x%08x" % hookAddress)
		else:
			print("[Error]: couldn't resolve hook address")
			sys.exit(-1)

if isProcess:
	print("waiting for occurring debugger event")
	dbg.run()
else:
	print("[Error]: There in no process [%s]"%processName)
	sys.exit(-1)
