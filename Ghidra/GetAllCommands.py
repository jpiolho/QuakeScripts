# This script will get all commands in the game
#
# To use: Make sure that the global gLastConsoleCommand exists. Then run script.


import json
import re
import ghidra.app.decompiler as decomp

# Finds the function entry and creates it
def FindAndCreateFunctionForAddress(addr):
    codeUnits = currentProgram.getListing().getCodeUnits(addr, False)
    codeUnits.next()
    codeUnit = codeUnits.next()
    while getSymbolAt(codeUnit.getAddress()) is None:
        previousCodeUnit = codeUnit
        codeUnit = codeUnits.next()
    createFunction(codeUnit.getAddress(),None)

def GetAndDefineTerminatedCStringAt(addr):
    cu = currentProgram.getListing().getCodeUnitAt(addr)
    if cu.getDataType().getName() != "TerminatedCString":
        print("Setting " + str(addr) + " data to TerminatedCString")
        clearListing(cu.getAddress())
        createData(cu.getAddress(),getDataTypes("TerminatedCString")[0])
        cu = currentProgram.getListing().getCodeUnitAt(addr)
    return cu.getValue()


def main():
    global pCodeOp
    global debugOut
    
    commands = []
    
    addr_lastConsoleCommand = toAddr("gLastConsoleCommand")
    
    listing = currentProgram.getListing()
    references = currentProgram.referenceManager.getReferencesTo(addr_lastConsoleCommand)
    iface = decomp.DecompInterface()
    
    for xref in references:	
        if not xref.getReferenceType().isWrite():
            continue
        
        codeUnits = listing.getCodeUnits(xref.getFromAddress(), False)
        codeUnit = codeUnits.next()
        
        print("Write at " + str(codeUnit.getAddress()))
        
        # Check if call is inside a function
        if getFunctionContaining(codeUnit.getAddress()) is None:
            FindAndCreateFunctionForAddress(codeUnit.getAddress())
            print("Created function")
        
        fn = getFunctionContaining(codeUnit.getAddress())
        
        if fn is None: raise Exception("Function expected at " + str(codeUnit.getAddress()))
        
        iface.openProgram(fn.getProgram())
        decompilation = iface.decompileFunction(fn,0,monitor)
        
        if not decompilation.decompileCompleted(): raise Exception("Decompilation failed for function at " + str(fn.getAddress()) + ". Error: " + decompilation.getErrorMessage())
        
        c = decompilation.getCCodeMarkup();
        
        regex = re.search("gLastConsoleCommand = &(.+?);",c.toString())
        
        if regex is None:
            continue
        
        token = regex.group(1)
        
        cu = currentProgram.getListing().getCodeUnitAt(toAddr(token))
        
        command = GetAndDefineTerminatedCStringAt(cu.getValue())
        
        commands.append(command)
    
    commands.sort()
    print("dump")
    print(json.dumps(commands))

main()