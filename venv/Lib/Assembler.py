import importlib
import MnemonicsList
import Arguments
import re
srcName = "prog";
srcFormat = "txt";
srcCompleteName = srcName + '.' + srcFormat;

destName = srcName;
destFormat = "mif";
destCompleteName = destName + '.' + destFormat;

srcFile = open(srcCompleteName, "r");

#destFile = open(destCompleteName, "x");

srcLineCounter = 0;
destLineCounter = 0;

currentLineList = " ";

address = 0;
mnemonic = " ";
opcode = " ";
regDestination = " ";
regSource1 = " ";
regSource2 = " ";
aluCode = " ";
immediate = " ";
rTypeAuxOpcode = " ";
shiftAmount = " ";

arg1 = 0;
arg2 = 0;
arg3 = 0;

binaryInstruction = 0;


while 1:

    srcCurrentLine = srcFile.readline();
    #print(srcCurrentLine);
    srcLineCounter = srcLineCounter + 1;

    currentLineList = re.split(';|, |    | ', srcCurrentLine);
    print(currentLineList);
    """
        if(currentLineList):
        mnemonic = currentLineList[0];
        if mnemonic in MnemonicsList.mnemonicsList:
            print(len(currentLineList));
            arg1 = currentLineList[1];
            arg2 = currentLineList[3];
            if len(currentLineList) > 4:
                arg3 = currentLineList[4];
            print(mnemonic);
            print(arg1);
            print(arg2);
            print(arg3);

            if mnemonic == "ADDI" :
                opcode = MnemonicsList.opcodeDictionary(mnemonic);
                print(opcode);
                regSource1 = Arguments.extractRegister(arg1);
                regDestination = regSource1;
                immediate = bin(int(arg2));
                regDestination = regSource1;
                aluCode = "000";
                print("huj: ", immediate)
                binaryInstruction = immediate + regSource1;
                print(binaryInstruction);

    """

    if srcCurrentLine == ".STOP":
        break;

print("Number of lines in source: ", srcLineCounter);

srcFile.close();