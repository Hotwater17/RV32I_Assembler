import importlib
import MnemonicsList
import Arguments
import re

memoryDepth = "256";
memoryWidth = "32";
addressRadix = "HEX";
dataRadix = "BIN";

srcName = "prog";
srcFormat = "txt";
srcCompleteName = srcName + '.' + srcFormat;

destName = srcName;
destFormat = "mif";
destCompleteName = destName + '.' + destFormat;

srcFile = open(srcCompleteName, "r");

destFile = open(destCompleteName, "w");

srcLineCounter = 0;
destLineCounter = 0;

currentLineList = " ";

address = 0;
addressString = "00";
mnemonic = "";
opcode = "";
regDestination = "";
regSource1 = "";
regSource2 = "";
aluCode = "";
immediate = "";
riTypeAuxOpcode = "";
shiftAmount = "";

fileWriteString = "DEPTH = ", memoryDepth;

arg1 = 0;
arg2 = 0;
arg3 = 0;

binaryInstruction = 0;


print("DEPTH = ", memoryDepth);
print("WIDTH = ", memoryWidth);
print("ADDRESS_RADIX = ", addressRadix);
print("DATA_RADIX = ", dataRadix);
print("CONTENT");
print("BEGIN");

fileWriteString = "DEPTH = "+memoryDepth+'\n';
destFile.write(fileWriteString);
fileWriteString = "WIDTH = "+memoryWidth+'\n';
destFile.write(fileWriteString);
fileWriteString = "ADDRESS_RADIX = "+addressRadix+'\n';
destFile.write(fileWriteString);
fileWriteString = "DATA_RADIX = "+dataRadix+'\n';
destFile.write(fileWriteString);

destFile.write("CONTENT \n");
destFile.write("BEGIN \n");


while 1:

    srcCurrentLine = srcFile.readline();




    srcLineCounter = srcLineCounter + 1;


    currentLineList = re.split(';|, |    | ', srcCurrentLine);
    #print("-- ", currentLineList);
    #If current line is not empty
    if(currentLineList):
        mnemonic = currentLineList[0];
        if len(currentLineList) > 1: arg1 = currentLineList[1];
        if len(currentLineList) > 2: arg2 = currentLineList[2];
        if len(currentLineList) > 3: arg3 = currentLineList[3];

        if mnemonic in MnemonicsList.pseudoInstructionsList :
            print("--Pseudoinstruction found: ", mnemonic);

        if mnemonic in MnemonicsList.mnemonicsList:

            addressString = str(hex(address)[2:]);
            addressString = addressString.zfill(2);
            address = address + 1;
            destLineCounter = destLineCounter + 1;
            opcode = MnemonicsList.opcodeDictionary(mnemonic);

            #Register
            if mnemonic in MnemonicsList.RtypeList :
                riTypeAuxOpcode = MnemonicsList.extractAuxOpcode(mnemonic);
                regSource1 = Arguments.extractRegister(arg1);
                regSource2 = Arguments.extractRegister(arg2);
                regDestination = regSource1;
                immediate = 0;
                aluCode = MnemonicsList.extractAluCode(mnemonic);
                binaryInstruction = riTypeAuxOpcode+regSource2+regSource1+aluCode+regDestination+opcode;
            #Immediate
            elif mnemonic in MnemonicsList.ItypeList :
                regSource1 = Arguments.extractRegister(arg1);
                regSource2 = 0;
                regDestination = regSource1;

                aluCode = MnemonicsList.extractAluCode(mnemonic);
                riTypeAuxOpcode = MnemonicsList.extractAuxOpcode(mnemonic);
                if mnemonic in MnemonicsList.ShiftImmediateList :
                    shiftAmount = Arguments.extract5BitShift(arg2);
                    binaryInstruction = riTypeAuxOpcode+shiftAmount+regSource1+aluCode+regDestination+opcode;
                else :
                    immediate = Arguments.extract12BitImmediate(arg2);
                    binaryInstruction = immediate+regSource1+aluCode+regDestination+opcode;
            #Store
            elif mnemonic in MnemonicsList.StypeList :
                regSource1 = Arguments.extractRegister(arg1);
                regSource2 = Arguments.extractRegister(arg2);
                regDestination = 0;
                immediate = Arguments.extract12BitImmediate(arg3);
                aluCode = MnemonicsList.extractAluCode(mnemonic);
                riTypeAuxOpcode = 0;
                binaryInstruction = immediate[0:7]+regSource2+regSource1+aluCode+immediate[7:12]+opcode;
            #Load
            elif mnemonic in MnemonicsList.LtypeList :
                regSource1 = Arguments.extractRegister(arg2);
                regSource2 = 0;
                regDestination = Arguments.extractRegister(arg1);
                immediate = Arguments.extract12BitImmediate(arg3);
                aluCode = MnemonicsList.extractAluCode(mnemonic);
                riTypeAuxOpcode = 0;
                binaryInstruction = immediate+regSource1+aluCode+regDestination+opcode;
            #Branch
            elif mnemonic in MnemonicsList.BtypeList :
                regSource1 = Arguments.extractRegister(arg1);
                regSource2 = Arguments.extractRegister(arg2);
                regDestination = 0;
                immediate = Arguments.extract12BitImmediate(arg3);
                aluCode = MnemonicsList.extractAluCode(mnemonic);
                riTypeAuxOpcode = 0;
                binaryInstruction = immediate[0]+immediate[2:8]+regSource2+regSource1+aluCode+immediate[8:12]+immediate[1]+opcode;
            #Upper Immediate
            elif mnemonic in MnemonicsList.UtypeList :
                regSource1 = 0;
                regSource2 = 0;
                regDestination = Arguments.extractRegister(arg1);
                immediate = Arguments.extract20BitImmediate(arg2);
                aluCode = MnemonicsList.extractAluCode(mnemonic);
                riTypeAuxOpcode = 0;
                binaryInstruction = immediate+regDestination+opcode;
            #Jump
            elif mnemonic in MnemonicsList.JtypeList :
                regDestination = Arguments.extractRegister(arg1);
                regSource2 = 0;
                riTypeAuxOpcode = 0;
                if mnemonic == "JAL" :
                    regSource1 = 0;
                    immediate = Arguments.extract20BitImmediate(arg2);
                    aluCode = 0;
                    binaryInstruction = immediate[0]+immediate[10:20]+immediate[9]+immediate[1:9]+regDestination+opcode;
                else :
                    regSource1 = Arguments.extractRegister(arg2);
                    immediate = Arguments.extract12BitImmediate(arg3);
                    aluCode = MnemonicsList.extractAluCode(mnemonic);
                    binaryInstruction = immediate+regSource1+aluCode+regDestination+opcode;
            #Fence
            elif mnemonic == "FENCE" :
                print("-- FENCE not supported yet, insterted NOP instead");
                binaryInstruction = "00000000000000000000000000010011";

            #Environment
            elif mnemonic in MnemonicsList.EtypeList :

                #All zeros in fields other than IMM and OPCODE
                if mnemonic == "ECALL" :
                    immediate = "000000000000";
                else :
                    immediate = "000000000001";
                regSource1 = "00000";
                regSource2 = 0;
                riTypeAuxOpcode = 0;
                regDestination = "00000";
                aluCode = "000";
                binaryInstruction = immediate+regSource1+aluCode+regDestination+opcode;

            """
            
            print("Opcode: ", opcode);
            print("ALU Code: ", aluCode);
            print("ALU Aux: ", riTypeAuxOpcode);
            print("Rs1: ", regSource1);
            print("Rs2: ", regSource2);
            print("Rd: ", regDestination);
            print("Immediate: ", immediate);
            print("Current address: ",hex(address));
            print("Binary instruction: ", binaryInstruction);
            """

            print(addressString, ":", binaryInstruction, ";    --", srcCurrentLine);
            fileWriteString = addressString+" : "+binaryInstruction+";  --"+srcCurrentLine;
            destFile.write(fileWriteString);






    if srcCurrentLine in ".STOP" :
        break;
print("END;")
destFile.write("END;");
print("Number of lines in source: ", srcLineCounter);
print("Number of lines in destination: ", destLineCounter);

srcFile.close();
destFile.close();