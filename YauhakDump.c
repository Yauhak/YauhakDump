#include "YauhakDump.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Memory for PE file
uint8_t *machineCode;
uint8_t *ptrOfMC;
// Memory for generated Re-ASM code(GNU ASM)
char ASMCode[250 * 1024];
char *ASMptr = ASMCode;
// Flags of prefixes
// isRet indicates whether a RET instruction was encountered
// segPrefix indicates which segment of memory would the instruction read from
uint8_t is64bit = 0, isExtReg = 0, isExtCmd = 0, isRet = 0, segPrefix;
// Size of raw text section data
uint32_t sizeOfRawData;
// Names of normal registers
const char *reg8[] = {"%AL", "%CL", "%DL", "%BL", "%AH", "%CH", "%DH", "%BH"};
const char *reg16[] = {"%AX", "%CX", "%DX", "%BX", "%SP", "%BP", "%SI", "%DI"};
const char *reg32[] = {"%EAX", "%ECX", "%EDX", "%EBX", "%ESP", "%EBP", "%ESI", "%EDI"};
const char *reg64[] = {
	"%RAX", "%RCX", "%RDX", "%RBX", "%RSP", "%RBP", "%RSI", "%RDI",
	"%R08", "%R09", "%R10", "%R11", "%R12", "%R13", "%R14", "%R15"
};
// (regName) means the computer see value in some register as some memory's address
const char *reg8_add[] = {"(%AL)", "(%CL)", "(%DL)", "(%BL)", "(%AH)", "(%CH)", "(%DH)", "(%BH)"};
const char *reg16_add[] = {"(%AX)", "(%CX)", "(%DX)", "(%BX)", "(%SP)", "(%BP)", "(%SI)", "(%DI)"};
const char *reg32_add[] = {"(%EAX)", "(%ECX)", "(%EDX)", "(%EBX)", "(%ESP)", "(%EBP)", "(%ESI)", "(%EDI)"};
const char *reg64_add[] = {
	"(%RAX)", "(%RCX)", "(%RDX)", "(%RBX)", "(%RSP)", "(%RBP)", "(%RSI)", "(%RDI)",
	"(%R08)", "(%R09)", "(%R10)", "(%R11)", "(%R12)", "(%R13)", "(%R14)", "(%R15)"
};
// Variables to simulate 64-bit registers
// We can use them to track program progress when meet code like "SUB 33,%RIP;CALL %RIP"
int64_t R64s[9];
// RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, RIP
// Array to store call's address in current sub function
CALL calls[32] = {0};
uint8_t callIndex;

//---------------------------------Support functions----------------------------------------

// Mapping PE file to memory "machineCode"
// And link pointer "ptrOfMC" to this memory
void mapFileToMem(const char *fileName) {
	FILE* fp = fopen(fileName, "r+b");
	if (!fp) {
		perror("fopen");
		return;
	}
	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	// printf("%ld\n", size);
	fseek(fp, 0, SEEK_SET);
	machineCode = (uint8_t *)malloc(size + 1);
	fread(machineCode, 1, size, fp);
	fclose(fp);
	ptrOfMC = machineCode;
}

// Skip to text section table
void skipToEntry() {
	if (machineCode[0] != 'M' || machineCode[1] != 'Z') {
		printf("Not a valid PE file: Missing MZ signature\n");
		return;
	}
	uint32_t e_lfanew = *(uint32_t*)(machineCode + 0x3C);
	if (memcmp(machineCode + e_lfanew, "PE\0\0", 4) != 0) {
		printf("Not a valid PE file: Missing PE signature\n");
		return;
	}
	ptrOfMC = machineCode + e_lfanew + 4;
	IMAGE_FILE_HEADER *fHead = (IMAGE_FILE_HEADER *)ptrOfMC;
	ptrOfMC += sizeof(IMAGE_FILE_HEADER);
	PART_OF_IMAGE_OPTIONAL_HEADER32 *opHeader = (PART_OF_IMAGE_OPTIONAL_HEADER32 *)ptrOfMC;
	uint32_t entry = opHeader->AddressOfEntryPoint;
	ptrOfMC += fHead->SizeOfOptionalHeader;
	// Now ptrOfMC is point to section head list
	IMAGE_SECTION_HEADER *sHead = (IMAGE_SECTION_HEADER *)ptrOfMC;
	int i;
	for (i = 0; i < fHead->NumberOfSections; i++) {
		// printf("%s", sHead[i].Name);
		if (memcmp(sHead[i].Name, ".text", 5) == 0) {
			// Find section .text
			uint32_t a = sHead[i].PointerToRawData;
			uint32_t r = sHead[i].VirtualAddress;
			// printf("Pointer to .text's RawData: %d\n", a);
			ptrOfMC = &machineCode[a + entry - r];
			sizeOfRawData = sHead[i].SizeOfRawData;
			// printf("Size of .text's RawData: %d\n", sizeOfRawData);
			// printf("Entry point of program: %d\n", a + entry - r);
			// printf("%x %x %x %x\n", *ptrOfMC, *(ptrOfMC + 1), *(ptrOfMC + 2), *(ptrOfMC + 3));
			return;
		}
	}
	printf(".text section not found\n");
}

// Check whether the byte is a prefix byte
// If so,set up relevant flags
uint8_t isPrefixByte(uint8_t byte) {
	int i = 0;
	uint8_t prefix = byte & 0xF0;
	for (; i <= 12; i++) {
		if (prefix == PrefixBytes[i] || byte == PrefixBytes[i]) {
			break;
		}
	}
	if (i <= 12) {
		if (prefix == REX_START) {
			// If it is an extended-code prefix byte
			if (byte == 0x0F) {
				//Set up the flag
				isExtCmd = 1;
			} else isExtCmd = 0;
			// If it is a REX prefix byte
			if (byte & 0x08) {
				is64bit = 1;
			} else is64bit = 0;
			if (byte & 0x01) {
				isExtReg = 1;
			} else isExtReg = 0;
		}
		if (byte == 0x65 || byte == 0x64 ||
		    byte == 0x3E || byte == 0x2E ||
		    byte == 0x36 || byte == 0x26) {
			segPrefix = byte;
		}
		return 1;
	}
	return 0;
}

// Emit generated ASM code to memory "ASMCode"
void writeASM(const char *string, int size) {
	for (int i = 0; i < size; i++) {
		*ASMptr++ = string[i];
	}
	*ASMptr = 0;
}

//---------------------------------Core functions----------------------------------------

// RET ;return immediately to last calling position
void ret() {
	writeASM("RET\n", 4);
}

// PUSH %RBP ;Push RBP's value to stack
void handle_push_register(uint8_t byte) {
	uint8_t reg_num = byte & 0x07;
	if (is64bit) {
		if (isExtReg) {
			reg_num += 8; // R8-R15
		}
		writeASM("PUSHQ ", 6);
		writeASM(reg64[reg_num], strlen(reg64[reg_num]));
	} else {
		writeASM("PUSHL ", 6);
		writeASM(reg32[reg_num], strlen(reg32[reg_num]));
	}
	writeASM("\n", 1);
	R64s[REG_RSP] -= is64bit ? 8 : 4;
}

// PUSH %RBP ;Pop stack's top element and save it to RBP
void popRBP() {
	writeASM("POPQ %RBP\n", 10);
}

void nop() {
	writeASM("NOP\n", 4);
}

// MOVSBL/MOVZBL/MOVSBQ/MOVZBQ r8,r32/r64 ;Extend an 8-bit number to 32-bit/64-bit number
void mov_szb_r_rm(uint8_t isSB) {
	if (is64bit) {
		//Q-extension:64-bit
		//L-extension:32-bit
		if (isSB)
			writeASM("MOVSBQ ", 7);
		else
			writeASM("MOVZBQ ", 7);
	} else {
		if (isSB)
			writeASM("MOVSBL ", 7);
		else
			writeASM("MOVZBL ", 7);
	}
	/*
		modRM byte
		|mod(2 bit)|reg(3 bit)|reg/mem(3 bit)|
	*/
	uint8_t mod = *ptrOfMC >> 6;
	uint8_t reg = (*ptrOfMC << 2) >> 5;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int offset;
	char offset0, offsetNumStr[16];
	/*
		mod 0:move %r to (%r2)
		mod 1:move %r to (%r2 + offset : -127 ~ 128)
		mod 2:move %r to (%r2 + offset : -2^31-1 ~ 2^31)
		mod 3:move %r to %r2
	*/
	if (mod == 0 || mod == 3) {
		if (mod == 3) {
			/*
				As one of GNU-ASM's dio-parameter instruction
				The first param is usually seemed as source
				And the second param always be the destination
				For example,"MOVL %EAX,(%RBP)" means move 32-bit number from EAX to RBP-pointed memory
			*/
			writeASM(reg8[reg], 3);
			writeASM(",", 1);
			writeASM(is64bit ? reg32[r_m] : reg64[r_m], 4);
			if (is64bit) {
				// 64-bit extension
				R64s[r_m] = (isSB && (R64s[reg] & 0x80)) ?
				            (R64s[reg] | 0xFFFFFFFFFFFFFF00) :
				            (R64s[reg] & 0xFF);
			} else {
				// 32-bit extension
				R64s[r_m] = (isSB && (R64s[reg] & 0x80)) ?
				            (R64s[reg] | 0xFFFFFF00) :
				            (R64s[reg] & 0xFF);
			}
		} else {
			writeASM(reg64_add[reg], 6);
			writeASM(",", 1);
			writeASM(is64bit ? reg32[r_m] : reg64[r_m], 4);
		}
	} else if (mod == 1 || mod == 2) {
		// Due to offset's bound
		// We chose "char" or "int" type to record it
		// And use sprintf to convert the number to string
		if (mod == 1) {
			offset0 = *(ptrOfMC++);
			sprintf(offsetNumStr, "%d", offset0);
		} else {
			offset = *(ptrOfMC++) | (*(ptrOfMC++) << 8) | (*(ptrOfMC++) << 16) | (*(ptrOfMC++) << 24);
			sprintf(offsetNumStr, "%d", offset);
		}
		writeASM(offsetNumStr, strlen(offsetNumStr));
		writeASM(reg64_add[reg], 4);
		writeASM(",", 1);
		writeASM(is64bit ? reg32[r_m] : reg64[r_m], 4);
	}
	isExtCmd = 0;
	is64bit = 0;
	writeASM("\n", 1);
}

// Macros for determining source and destination operands based on is_r_rm flag
// R1: Source operand when is_r_rm=1, destination operand when is_r_rm=0
// R2: Destination operand when is_r_rm=1, source operand when is_r_rm=0
#define R1 is_r_rm?reg:r_m
#define R2 is_r_rm?r_m:reg

// Conditional string output macros for memory offsets
// CS1: Outputs offset string when is_r_rm=0 (memory as source)
// CS2: Outputs offset string when is_r_rm=1 (memory as destination)
#define CS1 if(!is_r_rm)\
				writeASM(offsetNumStr,strlen(offsetNumStr));
#define CS2 if(is_r_rm)\
				writeASM(offsetNumStr,strlen(offsetNumStr));

// MOVL/MOVQ R/M,M/R ;Move a 32-bit/64-bit number from reg/mem to mem/reg
void mov(uint8_t is_r_rm) {
	if (is64bit) {
		writeASM("MOVQ ", 5);
	} else {
		writeASM("MOVL ", 5);
	}
	uint8_t mod = *ptrOfMC >> 6;
	uint8_t reg = (*ptrOfMC >> 3) & 0x07;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int offset;
	char offset0, offsetNumStr[16];
	// Handle finding address relatively with register RIP(With REX.W prefix)
	// RIP stores current instruction's address
	if (is64bit && mod == 0 && r_m == 5) {
		// RIP + disp32
		int32_t disp32 = *(int32_t*)ptrOfMC;
		ptrOfMC += 4;
		char ripStr[50];
		if (disp32 >= 0) {
			sprintf(ripStr, "%d(%%RIP)", disp32);
		} else {
			sprintf(ripStr, "%d(%%RIP)", -disp32);
		}
		if (is_r_rm) {
			// MOV (RIP + disp32),reg
			writeASM(ripStr, strlen(ripStr));
			writeASM(",", 1);
			writeASM(reg64[reg], 4);
			R64s[reg] = (int64_t)(ptrOfMC - 5 + disp32);
		} else {
			// MOV reg,(RIP + disp32)
			writeASM(reg64[reg], 4);
			writeASM(",", 1);
			writeASM(ripStr, strlen(ripStr));
		}
	} else if (mod == 0 || mod == 3) {
		if (is_r_rm) {
			if (r_m != 4) {
				writeASM(is64bit ? reg64[R1] : reg32[R1], 4);
				writeASM(",", 1);
				writeASM(mod == 0 ? reg64_add[R2] : is64bit ? reg64[R2] : reg32[R2], mod == 0 ? 6 : 4);
			}
			if (mod == 3) {
				if (is64bit) {
					R64s[r_m] = R64s[reg];
				} else {
					R64s[r_m] = R64s[reg] & 0xFFFFFFFF;
				}
			} else {
				// mod == 0 && r_m == 4 indicates the instruction would use SIB byte
				if (r_m == 4) {
					uint8_t sib = *ptrOfMC++;
					uint8_t scale = (sib >> 6) & 0x03;
					uint8_t index = (sib >> 3) & 0x07;
					uint8_t base = sib & 0x07;
					// Now we can only match the case that index == 4 && base == 5 : use immNum32
					if (index == 4 && base == 5) {
						int32_t disp32 = *(int32_t*)ptrOfMC;
						ptrOfMC += 4;
						char memStr[50];
						sprintf(memStr, "$%d", disp32);
						writeASM(reg64[reg], 4);
						writeASM(",", 1);
						writeASM(memStr, strlen(memStr));
					} else {
						writeASM("SIB addressing", 14);
					}
				} else {
					writeASM(reg64_add[r_m], 6);
				}
				R64s[reg] = -1;
			}
		} else {
			if (r_m != 4) {
				writeASM(mod == 0 ? reg64_add[R1] : is64bit ? reg64[R1] : reg32[R1], mod == 0 ? 6 : 4);
				writeASM(",", 1);
				writeASM(is64bit ? reg64[R2] : reg32[R2], 4);
			}
			if (mod == 3) {
				if (is64bit) {
					R64s[reg] = R64s[r_m];
				} else {
					R64s[reg] = R64s[r_m] & 0xFFFFFFFF;
				}
			} else {
				if (r_m == 4) {
					uint8_t sib = *ptrOfMC++;
					uint8_t scale = (sib >> 6) & 0x03;
					uint8_t index = (sib >> 3) & 0x07;
					uint8_t base = sib & 0x07;
					if (index == 4 && base == 5) {
						int32_t disp32 = *(int32_t*)ptrOfMC;
						ptrOfMC += 4;
						char memStr[50];
						sprintf(memStr, "$%d", disp32);
						writeASM(memStr, strlen(memStr));
						writeASM(",", 1);
						writeASM(reg64[reg], 4);
					} else {
						writeASM("SIB addressing", 14);
					}
				} else {
					writeASM(reg64_add[r_m], 6);
				}
			}
		}
	} else if (mod == 1 || mod == 2) {
		if (mod == 1)
			offset0 = *(ptrOfMC++);
		else {
			offset = *(int32_t*)ptrOfMC;
			ptrOfMC += 4;
		}
		sprintf(offsetNumStr, "%d", mod == 1 ? offset0 : offset);
		CS1
		if (is_r_rm)
			writeASM(is64bit ? reg64[R1] : reg32[R1], 4);
		else
			writeASM(reg64_add[R1], 6);
		writeASM(",", 1);
		CS2
		if (is_r_rm)
			writeASM(reg64_add[R2], 6);
		else
			writeASM(is64bit ? reg64[R2] : reg32[R2], 4);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

// MOV r/m32, imm32 ; Move 32-bit immediate to register or memory
void mov_rm_imm32() {
	if (is64bit) {
		writeASM("MOVQ $", 6);
	} else {
		writeASM("MOVL $", 6);
	}
	uint8_t mod = *ptrOfMC >> 6;
	uint8_t reg = (*ptrOfMC >> 3) & 0x07;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int32_t imm32 = *(int32_t*)ptrOfMC;
	ptrOfMC += 4;
	char immStr[16];
	sprintf(immStr, "%d", imm32);
	int offset;
	char offset0, offsetNumStr[16];
	//Find address relatively with register RIP
	if (is64bit && mod == 0 && r_m == 5) {
		int32_t disp32 = *(int32_t*)ptrOfMC;
		ptrOfMC += 4;
		char ripStr[50];
		if (disp32 >= 0) {
			sprintf(ripStr, "%d(%%RIP)", disp32);
		} else {
			sprintf(ripStr, "%d(%%RIP)", -disp32);
		}
		writeASM(immStr, strlen(immStr));
		writeASM(",", 1);
		writeASM(ripStr, strlen(ripStr));
	} else if (mod == 0 || mod == 3) {
		writeASM(immStr, strlen(immStr));
		writeASM(",", 1);
		if (mod == 0) {
			if (r_m == 4) {
				uint8_t sib = *ptrOfMC++;
				uint8_t scale = (sib >> 6) & 0x03;
				uint8_t index = (sib >> 3) & 0x07;
				uint8_t base = sib & 0x07;
				if (index == 4 && base == 5) {
					int32_t disp32 = *(int32_t*)ptrOfMC;
					ptrOfMC += 4;
					char memStr[50];
					sprintf(memStr, "$%d", disp32);
					writeASM(memStr, strlen(memStr));
					writeASM(",", 1);
					writeASM(reg64[reg], 4);
				} else {
					writeASM("SIB addressing", 14);
				}
			} else {
				writeASM(reg64_add[r_m], 6);
			}
		} else {
			writeASM(is64bit ? reg64[r_m] : reg32[r_m], 4);
			if (is64bit) {
				R64s[r_m] = (long)imm32;
			} else {
				R64s[r_m] = imm32;
			}
		}
	} else if (mod == 1 || mod == 2) {
		if (mod == 1) {
			offset0 = *(ptrOfMC++);
			sprintf(offsetNumStr, "%d", offset0);
		} else {
			offset = *(int32_t*)ptrOfMC;
			ptrOfMC++;
			sprintf(offsetNumStr, "%d", offset);
		}
		writeASM(immStr, strlen(immStr));
		writeASM(",", 1);
		writeASM(offsetNumStr, strlen(offsetNumStr));
		writeASM(reg64_add[r_m], 6);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

// XOR r/m, reg - XOR operation between register/memory and register
void xor_rm_reg(uint8_t is_r_rm) {
	if (is64bit) {
		writeASM("XORQ ", 5);
	} else {
		writeASM("XORL ", 5);
	}
	uint8_t mod = *ptrOfMC >> 6;
	uint8_t reg = (*ptrOfMC >> 3) & 0x07;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int offset;
	char offset0, offsetNumStr[16];
	if (mod == 0 || mod == 3) {
		if (is_r_rm) {
			// XOR reg, r/m
			writeASM(is64bit ? reg64[R1] : reg32[R1], 4);
			writeASM(",", 1);
			writeASM(mod == 0 ? reg64_add[R2] : is64bit ? reg64[R2] : reg32[R2], mod == 0 ? 6 : 4);
			if (mod == 3) {
				R64s[reg] ^= R64s[r_m];
				if (!is64bit) {
					R64s[reg] &= 0xFFFFFFFF;
				}
			}
		} else {
			// XOR r/m, reg
			writeASM(mod == 0 ? reg64_add[R1] : is64bit ? reg64[R1] : reg32[R1], mod == 0 ? 6 : 4);
			writeASM(",", 1);
			writeASM(is64bit ? reg64[R2] : reg32[R2], 4);
			if (mod == 3) {
				R64s[r_m] ^= R64s[reg];
				if (!is64bit) {
					R64s[r_m] &= 0xFFFFFFFF;
				}
			}
		}
	} else if (mod == 1 || mod == 2) {
		if (mod == 1) {
			offset0 = *(ptrOfMC++);
			sprintf(offsetNumStr, "%d", offset0);
		} else {
			offset = *(int32_t*)ptrOfMC;
			ptrOfMC += 4;
			sprintf(offsetNumStr, "%d", offset);
		}
		CS1
		if (is_r_rm)
			writeASM(is64bit ? reg64[R1] : reg32[R1], 4);
		else
			writeASM(reg64_add[R1], 6);
		writeASM(",", 1);
		CS2
		if (is_r_rm)
			writeASM(reg64_add[R2], 6);
		else
			writeASM(is64bit ? reg64[R2] : reg32[R2], 4);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

// ADDQ/ADDL/SUBQ/SUBL r/m, r or r, r/m ;Performs addition or subtraction between registers and/or memory
// isAdd: 1 for ADD, 0 for SUB
// is_r_rm: Determines the direction of operation (register to memory or memory to register)
void add_sub(uint8_t isAdd, uint8_t is_r_rm) {
	if (is64bit) {
		if (isAdd)
			writeASM("ADDQ ", 5);
		else
			writeASM("SUBQ ", 5);
	} else {
		if (isAdd)
			writeASM("ADDL ", 5);
		else
			writeASM("SUBL ", 5);
	}
	uint8_t mod = *ptrOfMC >> 6;
	uint8_t reg = (*ptrOfMC << 2) >> 5;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int offset;
	char offset0, offsetNumStr[16];
	if (mod == 0 || mod == 3) {
		if (is_r_rm) {
			writeASM(is64bit ? reg64[R1] : reg32[R1], 4);
			writeASM(",", 1);
			writeASM(mod == 0 ? reg64_add[R2] : is64bit ? reg64[R2] : reg32[R2], mod == 0 ? 6 : 4);
			if (mod == 3) {
				if (isAdd) {
					R64s[reg] += R64s[r_m];
				} else {
					R64s[reg] -= R64s[r_m];
				}
				if (!is64bit) {
					R64s[reg] &= 0xFFFFFFFF;
				}
			} else {
				R64s[reg] = -1;
			}
		} else {
			writeASM(mod == 0 ? reg64_add[R1] : is64bit ? reg64[R1] : reg32[R1], mod == 0 ? 6 : 4);
			writeASM(",", 1);
			writeASM(is64bit ? reg64[R2] : reg32[R2], 4);
			if (mod == 3) {
				if (isAdd) {
					R64s[r_m] += R64s[reg];
				} else {
					R64s[r_m] -= R64s[reg];
				}
				if (!is64bit) {
					R64s[r_m] &= 0xFFFFFFFF;
				}
			}
		}
	} else if (mod == 1 || mod == 2) {
		if (mod == 1)
			offset0 = *(ptrOfMC++);
		else {
			offset = *(int32_t*)ptrOfMC;
			ptrOfMC++;
		}
		sprintf(offsetNumStr, "%d", mod == 1 ? offset0 : offset);
		CS1
		if (is_r_rm)
			writeASM(is64bit ? reg64[R1] : reg32[R1], 4);
		else
			writeASM(reg64_add[R1], 6);
		writeASM(",", 1);
		CS2
		if (is_r_rm)
			writeASM(reg64_add[R2], 6);
		else
			writeASM(is64bit ? reg64[R2] : reg32[R2], 4);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

// ADDQ/ADDL/SUBQ/SUBL imm, r/m ;Performs addition or subtraction between immediate value and register/memory
// isAdd: 1 for ADD, 0 for SUB
// immSize: 1 for 8-bit immediate, 4 for 32-bit immediate
void alu_imm8_rm(uint8_t operation) {
	// 0x83 is the code of a series of calculate operations
	const char* opcode_str[] = {
		"ADD", "OR", "ADC", "SBB",
		"AND", "SUB", "XOR", "CMP"
	};
	if (is64bit) {
		writeASM(opcode_str[operation], strlen(opcode_str[operation]));
		writeASM("Q ", 2);
	} else {
		writeASM(opcode_str[operation], strlen(opcode_str[operation]));
		writeASM("L ", 2);
	}
	uint8_t mod = *ptrOfMC >> 6;
	uint8_t reg = (*ptrOfMC >> 3) & 0x07;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	// Get an 8-bit immNum
	int8_t imm8 = *(int8_t*)ptrOfMC;
	ptrOfMC++;
	char immStr[16];
	sprintf(immStr, "$%d", imm8);
	int offset;
	char offset0, offsetNumStr[16];
	// Handle finding address relatively with register RIP(With REX.W prefix)
	if (is64bit && mod == 0 && r_m == 5) {
		int32_t disp32 = *(int32_t*)ptrOfMC;
		ptrOfMC += 4;
		char ripStr[50];
		if (disp32 >= 0) {
			sprintf(ripStr, "%d(%%RIP)", disp32);
		} else {
			sprintf(ripStr, "%d(%%RIP)", -disp32);
		}
		writeASM(immStr, strlen(immStr));
		writeASM(", ", 2);
		writeASM(ripStr, strlen(ripStr));
	} else if (mod == 0 || mod == 3) {
		writeASM(immStr, strlen(immStr));
		writeASM(", ", 2);
		writeASM(mod == 0 ? reg64_add[r_m] : is64bit ? reg64[r_m] : reg32[r_m], mod == 0 ? 6 : 4);
		if (mod == 3) {
			// Update reg's value
			long old_value = R64s[r_m];
			long imm_value = (long)imm8;
			switch (operation) {
				case 0: // ADD
					R64s[r_m] = old_value + imm_value;
					break;
				case 1: // OR
					R64s[r_m] = old_value | imm_value;
					break;
				case 2: // ADC
					// We simplified it to ADD
					R64s[r_m] = old_value + imm_value;
					break;
				case 3: // SBB
					// We simplified it to SUB
					R64s[r_m] = old_value - imm_value;
					break;
				case 4: // AND
					R64s[r_m] = old_value & imm_value;
					break;
				case 5: // SUB
					R64s[r_m] = old_value - imm_value;
					break;
				case 6: // XOR
					R64s[r_m] = old_value ^ imm_value;
					break;
				case 7: // CMP
					// Keep original value
					break;
			}
			if (!is64bit && mod == 3) {
				R64s[r_m] &= 0xFFFFFFFF;
			}
		}
	} else if (mod == 1 || mod == 2) {
		if (mod == 1) {
			offset0 = *(ptrOfMC++);
			sprintf(offsetNumStr, "%d", offset0);
		} else {
			offset = *(ptrOfMC++) | (*(ptrOfMC++) << 8) | (*(ptrOfMC++) << 16) | (*(ptrOfMC++) << 24);
			sprintf(offsetNumStr, "%d", offset);
		}
		writeASM(immStr, strlen(immStr));
		writeASM(", ", 2);
		writeASM(offsetNumStr, strlen(offsetNumStr));
		writeASM(reg64_add[r_m], 6);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

// Just like last function
// It's used in 32-bit case
void alu_imm32_rm(uint8_t operation) {
	const char* opcode_str[] = {
		"ADD", "OR", "ADC", "SBB",
		"AND", "SUB", "XOR", "CMP"
	};
	if (is64bit) {
		writeASM(opcode_str[operation], strlen(opcode_str[operation]));
		writeASM("Q ", 2);
	} else {
		writeASM(opcode_str[operation], strlen(opcode_str[operation]));
		writeASM("L ", 2);
	}
	uint8_t mod = *ptrOfMC >> 6;
	uint8_t reg = (*ptrOfMC >> 3) & 0x07;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int32_t imm32 = *(int32_t*)ptrOfMC;
	ptrOfMC += 4;
	char immStr[16];
	sprintf(immStr, "$%d", imm32);
	int offset;
	char offset0, offsetNumStr[16];
	// Handle finding address relatively with register RIP(With REX.W prefix)
	if (is64bit && mod == 0 && r_m == 5) {
		int32_t disp32 = *(int32_t*)ptrOfMC;
		ptrOfMC += 4;
		char ripStr[50];
		if (disp32 >= 0) {
			sprintf(ripStr, "%d(%%RIP)", disp32);
		} else {
			sprintf(ripStr, "-%d(%%RIP)", -disp32);
		}
		writeASM(immStr, strlen(immStr));
		writeASM(", ", 2);
		writeASM(ripStr, strlen(ripStr));
	} else if (mod == 0 || mod == 3) {
		writeASM(immStr, strlen(immStr));
		writeASM(", ", 2);
		writeASM(mod == 0 ? reg64_add[r_m] : is64bit ? reg64[r_m] : reg32[r_m], mod == 0 ? 6 : 4);
		if (mod == 3) {
			long old_value = R64s[r_m];
			long imm_value;
			if (is64bit) {
				imm_value = (long)imm32;
			} else {
				imm_value = imm32;
			}
			switch (operation) {
				case 0: // ADD
					R64s[r_m] = old_value + imm_value;
					break;
				case 1: // OR
					R64s[r_m] = old_value | imm_value;
					break;
				case 2: // ADC
					R64s[r_m] = old_value + imm_value;
					break;
				case 3: // SBB
					R64s[r_m] = old_value - imm_value;
					break;
				case 4: // AND
					R64s[r_m] = old_value & imm_value;
					break;
				case 5: // SUB
					R64s[r_m] = old_value - imm_value;
					break;
				case 6: // XOR
					R64s[r_m] = old_value ^ imm_value;
					break;
				case 7: // CMP
					break;
			}
			if (!is64bit && mod == 3) {
				R64s[r_m] &= 0xFFFFFFFF;
			}
		}
	} else if (mod == 1 || mod == 2) {
		if (mod == 1) {
			offset0 = *(ptrOfMC++);
			sprintf(offsetNumStr, "%d", offset0);
		} else {
			offset = *(ptrOfMC++) | (*(ptrOfMC++) << 8) | (*(ptrOfMC++) << 16) | (*(ptrOfMC++) << 24);
			sprintf(offsetNumStr, "%d", offset);
		}
		writeASM(immStr, strlen(immStr));
		writeASM(", ", 2);
		writeASM(offsetNumStr, strlen(offsetNumStr));
		writeASM(reg64_add[r_m], 6);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

// LEA r32/r64,m ;Load Effective Address
void lea() {
	if (is64bit) {
		writeASM("LEAQ ", 5);
	} else {
		writeASM("LEAL ", 5);
	}
	uint8_t mod = *ptrOfMC >> 6;
	uint8_t reg = (*ptrOfMC << 2) >> 5;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int offset;
	char offset0, offsetNumStr[16];
	if (mod == 0 || mod == 3) {
		if (mod == 0) {
			writeASM(reg64_add[r_m], 6);
		} else {
			writeASM(is64bit ? reg64[r_m] : reg32[r_m], 4);
		}
		writeASM(",", 1);
		writeASM(is64bit ? reg64[reg] : reg32[reg], 4);
		if (mod == 3)R64s[reg] = R64s[r_m];
	} else if (mod == 1 || mod == 2) {
		if (mod == 1) {
			offset0 = *(ptrOfMC++);
			sprintf(offsetNumStr, "%d", offset0);
		} else {
			offset = *(ptrOfMC++) | (*(ptrOfMC++) << 8) | (*(ptrOfMC++) << 16) | (*(ptrOfMC++) << 24);
			sprintf(offsetNumStr, "%d", offset);
		}
		writeASM(offsetNumStr, strlen(offsetNumStr));
		writeASM(reg64_add[r_m], 6);
		writeASM(",", 1);
		writeASM(is64bit ? reg64[reg] : reg32[reg], 4);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

// JMP rel32 ;Jump to relative address
void jmp_rel32() {
	writeASM("JMP ", 4);
	int32_t rel_offset = *(ptrOfMC++) | (*(ptrOfMC++) << 8) |
	                     (*(ptrOfMC++) << 16) | (*(ptrOfMC++) << 24);
	char offsetStr[16];
	if (rel_offset >= 0) {
		sprintf(offsetStr, ".+%d", rel_offset + 5);
	} else {
		sprintf(offsetStr, ".%d", rel_offset + 5);
	}
	writeASM(offsetStr, strlen(offsetStr));
	writeASM("\n", 1);
}

// JMP r/m32/r/m64 ;Jump to address in register or memory
void jmp_rm() {
	writeASM("JMP *", 5);
	uint8_t mod = *ptrOfMC >> 6;
	// uint8_t reg = (*ptrOfMC << 2) >> 5;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int offset;
	char offset0, offsetNumStr[16];
	if (mod == 0 || mod == 3) {
		if (mod == 3) {
			writeASM(is64bit ? reg64[r_m] : reg32[r_m], 4);
		} else {
			writeASM(reg64_add[r_m], 6);
		}
	} else if (mod == 1 || mod == 2) {
		if (mod == 1) {
			offset0 = *(ptrOfMC++);
			sprintf(offsetNumStr, "%d", offset0);
		} else {
			offset = *(ptrOfMC++) | (*(ptrOfMC++) << 8) | (*(ptrOfMC++) << 16) | (*(ptrOfMC++) << 24);
			sprintf(offsetNumStr, "%d", offset);
		}
		writeASM(offsetNumStr, strlen(offsetNumStr));
		writeASM(reg64_add[r_m], 6);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

// CALL rel32 ;Call function at relative address
void call_rel32() {
	calls[callIndex].addrOfCall = (uint64_t)(ptrOfMC - 1 - machineCode);
	calls[callIndex].isReg = 0;
	writeASM("CALL ", 5);
	int32_t rel_offset = *(ptrOfMC++) | (*(ptrOfMC++) << 8) |
	                     (*(ptrOfMC++) << 16) | (*(ptrOfMC++) << 24);
	calls[callIndex].val = rel_offset + 5;
	callIndex++;
	char offsetStr[16];
	if (rel_offset >= 0) {
		sprintf(offsetStr, ".+%d", rel_offset + 5);
	} else {
		sprintf(offsetStr, ".%d", rel_offset + 5);
	}
	writeASM(offsetStr, strlen(offsetStr));
	writeASM("\n", 1);
}

// CALL r/m32/r/m64 ;Call function at address in register or memory
void call_rm() {
	writeASM("CALL *", 6);
	uint8_t mod = *ptrOfMC >> 6;
	// uint8_t reg = (*ptrOfMC << 2) >> 5;
	uint8_t r_m = *ptrOfMC & 0x07;
	ptrOfMC++;
	int offset;
	char offset0, offsetNumStr[16];
	if (mod == 0 || mod == 3) {
		if (mod == 3) {
			calls[callIndex].addrOfCall = (uint64_t)(ptrOfMC - 1 - machineCode);
			calls[callIndex].isReg = 1;
			calls[callIndex].val = R64s[r_m];
			callIndex++;
			writeASM(is64bit ? reg64[r_m] : reg32[r_m], 4);
		} else {
			writeASM(reg64_add[r_m], 6);
		}
	} else if (mod == 1 || mod == 2) {
		if (mod == 1) {
			offset0 = *(ptrOfMC++);
			sprintf(offsetNumStr, "%d", offset0);
		} else {
			offset = *(ptrOfMC++) | (*(ptrOfMC++) << 8) | (*(ptrOfMC++) << 16) | (*(ptrOfMC++) << 24);
			sprintf(offsetNumStr, "%d", offset);
		}
		writeASM(offsetNumStr, strlen(offsetNumStr));
		writeASM(reg64_add[r_m], 6);
	}
	is64bit = 0;
	writeASM("\n", 1);
}

void ReSub() {
	uint8_t byte;
	while (!isRet) {
		byte = *ptrOfMC;
		ptrOfMC++;
		if (!isPrefixByte(byte)) {
			switch (byte) {
				case RET:
					ret();
					isRet = 1;
					break;
				case 0x50:
				case 0x51:
				case 0x52:
				case 0x53:
				case 0x54:
				case 0x55:
				case 0x56:
				case 0x57:
					// PUSH instruction
					handle_push_register(byte);
					break;
				case POP_RBP:
					popRBP();
					break;
				case NOP:
					nop();
					break;
				case MOV_SB:
				case MOV_ZB: {
					if (isExtCmd) {
						mov_szb_r_rm(byte == MOV_SB ? 1 : 0);
					}
					break;
				}
				case MOV_MEM_REG:
					mov(0);  // MOV r/m, reg
					break;
				case MOV_REG_MEM:
					mov(1);  // MOV reg, r/m
					break;
				case MOV_RM_IMM32:
					mov_rm_imm32();
					break;
				case XOR_RM_REG:
					xor_rm_reg(0);  // XOR r/m, reg
					break;
				case ADD_REG_REG32:
					add_sub(1, 1);  // ADD reg, r/m
					break;
				case ADD_RM_REG32:
					add_sub(1, 0);  // ADD r/m, reg
					break;
				case SUB_RM_REG32:
					add_sub(0, 0);  // SUB r/m, reg
					break;
				case SUB_REG_RM32:
					add_sub(0, 1);  // SUB reg, r/m
					break;
				case OP_IMM32_REG: {
					uint8_t nextByte = *ptrOfMC;
					uint8_t regField = (nextByte >> 3) & 0x07;
					switch (regField) {
						case 0: // ADD
							alu_imm32_rm(0);
							break;
						case 1: // OR
							alu_imm32_rm(1);
							break;
						case 2: // ADC
							alu_imm32_rm(2);
							break;
						case 3: // SBB
							alu_imm32_rm(3);
							break;
						case 4: // AND
							alu_imm32_rm(4);
							break;
						case 5: // SUB
							alu_imm32_rm(5);
							break;
						case 6: // XOR
							alu_imm32_rm(6);
							break;
						case 7: // CMP
							alu_imm32_rm(7);
							break;
						default:
							ptrOfMC += 6;
							writeASM("// Unknown 0x81 variant\n", 24);
							break;
					}
					break;
				}
				case OP_IMM8_REG: {
					uint8_t nextByte = *ptrOfMC;
					uint8_t regField = (nextByte >> 3) & 0x07;
					switch (regField) {
						case 0: // ADD
							alu_imm8_rm(0);
							break;
						case 1: // OR
							alu_imm8_rm(1);
							break;
						case 2: // ADC
							alu_imm8_rm(2);
							break;
						case 3: // SBB
							alu_imm8_rm(3);
							break;
						case 4: // AND
							alu_imm8_rm(4);
							break;
						case 5: // SUB
							alu_imm8_rm(5);
							break;
						case 6: // XOR
							alu_imm8_rm(6);
							break;
						case 7: // CMP
							alu_imm8_rm(7);
							break;
						default:
							// printf("Unknown 0x83 variant, regField=%d\n", regField);
							ptrOfMC += 3; // Skip this whole 0x83 instruction
							writeASM("// Unknown 0x83 variant\n", 24);
							break;
					}
					break;
				}
				case LEA_REG_MEM:
					lea();
					break;
				case JMP_REL:
					jmp_rel32();
					break;
				case JMP_CALL_RM: {
					uint8_t nextByte = *ptrOfMC;
					uint8_t regField = (nextByte >> 3) & 0x07;
					if (regField == 4) { // JMP
						jmp_rm();
					} else if (regField == 2) { // CALL
						call_rm();
					}
					break;
				}
				case CALL_REL:
					call_rel32();
					break;
				default:
					// Unknown opcode
					char unknown[50];
					sprintf(unknown, "# Unknown opcode: %x\n", byte);
					writeASM(unknown, strlen(unknown));
			}
			isExtCmd = 0;
		} else if (segPrefix) {
			switch (segPrefix) {
				case 0x65:
					writeASM("GS: ", 4);
					break;
				case 0x64:
					writeASM("FS: ", 4);
					break;
				case 0x3E:
					writeASM("DS: ", 4);
					break;
				case 0x2E:
					writeASM("CS: ", 4);
					break;
				case 0x36:
					writeASM("SS: ", 4);
					break;
				case 0x26:
					writeASM("ES: ", 4);
					break;
			}
			segPrefix = 0;  // 重置
		}
	}
}

int main(int argv, char *argc[]) {
	// printf("ISH:%d\n", sizeof(IMAGE_SECTION_HEADER));
	if (argv == 1) {
		printf("No file param input\n");
		system("pause");
		exit(0);
	}
	mapFileToMem(argc[1]);
	skipToEntry();
	printf("Generated ASM Code @0x%d\n---------------------------\n", ptrOfMC - machineCode);
	ReSub();
	printf("%s\n", ASMCode);
	memset(ASMCode, 0, 250 * 1024);
	ASMptr = ASMCode;
	ptrOfMC = &machineCode[calls[0].addrOfCall + calls[0].val];
	printf("Generated ASM Code @0x%d\n---------------------------\n", calls[0].addrOfCall + calls[0].val);
	//printf("%x%x%x%x\n", *ptrOfMC, ptrOfMC[1], ptrOfMC[2], ptrOfMC[3]);
	isRet = 0;
	ReSub();
	printf("%s\n", ASMCode);
	free(machineCode);
	return 0;
}
