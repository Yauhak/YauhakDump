#include <stdint.h>

typedef struct _PART_OF_IMAGE_OPTIONAL_HEADER32 {
	uint16_t Magic;
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	// ... We don't need other sections currently
} PART_OF_IMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_SECTION_HEADER {
	uint8_t  Name[8];              // Section name like ".text"
	uint32_t VirtualSize;          // Section's real size in memory
	uint32_t VirtualAddress;       // Section's RVA
	uint32_t SizeOfRawData;        // Section's size in PE file
	uint32_t PointerToRawData;     // Section's offset in PE file
	uint32_t PointerToRelocations; // Section's relocation message
	uint32_t PointerToLinenumbers; // Section's line numbers
	uint16_t NumberOfRelocations; 
	uint16_t NumberOfLinenumbers; 
	uint32_t Characteristics;      // Readable,writable,executable
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	uint16_t  Machine;             
	uint16_t  NumberOfSections;     
	uint32_t TimeDateStamp;      
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols; 
	uint16_t  SizeOfOptionalHeader; // We'll use it to locate the program's entry
	uint16_t  Characteristics; 
} IMAGE_FILE_HEADER;

// Stack to store CALL commands' message
typedef struct _CALL {
	uint8_t isReg; // Relative address is stored in some register?(0 = immNum)
	uint64_t addrOfCall; //Absolute address of CALL commands
	long val;// register code or immNUm
} CALL;

// Normal registers' code
typedef enum {
	REG_AL  = 0,    // 000 - Accumulator Low
	REG_CL  = 1,    // 001 - Counter Low
	REG_DL  = 2,    // 010 - Data Low
	REG_BL  = 3,    // 011 - Base Low
	REG_AH  = 4,    // 100 - Accumulator High
	REG_CH  = 5,    // 101 - Counter High
	REG_DH  = 6,    // 110 - Data High
	REG_BH  = 7     // 111 - Base High
} REG8_CODE;

typedef enum {
	REG_AX  = 0,    // 000 - Accumulator
	REG_CX  = 1,    // 001 - Counter
	REG_DX  = 2,    // 010 - Data
	REG_BX  = 3,    // 011 - Base
	REG_SP  = 4,    // 100 - Stack Pointer
	REG_BP  = 5,    // 101 - Base Pointer
	REG_SI  = 6,    // 110 - Source Index
	REG_DI  = 7     // 111 - Destination Index
} REG16_CODE;

typedef enum {
	REG_EAX = 0,    // 000 - Extended Accumulator
	REG_ECX = 1,    // 001 - Extended Counter
	REG_EDX = 2,    // 010 - Extended Data
	REG_EBX = 3,    // 011 - Extended Base
	REG_ESP = 4,    // 100 - Extended Stack Pointer
	REG_EBP = 5,    // 101 - Extended Base Pointer
	REG_ESI = 6,    // 110 - Extended Source Index
	REG_EDI = 7     // 111 - Extended Destination Index
} REG32_CODE;

typedef enum {
	REG_RAX = 0,    // 000 - 64-bit Accumulator
	REG_RCX = 1,    // 001 - 64-bit Counter
	REG_RDX = 2,    // 010 - 64-bit Data
	REG_RBX = 3,    // 011 - 64-bit Base
	REG_RSP = 4,    // 100 - 64-bit Stack Pointer
	REG_RBP = 5,    // 101 - 64-bit Base Pointer
	REG_RSI = 6,    // 110 - 64-bit Source Index
	REG_RDI = 7     // 111 - 64-bit Destination Index
} REG64_CODE;

/*
enum ModField {
	MOD_INDIRECT = 0,      // [register] - Register indirect addressing
	MOD_INDIRECT_DISP8 = 1, // [register + disp8] - Indirect addressing with 8-bit displacement
	MOD_INDIRECT_DISP32 = 2, // [register + disp32] - Indirect addressing with 32-bit displacement
	MOD_REGISTER = 3        // register - Register direct addressing
};
*/

// All known prefix bytes
enum PrefixBytes {
	PREFIX_ES = 0x26,
	PREFIX_CS = 0x2E,
	PREFIX_SS = 0x36,
	PREFIX_DS = 0x3E,
	PREFIX_FS = 0x64,
	PREFIX_GS = 0x65,
	PREFIX_OPSIZE = 0x66,
	PREFIX_ADDRSIZE = 0x67,
	REX_START = 0x40,
	REX_END = 0x4F,
	PREFIX_LOCK = 0xF0,
	PREFIX_REPNE = 0xF2,
	PREFIX_REP = 0xF3
};

uint8_t PrefixBytes[] = {
	PREFIX_ES,
	PREFIX_CS,
	PREFIX_SS,
	PREFIX_DS,
	PREFIX_FS,
	PREFIX_GS,
	PREFIX_OPSIZE,
	PREFIX_ADDRSIZE,
	REX_START,
	REX_END,
	PREFIX_LOCK,
	PREFIX_REPNE,
	PREFIX_REP
};

// Common instruction opcodes
typedef enum {
	RET     = 0xC3,
	NOP     = 0x90,
	PUSH_RBP = 0x55,
	POP_RBP  = 0x5D,
	MOV_REG_MEM = 0x89,
	MOV_MEM_REG = 0x8B,
	MOV_SB = 0xB1,
	MOV_ZB = 0xB6,
	MOV_RM_IMM32 = 0xC7,     // MOV r/m32, imm32
	// Arithmetic instructions
	ADD_REG_REG32 = 0x01,
	ADD_RM_REG32 = 0x03,      // ADD reg32, r/m32
	OP_IMM32_REG = 0x81,     // ADD r/m32, imm32 (requires modrm reg field=0)
	SUB_REG_RM32 = 0x2B,      // SUB reg32, r/m32
	OP_IMM8_REG = 0x83,     // SUB r/m32, imm8 (requires modrm reg field=5)
	SUB_RM_REG32 = 0x29,      // SUB r/m32, reg32
	XOR_RM_REG = 0x31,      // XOR r/m32, r32
	PUSH_IMM  = 0x68,
	PUSH_REG  = 0x50,
	CALL_REL  = 0xE8,
	JMP_REL   = 0xE9,
	JCC_REL   = 0x70,
	REX_PREFIX = 0x40,
	// Other common instructions
	LEA_REG_MEM = 0x8D,       // LEA reg, m
	CMP_REG_REG = 0x39,       // CMP r/m32, reg32
	TEST_REG_REG = 0x85,      // TEST r/m32, reg32
	// JMP r/m32 (requires modrm reg field=4)
	JMP_CALL_RM = 0xFF            // CALL r/m32 (requires modrm reg field=2)
} Opcode;

#define DOS_HEAD 64
#define DOS_SIGN "PE\0\0"
#define COFF 20
