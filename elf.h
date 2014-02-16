#ifndef _ELF_H_
#define _ELF_H_

typedef enum
{
	NOT_ELF_FILE = -10,
	NOT_ARM_ELF = -11,
	NON_EXECUTABLE_ELF = -12,
	ELF_SECTION_NOT_FOUND = -13,
	NOT_FIND_BSS_SIZE = -14,
	NOT_FIND_CODE_SECTIONS = -15,
	ELF_SEGMENT_SECTION_SIZE_MISMATCH = -16,
	ELF_SEGMENTS_NOT_CONTINUOUS = -17,
	ELF_SEGMENTS_NOT_FOUND = -18,
} elf_errors;

typedef struct
{
	char *Name;
	u64 Type;
	u64 Flags;
	u8 *Ptr;
	u64 OffsetInFile;
	u64 Size;
	u64 Address;
	u64 Alignment;
} ElfSectionEntry;

typedef struct
{
	u64 Type;
	u64 Flags;
	u8 *Ptr;
	u64 OffsetInFile;
	u64 SizeInFile;
	u64 VirtualAddress;
	u64 PhysicalAddress;
	u64 SizeInMemory;
	u64 Alignment;
	
} ElfProgramEntry;

typedef struct
{
	char *Name;
	u64 VAddr;

	ElfProgramEntry *Header;
	u32 SectionNum;
	ElfSectionEntry *Sections;
} ElfSegment;

typedef struct
{
	u32 Address;
	u32 Size;
	u32 MaxPageNum;
	u8 *Data;
} CodeSegment;

typedef struct
{
	u32 PageSize;
	bool IsLittleEndian;
	bool Is64bit;
		
	u64 ProgramTableOffset;
	u16 ProgramTableEntrySize;
	u16 ProgramTableEntryCount;
	
	u64 SectionTableOffset;
	u16 SectionTableEntrySize;
	u16 SectionTableEntryCount;
	
	u16 SectionHeaderNameEntryIndex;

	ElfSectionEntry *Sections;
	ElfProgramEntry *ProgramHeaders;

	u16 ActiveSegments;
	ElfSegment *Segments;

} ElfContext;

#endif

int BuildExeFsCode(ncch_settings *ncchset);