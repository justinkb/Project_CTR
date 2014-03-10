#include "lib.h"
#include "ncch.h"
#include "elf_hdr.h"
#include "elf.h"
#include "blz.h"

int ImportPlainRegionFromFile(ncch_settings *ncchset);
int ImportExeFsCodeBinaryFromFile(ncch_settings *ncchset);

u32 GetPageSize(ncch_settings *ncchset);
u32 SizeToPage(u32 memorySize, ElfContext *elf);

int GetBSS_SizeFromElf(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset);
int ImportPlainRegionFromElf(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset);
int CreateExeFsCode(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset);
int CreateCodeSegmentFromElf(CodeSegment *out, ElfContext *elf, u8 *ElfFile, char **Names, u32 NameNum);
ElfSegment** GetContinuousSegments(u16 *ContinuousSegmentNum, ElfContext *elf, char **Names, u32 NameNum);
ElfSegment** GetSegments(u16 *SegmentNum, ElfContext *elf, char **Names, u32 NameNum);

// ELF Functions
int GetElfContext(ElfContext *elf, u8 *ElfFile);
int GetElfSectionEntries(ElfContext *elf, u8 *ElfFile);
int GetElfProgramEntries(ElfContext *elf, u8 *ElfFile);
void PrintElfContext(ElfContext *elf, u8 *ElfFile);
int ReadElfHdr(ElfContext *elf, u8 *ElfFile);

int CreateElfSegments(ElfContext *elf, u8 *ElfFile);
bool IsIgnoreSection(ElfSectionEntry info);

/* ELF Section Entry Functions */
u8* GetELFSectionHeader(u16 Index, ElfContext *elf, u8 *ElfFile);
u8* GetELFSectionEntry(u16 Index, ElfContext *elf, u8 *ElfFile);
char* GetELFSectionEntryName(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryType(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryFlags(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryAddress(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryFileOffset(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntrySize(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryAlignment(u16 Index, ElfContext *elf, u8 *ElfFile);

u16 GetElfSectionIndexFromName(char *Name, ElfContext *elf, u8 *ElfFile);

bool IsBss(ElfSectionEntry *Section);
bool IsData(ElfSectionEntry *Section);
bool IsRO(ElfSectionEntry *Section);
bool IsText(ElfSectionEntry *Section);

/* ELF Program Entry Functions */
u8* GetELFProgramHeader(u16 Index, ElfContext *elf, u8 *ElfFile);
u8* GetELFProgramEntry(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryType(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryFlags(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryFileSize(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryFileOffset(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryMemorySize(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryVAddress(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryPAddress(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryAlignment(u16 Index, ElfContext *elf, u8 *ElfFile);


int BuildExeFsCode(ncch_settings *ncchset)
{
	int result = 0;
	if(ncchset->ComponentFilePtrs.plainregion){ // Import PlainRegion from file
		result = ImportPlainRegionFromFile(ncchset);
		if(result) return result;
	}
	if(!ncchset->Options.IsBuildingCodeSection){ // Import ExeFs Code from file and return
		result = ImportExeFsCodeBinaryFromFile(ncchset);
		return result;
	}

#ifdef DEBUG
	printf("[DEBUG] Import ELF\n");
#endif
	/* Import ELF */
	u8 *ElfFile = malloc(ncchset->ComponentFilePtrs.elf_size);
	if(!ElfFile) {fprintf(stderr,"[ELF ERROR] MEM ERROR\n"); return MEM_ERROR;}
	ReadFile_64(ElfFile,ncchset->ComponentFilePtrs.elf_size,0,ncchset->ComponentFilePtrs.elf);

#ifdef DEBUG
	printf("[DEBUG] Create ELF Context\n");
#endif
	/* Create ELF Context */
	ElfContext *elf = malloc(sizeof(ElfContext));
	if(!elf) {fprintf(stderr,"[ELF ERROR] MEM ERROR\n"); free(ElfFile); return MEM_ERROR;}
	memset(elf,0,sizeof(ElfContext));
	
	result = GetElfContext(elf,ElfFile);
	if(result) goto finish;

	/* Setting Page Size */
	elf->PageSize = GetPageSize(ncchset);

	if(!ncchset->ComponentFilePtrs.plainregion){
		result = ImportPlainRegionFromElf(elf,ElfFile,ncchset);
		if(result) goto finish;
	}

#ifdef ELF_DEBUG
	PrintElfContext(elf,ElfFile);
#endif

#ifdef DEBUG
	PrintElfContext(elf,ElfFile);
#endif

#ifdef DEBUG
	printf("[DEBUG] Create ExeFs Code\n");
#endif
	result = CreateExeFsCode(elf,ElfFile,ncchset);
	if(result) goto finish;
#ifdef DEBUG
	printf("[DEBUG] Get BSS Size\n");
#endif
	result = GetBSS_SizeFromElf(elf,ElfFile,ncchset);
	if(result) goto finish;

finish:
	if(result){
		if(result == NOT_ELF_FILE) fprintf(stderr,"[ELF ERROR] Not ELF File\n");
		else if(result == NOT_ARM_ELF) fprintf(stderr,"[ELF ERROR] Not ARM ELF\n");
		else if(result == NON_EXECUTABLE_ELF) fprintf(stderr,"[ELF ERROR] Not Executeable ELF\n");
		else if(result == NOT_FIND_BSS_SIZE) fprintf(stderr,"[ELF ERROR] BSS Size Could not be found\n");
		else if(result == NOT_FIND_CODE_SECTIONS) fprintf(stderr,"[ELF ERROR] Failed to retrieve code sections from ELF\n");
		else fprintf(stderr,"[ELF ERROR] Failed to process ELF file (%d)\n",result);
	}
#ifdef DEBUG
	printf("[DEBUG] Free Segment Header/Sections\n");
#endif
	for(int i = 0; i < elf->ActiveSegments; i++){
#ifdef DEBUG
	printf("[DEBUG] %d\n",i);
#endif
		free(elf->Segments[i].Sections);
	}
#ifdef DEBUG
	printf("[DEBUG] Free others\n");
#endif
	free(ElfFile);
	free(elf->Sections);
	free(elf->ProgramHeaders);
	free(elf->Segments);
	free(elf);
	return result;	
}

int ImportPlainRegionFromFile(ncch_settings *ncchset)
{
	ncchset->Sections.PlainRegion.size = align_value(ncchset->ComponentFilePtrs.plainregion_size,ncchset->Options.MediaSize);
	ncchset->Sections.PlainRegion.buffer = malloc(ncchset->Sections.PlainRegion.size);
	if(!ncchset->Sections.PlainRegion.buffer) {fprintf(stderr,"[ELF ERROR] MEM ERROR\n"); return MEM_ERROR;}
	ReadFile_64(ncchset->Sections.PlainRegion.buffer,ncchset->ComponentFilePtrs.plainregion_size,0,ncchset->ComponentFilePtrs.plainregion);
	return 0;
}

int ImportExeFsCodeBinaryFromFile(ncch_settings *ncchset)
{
	u32 size = ncchset->ComponentFilePtrs.code_size;
	u8 *buffer = malloc(size);
	if(!buffer) {fprintf(stderr,"[ELF ERROR] MEM ERROR\n"); return MEM_ERROR;}
	ReadFile_64(buffer,size,0,ncchset->ComponentFilePtrs.code);

	ncchset->ExeFs_Sections.Code.size = ncchset->ComponentFilePtrs.code_size;
	ncchset->ExeFs_Sections.Code.buffer = malloc(ncchset->ExeFs_Sections.Code.size);
	if(!ncchset->ExeFs_Sections.Code.buffer) {fprintf(stderr,"[ELF ERROR] MEM ERROR\n"); return MEM_ERROR;}
	ReadFile_64(ncchset->ExeFs_Sections.Code.buffer,ncchset->ExeFs_Sections.Code.size,0,ncchset->ComponentFilePtrs.code);
	if(ncchset->Options.CompressCode){
		u32 new_len;
		ncchset->ExeFs_Sections.Code.buffer = BLZ_Code(buffer,size,&new_len,BLZ_NORMAL);
		ncchset->ExeFs_Sections.Code.size = new_len;
		free(buffer);
	}
	else{
		ncchset->ExeFs_Sections.Code.size = size;
		ncchset->ExeFs_Sections.Code.buffer = buffer;
	}
	return 0;
}

u32 GetPageSize(ncch_settings *ncchset)
{
	if(ncchset->yaml_set->Option.PageSize)
		return strtoul(ncchset->yaml_set->Option.PageSize,NULL,10);
	return 0x1000;
}

u32 SizeToPage(u32 memorySize, ElfContext *elf)
{
	return align_value(memorySize,elf->PageSize)/elf->PageSize;
}


int GetBSS_SizeFromElf(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset)
{
	for(int i = 0; i < elf->SectionTableEntryCount; i++){
		if(IsBss(&elf->Sections[i])) {
			ncchset->CodeDetails.BSS_Size = elf->Sections[i].Size;
			return 0;
		}
	}
	return NOT_FIND_BSS_SIZE;
}

int ImportPlainRegionFromElf(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset) // Doesn't work same as N makerom
{
	if(!ncchset->yaml_set->PlainRegionNum) return 0;
	u16 *Index = malloc(sizeof(u16)*ncchset->yaml_set->PlainRegionNum);

	/* Getting Index Values for each section */
	for(int i = 0; i < ncchset->yaml_set->PlainRegionNum; i++){
		Index[i] = GetElfSectionIndexFromName(ncchset->yaml_set->PlainRegion[i],elf,ElfFile);
	}

	// Eliminating Duplicated Sections
	for(int i = ncchset->yaml_set->PlainRegionNum - 1; i >= 0; i--){
		for(int j = i-1; j >= 0; j--){
			if(Index[i] == Index[j]) Index[i] = 0;
		}
	}

	/* Calculating Total Size of Data */
	u64 TotalSize = 0;
	for(int i = 0; i < ncchset->yaml_set->PlainRegionNum; i++){
		TotalSize += elf->Sections[Index[i]].Size;
	}
	
	/* Creating Output Buffer */
	ncchset->Sections.PlainRegion.size = align_value(TotalSize,ncchset->Options.MediaSize);
	ncchset->Sections.PlainRegion.buffer = malloc(ncchset->Sections.PlainRegion.size);
	if(!ncchset->Sections.PlainRegion.buffer) {fprintf(stderr,"[ELF ERROR] MEM ERROR\n"); return MEM_ERROR;}
	memset(ncchset->Sections.PlainRegion.buffer,0,ncchset->Sections.PlainRegion.size);

	/* Storing Sections */
	u64 pos = 0;
	for(int i = 0; i < ncchset->yaml_set->PlainRegionNum; i++){
		memcpy((ncchset->Sections.PlainRegion.buffer+pos),elf->Sections[Index[i]].Ptr,elf->Sections[Index[i]].Size);
		pos += elf->Sections[Index[i]].Size;
	}
	return 0;
}

int CreateExeFsCode(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset)
{
	/* Getting Code Segments */
	CodeSegment Text;
	memset(&Text,0,sizeof(CodeSegment));
	CodeSegment RO;
	memset(&RO,0,sizeof(CodeSegment));
	CodeSegment Data;
	memset(&Data,0,sizeof(CodeSegment));

	int result = CreateCodeSegmentFromElf(&Text,elf,ElfFile,ncchset->yaml_set->ExeFs.Text,ncchset->yaml_set->ExeFs.TextNum);
	if(result) return result;
	result = CreateCodeSegmentFromElf(&RO,elf,ElfFile,ncchset->yaml_set->ExeFs.ReadOnly,ncchset->yaml_set->ExeFs.ReadOnlyNum);
	if(result) return result;
	result = CreateCodeSegmentFromElf(&Data,elf,ElfFile,ncchset->yaml_set->ExeFs.ReadWrite,ncchset->yaml_set->ExeFs.ReadWriteNum);
	if(result) return result;

	/* Allocating Buffer for ExeFs Code */
	u32 size = (Text.MaxPageNum + RO.MaxPageNum + Data.MaxPageNum)*elf->PageSize;
	u8 *code = malloc(size);

	/* Writing Code into Buffer */
	u8 *TextPos = (code + 0);
	u8 *ROPos = (code + Text.MaxPageNum*elf->PageSize);
	u8 *DataPos = (code + (Text.MaxPageNum + RO.MaxPageNum)*elf->PageSize);
	if(Text.Size) memcpy(TextPos,Text.Data,Text.Size);
	if(RO.Size) memcpy(ROPos,RO.Data,RO.Size);
	if(Data.Size) memcpy(DataPos,Data.Data,Data.Size);


	/* Compressing If needed */
	if(ncchset->Options.CompressCode){
		u32 new_len;
		ncchset->ExeFs_Sections.Code.buffer = BLZ_Code(code,size,&new_len,BLZ_NORMAL);
		ncchset->ExeFs_Sections.Code.size = new_len;
		free(code);
	}
	else{
		ncchset->ExeFs_Sections.Code.size = size;
		ncchset->ExeFs_Sections.Code.buffer = code;
	}

	/* Setting CodeSegment Data and freeing original buffers */
	ncchset->CodeDetails.TextAddress = Text.Address;
	ncchset->CodeDetails.TextMaxPages = Text.MaxPageNum;
	ncchset->CodeDetails.TextSize = Text.Size;
	if(Text.Size) free(Text.Data);

	ncchset->CodeDetails.ROAddress = RO.Address;
	ncchset->CodeDetails.ROMaxPages = RO.MaxPageNum;
	ncchset->CodeDetails.ROSize = RO.Size;
	if(RO.Size) free(RO.Data);

	ncchset->CodeDetails.DataAddress = Data.Address;
	ncchset->CodeDetails.DataMaxPages = Data.MaxPageNum;
	ncchset->CodeDetails.DataSize = Data.Size;
	if(Data.Size) free(Data.Data);

	/* Return */
	return 0;
}

int CreateCodeSegmentFromElf(CodeSegment *out, ElfContext *elf, u8 *ElfFile, char **Names, u32 NameNum)
{
	u16 ContinuousSegmentNum = 0;
	memset(out,0,sizeof(CodeSegment));
	ElfSegment **ContinuousSegments = GetContinuousSegments(&ContinuousSegmentNum,elf,Names,NameNum);
	if (ContinuousSegments == NULL){
		if(!ContinuousSegmentNum) // Nothing Was Found
			return 0;
		else // Error with found segments
			return ELF_SEGMENTS_NOT_CONTINUOUS;
	}
	
	/* Getting Segment Size/Settings */
	u32 vAddr = 0;
	u32 memorySize = 0;
	for(int i = 0; i < ContinuousSegmentNum; i++){
		if (i==0){
			vAddr = ContinuousSegments[i]->VAddr;
		}
		else{ // Add rounded size from previous segment
			u32 num = ContinuousSegments[i]->VAddr - (vAddr + memorySize);
			memorySize += num;
		}

		memorySize += ContinuousSegments[i]->Header->SizeInMemory;
		for (int j = 0; j < ContinuousSegments[i]->SectionNum; j++){
			ElfSectionEntry *Section = &ContinuousSegments[i]->Sections[j];
			if (IsBss(Section) && j == (ContinuousSegments[i]->SectionNum-1))
				memorySize -= Section->Size;
		}
	}
	
	// For Check
#ifdef ELF_DEBUG
	printf("Address: 0x%x\n",vAddr);
	printf("Size:    0x%x\n",memorySize);
#endif

	out->Address = vAddr;
	out->Size = memorySize;
	out->MaxPageNum = SizeToPage(memorySize,elf);
	out->Data = malloc(memorySize);
	
	/* Writing Segment to Buffer */
	vAddr = 0;
	memorySize = 0;
	for(int i = 0; i < ContinuousSegmentNum; i++){
		if (i==0){
			vAddr = ContinuousSegments[i]->VAddr;
		}
		else{
			u32 num = ContinuousSegments[i]->VAddr - (vAddr + memorySize);
			memorySize += num;
		}
		u32 size = 0;
		for (int j = 0; j < ContinuousSegments[i]->SectionNum; j++){
			ElfSectionEntry *Section = &ContinuousSegments[i]->Sections[j];
			if (!IsBss(Section)){
				u8 *pos = (out->Data + memorySize + size);
				memcpy(pos,Section->Ptr,Section->Size);
				size += Section->Size;
			}

			else if (j == (ContinuousSegments[i]->SectionNum-1))
				memorySize -= Section->Size;
			else
				size += Section->Size;
		}
	}

	free(ContinuousSegments);
	return 0;
}


ElfSegment** GetContinuousSegments(u16 *ContinuousSegmentNum, ElfContext *elf, char **Names, u32 NameNum)
{
	u16 SegmentNum = 0;
	ElfSegment **Segments = GetSegments(&SegmentNum, elf, Names, NameNum);
	if (Segments == NULL || SegmentNum == 0){ // No Segments for the names were found
		//printf("Not Found Segment\n");
		return NULL;
	}

	if (SegmentNum == 1){ //Return as there is no need to check
		*ContinuousSegmentNum = SegmentNum;
		return Segments;
	}

	u32 vAddr = Segments[0]->VAddr + Segments[0]->Header->SizeInMemory;
	for (int i = 1; i < SegmentNum; i++){
		if (Segments[i]->VAddr != (u32)align_value(vAddr,Segments[i]->Header->Alignment)){ //Each Segment must start after each other
			fprintf(stderr,"[ELF ERROR] %s segment and %s segment are not continuous\n", Segments[i]->Name, Segments[i - 1]->Name);
			free(Segments);
			*ContinuousSegmentNum = 0xffff; // Signify to function that an error occured
			return NULL;
		}
	}
	*ContinuousSegmentNum = SegmentNum;
	return Segments;
}


ElfSegment** GetSegments(u16 *SegmentNum, ElfContext *elf, char **Names, u32 NameNum)
{
	if (Names == NULL)
	{
		return NULL;
	}

	ElfSegment **Segments = malloc(sizeof(ElfSegment*)*NameNum); 
	*SegmentNum = 0; // There can be a max of NameNum Segments, however, they might not all exist
	for (int i = 0; i < NameNum; i++){
		for(int j = 0; j < elf->ActiveSegments; j++){
			if(strcmp(Names[i],elf->Segments[j].Name) == 0){ // If there is a match, store Segment data pointer & increment index
				Segments[*SegmentNum] = &elf->Segments[j];
				*SegmentNum = *SegmentNum + 1;
			}
		}
	}
	return Segments;
}

// ELF Functions

int GetElfContext(ElfContext *elf, u8 *ElfFile)
{
	if(u8_to_u32(ElfFile,BE) != ELF_MAGIC) return NOT_ELF_FILE;
	
	elf->Is64bit = (ElfFile[4] == elf_64_bit);
	elf->IsLittleEndian = (ElfFile[5] == elf_little_endian);
	
	int result = ReadElfHdr(elf,ElfFile);
	if(result) return result;

	result = GetElfSectionEntries(elf,ElfFile);
	if(result) return result;

	result = GetElfProgramEntries(elf,ElfFile);
	if(result) return result;

	result = CreateElfSegments(elf,ElfFile);
	if(result) return result;

	return 0;
}

int GetElfSectionEntries(ElfContext *elf, u8 *ElfFile)
{
	elf->Sections = malloc(sizeof(ElfSectionEntry)*elf->SectionTableEntryCount);
	if(!elf->Sections) {fprintf(stderr,"[ELF ERROR] MEM ERROR\n"); return MEM_ERROR;}

	for(int i = 0; i < elf->SectionTableEntryCount; i++){
		elf->Sections[i].Name = GetELFSectionEntryName(i,elf,ElfFile);
		elf->Sections[i].Type = GetELFSectionEntryType(i,elf,ElfFile);
		elf->Sections[i].Flags = GetELFSectionEntryFlags(i,elf,ElfFile);
		elf->Sections[i].Ptr = GetELFSectionEntry(i,elf,ElfFile);
		elf->Sections[i].OffsetInFile = GetELFSectionEntryFileOffset(i,elf,ElfFile);
		elf->Sections[i].Size = GetELFSectionEntrySize(i,elf,ElfFile);
		elf->Sections[i].Address = GetELFSectionEntryAddress(i,elf,ElfFile);
		elf->Sections[i].Alignment = GetELFSectionEntryAlignment(i,elf,ElfFile);
	}
	return 0;
}

int GetElfProgramEntries(ElfContext *elf, u8 *ElfFile)
{
	elf->ProgramHeaders = malloc(sizeof(ElfProgramEntry)*elf->ProgramTableEntryCount);
	if(!elf->ProgramHeaders) {fprintf(stderr,"[ELF ERROR] MEM ERROR\n"); return MEM_ERROR;}

	for(int i = 0; i < elf->ProgramTableEntryCount; i++){
		elf->ProgramHeaders[i].Type = GetELFProgramEntryType(i,elf,ElfFile);
		elf->ProgramHeaders[i].Flags = GetELFProgramEntryFlags(i,elf,ElfFile);
		elf->ProgramHeaders[i].Ptr = GetELFProgramEntry(i,elf,ElfFile);
		elf->ProgramHeaders[i].OffsetInFile = GetELFProgramEntryFileOffset(i,elf,ElfFile);
		elf->ProgramHeaders[i].SizeInFile = GetELFProgramEntryFileSize(i,elf,ElfFile);
		elf->ProgramHeaders[i].PhysicalAddress = GetELFProgramEntryPAddress(i,elf,ElfFile);
		elf->ProgramHeaders[i].VirtualAddress = GetELFProgramEntryVAddress(i,elf,ElfFile);
		elf->ProgramHeaders[i].SizeInMemory = GetELFProgramEntryMemorySize(i,elf,ElfFile);
		elf->ProgramHeaders[i].Alignment = GetELFProgramEntryAlignment(i,elf,ElfFile);
	}

	return 0;
}

void PrintElfContext(ElfContext *elf, u8 *ElfFile)
{
	printf("[+] Basic Details\n");
	printf(" Class:  %s\n",elf->Is64bit ? "64-bit" : "32-bit");
	printf(" Data:   %s\n",elf->IsLittleEndian ? "Little Endian" : "Big Endian");
	printf("\n[+] Program Table Data\n");
	printf(" Offset: 0x%lx\n",elf->ProgramTableOffset);
	printf(" Size:   0x%x\n",elf->ProgramTableEntrySize);
	printf(" Count:  0x%x\n",elf->ProgramTableEntryCount);
	printf("\n[+] Section Table Data\n");
	printf(" Offset: 0x%lx\n",elf->SectionTableOffset);
	printf(" Size:   0x%x\n",elf->SectionTableEntrySize);
	printf(" Count:  0x%x\n",elf->SectionTableEntryCount);
	printf(" Lable Index: 0x%x\n",elf->SectionHeaderNameEntryIndex);
	for(int i = 0; i < elf->ActiveSegments; i++){
		printf(" Segment [%d][%s]\n",i,elf->Segments[i].Name);
		printf(" > Size :     0x%x\n",elf->Segments[i].Header->SizeInFile);
		printf(" > Address :  0x%x\n",elf->Segments[i].VAddr);
		printf(" > Sections : %d\n",elf->Segments[i].SectionNum);  
		for(int j = 0; j < elf->Segments[i].SectionNum; j++){
			printf("    > Section [%d][%s]\n",j,elf->Segments[i].Sections[j].Name);
		}
		
		/*
		char outpath[100];
		memset(&outpath,0,100);
		sprintf(outpath,"%s.bin",elf->Sections[i].Name);
		chdir("elfsections");
		FILE *tmp = fopen(outpath,"wb");
		WriteBuffer(elf->Sections[i].Ptr,elf->Sections[i].Size,0,tmp);
		fclose(tmp);
		chdir("..");
		*/
	}

}

int ReadElfHdr(ElfContext *elf, u8 *ElfFile)
{
	if(elf->Is64bit){
		elf_64_hdr *hdr = (elf_64_hdr*)ElfFile;

		u16 Architecture = u8_to_u16(hdr->TargetArchitecture,elf->IsLittleEndian);
		u16 Type = u8_to_u16(hdr->Type,elf->IsLittleEndian);
		if(Architecture != elf_arm) return NOT_ARM_ELF;
		if(Type != elf_executeable) return NON_EXECUTABLE_ELF;

		elf->ProgramTableOffset = u8_to_u64(hdr->ProgramHeaderTableOffset,elf->IsLittleEndian);
		elf->ProgramTableEntrySize = u8_to_u16(hdr->ProgramHeaderEntrySize,elf->IsLittleEndian);
		elf->ProgramTableEntryCount = u8_to_u16(hdr->ProgramHeaderEntryCount,elf->IsLittleEndian);

		elf->SectionTableOffset = u8_to_u64(hdr->SectionHeaderTableOffset,elf->IsLittleEndian);
		elf->SectionTableEntrySize = u8_to_u16(hdr->SectionTableEntrySize,elf->IsLittleEndian);
		elf->SectionTableEntryCount = u8_to_u16(hdr->SectionHeaderEntryCount,elf->IsLittleEndian);

		elf->SectionHeaderNameEntryIndex = u8_to_u16(hdr->SectionHeaderNameEntryIndex,elf->IsLittleEndian);
	}
	else{
		elf_32_hdr *hdr = (elf_32_hdr*)ElfFile;

		u16 Architecture = u8_to_u16(hdr->TargetArchitecture,elf->IsLittleEndian);
		u16 Type = u8_to_u16(hdr->Type,elf->IsLittleEndian);
		if(Architecture != elf_arm) return NOT_ARM_ELF;
		if(Type != elf_executeable) return NON_EXECUTABLE_ELF;

		elf->ProgramTableOffset = u8_to_u32(hdr->ProgramHeaderTableOffset,elf->IsLittleEndian);
		elf->ProgramTableEntrySize = u8_to_u16(hdr->ProgramHeaderEntrySize,elf->IsLittleEndian);
		elf->ProgramTableEntryCount = u8_to_u16(hdr->ProgramHeaderEntryCount,elf->IsLittleEndian);

		elf->SectionTableOffset = u8_to_u32(hdr->SectionHeaderTableOffset,elf->IsLittleEndian);
		elf->SectionTableEntrySize = u8_to_u16(hdr->SectionTableEntrySize,elf->IsLittleEndian);
		elf->SectionTableEntryCount = u8_to_u16(hdr->SectionHeaderEntryCount,elf->IsLittleEndian);

		elf->SectionHeaderNameEntryIndex = u8_to_u16(hdr->SectionHeaderNameEntryIndex,elf->IsLittleEndian);
	}
	return 0;
}

/* Section Hdr Functions */

u8* GetELFSectionHeader(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return NULL;

	return (ElfFile + elf->SectionTableOffset + elf->SectionTableEntrySize*Index);
}

u8* GetELFSectionEntry(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return NULL;

	return (u8*) (ElfFile + GetELFSectionEntryFileOffset(Index,elf,ElfFile));
}

char* GetELFSectionEntryName(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return 0;

	u64 NameIndex = 0;
	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		NameIndex = u8_to_u64(shdr->sh_name,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		NameIndex = u8_to_u32(shdr->sh_name,elf->IsLittleEndian);
	}

	u8 *NameTable = GetELFSectionEntry(elf->SectionHeaderNameEntryIndex,elf,ElfFile);
	
	return (char*)(NameTable+NameIndex);
}

u64 GetELFSectionEntryType(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_type,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_type,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryFlags(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_flags,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_flags,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryAddress(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_addr,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_addr,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryFileOffset(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_offset,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_offset,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntrySize(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_size,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_size,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryAlignment(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->SectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_addralign,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_addralign,elf->IsLittleEndian);
	}

	return 0;
}


u16 GetElfSectionIndexFromName(char *Name, ElfContext *elf, u8 *ElfFile)
{
	for(int i = 0; i < elf->SectionTableEntryCount; i++){
		if(strcmp(Name,elf->Sections[i].Name) == 0) return i;
	}
	return 0; // Assuming 0 is always empty
}

bool IsBss(ElfSectionEntry *Section)
{
	if(Section->Type == 8 && Section->Flags == 3)
		return true;
	return false;
}

bool IsData(ElfSectionEntry *Section)
{
	if(Section->Type == 1 && Section->Flags == 3)
		return true;
	return false;
}

bool IsRO(ElfSectionEntry *Section)
{
	if(Section->Type == 1 && Section->Flags == 2)
		return true;
	return false;
}

bool IsText(ElfSectionEntry *Section)
{
	if(Section->Type == 1 && Section->Flags == 6)
		return true;
	return false;
}

/* ProgramHeader Functions */

u8* GetELFProgramHeader(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return NULL;

	return (ElfFile + elf->ProgramTableOffset + elf->ProgramTableEntrySize*Index);
}

u8* GetELFProgramEntry(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return NULL;

	return (u8*) (ElfFile + GetELFProgramEntryFileOffset(Index,elf,ElfFile));

	return NULL;
}

u64 GetELFProgramEntryType(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_type,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_type,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFlags(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_flags,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_flags,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFileSize(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_filesz,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_filesz,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFileOffset(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_offset,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_offset,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryMemorySize(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_memsz,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_memsz,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryVAddress(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_vaddr,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_vaddr,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryPAddress(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_paddr,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_paddr,elf->IsLittleEndian);
	}

	return 0;
}


u64 GetELFProgramEntryAlignment(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->ProgramTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_align,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_align,elf->IsLittleEndian);
	}

	return 0;
}


int CreateElfSegments(ElfContext *elf, u8 *ElfFile)
{
	int num = 0;
	// Interate through Each Program Header
	elf->ActiveSegments = 0;
	elf->Segments = malloc(sizeof(ElfSegment)*elf->ProgramTableEntryCount);
	ElfSegment *segment = malloc(sizeof(ElfSegment)); // Temporary Buffer
	for (int i = 0; i < elf->ProgramTableEntryCount; i++){
		if (elf->ProgramHeaders[i].SizeInMemory != 0 && elf->ProgramHeaders[i].Type == 1){
			memset(segment,0,sizeof(ElfSegment));

			bool flag = false;
			u32 size = 0;
			u32 vAddr = elf->ProgramHeaders[i].VirtualAddress;
 			u32 memorySize = elf->ProgramHeaders[i].SizeInMemory;
			
			u16 SectionInfoCapacity = 10;
			segment->SectionNum = 0;
			segment->Sections = malloc(sizeof(ElfSectionEntry)*SectionInfoCapacity);

			// Itterate Through Section Headers
			for (int j = num; j < elf->SectionTableEntryCount; j++){
				if (!flag){
					if (elf->Sections[j].Address != vAddr)
                        goto Skip;
                    
					while (j < (int)elf->Sections[j].Size && elf->Sections[j].Address == vAddr && !IsIgnoreSection(elf->Sections[j]))
                        j++;

					j--;

					flag = true;
					segment->VAddr = elf->Sections[j].Address;
					segment->Name = elf->Sections[j].Name;
                }

				if(segment->SectionNum < SectionInfoCapacity)
					memcpy(&segment->Sections[segment->SectionNum],&elf->Sections[j],sizeof(ElfSectionEntry));
				else{
					SectionInfoCapacity = SectionInfoCapacity*2;
					ElfSectionEntry *tmp = malloc(sizeof(ElfSectionEntry)*SectionInfoCapacity);
					for(int k = 0; k < segment->SectionNum; k++)
						memcpy(&tmp[k],&segment->Sections[k],sizeof(ElfSectionEntry));
					free(segment->Sections);
					segment->Sections = tmp;
					memcpy(&segment->Sections[segment->SectionNum],&elf->Sections[j],sizeof(ElfSectionEntry));
				}
				segment->SectionNum++;

                size += elf->Sections[j].Size;

                if (size == memorySize)
					break;

				if (size > memorySize){
					fprintf(stderr,"[ELF ERROR] Too large section size.\n Segment size = 0x%x\n Section Size = 0x%x\n", memorySize, size);
					return ELF_SEGMENT_SECTION_SIZE_MISMATCH;
				}
			Skip: ;
            }
			if(segment->SectionNum){
				segment->Header = &elf->ProgramHeaders[i];
				memcpy(&elf->Segments[elf->ActiveSegments],segment,sizeof(ElfSegment));
				elf->ActiveSegments++;
			}
			else{
				free(segment->Sections);
				free(segment);
				fprintf(stderr,"[ELF ERROR] Program Header Has no corresponding Sections, ELF Cannot be proccessed\n");
				return ELF_SEGMENTS_NOT_FOUND;
			}
		}
	}

	free(segment);
	return 0;
}

bool IsIgnoreSection(ElfSectionEntry info)
{
	if (info.Address)
		return false;

	if (info.Type != 1 && info.Type != 0)
		return true;

	char IgnoreSectionNames[7][20] = { ".debug_abbrev", ".debug_frame", ".debug_info", ".debug_line", ".debug_loc", ".debug_pubnames", ".comment" };
	for (int i = 0; i < 7; i++){
		if (strcmp(IgnoreSectionNames[i],info.Name) == 0)
			return true;
	}
	return false;

}
