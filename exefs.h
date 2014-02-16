#ifndef _EXEFS_H_
#define _EXEFS_H_

#define MAX_EXEFS_SECTIONS 10 // DO NOT CHANGE

typedef enum
{
	PTR_ERROR = -10,
	EXEFS_MAX_REACHED = -11,
	EXEFS_SECTION_NAME_ERROR = -12,

} exefs_errors;

typedef struct
{
	char name[8];
	u8 offset[4];
	u8 size[4];
} ExeFs_FileHeader;

typedef struct
{
	//Input
	int section_count;
	u8 *section[10];
	u32 section_size[10];
	u32 section_offset[10];
	char lable[10][8];
	u32 media_unit;
	
	//Working Data
	ExeFs_FileHeader file_header[10];
	u8 file_hashes[10][0x20];
	
} ExeFs_BuildContext;

typedef struct
{
	ExeFs_FileHeader SectionHdr[MAX_EXEFS_SECTIONS];
	u8 Reserved[0x20];
	u8 SectionHashes[MAX_EXEFS_SECTIONS][0x20];
} ExeFs_Header;

#endif

/* ExeFs Build Functions */
int BuildExeFs(ncch_settings *ncchset);

/* ExeFs Read Functions */
bool DoesExeFsSectionExist(char *section, u8 *ExeFs);
u8* GetExeFsSection(char *section, u8 *ExeFs);
u8* GetExeFsSectionHash(char *section, u8 *ExeFs);
u32 GetExeFsSectionSize(char *section, u8 *ExeFs);
u32 GetExeFsSectionOffset(char *section, u8 *ExeFs);
