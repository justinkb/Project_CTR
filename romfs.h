#pragma once

typedef enum
{
	INVALID_ROMFS_FILE = -10,
} romfs_errors;


// IVFC Structs
typedef struct
{
	u8 logicalOffset[8];
	u8 hashDataSize[8];
	u8 blockSize[4];
	u8 reserved[4];
} ivfc_levelheader;

typedef struct
{
	u8 magic[4];
	u8 id[4];
	u8 masterHashSize[4];
	ivfc_levelheader level1;
	ivfc_levelheader level2;
	ivfc_levelheader level3;
	u8 reserved[4];
	u8 optionalSize[4];
} ivfc_hdr;

// ROMFS FS Structs
typedef struct
{
	u8 offset[4];
	u8 size[4];
} romfs_sectionheader;

typedef struct
{
	u8 headersize[4];
	romfs_sectionheader section[4];
	u8 dataoffset[4];
} romfs_infoheader;


typedef struct
{
	u8 parentoffset[4];
	u8 siblingoffset[4];
	u8 childoffset[4];
	u8 fileoffset[4];
	u8 weirdoffset[4]; // this one is weird. it always points to a dir entry, but seems unrelated to the romfs structure.
	u8 namesize[4];
	//u8 name[ROMFS_MAXNAMESIZE];
} romfs_direntry; //sizeof(romfs_direntry)  = 0x18

typedef struct
{
	u8 parentdiroffset[4];
	u8 siblingoffset[4];
	u8 dataoffset[8];
	u8 datasize[8];
	u8 weirdoffset[4]; // this one is also weird. it always points to a file entry, but seems unrelated to the romfs structure.
	u8 namesize[4];
	//u8 name[ROMFS_MAXNAMESIZE];
} romfs_fileentry; //sizeof(romfs_fileentry)  = 0x20


typedef struct
{
	u8 *output;
	u64 romfsSize;


	bool ImportRomfsBinary;
	FILE *romfsBinary;
} romfs_buildctx;

