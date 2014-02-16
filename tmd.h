#ifndef _TMD_H_
#define _TMD_H_

typedef enum
{
	TYPE_CTR = 0x40,
	TYPE_DATA = 0x8
} title_type;

typedef enum
{
	Encrypted = 0x0001,
	Optional = 0x4000,
	Shared = 0x8000
} content_types;

typedef struct
{
	u8 content_id[4];
	u8 content_index[2];
	u8 content_type[2];
	u8 content_size[8];
	u8 sha_256_hash[0x20];
} TMD_CONTENT_CHUNK_STRUCT;

typedef struct
{
	u8 content_index_offset[2];
	u8 content_command_count[2];
	u8 sha_256_hash[0x20];
} TMD_CONTENT_INFO_RECORD;

typedef struct
{
	u8 sig_type[4];
	u8 data[0x100];
	u8 padding[0x3C];
} TMD_SignatureStruct;

typedef struct
{
	u8 Issuer[0x40];
	u8 TMDFormatVersion;
	u8 ca_crl_version;
	u8 signer_crl_version;
	u8 padding_1;
	u8 SystemVersion[8];
	u8 TitleID[8];
	u8 TitleType[4];
	u8 GroupID[2];
	u8 SaveDataSize[4];
	u8 PrivSaveDataSize[4]; // Zero for CXI Content0
	u8 Reserved_0[4];
	u8 TWL_Flag; // Zero for CXI Content0
	u8 Reserved_1[0x31];
	u8 AccessRights[4];
	u8 TitleVersion[2];
	u8 ContentCount[2];
	u8 BootContent[2];
	u8 Padding[2];
	u8 sha_256_hash[0x20];	
} TMD_Struct;

#endif

// Prototypes
u32 PredictTMDSize(u16 ContentCount);
int BuildTMD(cia_settings *ciaset);