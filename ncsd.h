#ifndef _NCSD_H_
#define _NCSD_H_


// Enums
typedef enum
{
	NCSD_NO_NCCH0 = -1,
	NCSD_INVALID_NCCH0 = -2,
	INVALID_YAML_OPT = -3,
	CCI_SIG_FAIL = -4,
	
} ncsd_errors;

typedef enum
{
	FW6x_BackupWriteWaitTime = 0,
	FW6x_SaveCryptoFlag = 1,
	CardDeviceFlag = 3,
	MediaPlatformIndex = 4,
	MediaTypeIndex = 5,
	MediaUnitSize = 6,
	OldCardDeviceFlag = 7
} FlagIndex;

typedef enum
{
	CARD_DEVICE_NOR_FLASH = 1,
	CARD_DEVICE_NONE = 2,
	CARD_DEVICE_BT = 3
} _CardDevice;

typedef enum
{
	CTR = 1,
} _PlatformIndex;

typedef enum
{
	INNER_DEVICE,
	CARD1,
	CARD2,
	EXTENDED_DEVICE
} _TypeIndex;

// Structs
typedef struct
{
	u8 offset[4];
	u8 size[4];
} partition_offsetsize;

typedef struct
{
	u8 magic[4];
	u8 mediaSize[4];
	u8 titleId[8];
	u8 partitionsFsType[8];
	u8 partitionsCryptoType[8];
	partition_offsetsize offset_sizeTable[8];
	u8 exhdrHash[0x20];
	u8 additionalHdrSize[0x4];
	u8 sectorZeroOffset[0x4];
	u8 partitionFlags[8];
	u8 partitionIdTable[8][8];
	u8 padding[0x30];
} ncsd_hdr;

typedef struct
{
	u8 magic[4];
	u8 mediaSize[4];
	u8 titleId[8];
	u8 partitionsFsType[8];
	u8 partitionsCryptoType[8];
	partition_offsetsize offset_sizeTable[8];
	u8 padding0[0x28];
	u8 partitionFlags[8];
	u8 partitionIdTable[8][8];
	u8 padding1[0x30];
} cci_hdr;

typedef struct
{
	u8 writable_address[4];
	u8 card_info_bitmask[4];
	// Notes
	u8 reserved_0[0xf8];
	u8 media_size_used[8];
	u8 reserved_1[0x18];
	u8 cver_title_id[8];
	u8 cver_title_titleVersion[2];
	u8 reserved_2[0xcd6];
	//
	u8 ncch_0_title_id[8];
	u8 reserved_3[8];
	u8 initial_data[0x30];
	u8 reserved_4[0xc0];
	u8 ncch_0_header[0x100];
} cardinfo_hdr;

typedef struct
{
	u8 CardDeviceReserved1[0x200];
	u8 TitleKey[0x10];
	u8 CardDeviceReserved2[0xf0];
} devcardinfo_hdr;

typedef struct
{
	u8 signature[0x100];
	cci_hdr cciHdr;
	cardinfo_hdr cardinfo;
	devcardinfo_hdr devcardinfo;
	u8 *ncchImportBuffer;
	keys_struct *keys;
} InternalCCI_Context;

typedef struct
{
	u64 mediaSize;
	u8 mediaId[8];
	u8 flags[8];
	u64 savedataSize;
	u64 writableAddress;
	u32 cardInfoBitmask;
	
	u8 initialData[0x30];
	ncch_hdr *ncchHdr;
	u8 titleKey[0x10];
	
	u8 *ncch0;
	u64 ncch0_FileLen;
	FILE **content;
	u64 contentSize[CCI_MAX_CONTENT];
	u64 contentOffset[CCI_MAX_CONTENT];
	u8 contentTitleId[CCI_MAX_CONTENT][8];
	u64 cciTotalSize;
	
	bool fillOutCci;
	u32 mediaUnit;
	
	FILE *out;
} cci_settings;

static const u8 stock_initial_data[0x30] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0xAD, 0x88, 
	0xAC, 0x41, 0xA2, 0xB1, 0x5E, 0x8F, 
	0x66, 0x9C, 0x97, 0xE5, 0xE1, 0x5E, 
	0xA3, 0xEB, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const u8 stock_title_key[0x10] = 
{
	0x6E, 0xC7, 0x5F, 0xB2, 0xE2, 0xB4, 
	0x87, 0x46, 0x1E, 0xDD, 0xCB, 0xB8, 
	0x97, 0x11, 0x92, 0xBA
};

#endif

// Public Prototypes


// Build Functions
int build_CCI(user_settings *usrset);

// Read Functions
bool IsCci(u8 *ncsd);
u8* GetPartition(u8 *ncsd, u8 index);
u64 GetPartitionOffset(u8 *ncsd, u8 index);
u64 GetPartitionSize(u8 *ncsd, u8 index);