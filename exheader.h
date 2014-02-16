#ifndef _EXHEADER_H_
#define _EXHEADER_H_

typedef enum
{
	COMMON_HEADER_KEY_NOT_FOUND = -10,
	EXHDR_BAD_YAML_OPT = -11,
} exheader_errors;

typedef enum
{
	ExeFsCodeCompress = 1,
	RetailSDAppFlag = 2,
} SystemInfoFlags_Flagbitmask;

typedef enum
{
	APPLICATION = 1,
    SYSTEM = 2,
    BASE = 3
} MemoryTypeName;

typedef enum
{
	PERMIT_DEBUG = 1,
	FORCE_DEBUG = 2,
	CAN_USE_NON_ALPHABET_AND_NUMBER = 4,
	CAN_WRITE_SHARED_PAGE = 8,
	CAN_USE_PRIVILEGE_PRIORITY = 16,
	PERMIT_MAIN_FUNCTION_ARGUMENT = 32,
	CAN_SHARE_DEVICE_MEMORY = 64,
	RUNNABLE_ON_SLEEP = 128,
	SPECIAL_MEMORY_ARRANGE = 4096
} OtherCapabilities_Flagbitmask;

typedef struct
{
	u8 reserved[5];
	u8 flag;
	u8 remasterVersion[2]; // le u16
} exhdr_SystemInfoFlags;

typedef struct
{
	u8 Address[4]; // le u32
	u8 NumMaxPages[4]; // le u32
	u8 CodeSize[4]; // le u32
} exhdr_CodeSegmentInfo;

typedef struct
{
	u8 Name[8];
	exhdr_SystemInfoFlags Flags;
	exhdr_CodeSegmentInfo TextSectionInfo;
	u8 StackSize[4]; // le u32
	exhdr_CodeSegmentInfo ReadOnlySectionInfo;
	u8 Reserved[4];
	exhdr_CodeSegmentInfo DataSectionInfo;
	u8 BssSize[4]; // le u32
} exhdr_CodeSetInfo;

typedef struct
{
	u8 SaveDataSize[8];
	u8 JumpId[8];
	u8 Reserved[0x30];
} exhdr_SystemInfo;

typedef struct
{
	u8 extsavedataid[8];
	u8 systemsavedataid[8];
	u8 reserved[8];
	u8 accessinfo[7];
	u8 otherattributes;
} exhdr_StorageInfo;

typedef struct
{
	u8 ProgramId[8];
	u8 Flags[8];
	u8 MaxCpu;
	u8 Reserved0;
	u8 ResourceLimitDescriptor[15][2];
	exhdr_StorageInfo StorageInfo;
	u8 ServiceAccessControl[32][8]; // Those char[8] svc handles
	u8 Reserved1[0x1f];
	u8 ResourceLimitCategory;
} exhdr_ARM11SystemLocalCapabilities;

typedef struct
{
	u8 descriptors[28][4];// Descripters are a collection of u32s, with bitmask idents so they can be identified, no matter the pos
	/*
	struct
	{
		u32 data[8];
	} SystemCallAccessControl;

	struct
	{
		u32 data[8];
	} InterruptNumberList;

	struct
	{
		
	} AddressMapping;

	struct
	{
		u32 Data; // le u32 : Flags 
	} OtherCapabilities;

	struct
	{
		u32 Data;
	} HandleTableSize;

	struct
	{
		u32 Data;
	} ReleaseKernelVersion;
	*/
	u8 reserved[0x10];
} exhdr_ARM11KernelCapabilities;

typedef struct
{
        u8 descriptors[15];
        u8 descversion;
} exhdr_ARM9AccessControlInfo;

typedef struct
{
	// systemcontrol info {
	// coreinfo {
	exhdr_CodeSetInfo CodeSetInfo;
	u8 DependencyList[0x30][8];
	// }
	exhdr_SystemInfo SystemInfo;
	// }
	// accesscontrolinfo {
	exhdr_ARM11SystemLocalCapabilities ARM11SystemLocalCapabilities;
	exhdr_ARM11KernelCapabilities ARM11KernelCapabilities;
	exhdr_ARM9AccessControlInfo ARM9AccessControlInfo;
	// }
	struct {
		u8 signature[0x100];
		u8 ncchpubkeymodulus[0x100];
		exhdr_ARM11SystemLocalCapabilities ARM11SystemLocalCapabilities;
		exhdr_ARM11KernelCapabilities ARM11KernelCapabilities;
		exhdr_ARM9AccessControlInfo ARM9AccessControlInfo;
	} AccessDescriptor;
} ExtendedHeader_Struct;

typedef struct
{
	keys_struct *keys;
	desc_settings *yaml;

	/* Output */
	ExtendedHeader_Struct *ExHdr; // is the exheader output buffer ptr(in ncchset) cast as exheader struct ptr;
} exheader_settings;

#endif
/* ExHeader Signature Functions */
int SignAccessDesc(ExtendedHeader_Struct *ExHdr, keys_struct *keys);
int CheckAccessDescSignature(ExtendedHeader_Struct *ExHdr, keys_struct *keys);

/* ExHeader Build Functions */
int BuildExHeader(ncch_settings *ncchset);

/* ExHeader Binary Print Functions */
void exhdr_Print_ServiceAccessControl(ExtendedHeader_Struct *hdr);

/* ExHeader Binary Read Functions */
u8* GetAccessDescSig_frm_exhdr(ExtendedHeader_Struct *hdr);
u8* GetNcchHdrPubKey_frm_exhdr(ExtendedHeader_Struct *hdr);
u8* GetAccessDesc_frm_exhdr(ExtendedHeader_Struct *hdr);
u16 GetRemasterVersion_frm_exhdr(ExtendedHeader_Struct *hdr);
u64 GetSaveDataSize_frm_exhdr(ExtendedHeader_Struct *hdr);
int GetDependancyList_frm_exhdr(u8 *Dest,ExtendedHeader_Struct *hdr);
int GetCoreVersion_frm_exhdr(u8 *Dest, ExtendedHeader_Struct *hdr);

/* ExHeader Settings Read from Yaml */
int GetSaveDataSize_yaml(u64 *SaveDataSize, user_settings *usrset);
int GetRemasterVersion_yaml(u16 *RemasterVersion, user_settings *usrset);