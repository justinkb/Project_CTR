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
	memtype_APPLICATION = 1,
    memtype_SYSTEM = 2,
    memtype_BASE = 3
} MemoryTypeName;

typedef enum
{
	processtype_DEFAULT = -1,
	processtype_SYSTEM = 0,
	processtype_APPLICATION = 1
} ProcessTypeName;

typedef enum
{
	resrc_limit_APPLICATION,
	resrc_limit_SYS_APPLET,
	resrc_limit_LIB_APPLET,
	resrc_limit_OTHER
} ResourceLimitCategoryName;

typedef enum
{
	PERMIT_DEBUG,
	FORCE_DEBUG,
	CAN_USE_NON_ALPHABET_AND_NUMBER,
	CAN_WRITE_SHARED_PAGE,
	CAN_USE_PRIVILEGE_PRIORITY,
	PERMIT_MAIN_FUNCTION_ARGUMENT,
	CAN_SHARE_DEVICE_MEMORY,
	RUNNABLE_ON_SLEEP,
	SPECIAL_MEMORY_ARRANGE = 12,
} OtherCapabilities_Flagbitmask;

typedef enum
{
	CATEGORY_SYSTEM_APPLICATION,
	CATEGORY_HARDWARE_CHECK,
	CATEGORY_FILE_SYSTEM_TOOL,
	DEBUG,
	TWL_CARD_BACKUP,
	TWL_NAND_DATA,
	BOSS,
	DIRECT_SDMC,
	CORE,
	CTR_NAND_RO,
	CTR_NAND_RW,
	CTR_NAND_RO_WRITE,
	CATEGORY_SYSTEM_SETTINGS,
	CARD_BOARD,
	EXPORT_IMPORT_IVS,
	DIRECT_SDMC_WRITE,
	SWITCH_CLEANUP,
	SAVE_DATA_MOVE,
	SHOP,
	SHELL,
	CATEGORY_HOME_MENU
} FileSystemAccess;

typedef enum
{
	NOT_USE_ROMFS,
	USE_EXTENDED_SAVEDATA_ACCESS_CONTROL
} AttributeName;

typedef enum
{
	FS_MOUNT_NAND,
	FS_MOUNT_NAND_RO_WRITE,
	FS_MOUNT_TWLN,
	FS_MOUNT_WNAND,
	FS_MOUNT_CARD_SPI,
	USE_SDIF3,
	CREATE_SEED,
	USE_CARD_SPI,
	SD_APPLICATION,
	USE_DIRECT_SDMC
} Arm9Capability;

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
	u8 ExtSaveDataId[8];
	u8 SystemSaveDataId[8];
	u8 StorageAccessableUniqueIds[8];
	//u8 reserved[7];
	//u8 flag;
	u8 AccessInfo[7];
	u8 OtherAttributes;
} exhdr_StorageInfo;

typedef struct
{
	u8 ProgramId[8];
	u8 Flags[8];
	u8 ResourceLimitDescriptor[16][2];
	exhdr_StorageInfo StorageInfo;
	u8 ServiceAccessControl[32][8]; // Those char[8] svc handles
	u8 Reserved1[0x1f];
	u8 ResourceLimitCategory;
} exhdr_ARM11SystemLocalCapabilities;

typedef struct
{
	u16 num;
	u32 *Data;
} ARM11KernelCapabilityDescriptor;

typedef enum
{
	desc_InteruptNumList = 0xe0000000,
	desc_SysCallControl = 0xf0000000,
	desc_KernelReleaseVersion = 0xfc000000,
	desc_HandleTableSize = 0xfe000000,
	desc_OtherCapabilities = 0xff000000,
	desc_MappingStatic = 0xff800000,
	desc_MappingIO = 0xffc00000,
} ARM11KernelCapabilityDescriptorBitmask;

typedef struct
{
	u8 descriptors[28][4];// Descripters are a collection of u32s, with bitmask idents so they can be identified, 'no matter the pos'
	u8 reserved[0x10];
} exhdr_ARM11KernelCapabilities;

typedef struct
{
	u8 descriptors[16]; //descriptors[15] = DescVersion
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
	rsf_settings *yaml;

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