#ifndef _EXHEADER_H_
#define _EXHEADER_H_

typedef enum
{
	COMMON_HEADER_KEY_NOT_FOUND = -10,
	EXHDR_BAD_YAML_OPT = -11,
	CANNOT_SIGN_ACCESSDESC = -12
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
	othcap_PERMIT_DEBUG,
	othcap_FORCE_DEBUG,
	othcap_CAN_USE_NON_ALPHABET_AND_NUMBER,
	othcap_CAN_WRITE_SHARED_PAGE,
	othcap_CAN_USE_PRIVILEGE_PRIORITY,
	othcap_PERMIT_MAIN_FUNCTION_ARGUMENT,
	othcap_CAN_SHARE_DEVICE_MEMORY,
	othcap_RUNNABLE_ON_SLEEP,
	othcap_SPECIAL_MEMORY_ARRANGE = 12,
} OtherCapabilities_Flagbitmask;

typedef enum
{
	fsaccess_CATEGORY_SYSTEM_APPLICATION,
	fsaccess_CATEGORY_HARDWARE_CHECK,
	fsaccess_CATEGORY_FILE_SYSTEM_TOOL,
	fsaccess_DEBUG,
	fsaccess_TWL_CARD_BACKUP,
	fsaccess_TWL_NAND_DATA,
	fsaccess_BOSS,
	fsaccess_DIRECT_SDMC,
	fsaccess_CORE,
	fsaccess_CTR_NAND_RO,
	fsaccess_CTR_NAND_RW,
	fsaccess_CTR_NAND_RO_WRITE,
	fsaccess_CATEGORY_SYSTEM_SETTINGS,
	fsaccess_CARD_BOARD,
	fsaccess_EXPORT_IMPORT_IVS,
	fsaccess_DIRECT_SDMC_WRITE,
	fsaccess_SWITCH_CLEANUP,
	fsaccess_SAVE_DATA_MOVE,
	fsaccess_SHOP,
	fsaccess_SHELL,
	fsaccess_CATEGORY_HOME_MENU
} FileSystemAccess;

typedef enum
{
	attribute_NOT_USE_ROMFS,
	attribute_USE_EXTENDED_SAVEDATA_ACCESS_CONTROL
} AttributeName;

typedef enum
{
	arm9cap_FS_MOUNT_NAND,
	arm9cap_FS_MOUNT_NAND_RO_WRITE,
	arm9cap_FS_MOUNT_TWLN,
	arm9cap_FS_MOUNT_WNAND,
	arm9cap_FS_MOUNT_CARD_SPI,
	arm9cap_USE_SDIF3,
	arm9cap_CREATE_SEED,
	arm9cap_USE_CARD_SPI,
	arm9cap_SD_APPLICATION,
	arm9cap_USE_DIRECT_SDMC
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
	bool UseAccessDescPreset;

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