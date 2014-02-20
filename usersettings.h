#ifndef _USERSETTINGS_H_
#define _USERSETTINGS_H_

#define CCI_MAX_CONTENT 8
#define CIA_MAX_CONTENT 65536


typedef enum
{
	USR_PTR_PASS_FAIL = -1,
	USR_HELP = -2,
	USR_ARG_REQ_PARAM = -3,
	USR_UNK_ARG = -4,
	USR_BAD_ARG = -5,
	USR_MEM_ERROR = -6,
} user_settings_errors;

typedef enum
{
	auto_gen,
	use_spec_file,
	app,
	demo,
	dlp,
} fixed_accessdesc_type;

typedef enum
{
	format_not_set,
	CXI,
	CFA,
	CCI,
	CIA
} output_format;

static const char output_extention[4][5] = {".cxi",".cfa",".cci",".cia"};

typedef struct
{	
	struct{
		// Booleans
		int NoPadding;
		int AllowUnalignedSection;
		int EnableCrypt;
		int EnableCompress;
		int FreeProductCode;
		int UseOnSD;

		// Strings
		char *PageSize;
		
		// String Collections
		u32 AppendSystemCallNum; // DELETE
		char **AppendSystemCall; // DELETE
	} Option;
	
	struct{
		// Booleans
		int DisableDebug;
		int EnableForceDebug;
		int CanWriteSharedPage;
		int CanUsePrivilegedPriority;
		int CanUseNonAlphabetAndNumber;
		int PermitMainFunctionArgument;
		int CanShareDeviceMemory;
		int UseOtherVariationSaveData;
		int UseExtSaveData;
		int UseExtendedSaveDataAccessControl;
		int RunnableOnSleep;
		int SpecialMemoryArrange;
		
		// Strings
		char *ProgramId; // DELETE
		char *IdealProcessor;
		char *Priority;
		char *MemoryType;
		char *SystemMode;
		char *CoreVersion;
		char *HandleTableSize;
		char *SystemSaveDataId1;
		char *SystemSaveDataId2;
		char *OtherUserSaveDataId1;
		char *OtherUserSaveDataId2;
		char *OtherUserSaveDataId3;
		char *ExtSaveDataId;
		char *AffinityMask;
		// Strings From DESC
		char *DescVersion;
		char *CryptoKey; // DELETE
		char *ResourceLimitCategory;
		char *ReleaseKernelMajor;
		char *ReleaseKernelMinor;
		char *MaxCpu;
		
		// String Collections
		u32 MemoryMappingNum;
		char **MemoryMapping;
		u32 IORegisterMappingNum;
		char **IORegisterMapping;
		u32 FileSystemAccessNum;
		char **FileSystemAccess;
		u32 IoAccessControlNum;
		char **IoAccessControl; //Equiv to Arm9AccessControl
		u32 InterruptNumbersNum;
		char **InterruptNumbers;
		u32 SystemCallAccessNum;
		char **SystemCallAccess;
		u32 ServiceAccessControlNum;
		char **ServiceAccessControl;
		u32 StorageIdNum; // DELETE
		char **StorageId; // DELETE
		u32 AccessibleSaveDataIdsNum;
		char **AccessibleSaveDataIds;
	} AccessControlInfo;

	struct{
		// Strings
		char *AppType;
		char *StackSize;
		char *RemasterVersion;
		char *JumpId;
		
		// String Collections
		u32 DependencyNum;
		char **Dependency;
	} SystemControlInfo;
	
	struct{
		// Booleans
		int MediaFootPadding;
		
		// Strings
		char *Title;
		char *CompanyCode;
		char *ProductCode;
		char *MediaSize;
		char *ContentType;
		char *Logo;
		char *BackupMemoryType;
		char *InitialCode;
	} BasicInfo;
	
	struct{
		// Strings
		char *HostRoot;
		char *Padding; // DELETE
		char *SaveDataSize;
		
		// String Collections
		u32 DefaultRejectNum;
		char **DefaultReject;
		u32 RejectNum;
		char **Reject;
		u32 IncludeNum;
		char **Include;
		u32 FileNum;
		char **File;
	} Rom;
	
	struct{
		u32 TextNum;
		char **Text;
		u32 ReadOnlyNum;
		char **ReadOnly;
		u32 ReadWriteNum;
		char **ReadWrite;
	} ExeFs;
	
	u32 PlainRegionNum;
	char **PlainRegion;
	
	struct{
		// Strings
		char *Platform;
		char *Category;
		char *UniqueId;
		char *Version;
		char *ContentsIndex;
		char *Variation;
		char *Use; // DELETE
		char *ChildIndex;
		char *DemoIndex;
		char *TargetCategory;
		
		// String Collections
		u32 CategoryFlagsNum;
		char **CategoryFlags;
	} TitleInfo;
	
	struct{
		char *WritableAddress;
		char *CardType;
		char *CryptoType;
		char *CardDevice;
		char *MediaType;
		char *BackupWriteWaitTime;
	} CardInfo;
	
	struct{
		bool Found;

		char *D;
		char *P;
		char *Q;
		char *DP;
		char *DQ;
		char *InverseQ;
		char *Modulus;
		char *Exponent;

		char *AccCtlDescSign;
		char *AccCtlDescBin;
	} CommonHeaderKey;
} rsf_settings;

typedef struct
{
	// General Settings
	char *rsf_path;
	bool outfile_mallocd;
	char *outfile;
	output_format out_format;

	// Content0
	bool ConvertCci;
	char *CciPath;
	bool Content0IsSrl;
	char *SrlPath;

	bool Content0IsNcch;
	COMPONENT_STRUCT Content0;
	char **ContentPath;
	u64 ContentID[CIA_MAX_CONTENT]; // For CIA

	// Ncch0 Build
	bool IsBuildingNCCH0;
	output_format build_ncch_type;
	char *elf_path;
	char *icon_path;
	char *banner_path;
	char *logo_path;

	fixed_accessdesc_type accessdesc;
	bool include_exefs_logo;
	
	char *exefs_code_path;
	char *exheader_path;
	char *plain_region_path;
	char *romfs_path;
	
	// CCI Settings
	bool GenSDKCardInfoHeader;
	bool OmitImportedNcchHdr;

	// CIA Settings
	bool RandomTitleKey;
	bool EncryptContents;
	u16 Version[3];

	// Keys
	keys_struct keys; 
	
	// RSF/DESC Imported Settings
	rsf_settings yaml_set;
} user_settings;
#endif

// Prototypes

void init_UserSettings(user_settings *usr_settings);
void free_UserSettings(user_settings *usr_settings);
int ParseArgs(int argc, char *argv[], user_settings *usr_settings);
void ReadYAMLtest(char *filepath);

void InvalidateRSFBooleans(rsf_settings *rsf_set);
void free_RsfSettings(rsf_settings *set);
