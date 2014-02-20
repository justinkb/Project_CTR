#ifndef _NCCH_H_
#define _NCCH_H_

typedef enum
{
	NCCH_MEMERROR = -1,
	SAVE_DATA_TOO_LARGE = -2,
	NCCH_SECTION_NOT_EXIST = -3,
	UNABLE_TO_LOAD_NCCH_KEY = -4,
	NCCH_EXPORT_BUFFER_TOO_SMALL = -5,
	NO_ROMFS_IN_CFA = -6,
	NO_EXHEADER_IN_CXI = -7,
	NO_EXEFS_IN_CXI = -8,
	// SigCheck Errors
	CXI_CORRUPT = -9,
	ACCESSDESC_SIG_BAD = -10,
	NCCH_HDR_SIG_BAD = -11,
	// HashCheck Errors
	ExHeader_Hashfail = -12,
	Logo_Hashfail = -13,
	ExeFs_Hashfail = -14,
	RomFs_Hashfail = -15,
	// Others
	NCCH_BAD_YAML_SET = -16,
	DATA_POS_DNE = -17,
} ncch_errors;

typedef enum
{
	ncch_ExHeader = 1,
	ncch_exefs,
	ncch_romfs,
	ncch_Logo,
	ncch_PlainRegion,
} ncch_section;

typedef enum
{
	NoKey,
	KeyIsNormalFixed,
	KeyIsSystemFixed,
	KeyIsUnFixed,
	KeyIsUnFixed2,
} ncch_key_type;

typedef enum
{
	SecureCrypto2 = 3,
	ContentPlatform = 4,
	ContentType = 5,
	ContentUnitSize = 6,
	OtherFlag = 7
} ncch_flags;

typedef enum
{
	FixedCryptoKey = 0x1,
	NoMountRomFs = 0x2,
	NoCrypto = 0x4,
} ncch_otherflag_bitmask;

typedef enum
{
	RomFS = 0x1,
	ExeFS = 0x2,
	SystemUpdate = 0x4,
	Manual = 0x8,
	Child = (0x4|0x8),
	Trial = 0x10
} ncch_content_bitmask;

typedef struct
{
	u16 version;
	u32 exheader_offset;
	u32 exheader_size;
	u64 logo_offset;
	u64 logo_size;
	u64 plain_region_offset;
	u64 plain_region_size;
	u64 exefs_offset;
	u64 exefs_size;
	u64 exefs_hash_src_size;
	u64 romfs_offset;
	u64 romfs_size;
	u64 romfs_hash_src_size;
	u8 titleID[8];
	u8 programID[8];
}NCCH_STRUCT;

typedef struct
{
	u8 magic[4];
	u8 content_size[4];
	u8 title_id[8];
	u8 maker_code[2];
	u8 version[2];
	u8 reserved_0[4];
	u8 program_id[8];
	u8 reserved_1[0x10];
	u8 logo_sha_256_hash[0x20];
	u8 product_code[0x10];
	u8 extended_header_sha_256_hash[0x20];
	u8 extended_header_size[4];
	u8 reserved_2[4];
	u8 flags[8];
	u8 plain_region_offset[4];
	u8 plain_region_size[4];
	u8 logo_region_offset[4];
	u8 logo_region_size[4];
	u8 exefs_offset[4];
	u8 exefs_size[4];
	u8 exefs_hash_size[4];
	u8 reserved_4[4];
	u8 romfs_offset[4];
	u8 romfs_size[4];
	u8 romfs_hash_size[4];
	u8 reserved_5[4];
	u8 exefs_sha_256_hash[0x20];
	u8 romfs_sha_256_hash[0x20];
} NCCH_Header;


typedef struct
{
	keys_struct *keys;
	rsf_settings *yaml_set;
	COMPONENT_STRUCT *out;

	struct{
		u8 *PubK;
		u8 *PrivK;
	} CxiRsaKey;

	struct
	{
		u32 MediaSize;

		fixed_accessdesc_type accessdesc;

		bool IncludeExeFsLogo;
		bool CompressCode;
		bool UseOnSD;
		bool Encrypt;
		bool FreeProductCode;
		bool IsCfa;
		bool IsBuildingCodeSection;
		bool UseRomFS;
	} Options;

	struct
	{
		FILE *elf;
		u64 elf_size;

		FILE *banner;
		u64 banner_size;

		FILE *icon;
		u64 icon_size;

		FILE *logo;
		u64 logo_size;

		FILE *code;
		u64 code_size;

		FILE *exheader;
		u64 exheader_size;

		FILE *romfs;
		u64 romfs_size;

		FILE *plainregion;
		u64 plainregion_size;
	} ComponentFilePtrs;

	struct
	{
		COMPONENT_STRUCT Code;
		COMPONENT_STRUCT Banner;
		COMPONENT_STRUCT Icon;
	} ExeFs_Sections;

	struct
	{
		u32 TextAddress;
		u32 TextSize;
		u32 TextMaxPages;
		u32 ROAddress;
		u32 ROSize;
		u32 ROMaxPages;
		u32 DataAddress;
		u32 DataSize;
		u32 DataMaxPages;
		u32 BSS_Size;
	} CodeDetails;

	struct
	{
		u64 TotalContentSize;
		COMPONENT_STRUCT CommonHeader;
		COMPONENT_STRUCT ExHeader;
		u64 LogoOffset;
		COMPONENT_STRUCT Logo;
		u64 PlainRegionOffset;
		COMPONENT_STRUCT PlainRegion;
		u64 ExeFsOffset;
		COMPONENT_STRUCT ExeFs;
		u64 RomFsOffset;
		COMPONENT_STRUCT RomFs;
	} Sections;

} ncch_settings;

#endif

// NCCH Build Functions
int build_NCCH(user_settings *usrset);


// NCCH Read Functions
int VerifyNCCH(u8 *ncch, keys_struct *keys, bool SuppressOutput);

u8* RetargetNCCH(FILE *fp, u64 size, u8 *TitleId, u8 *ProgramId, keys_struct *keys);

NCCH_Header* GetNCCH_CommonHDR(void *out, FILE *fp, u8 *buf);
bool IsNCCH(FILE *fp, u8 *buf);
bool IsCfa(NCCH_Header* hdr);
u32 GetNCCH_MediaUnitSize(NCCH_Header* hdr);
u32 GetNCCH_MediaSize(NCCH_Header* hdr);
ncch_key_type GetNCCHKeyType(NCCH_Header* hdr);

int GetNCCHSection(u8 *dest, u64 dest_max_size, u64 src_pos, u8 *ncch, NCCH_STRUCT *ncch_ctx, keys_struct *keys, ncch_section section);
u8* GetNCCHKey(NCCH_Header* hdr, keys_struct *keys);

int GetCXIStruct(NCCH_STRUCT *ctx, NCCH_Header *header);
void ncch_get_counter(NCCH_STRUCT *ctx, u8 counter[16], u8 type);
void CryptNCCHSection(u8 *buffer, u64 size, u64 src_pos, NCCH_STRUCT *ctx, u8 key[16], u8 type);