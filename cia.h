// Enums
typedef enum
{
	CIA_NO_NCCH0 = -1,
	CIA_INVALID_NCCH0 = -2,
	CIA_CONFILCTING_CONTENT_IDS = -3,
	CIA_BAD_VERSION = -4,
} cia_errors;

// Structs
typedef struct
{
	u8 HdrSize[4];
	u8 Type[2];
	u8 Version[2];
	u8 CertChainSize[4];
	u8 TicketSize[4];
	u8 TitleMetaDataSize[4];
	u8 CXI_MetaSize[4];
	u8 ContentSize[8];
	u8 ContentIndex[0x2000];
} CIA_Header;

typedef struct
{
	u8 DependancyList[0x30*0x8];
	u8 Reserved0[0x180];
	u8 CoreVersion[4];
	u8 Reserved1[0xfc];
} MetaData_Struct;

typedef struct
{
	FILE *out;

	u8 TitleID[8];
	u8 Title_type[4];
	u16 Version[3];

	keys_struct *keys;

	struct{
		u8 ca_crl_version;
		u8 signer_crl_version;
	} cert;

	struct{
		u8 TicketIssuer[0x40];
		u8 ticket_format_ver;
		u8 TicketID[8];
		u8 DeviceID[8];
		u8 TicketVersion[3];
		u8 TitleKey[16];
	} tik;

	struct{
		u8 TMDIssuer[0x40];
		u8 tmd_format_ver;
		u8 TitleVersion[3];
		u8 SaveDataSize[4];
		u8 PrivSaveDataSize[4];
		u8 twl_flag;
	} tmd;

	struct{
		u8 *content0;
		u64 content0_FileLen;
		bool IsCfa;
		bool KeyNotFound;
		bool EncryptContents;

		FILE **ContentFilePtrs;
		u64 CCIContentOffsets[CCI_MAX_CONTENT];
		u16 ContentCount;
		u64 ContentSize[CIA_MAX_CONTENT];
		u64 ContentOffset[CIA_MAX_CONTENT];
		u16 ContentIndex[CIA_MAX_CONTENT];
		u16 ContentType[CIA_MAX_CONTENT];
		u32 ContentId[CIA_MAX_CONTENT];
		u8 ContentHash[CIA_MAX_CONTENT][0x20];

		u8 ContentTitleId[CIA_MAX_CONTENT][8];
		u64 TotalContentSize;
	} content;

	struct{
		COMPONENT_STRUCT Header;
		
		u32 CertChainOffset;
		COMPONENT_STRUCT CertChain;

		u32 TicketOffset;
		COMPONENT_STRUCT Ticket;

		u32 TitleMetaDataOffset;
		COMPONENT_STRUCT TitleMetaData;

		u32 CXI_MetaDataOffset;
		COMPONENT_STRUCT CXI_MetaData;

		u64 ContentOffset;
	} CIA_Sections;

	// Finish CIA data req.
} cia_settings;

// Public Prototypes
int build_CIA(user_settings *usrset);