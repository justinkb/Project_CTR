#ifndef _KEYSET_H_
#define _KEYSET_H_

typedef enum
{
	RSA_1024_KEY_SIZE = 0x80,
	RSA_2048_KEY_SIZE = 0x100,
	RSA_4096_KEY_SIZE = 0x200,
} rsa_keysize;

typedef enum
{
	pki_TEST,
	pki_BETA,
	pki_DEVELOPMENT,
	pki_PRODUCTION,
	pki_CUSTOM,
} pki_keyset;

typedef enum
{
	not_preset,
	app,
	ec_app,
	dlp,
	demo,
} fixed_accessdesc_type;

// Structs

typedef struct
{
	char *keydir;
	pki_keyset keyset;

	bool dumpkeys;

	struct
	{
		fixed_accessdesc_type presetType;
		u32 targetFirmware;
	} accessDescSign;

	struct
	{
		// CIA
		u8 **commonKey;
		u16 currentCommonKey;
		
		// NCCH Keys
		u8 *normalKey;
		u8 *systemFixedKey;

		bool supportUnFixedKeys;
		u8 *ncchKeyX0;
		u8 *ncchKeyX1;
		u8 *unFixedKey0;
		u8 *unFixedKey1;
	} aes;
	
	struct
	{
		bool isFalseSign;
		// CIA RSA
		u8 *cpPvt; //cpPvt
		u8 *cpPub;
		u8 *xsPvt;
		u8 *xsPub;
		
		// CCI/CFA
		u8 *cciCfaPvt;
		u8 *cciCfaPub;
		
		// CXI
		bool requiresPresignedDesc;
		u8 *acexPvt;
		u8 *acexPub;
		u8 *cxiHdrPub;
		u8 *cxiHdrPvt;
	} rsa;
	
	struct
	{
		// CIA
		u8 *caCert;
		u8 *xsCert;
		u8 *cpCert;
	} certs;
} keys_struct;

#endif

// Public Prototypes
void InitKeys(keys_struct *keys);
int SetKeys(keys_struct *keys);
void FreeKeys(keys_struct *keys);

int SetcommonKey(keys_struct *keys, u8 *commonKey, u8 Index);
int SetcurrentCommonKey(keys_struct *keys, u8 Index);
int SetsystemFixedKey(keys_struct *keys, u8 *systemFixedKey);
