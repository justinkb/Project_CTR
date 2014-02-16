#ifndef _KEYSET_H_
#define _KEYSET_H_

// Structs

typedef struct
{
	struct
	{
		// CIA
		u8 **CommonKey;
		u8 CurrentCommonKey;		
		
		// NCCH Keys
		u8 *NormalKey;
		u8 *SystemFixedKey;
		u8 *UnFixedKey;
	} aes;
	
	struct
	{
		// CIA RSA
		u8 *TMD_Priv;
		u8 *TMD_Pub;
		u8 *TIK_Priv;
		u8 *TIK_Pub;
		
		// CFA
		u8 *CFA_Priv;
		u8 *CFA_Pub;
		
		// CCI
		u8 *CCI_Priv;
		u8 *CCI_Pub;
		
		// CXI
		u8 *AccessDesc_Priv;
		u8 *AccessDesc_Pub;
	} rsa;
	
	struct
	{
		// CIA
		u8 *ca_cert;
		u8 *tik_cert;
		u8 *tmd_cert;
	} certs;
} keys_struct;

#endif

// Public Prototypes
void InitKeys(keys_struct *keys);
void FreeKeys(keys_struct *keys);

int SetCommonKey(keys_struct *keys, u8 *CommonKey, u8 Index);
int SetCurrentCommonKey(keys_struct *keys, u8 Index);
int SetSystemFixedKey(keys_struct *keys, u8 *SystemFixedKey);
