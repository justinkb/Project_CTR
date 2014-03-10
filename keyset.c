#include "lib.h"

// KeyData
#include "keys_common.h"
#include "keys_retail.h"
#ifndef PUBLIC_BUILD
#include "keys_debug.h"
#endif

// Private Prototypes
int SetRsaKeySet(u8 **PrivDest, u8 *PrivSource, u8 **PubDest, u8 *PubSource);
int SetUnFixedKey(keys_struct *keys, u8 *UnFixedKey);
void InitCommonKeySlots(keys_struct *keys);

int SetTIK_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetTMD_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetCFA_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetCCI_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetAccessDesc_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetCXI_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);

int SetCaCert(keys_struct *keys, u8 *Cert);
int SetTikCert(keys_struct *keys, u8 *Cert);
int SetTmdCert(keys_struct *keys, u8 *Cert);


// Code
void InitKeys(keys_struct *keys)
{
	memset(keys,0,sizeof(keys_struct));
	InitCommonKeySlots(keys);
}

void SetKeys(keys_struct *keys)
{	
	if(keys->keyset == keyset_RETAIL){
		/* AES Keys */
		// CIA
		//SetCommonKey(keys,(u8*)zeros_fixed_aesKey,1);
		SetCurrentCommonKey(keys,1);
	
		// NCCH
		keys->aes.NormalKey = (u8*)zeros_fixed_aesKey;
		SetSystemFixedKey(keys,(u8*)system_fixed_aesKey);

		/* RSA Keys */
		keys->rsa.FalseSign = true;
		// CIA
		SetTIK_RsaKey(keys,(u8*)Dummy_rsa_privExp,(u8*)Dummy_rsa_pubMod);
		SetTMD_RsaKey(keys,(u8*)Dummy_rsa_privExp,(u8*)Dummy_rsa_pubMod);
		// CFA
		SetCFA_RsaKey(keys,(u8*)Dummy_rsa_privExp,(u8*)Dummy_rsa_pubMod);
		// CCI
		SetCCI_RsaKey(keys,(u8*)Dummy_rsa_privExp,(u8*)Dummy_rsa_pubMod);
		// CXI
		SetAccessDesc_RsaKey(keys,(u8*)Dummy_rsa_privExp,(u8*)Dummy_rsa_pubMod);
	
		/* Certs */
		SetCaCert(keys,(u8*)ca3_dpki_cert);
		SetTikCert(keys,(u8*)xsC_dpki_cert);
		SetTmdCert(keys,(u8*)cpB_dpki_cert);
	}
#ifndef PUBLIC_BUILD
	else if(keys->keyset == keyset_DEBUG){
		/* AES Keys */
		// CIA
		SetCommonKey(keys,(u8*)ctr_aes_common_key_dev0,0);
		SetCommonKey(keys,(u8*)ctr_aes_common_key_dev1,1);
		SetCurrentCommonKey(keys,0);
	
		// NCCH
		keys->aes.NormalKey = (u8*)zeros_fixed_aesKey;
		SetSystemFixedKey(keys,(u8*)system_fixed_aesKey);

		/* RSA Keys */
		// CIA
		SetTIK_RsaKey(keys,(u8*)xs9_dpki_rsa_privExp,(u8*)xs9_dpki_rsa_pubMod);
		SetTMD_RsaKey(keys,(u8*)cpA_dpki_rsa_privExp,(u8*)cpA_dpki_rsa_pubMod);
		// CFA
		SetCFA_RsaKey(keys,(u8*)DevNcsdCfa_privExp,(u8*)DevNcsdCfa_pubMod);
		// CCI
		SetCCI_RsaKey(keys,(u8*)DevNcsdCfa_privExp,(u8*)DevNcsdCfa_pubMod);
		// CXI
		SetAccessDesc_RsaKey(keys,(u8*)AccessDesc_privExp,(u8*)AccessDesc_pubMod);
	
		/* Certs */
		SetCaCert(keys,(u8*)ca4_dpki_cert);
		SetTikCert(keys,(u8*)xs9_dpki_cert);
		SetTmdCert(keys,(u8*)cpA_dpki_cert);
	}
#endif
	// Checking if AccessDesc can be signed
	u8 *tmp = malloc(0x100);
	memset(tmp,0,0x100);
	if(memcmp(tmp,keys->rsa.AccessDesc_Priv,0x100) == 0)
		keys->rsa.RequiresPresignedDesc = true;
	else 
		keys->rsa.RequiresPresignedDesc = false;

	free(tmp);

	return;
}

void FreeKeys(keys_struct *keys)
{
	// AES
	if(keys->aes.CommonKey){
		for(int i = 0; i < 256; i++){
			free(keys->aes.CommonKey[i]);
		}
	}
	free(keys->aes.CommonKey);
	free(keys->aes.SystemFixedKey);
	free(keys->aes.UnFixedKey);
	
	// RSA
	free(keys->rsa.TIK_Priv);
	free(keys->rsa.TIK_Pub);
	free(keys->rsa.TMD_Priv);
	free(keys->rsa.TMD_Pub);

	free(keys->rsa.CFA_Priv);
	free(keys->rsa.CFA_Pub);
	
	free(keys->rsa.CCI_Priv);
	free(keys->rsa.CCI_Pub);
	
	free(keys->rsa.AccessDesc_Priv);
	free(keys->rsa.AccessDesc_Pub);
	
	// Certs
	free(keys->certs.ca_cert);
	free(keys->certs.tik_cert);
	free(keys->certs.tmd_cert);
	memset(keys,0,sizeof(keys_struct));
}

int SetRsaKeySet(u8 **PrivDest, u8 *PrivSource, u8 **PubDest, u8 *PubSource)
{
	int result = 0;
	if(PrivSource){
		result = CopyData(PrivDest,PrivSource,0x100);
		if(result) return result;
	}
	if(PubSource){
		result = CopyData(PubDest,PubSource,0x100);
		if(result) return result;
	}
	return 0;
}

int SetCommonKey(keys_struct *keys, u8 *CommonKey, u8 Index)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.CommonKey[Index],CommonKey,16);
}

void InitCommonKeySlots(keys_struct *keys)
{
	if(!keys->aes.CommonKey){
		keys->aes.CommonKey = malloc(sizeof(u8*)*256);
		memset(keys->aes.CommonKey,0,sizeof(u8*)*256);
	}
}

int SetCurrentCommonKey(keys_struct *keys, u8 Index)
{
	if(!keys) return -1;
	keys->aes.CurrentCommonKey = Index;
	return 0;
}

int SetSystemFixedKey(keys_struct *keys, u8 *SystemFixedKey)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.SystemFixedKey,SystemFixedKey,16);
}

int SetUnFixedKey(keys_struct *keys, u8 *UnFixedKey)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.UnFixedKey,UnFixedKey,16);
}

int SetTIK_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.TIK_Priv,PrivateExp,&keys->rsa.TIK_Pub,PublicMod);
}

int SetTMD_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.TMD_Priv,PrivateExp,&keys->rsa.TMD_Pub,PublicMod);
}

int SetCFA_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.CFA_Priv,PrivateExp,&keys->rsa.CFA_Pub,PublicMod);
}

int SetCCI_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.CCI_Priv,PrivateExp,&keys->rsa.CCI_Pub,PublicMod);
}

int SetAccessDesc_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.AccessDesc_Priv,PrivateExp,&keys->rsa.AccessDesc_Pub,PublicMod);
}

int SetCaCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.ca_cert,Cert,0x400);
}
int SetTikCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.tik_cert,Cert,0x300);
}

int SetTmdCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.tmd_cert,Cert,0x400);
}