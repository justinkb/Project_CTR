#include "lib.h"

// KeyData
#include "tpki.h" // Test PKI
#ifndef PUBLIC_BUILD
#include "ppki.h" // Production PKI
#include "dpki.h" // Development PKI
#endif

// Private Prototypes
int SetRsaKeySet(u8 **PrivDest, u8 *PrivSource, u8 **PubDest, u8 *PubSource);
int SetunFixedKey(keys_struct *keys, u8 *unFixedKey);
void InitcommonKeySlots(keys_struct *keys);

FILE* keyset_OpenFile(char *dir, char *name, bool FileRequired);

int SetTIK_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetTMD_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int Set_CCI_CFA_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetAccessDesc_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetCXI_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);

int SetCaCert(keys_struct *keys, u8 *Cert);
int SetTikCert(keys_struct *keys, u8 *Cert);
int SetTmdCert(keys_struct *keys, u8 *Cert);


// Code
void InitKeys(keys_struct *keys)
{
	memset(keys,0,sizeof(keys_struct));
	InitcommonKeySlots(keys);
	keys->rsa.cxiHdrPub = malloc(RSA_2048_KEY_SIZE);
	keys->rsa.cxiHdrPvt = malloc(RSA_2048_KEY_SIZE);
	keys->aes.supportUnFixedKeys = false;
	keys->aes.unFixedKey0 = malloc(16);
	keys->aes.unFixedKey1 = malloc(16);
}

void PrintBadKeySize(char *path, u32 size)
{
	fprintf(stderr,"[KEYSET ERROR] %s is has invalid size (0x%x)\n",path,size);
}

int SetKeys(keys_struct *keys)
{	
	if(keys->keyset == pki_TEST){ // Ergo False Sign
		/* AES Keys */
		// CIA
		//SetcommonKey(keys,(u8*)zeros_aesKey,1);
		if(keys->aes.currentCommonKey > 0xff)
			SetcurrentCommonKey(keys,0);
	
		// NCCH
		keys->aes.normalKey = (u8*)zeros_aesKey;

		/* RSA Keys */
		keys->rsa.isFalseSign = true;
		// CIA
		SetTIK_RsaKey(keys,(u8*)tpki_rsa_privExp,(u8*)tpki_rsa_pubMod);
		SetTMD_RsaKey(keys,(u8*)tpki_rsa_privExp,(u8*)tpki_rsa_pubMod);
		// CCI/CFA
		Set_CCI_CFA_RsaKey(keys,(u8*)tpki_rsa_privExp,(u8*)tpki_rsa_pubMod);
		// CXI
		SetAccessDesc_RsaKey(keys,(u8*)tpki_rsa_privExp,(u8*)tpki_rsa_pubMod);
	
		/* Certs */
		SetCaCert(keys,(u8*)ca3_tpki_cert);
		SetTikCert(keys,(u8*)xsC_tpki_cert);
		SetTmdCert(keys,(u8*)cpB_tpki_cert);
	}
	else if(keys->keyset == pki_CUSTOM){
		int keydir_pathlen = strlen(keys->keydir);
		char *path = NULL;
#ifdef _WIN32
		char slash = '\\';
#else
		char slash = '/';
#endif
		if(keys->keydir[keydir_pathlen-1] != slash){
			path = malloc(sizeof(char)*(keydir_pathlen+1));
			memset(path,0,sizeof(char)*(keydir_pathlen+1));
			sprintf(path,"%s%c",keys->keydir,slash);
		}
		else{
			path = malloc(sizeof(char)*(keydir_pathlen));
			memset(path,0,sizeof(char)*(keydir_pathlen));
			sprintf(path,"%s",keys->keydir);
		}

		FILE *fp = NULL;

		// NCCH
		keys->aes.normalKey = (u8*)zeros_aesKey;
		fp = keyset_OpenFile(path,"systemfixed.aesKey",false);
		if(fp){
			keys->aes.systemFixedKey = malloc(16);
			fread(keys->aes.systemFixedKey,16,1,fp);
			fclose(fp);
		}

		// commonKeys
		char common_key_name[30];
		for(int i = 0; i < 256; i++){
			memset(common_key_name,0,sizeof(char)*30);
			sprintf(common_key_name,"common_etd_%d.aesKey",i);
			fp = keyset_OpenFile(path,common_key_name,false);
			if(fp){
				keys->aes.commonKey[i] = malloc(16);
				fread(keys->aes.commonKey[i],16,1,fp);
				if(keys->aes.currentCommonKey > 0xff)
					SetcurrentCommonKey(keys,i);
				fclose(fp);
			}
		}
	
		// Certs
		fp = keyset_OpenFile(path,"ca_cpki.cert",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			keys->certs.caCert = malloc(size);
			fread(keys->certs.caCert,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;
		
		fp = keyset_OpenFile(path,"xs_cpki.cert",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			keys->certs.xsCert = malloc(size);
			fread(keys->certs.xsCert,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		fp = keyset_OpenFile(path,"cp_cpki.cert",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			keys->certs.cpCert = malloc(size);
			fread(keys->certs.cpCert,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		// RSA Keys
		fp = keyset_OpenFile(path,"cp_cpki.rsaPubKey",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			if(size != RSA_2048_KEY_SIZE){
				PrintBadKeySize("cp_cpki.rsaPubKey",size);
				return FAILED_TO_IMPORT_FILE;
			}
			keys->rsa.cpPub = malloc(size);
			fread(keys->rsa.cpPub,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		fp = keyset_OpenFile(path,"cp_cpki.rsaPvtKey",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			if(size != RSA_2048_KEY_SIZE){
				PrintBadKeySize("cp_cpki.rsaPvtKey",size);
				return FAILED_TO_IMPORT_FILE;
			}
			keys->rsa.cpPvt = malloc(size);
			fread(keys->rsa.cpPvt,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		fp = keyset_OpenFile(path,"xs_cpki.rsaPubKey",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			if(size != RSA_2048_KEY_SIZE){
				PrintBadKeySize("xs_cpki.rsaPubKey",size);
				return FAILED_TO_IMPORT_FILE;
			}
			keys->rsa.xsPub = malloc(size);
			fread(keys->rsa.xsPub,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		fp = keyset_OpenFile(path,"xs_cpki.rsaPvtKey",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			if(size != RSA_2048_KEY_SIZE){
				PrintBadKeySize("xs_cpki.rsaPvtKey",size);
				return FAILED_TO_IMPORT_FILE;
			}
			keys->rsa.xsPvt = malloc(size);
			fread(keys->rsa.xsPvt,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		fp = keyset_OpenFile(path,"ncsd_cfa.rsaPubKey",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			if(size != RSA_2048_KEY_SIZE){
				PrintBadKeySize("ncsd_cfa.rsaPubKey",size);
				return FAILED_TO_IMPORT_FILE;
			}
			keys->rsa.cciCfaPub = malloc(size);
			fread(keys->rsa.cciCfaPub,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		fp = keyset_OpenFile(path,"ncsd_cfa.rsaPvtKey",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			if(size != RSA_2048_KEY_SIZE){
				PrintBadKeySize("ncsd_cfa.rsaPvtKey",size);
				return FAILED_TO_IMPORT_FILE;
			}
			keys->rsa.cciCfaPvt = malloc(size);
			fread(keys->rsa.cciCfaPvt,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		fp = keyset_OpenFile(path,"acex.rsaPubKey",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			if(size != RSA_2048_KEY_SIZE){
				PrintBadKeySize("acex.rsaPubKey",size);
				return FAILED_TO_IMPORT_FILE;
			}
			keys->rsa.acexPub = malloc(size);
			fread(keys->rsa.acexPub,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

		fp = keyset_OpenFile(path,"acex.rsaPvtKey",true);
		if(fp){
			u32 size = GetFileSize_u32(fp);
			if(size != RSA_2048_KEY_SIZE){
				PrintBadKeySize("acex.rsaPvtKey",size);
				return FAILED_TO_IMPORT_FILE;
			}
			keys->rsa.acexPvt = malloc(size);
			fread(keys->rsa.acexPvt,size,1,fp);
			fclose(fp);
		}
		else
			return FAILED_TO_IMPORT_FILE;

#ifdef DEBUG
	fprintf(stdout,"[DEBUG] Set Keys, free path now\n");
#endif

		free(path);
#ifdef DEBUG
	fprintf(stdout,"[DEBUG] freed path\n");
#endif
	}
#ifndef PUBLIC_BUILD
	else if(keys->keyset == pki_DEVELOPMENT){
		/* AES Keys */
		// CIA
		for(int i = 0; i < 2; i++){
			SetcommonKey(keys,(u8*)ctr_common_etd_key_dpki[i],i);
		}
		if(keys->aes.currentCommonKey > 0xff)
			SetcurrentCommonKey(keys,0);
	
		// NCCH
		keys->aes.normalKey = (u8*)ctr_fixed_ncch_key_dpki[0];
		SetsystemFixedKey(keys,(u8*)ctr_fixed_ncch_key_dpki[1]);
		keys->aes.supportUnFixedKeys = true;
		keys->aes.ncchKeyX0 = (u8*)ctr_unfixed_ncch_keyX_dpki[0];
		keys->aes.ncchKeyX1 = (u8*)ctr_unfixed_ncch_keyX_dpki[1];

		/* RSA Keys */
		// CIA
		SetTIK_RsaKey(keys,(u8*)xs9_dpki_rsa_priv,(u8*)xs9_dpki_rsa_pub);
		SetTMD_RsaKey(keys,(u8*)cpA_dpki_rsa_priv,(u8*)cpA_dpki_rsa_pub);
		// CCI/CFA
		Set_CCI_CFA_RsaKey(keys,(u8*)dev_ncsd_cfa_priv,(u8*)dev_ncsd_cfa_pub);
		// CXI
		SetAccessDesc_RsaKey(keys,(u8*)dev_acex_priv,(u8*)dev_acex_pub);
	
		/* Certs */
		SetCaCert(keys,(u8*)ca4_dpki_cert);
		SetTikCert(keys,(u8*)xs9_dpki_cert);
		SetTmdCert(keys,(u8*)cpA_dpki_cert);
	}
	else if(keys->keyset == pki_PRODUCTION){
		/* AES Keys */
		// CIA
		for(int i = 0; i < 6; i++){
			keys->aes.commonKey[i] = AesKeyScrambler((u8*)ctr_common_etd_keyX_ppki,(u8*)ctr_common_etd_keyY_ppki[i]);
		}
		SetcurrentCommonKey(keys,1);
	
		// NCCH
		keys->aes.normalKey = (u8*)zeros_aesKey;
		/*
		keys->aes.supportUnFixedKeys = true;
		keys->aes.ncchKeyX0 = (u8*)ctr_unfixed_ncch_keyX_ppki[0];
		keys->aes.ncchKeyX1 = (u8*)ctr_unfixed_ncch_keyX_ppki[1];
		*/

		/* RSA Keys */
		// CIA
		SetTIK_RsaKey(keys,(u8*)xsC_ppki_rsa_priv,(u8*)xsC_ppki_rsa_pub);
		SetTMD_RsaKey(keys,(u8*)cpB_ppki_rsa_priv,(u8*)cpB_ppki_rsa_pub);
		// CCI/CFA
		Set_CCI_CFA_RsaKey(keys,(u8*)prod_ncsd_cfa_priv,(u8*)prod_ncsd_cfa_pub);
		// CXI
		SetAccessDesc_RsaKey(keys,(u8*)prod_acex_priv,(u8*)prod_acex_pub);
	
		/* Certs */
		SetCaCert(keys,(u8*)ca3_ppki_cert);
		SetTikCert(keys,(u8*)xsC_ppki_cert);
		SetTmdCert(keys,(u8*)cpB_ppki_cert);
	}


#endif
#ifdef DEBUG
	fprintf(stdout,"[DEBUG] Checking if access desc\n");
#endif
	// Checking if AccessDesc can be signed
	u8 *tmp = malloc(0x100);
	memset(tmp,0,0x100);
	if(memcmp(tmp,keys->rsa.acexPvt,0x100) == 0)
		keys->rsa.requiresPresignedDesc = true;
	else 
		keys->rsa.requiresPresignedDesc = false;

	free(tmp);

	
	if(keys->dumpkeys)
	{
		printf("[+] Keys\n");
		
		printf(" > eTicket Common Keys\n");
		for(int i = 0; i < 256; i++)
		{
			if(keys->aes.commonKey[i])
			{
				printf(" [0x%02x]     ",i);
				memdump(stdout,"",keys->aes.commonKey[i],16);
			}
		}
		printf(" > Fixed NCCH Keys\n");
		memdump(stdout," [Normal]   ",keys->aes.normalKey,16);
		if(keys->aes.systemFixedKey)
			memdump(stdout," [System]   ",keys->aes.systemFixedKey,16);
		printf(" > TIK RSA Keys\n");
		memdump(stdout," [PUB]      ",keys->rsa.xsPub,0x100);
		memdump(stdout," [PVT]      ",keys->rsa.xsPvt,0x100);
		printf(" > TMD RSA Keys\n");
		memdump(stdout," [PUB]      ",keys->rsa.cpPub,0x100);
		memdump(stdout," [PVT]      ",keys->rsa.cpPvt,0x100);
		printf(" > AcexDesc RSA Keys\n");
		memdump(stdout," [PUB]      ",keys->rsa.acexPub,0x100);
		memdump(stdout," [PVT]      ",keys->rsa.acexPvt,0x100);
		printf(" > NcsdCfa RSA Keys\n");
		memdump(stdout," [PUB]      ",keys->rsa.cciCfaPub,0x100);
		memdump(stdout," [PVT]      ",keys->rsa.cciCfaPvt,0x100);
	}
	
#ifdef DEBUG
	fprintf(stdout,"[DEBUG] Done setting keys\n");
#endif
	return 0;
}

FILE* keyset_OpenFile(char *dir, char *name, bool FileRequired)
{
	int file_path_len = sizeof(char)*(strlen(dir)+strlen(name)+1);
	char *file_path = malloc(file_path_len);
	memset(file_path,0,file_path_len);

	sprintf(file_path,"%s%s",dir,name);

	FILE *fp = fopen(file_path,"rb");
	
	if(!fp && FileRequired)
		fprintf(stderr,"[KEYSET ERROR] Failed to open: %s\n",file_path);

	free(file_path);
	return fp;
}

void FreeKeys(keys_struct *keys)
{
	// AES
	if(keys->aes.commonKey){
		for(int i = 0; i < 256; i++){
			free(keys->aes.commonKey[i]);
		}
	}
	free(keys->aes.commonKey);
	free(keys->aes.systemFixedKey);
	free(keys->aes.unFixedKey0);
	free(keys->aes.unFixedKey1);
	
	// RSA
	free(keys->rsa.xsPvt);
	free(keys->rsa.xsPub);
	free(keys->rsa.cpPvt);
	free(keys->rsa.cpPub);

	free(keys->rsa.cciCfaPvt);
	free(keys->rsa.cciCfaPub);
	
	free(keys->rsa.acexPvt);
	free(keys->rsa.acexPub);
	free(keys->rsa.cxiHdrPub);
	free(keys->rsa.cxiHdrPvt);
	
	// Certs
	free(keys->certs.caCert);
	free(keys->certs.xsCert);
	free(keys->certs.cpCert);
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

int SetcommonKey(keys_struct *keys, u8 *commonKey, u8 Index)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.commonKey[Index],commonKey,16);
}

void InitcommonKeySlots(keys_struct *keys)
{
	if(!keys->aes.commonKey){
		keys->aes.commonKey = malloc(sizeof(u8*)*256);
		memset(keys->aes.commonKey,0,sizeof(u8*)*256);
	}
}

int SetcurrentCommonKey(keys_struct *keys, u8 Index)
{
	if(!keys) return -1;
	keys->aes.currentCommonKey = Index;
	return 0;
}

int SetsystemFixedKey(keys_struct *keys, u8 *systemFixedKey)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.systemFixedKey,systemFixedKey,16);
}

int SetTIK_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.xsPvt,PrivateExp,&keys->rsa.xsPub,PublicMod);
}

int SetTMD_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.cpPvt,PrivateExp,&keys->rsa.cpPub,PublicMod);
}

int Set_CCI_CFA_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.cciCfaPvt,PrivateExp,&keys->rsa.cciCfaPub,PublicMod);
}

int SetAccessDesc_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.acexPvt,PrivateExp,&keys->rsa.acexPub,PublicMod);
}

int SetCaCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.caCert,Cert,0x400);
}
int SetTikCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.xsCert,Cert,0x300);
}

int SetTmdCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.cpCert,Cert,0x400);
}