#include "lib.h"
#include "cia.h"
#include "tmd.h"

// Private Prototypes
int SetupTMDBuffer(COMPONENT_STRUCT *tik);
int SetupTMDHeader(TMD_Struct *hdr, TMD_CONTENT_INFO_RECORD *info_record, cia_settings *ciaset);
int SignTMDHeader(TMD_Struct *hdr, TMD_SignatureStruct *sig, keys_struct *keys);
int SetupTMDInfoRecord(TMD_CONTENT_INFO_RECORD *info_record, u8 *content_record, u16 ContentCount);
int SetupTMDContentRecord(u8 *content_record, cia_settings *ciaset);

u32 PredictTMDSize(u16 ContentCount)
{
	return sizeof(TMD_SignatureStruct) + sizeof(TMD_Struct) + sizeof(TMD_CONTENT_INFO_RECORD)*64 + sizeof(TMD_CONTENT_CHUNK_STRUCT)*ContentCount;
}

int BuildTMD(cia_settings *ciaset)
{
	int result = 0;
	result = SetupTMDBuffer(&ciaset->CIA_Sections.TitleMetaData);
	if(result) return result;

	// Setting TMD Struct Ptrs
	TMD_SignatureStruct *sig = (TMD_SignatureStruct*)ciaset->CIA_Sections.TitleMetaData.buffer;
	TMD_Struct *hdr = (TMD_Struct*)(ciaset->CIA_Sections.TitleMetaData.buffer+sizeof(TMD_SignatureStruct));
	TMD_CONTENT_INFO_RECORD *info_record = (TMD_CONTENT_INFO_RECORD*)(ciaset->CIA_Sections.TitleMetaData.buffer+sizeof(TMD_SignatureStruct)+sizeof(TMD_Struct));
	u8 *content_record = (u8*)(ciaset->CIA_Sections.TitleMetaData.buffer+sizeof(TMD_SignatureStruct)+sizeof(TMD_Struct)+sizeof(TMD_CONTENT_INFO_RECORD)*64);


	SetupTMDContentRecord(content_record,ciaset);
	SetupTMDInfoRecord(info_record,content_record,ciaset->content.ContentCount);
	result = SetupTMDHeader(hdr,info_record,ciaset);
	if(result) return result;
	result = SignTMDHeader(hdr,sig,ciaset->keys);
	return 0;
}

int SetupTMDBuffer(COMPONENT_STRUCT *tmd)
{
	tmd->buffer = malloc(tmd->size); // already set before
	if(!tmd->buffer) { fprintf(stderr,"[ERROR] MEM ERROR\n"); return MEM_ERROR; }
	memset(tmd->buffer,0,tmd->size);
	return 0;
}

int SetupTMDHeader(TMD_Struct *hdr, TMD_CONTENT_INFO_RECORD *info_record, cia_settings *ciaset)
{
	memset(hdr,0,sizeof(TMD_Struct));

	memcpy(hdr->Issuer,ciaset->tmd.TMDIssuer,0x40);
	hdr->TMDFormatVersion = ciaset->tmd.tmd_format_ver;
	hdr->ca_crl_version = ciaset->cert.ca_crl_version;
	hdr->signer_crl_version = ciaset->cert.signer_crl_version;
	memcpy(hdr->TitleID,ciaset->TitleID,8);
	memcpy(hdr->TitleType,ciaset->Title_type,4);
	memcpy(hdr->SaveDataSize,ciaset->tmd.SaveDataSize,4);
	memcpy(hdr->PrivSaveDataSize,ciaset->tmd.PrivSaveDataSize,4);
	hdr->TWL_Flag = ciaset->tmd.twl_flag;
	memcpy(hdr->TitleVersion,ciaset->tmd.TitleVersion,2);
	u16_to_u8(hdr->ContentCount,ciaset->content.ContentCount,BE);
	ctr_sha(info_record,sizeof(TMD_CONTENT_INFO_RECORD)*64,hdr->sha_256_hash,CTR_SHA_256);
	return 0;
}

int SignTMDHeader(TMD_Struct *hdr, TMD_SignatureStruct *sig, keys_struct *keys)
{
	memset(sig,0,sizeof(TMD_SignatureStruct));
	u32_to_u8(sig->sig_type,RSA_2048_SHA256,BE);
	return ctr_sig((u8*)hdr,sizeof(TMD_Struct),sig->data,keys->rsa.TMD_Pub,keys->rsa.TMD_Priv,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int SetupTMDInfoRecord(TMD_CONTENT_INFO_RECORD *info_record, u8 *content_record, u16 ContentCount)
{
	memset(info_record,0x0,sizeof(TMD_CONTENT_INFO_RECORD)*0x40);
	u16_to_u8(info_record->content_index_offset,0x0,BE);
	u16_to_u8(info_record->content_command_count,ContentCount,BE);
	ctr_sha(content_record,sizeof(TMD_CONTENT_CHUNK_STRUCT)*ContentCount,info_record->sha_256_hash,CTR_SHA_256);
	return 0;
}

int SetupTMDContentRecord(u8 *content_record, cia_settings *ciaset)
{
	for(int i = 0; i < ciaset->content.ContentCount; i++){
		TMD_CONTENT_CHUNK_STRUCT *ptr = (TMD_CONTENT_CHUNK_STRUCT*)(content_record+sizeof(TMD_CONTENT_CHUNK_STRUCT)*i);
		u32_to_u8(ptr->content_id,ciaset->content.ContentId[i],BE);
		u16_to_u8(ptr->content_index,ciaset->content.ContentIndex[i],BE);
		u16_to_u8(ptr->content_type,ciaset->content.ContentType[i],BE);
		u64_to_u8(ptr->content_size,ciaset->content.ContentSize[i],BE);
		memcpy(ptr->sha_256_hash,ciaset->content.ContentHash[i],0x20);
	}
	return 0;
}