#include "lib.h"
#include "cia.h"
#include "tik.h"

// Private Prototypes
int SetupTicketBuffer(COMPONENT_STRUCT *tik);
int SetupTicketHeader(TicketStruct *hdr, cia_settings *ciaset);
int SignTicketHeader(TicketStruct *hdr, TicketSignatureStruct *sig, keys_struct *keys);
void SetUnknownTicketData(u8 *dest, u8 type);


int BuildTicket(cia_settings *ciaset)
{
	int result = 0;
	result = SetupTicketBuffer(&ciaset->CIA_Sections.Ticket);
	if(result) return result;
	
	// Setting Ticket Struct Ptrs
	TicketSignatureStruct *sig = (TicketSignatureStruct*)ciaset->CIA_Sections.Ticket.buffer;
	TicketStruct *hdr = (TicketStruct*)(ciaset->CIA_Sections.Ticket.buffer+sizeof(TicketSignatureStruct));

	result = SetupTicketHeader(hdr,ciaset);
	if(result) return result;
	result = SignTicketHeader(hdr,sig,ciaset->keys);
	return 0;
}

int SetupTicketBuffer(COMPONENT_STRUCT *tik)
{
	tik->size = sizeof(TicketSignatureStruct) + sizeof(TicketStruct);
	tik->buffer = malloc(tik->size);
	if(!tik->buffer) { fprintf(stderr,"[ERROR] MEM ERROR\n"); return MEM_ERROR; }
	memset(tik->buffer,0,tik->size);
	return 0;
}

int SetupTicketHeader(TicketStruct *hdr, cia_settings *ciaset)
{
	memset(hdr,0,sizeof(TicketStruct));

	memcpy(hdr->Issuer,ciaset->tik.TicketIssuer,0x40);
	hdr->TicketFormatVersion = ciaset->tik.ticket_format_ver;
	hdr->ca_crl_version = ciaset->cert.ca_crl_version;
	hdr->signer_crl_version = ciaset->cert.signer_crl_version;
	CryptTitleKey(hdr->EncryptedTitleKey, ciaset->tik.TitleKey,ciaset->TitleID,ciaset->keys,ENC);
	memcpy(hdr->TicketID,ciaset->tik.TicketID,8);
	memcpy(hdr->DeviceID,ciaset->tik.DeviceID,8);
	memcpy(hdr->TitleID,ciaset->TitleID,8);
	memcpy(hdr->TicketVersion,ciaset->tik.TicketVersion,2);
	hdr->CommonKeyID = ciaset->keys->aes.CurrentCommonKey;
	SetUnknownTicketData(hdr->StaticData,ciaset->tik.UnknownDataType);
	return 0;
}

int SignTicketHeader(TicketStruct *hdr, TicketSignatureStruct *sig, keys_struct *keys)
{
	memset(sig,0,sizeof(TicketSignatureStruct));
	u32_to_u8(sig->sig_type,RSA_2048_SHA256,BE);
	return ctr_sig((u8*)hdr,sizeof(TicketStruct),sig->data,keys->rsa.TIK_Pub,keys->rsa.TIK_Priv,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CryptTitleKey(u8 *EncTitleKey, u8 *DecTitleKey, u8 *TitleID, keys_struct *keys, u8 mode)
{
	//Generating IV
	u8 iv[16];
	memset(&iv,0x0,16);
	memcpy(iv,TitleID,0x8);
	
	//Setting up Aes Context
	ctr_aes_context ctx;
	memset(&ctx,0x0,sizeof(ctr_aes_context));
	
	//Crypting TitleKey
	ctr_init_aes_cbc(&ctx,keys->aes.CommonKey[keys->aes.CurrentCommonKey],iv,mode);
	if(mode == ENC) ctr_aes_cbc(&ctx,DecTitleKey,EncTitleKey,0x10,ENC);
	else ctr_aes_cbc(&ctx,EncTitleKey,DecTitleKey,0x10,DEC);

	// Return
	return 0;
}

void SetUnknownTicketData(u8 *dest, u8 type)
{
	switch(type){
		case tik_normal: memcpy(dest,normal_static_ticket_data,0x30); break;
		case tik_system: memcpy(dest,system_static_ticket_data,0x30); break;
		case tik_test: memset(dest,0xff,0x30); break;
	}
}
