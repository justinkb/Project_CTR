#include "lib.h"
#include "ncch.h"
#include "exheader.h"
#include "exefs.h"
#include "certs.h"
#include "cia.h"
#include "tik.h"
#include "tmd.h"
#include "titleid.h"
#include "srl.h"
#include "ncsd.h"

// Private Prototypes
/* cia_settings tools */
void init_CIASettings(cia_settings *set);
void free_CIASettings(cia_settings *set);
int get_CIASettings(cia_settings *ciaset, user_settings *usrset);

int GetSettingsFromUsrset(cia_settings *ciaset, user_settings *usrset);
int GetSettingsFromNcch0(cia_settings *ciaset, u32 ncch0_offset);
int GetCIADataFromNcch(cia_settings *ciaset, NCCH_Header *NcchHdr, ExtendedHeader_Struct *ExHeader);
int GetMetaRegion(cia_settings *ciaset, ExtendedHeader_Struct *ExHeader, u8 *ExeFs);
int GetContentFilePtrs(cia_settings *ciaset, user_settings *usrset);
int GetSettingsFromSrl(cia_settings *ciaset);
int GetSettingsFromCci(cia_settings *ciaset);

u16 SetupVersion(u16 Major, u16 Minor, u16 Micro);

int BuildCIA_CertChain(cia_settings *ciaset);
int BuildCIA_Header(cia_settings *ciaset);

int WriteCurrentSectionstoFile(cia_settings *ciaset);
int WriteContentsToFile(cia_settings *ciaset, user_settings *usrset);
int WriteTMDToFile(cia_settings *ciaset);

int CryptContent(u8 *EncBuffer,u8 *DecBuffer,u64 size,u8 *title_key, u16 index, u8 mode);


int build_CIA(user_settings *usrset)
{
	int result = 0;

	// Init Settings
	cia_settings *ciaset = malloc(sizeof(cia_settings));
	if(!ciaset) {fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); return MEM_ERROR;}
	init_CIASettings(ciaset);

	// Get Settings
	result = get_CIASettings(ciaset,usrset);
	if(result) goto finish;

	// Create Output File
	ciaset->out = fopen(usrset->outfile,"wb");
	if(!ciaset->out){
		fprintf(stderr,"[CIA ERROR] Failed to create '%s'\n",usrset->outfile);
		result = FAILED_TO_CREATE_OUTFILE;
		goto finish;
	}

	// Create CIA Sections
	/* Certificate Chain */
	result = BuildCIA_CertChain(ciaset);
	if(result) goto finish;

	/* Ticket */
	result = BuildTicket(ciaset);
	if(result) goto finish;

	/* CIA Header */
	result = BuildCIA_Header(ciaset);
	if(result) goto finish;
	/* Write To File Current Sections to File */
	/* Explanation :
		In order to conserve memory, only one Content is in memory at a time.
		This however has the limitation of only being able to generate TMD after all content 
		has been processed (, encrypted) and written to file.
	*/
	result = WriteCurrentSectionstoFile(ciaset);
	if(result) goto finish;

	result = WriteContentsToFile(ciaset, usrset);
	if(result) goto finish;

	result = BuildTMD(ciaset);
	if(result) goto finish;

	result = WriteTMDToFile(ciaset);

finish:
	if(result != FAILED_TO_CREATE_OUTFILE && ciaset->out) fclose(ciaset->out);
	free_CIASettings(ciaset);
	return result;
}

void init_CIASettings(cia_settings *set)
{
	memset(set,0,sizeof(cia_settings));
}

void free_CIASettings(cia_settings *set)
{
	if(set->content.ContentFilePtrs){
		for(u32 i = 1; i < set->content.ContentCount; i++){
			fclose(set->content.ContentFilePtrs[i]);
		}
		free(set->content.ContentFilePtrs);
	}
	free(set->CIA_Sections.CertChain.buffer);
	free(set->CIA_Sections.Ticket.buffer);
	free(set->CIA_Sections.TitleMetaData.buffer);
	free(set->CIA_Sections.CXI_MetaData.buffer);

	memset(set,0,sizeof(cia_settings));

	free(set);
}

int get_CIASettings(cia_settings *ciaset, user_settings *usrset)
{
	int result = 0;

	// Transfering data from usrset
	result = GetSettingsFromUsrset(ciaset,usrset);

	if(usrset->Content0IsNcch){
		result = GetSettingsFromNcch0(ciaset,0);
		if(result) return result;
		result = GetContentFilePtrs(ciaset,usrset);
		if(result) return result;
	}

	else if(usrset->Content0IsSrl){
		result = GetSettingsFromSrl(ciaset);
		if(result) return result;
	}

	else if(usrset->ConvertCci){
		result = GetSettingsFromCci(ciaset);
		if(result) return result;
	}
	

	return 0;
}

int GetSettingsFromUsrset(cia_settings *ciaset, user_settings *usrset)
{
	// General Stuff
	ciaset->keys = &usrset->keys;
	ciaset->content.content0 = usrset->Content0.buffer;
	ciaset->content.content0_FileLen = usrset->Content0.size;
	u32_to_u8(ciaset->Title_type,TYPE_CTR,BE);
	ciaset->content.EncryptContents = usrset->EncryptContents;
	ciaset->cert.ca_crl_version = 0;
	ciaset->cert.signer_crl_version = 0;

	for(int i = 0; i < 3; i++){
		ciaset->Version[i] = usrset->Version[i];
	}

	// Random Number generator
	u8 hash[0x20];
	ctr_sha(ciaset->content.content0,0x100,hash,CTR_SHA_256);
	
	// Ticket Data
	memcpy(ciaset->tik.TicketID,(hash+0x8),8);
	if(usrset->RandomTitleKey){
		memcpy(ciaset->tik.TitleKey,(hash+0x10),16);
	}
	else{
		memcpy(ciaset->tik.TitleKey,usrset->keys.aes.NormalKey,16);
	}
	
	ciaset->tik.ticket_format_ver = 1;
	ciaset->tik.UnknownDataType = tik_normal;

	int result = GenCertChildIssuer(ciaset->tik.TicketIssuer,usrset->keys.certs.tik_cert);
	if(result) return result;
	
	// Tmd Stuff
	if(usrset->ContentID[0] > 0xffffffff){
		ciaset->content.ContentId[0] = u8_to_u32(hash,BE);
	}
	else ciaset->content.ContentId[0] = usrset->ContentID[0];
	ciaset->tmd.tmd_format_ver = 1;
	result = GenCertChildIssuer(ciaset->tmd.TMDIssuer,usrset->keys.certs.tmd_cert);
	return 0;
}

int GetSettingsFromNcch0(cia_settings *ciaset, u32 ncch0_offset)
{
	/* Sanity Checks */
	if(!ciaset->content.content0_FileLen) 
		return CIA_NO_NCCH0;

	u8 *ncch0 = (u8*)(ciaset->content.content0+ncch0_offset);

	if(!IsNCCH(NULL,ncch0)){
		fprintf(stderr,"[CIA ERROR] Content0 is not NCCH\n");
		return CIA_INVALID_NCCH0;
	}

	/* Get Ncch0 Header */
	NCCH_Header *hdr = NULL;
	hdr = GetNCCH_CommonHDR(hdr,NULL,ncch0);
	if(IsCfa(hdr)){
		ciaset->content.IsCfa = true;
	}

	ciaset->content.ContentOffset[0] = 0;
	ciaset->content.ContentSize[0] = GetNCCH_MediaSize(hdr)*GetNCCH_MediaUnitSize(hdr);
	ciaset->content.TotalContentSize = ciaset->content.ContentSize[0];

	/* Get Ncch0 Import Context */
	NCCH_STRUCT *ncch_ctx = malloc(sizeof(NCCH_STRUCT));
	if(!ncch_ctx){ fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); return MEM_ERROR; }
	memset(ncch_ctx,0x0,sizeof(NCCH_STRUCT));
	GetCXIStruct(ncch_ctx,hdr);

	/* Verify Ncch0 (Sig&Hash Checks) */
	int result = VerifyNCCH(ncch0,ciaset->keys,true);
	if(result == UNABLE_TO_LOAD_NCCH_KEY){
		ciaset->content.KeyNotFound = true;
		if(!ciaset->content.IsCfa){
			fprintf(stderr,"[CIA WARNING] CXI AES Key could not be loaded\n");
			fprintf(stderr,"      Meta Region, SaveDataSize, Remaster Version cannot be obtained\n");
		}
	}
	else if(result != 0){
		fprintf(stderr,"[CIA ERROR] Content 0 Is Corrupt (res = %d)\n",result);
		return CIA_INVALID_NCCH0;
	}

	/* Gen Settings From Ncch0 */
	endian_memcpy(ciaset->TitleID,hdr->title_id,8,LE);


	/* Getting ExeFs/ExHeader */
	u8 *ExeFs = malloc(ncch_ctx->exefs_size);
	if(!ExeFs){ fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); return MEM_ERROR; }
	ExtendedHeader_Struct *ExHeader = malloc(ncch_ctx->exheader_size);
	if(!ExHeader){ fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); free(ExeFs); return MEM_ERROR; }

	if(!(ciaset->content.IsCfa||ciaset->content.KeyNotFound)) GetNCCHSection(ExeFs, ncch_ctx->exefs_size, 0, ncch0, ncch_ctx, ciaset->keys, ncch_exefs);
	if(!(ciaset->content.IsCfa||ciaset->content.KeyNotFound)) GetNCCHSection((u8*)ExHeader, ncch_ctx->exheader_size, 0, ncch0, ncch_ctx, ciaset->keys, ncch_ExHeader);
	
	result = GetCIADataFromNcch(ciaset,hdr,ExHeader); // Data For TMD
	if(result) goto finish;
	result = GetMetaRegion(ciaset,ExHeader,ExeFs); // Meta Region
	/* Finish */
finish:
	free(ExeFs);
	free(ExHeader);

	/* Return */
	free(ncch_ctx);
	return result;	
}

int GetCIADataFromNcch(cia_settings *ciaset, NCCH_Header *NcchHdr, ExtendedHeader_Struct *ExHeader)
{
	u16 Category = u8_to_u16((ciaset->TitleID+2),BE);
	bool IsPatch = (Category == 0x000E);
	if(IsPatch||ciaset->content.IsCfa||ciaset->content.KeyNotFound) u32_to_u8(ciaset->tmd.SaveDataSize,0,LE);
	else u32_to_u8(ciaset->tmd.SaveDataSize,(u32)GetSaveDataSize_frm_exhdr(ExHeader),LE);

	
	if(ciaset->content.IsCfa||ciaset->content.KeyNotFound){
		if(ciaset->Version[0] == 0xffff){ // '-major' wasn't set
			if(ciaset->content.IsCfa){ // Is a CFA and can be decrypted
				fprintf(stderr,"[CIA ERROR] Invalid major version. Use '-major' option.\n");
				return CIA_BAD_VERSION;
			}
			else // CXI which cannot be decrypted
				ciaset->Version[0] = 0;
		}
	}
	else{ // Is a CXI and can be decrypted
		if(ciaset->Version[0] != 0xffff){ // '-major' was set
			fprintf(stderr,"[CIA ERROR] Option '-major' cannot be applied for cxi.\n");
			return CIA_BAD_VERSION;
		}
		// Setting remaster ver
		ciaset->Version[0] = GetRemasterVersion_frm_exhdr(ExHeader);
	}
	SetupVersion(ciaset->Version[0],ciaset->Version[1],ciaset->Version[2]);

	u16 version = SetupVersion(ciaset->Version[0],ciaset->Version[1],ciaset->Version[2]);
	u16_to_u8(ciaset->tik.TicketVersion,version,BE);
	u16_to_u8(ciaset->tmd.TitleVersion,version,BE);
	return 0;
}

int GetMetaRegion(cia_settings *ciaset, ExtendedHeader_Struct *ExHeader, u8 *ExeFs)
{
	if(ciaset->content.IsCfa || ciaset->content.KeyNotFound) return 0;
	ciaset->CIA_Sections.CXI_MetaData.size = sizeof(MetaData_Struct) + GetExeFsSectionSize("icon",ExeFs);
	ciaset->CIA_Sections.CXI_MetaData.buffer = malloc(ciaset->CIA_Sections.CXI_MetaData.size);
	if(!ciaset->CIA_Sections.CXI_MetaData.buffer){ fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); return MEM_ERROR; }
	MetaData_Struct *hdr = (MetaData_Struct*)ciaset->CIA_Sections.CXI_MetaData.buffer;
	memset(hdr,0,sizeof(MetaData_Struct));
	GetDependancyList_frm_exhdr(hdr->DependancyList,ExHeader);
	GetCoreVersion_frm_exhdr(hdr->CoreVersion,ExHeader);
	if(DoesExeFsSectionExist("icon",ExeFs)){
		u8 *IconDestPos = (ciaset->CIA_Sections.CXI_MetaData.buffer + sizeof(MetaData_Struct));
		memcpy(IconDestPos,GetExeFsSection("icon",ExeFs),GetExeFsSectionSize("icon",ExeFs));
	}
	return 0;
}

int GetContentFilePtrs(cia_settings *ciaset, user_settings *usrset)
{
	ciaset->content.ContentFilePtrs = malloc(sizeof(FILE*)*CIA_MAX_CONTENT);
	if(!ciaset->content.ContentFilePtrs){ fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); return MEM_ERROR; }
	memset(ciaset->content.ContentFilePtrs,0,sizeof(FILE*)*CIA_MAX_CONTENT);
	int j = 1;
	NCCH_Header *hdr = malloc(sizeof(NCCH_Header));
	for(int i = 1; i < CIA_MAX_CONTENT; i++){
		if(usrset->ContentPath[i]){
			ciaset->content.ContentFilePtrs[j] = fopen(usrset->ContentPath[i],"rb");
			if(!ciaset->content.ContentFilePtrs[j]){ fprintf(stderr,"[CIA ERROR] Failed to open '%s'\n",usrset->ContentPath[i]); return FAILED_TO_OPEN_FILE; }
			if(usrset->ContentID[i] == 0x100000000){
				u8 hash[0x20];
				ctr_sha(usrset->ContentPath[i],strlen(usrset->ContentPath[i]),hash,CTR_SHA_256);
				ciaset->content.ContentId[j]  = u8_to_u32(hash,BE);
			}
			else ciaset->content.ContentId[j] = (u32)usrset->ContentID[i];
			ciaset->content.ContentIndex[j] = (u16)i;

			// Get Data from ncch HDR
			GetNCCH_CommonHDR(hdr,ciaset->content.ContentFilePtrs[j],NULL);

			// Get TitleID
			memcpy(ciaset->content.ContentTitleId[j],hdr->title_id,8);
			
			// Get Size
			ciaset->content.ContentSize[j] =  GetNCCH_MediaSize(hdr)*GetNCCH_MediaUnitSize(hdr);
			ciaset->content.ContentOffset[j] = ciaset->content.TotalContentSize;
			
			ciaset->content.TotalContentSize += ciaset->content.ContentSize[j];
			

			// Finish get next content
			j++;
		}
	}
	free(hdr);
	ciaset->content.ContentCount = j;

	// Check Conflicting IDs
	for(int i = 0; i < ciaset->content.ContentCount; i++){
		for(j = i+1; j < ciaset->content.ContentCount; j++){
			if(ciaset->content.ContentId[j] == ciaset->content.ContentId[i]){
				fprintf(stderr,"[CIA ERROR] CIA Content %d and %d, have conflicting IDs\n",ciaset->content.ContentIndex[j],ciaset->content.ContentIndex[i]);
				return CIA_CONFILCTING_CONTENT_IDS;
			}
		}
	}
	return 0;
}

int GetSettingsFromSrl(cia_settings *ciaset)
{
	SRL_Header *hdr = (SRL_Header*)ciaset->content.content0;
	if(!hdr || ciaset->content.content0_FileLen < sizeof(SRL_Header)) {
		fprintf(stderr,"[CIA ERROR] Invalid TWL SRL File\n");
		return FAILED_TO_IMPORT_FILE;
	}
	
	// Check if TWL SRL File
	if(u8_to_u16(&hdr->title_id[6],LE) != 0x0003){
		fprintf(stderr,"[CIA ERROR] Invalid TWL SRL File\n");
		return FAILED_TO_IMPORT_FILE;
	}

	// Generate and store Converted TitleID
	u64_to_u8(ciaset->TitleID,ConvertTwlIdToCtrId(u8_to_u64(hdr->title_id,LE)),BE);
	//memdump(stdout,"SRL TID: ",ciaset->TitleID,8);

	// Get TWL Flag
	ciaset->tmd.twl_flag = ((hdr->reserved_flags[3] & 6) >> 1);

	// Get Remaster Version
	u16 version = SetupVersion(hdr->rom_version,ciaset->Version[1],0);
	u16_to_u8(ciaset->tik.TicketVersion,version,BE);
	u16_to_u8(ciaset->tmd.TitleVersion,version,BE);

	// Get SaveDataSize (Public and Private)
	memcpy(ciaset->tmd.SaveDataSize,hdr->pub_save_data_size,4);
	memcpy(ciaset->tmd.PrivSaveDataSize,hdr->priv_save_data_size,4);

	// Setting CIA Content Settings
	ciaset->content.ContentCount = 1;
	ciaset->content.ContentOffset[0] = 0;
	ciaset->content.ContentSize[0] = ciaset->content.content0_FileLen;
	ciaset->content.TotalContentSize = ciaset->content.content0_FileLen;

	return 0;
}



int GetSettingsFromCci(cia_settings *ciaset)
{
	int result = 0;

	if(!IsCci(ciaset->content.content0)){
		fprintf(stderr,"[CIA ERROR] Invalid CCI file\n");
		return FAILED_TO_IMPORT_FILE;
	}
	
	u32 ncch0_offset = GetPartitionOffset(ciaset->content.content0,0);
	if(!ncch0_offset){
		fprintf(stderr,"[CIA ERROR] Invalid CCI file (invalid ncch0 size)\n");
		return FAILED_TO_IMPORT_FILE;
	}

	result = GetSettingsFromNcch0(ciaset, ncch0_offset);
	if(result){
		fprintf(stderr,"Import of Ncch 0 failed(%d)\n",result);	
		return result;
	}
	ciaset->content.ContentCount = 1;
	ciaset->content.CCIContentOffsets[0] = ncch0_offset;
	NCCH_Header *hdr = malloc(sizeof(NCCH_Header));
	for(int i = 1; i < 8; i++){
		if(GetPartitionSize(ciaset->content.content0,i)){
			ciaset->content.CCIContentOffsets[ciaset->content.ContentCount] = GetPartitionOffset(ciaset->content.content0,i);

			// Get Data from ncch HDR
			GetNCCH_CommonHDR(hdr,NULL,GetPartition(ciaset->content.content0,i));
			
			// Get Size
			ciaset->content.ContentSize[ciaset->content.ContentCount] =  GetPartitionSize(ciaset->content.content0,i);
			ciaset->content.ContentOffset[ciaset->content.ContentCount] = ciaset->content.TotalContentSize;
			
			ciaset->content.TotalContentSize += ciaset->content.ContentSize[ciaset->content.ContentCount];
			
			// Get ID
			u8 hash[0x20];
			ctr_sha((u8*)hdr,0x200,hash,CTR_SHA_256);
			ciaset->content.ContentId[ciaset->content.ContentCount] = u8_to_u32(hash,BE);

			// Get Index
			ciaset->content.ContentIndex[ciaset->content.ContentCount] = i;

			// Increment Content Count
			ciaset->content.ContentCount++;
		}
	}
	free(hdr);

	return 0;
}

u16 SetupVersion(u16 Major, u16 Minor, u16 Micro)
{
	return (((Major << 10) & 0xFC00) | ((Minor << 4) & 0x3F0) | (Micro & 0xf));
}

int BuildCIA_CertChain(cia_settings *ciaset)
{
	ciaset->CIA_Sections.CertChain.size = GetCertSize(ciaset->keys->certs.ca_cert) + GetCertSize(ciaset->keys->certs.tik_cert) + GetCertSize(ciaset->keys->certs.tmd_cert);
	ciaset->CIA_Sections.CertChain.buffer = malloc(ciaset->CIA_Sections.CertChain.size);
	if(!ciaset->CIA_Sections.CertChain.buffer) { fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); return MEM_ERROR; }
	memcpy(ciaset->CIA_Sections.CertChain.buffer,ciaset->keys->certs.ca_cert,GetCertSize(ciaset->keys->certs.ca_cert));
	memcpy((ciaset->CIA_Sections.CertChain.buffer+GetCertSize(ciaset->keys->certs.ca_cert)),ciaset->keys->certs.tik_cert,GetCertSize(ciaset->keys->certs.tik_cert));
	memcpy((ciaset->CIA_Sections.CertChain.buffer+GetCertSize(ciaset->keys->certs.ca_cert)+GetCertSize(ciaset->keys->certs.tik_cert)),ciaset->keys->certs.tmd_cert,GetCertSize(ciaset->keys->certs.tmd_cert));
	return 0;
}

int BuildCIA_Header(cia_settings *ciaset)
{
	// Allocating memory for header
	ciaset->CIA_Sections.Header.size = sizeof(CIA_Header);
	ciaset->CIA_Sections.Header.buffer = malloc(ciaset->CIA_Sections.Header.size);
	if(!ciaset->CIA_Sections.Header.buffer){ fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); return MEM_ERROR; }
	
	CIA_Header *hdr = (CIA_Header*)ciaset->CIA_Sections.Header.buffer;

	// Clearing 
	memset(hdr,0,sizeof(CIA_Header));

	// Predict TMD Size
	ciaset->CIA_Sections.TitleMetaData.size = PredictTMDSize(ciaset->content.ContentCount);

	// Setting Data
	u32_to_u8(hdr->HdrSize,sizeof(CIA_Header),LE);
	u16_to_u8(hdr->Type,0x0,LE);
	u16_to_u8(hdr->Version,0x0,LE);
	u32_to_u8(hdr->CertChainSize,ciaset->CIA_Sections.CertChain.size,LE);
	u32_to_u8(hdr->TicketSize,ciaset->CIA_Sections.Ticket.size,LE);
	u32_to_u8(hdr->TitleMetaDataSize,ciaset->CIA_Sections.TitleMetaData.size,LE);
	u32_to_u8(hdr->CXI_MetaSize,ciaset->CIA_Sections.CXI_MetaData.size,LE);
	u64_to_u8(hdr->ContentSize,ciaset->content.TotalContentSize,LE);

	// Recording Offsets
	ciaset->CIA_Sections.CertChainOffset = align_value(sizeof(CIA_Header),0x40);
	ciaset->CIA_Sections.TicketOffset = align_value(ciaset->CIA_Sections.CertChainOffset+ciaset->CIA_Sections.CertChain.size,0x40);
	ciaset->CIA_Sections.TitleMetaDataOffset = align_value(ciaset->CIA_Sections.TicketOffset+ciaset->CIA_Sections.Ticket.size,0x40);
	ciaset->CIA_Sections.ContentOffset = align_value(ciaset->CIA_Sections.TitleMetaDataOffset+ciaset->CIA_Sections.TitleMetaData.size,0x40);
	ciaset->CIA_Sections.CXI_MetaDataOffset = align_value(ciaset->CIA_Sections.ContentOffset+ciaset->content.TotalContentSize,0x40);
	
	// SetCIAContentIndex, actually works for all index values now. CIA files generated can now hold, with
	// validity, 65536 contents. Or at least have a content with index value of 65535.
	for(int i = 0; i < ciaset->content.ContentCount; i++){
		// This works by treating the 0x2000 byte index array as an array of 2048 u32 values
		
		// Used for determining which u32 chunk to write the value to
		u16 section = ciaset->content.ContentIndex[i]/32;
		
		// Calculating the value added to the u32
		u32 value = 0x80000000/(1<<ciaset->content.ContentIndex[i]);
		
		// Retrieving current u32 block
		u32 cur_content_index_section = u8_to_u32(hdr->ContentIndex+(sizeof(u32)*section),BE);
		
		// Adding value to block
		cur_content_index_section += value;
		
		// Returning block
		u32_to_u8(hdr->ContentIndex+(sizeof(u32)*section),cur_content_index_section,BE);
	}
	return 0;
}

int WriteCurrentSectionstoFile(cia_settings *ciaset)
{
	WriteBuffer(ciaset->CIA_Sections.Header.buffer,ciaset->CIA_Sections.Header.size,0,ciaset->out);
	WriteBuffer(ciaset->CIA_Sections.CertChain.buffer,ciaset->CIA_Sections.CertChain.size,ciaset->CIA_Sections.CertChainOffset,ciaset->out);
	WriteBuffer(ciaset->CIA_Sections.Ticket.buffer,ciaset->CIA_Sections.Ticket.size,ciaset->CIA_Sections.TicketOffset,ciaset->out);
	WriteBuffer(ciaset->CIA_Sections.CXI_MetaData.buffer,ciaset->CIA_Sections.CXI_MetaData.size,ciaset->CIA_Sections.CXI_MetaDataOffset,ciaset->out);
	return 0;
}

int WriteContentsToFile(cia_settings *ciaset, user_settings *usrset)
{
	u8 *Content0 = ciaset->content.content0;
	if(usrset->ConvertCci) Content0 = (u8*)(ciaset->content.content0+ciaset->content.CCIContentOffsets[0]);

	ctr_sha(Content0,ciaset->content.ContentSize[0],ciaset->content.ContentHash[0],CTR_SHA_256);
	if(ciaset->content.EncryptContents) {
		ciaset->content.ContentType[0] |= Encrypted;
		CryptContent(Content0,Content0,ciaset->content.ContentSize[0],ciaset->tik.TitleKey,ciaset->content.ContentIndex[0],ENC);
	}
	WriteBuffer(Content0,ciaset->content.ContentSize[0],ciaset->content.ContentOffset[0]+ciaset->CIA_Sections.ContentOffset,ciaset->out);
	
	// Free Buffer if Not CCI
	if(!usrset->ConvertCci){
		free(usrset->Content0.buffer);
		usrset->Content0.buffer = NULL;
		usrset->Content0.size = 0;
	}

	// Add additional contents, recreating them with their new TitleID
	if(usrset->Content0IsNcch){
		u8 TitleId[8];
		endian_memcpy(TitleId,ciaset->TitleID,8,LE);
		for(int i = 1; i < ciaset->content.ContentCount; i++){
			u8 *ContentBuff = RetargetNCCH(ciaset->content.ContentFilePtrs[i],ciaset->content.ContentSize[i],ciaset->content.ContentTitleId[i],TitleId,ciaset->keys);
			if(!ContentBuff){
				fprintf(stderr,"[CIA ERROR] Could not import content %d to CIA\n",i);
				return FAILED_TO_IMPORT_FILE;
			}
			ctr_sha(ContentBuff,ciaset->content.ContentSize[i],ciaset->content.ContentHash[i],CTR_SHA_256);
			if(ciaset->content.EncryptContents) {
				ciaset->content.ContentType[i] |= Encrypted;
				CryptContent(ContentBuff,ContentBuff,ciaset->content.ContentSize[i],ciaset->tik.TitleKey,ciaset->content.ContentIndex[i],ENC);
			}
			WriteBuffer(ContentBuff,ciaset->content.ContentSize[i],ciaset->content.ContentOffset[i]+ciaset->CIA_Sections.ContentOffset,ciaset->out);
			free(ContentBuff);
		}
	}
	else if(usrset->ConvertCci){
		for(int i = 1; i < ciaset->content.ContentCount; i++){
			u8 *ContentBuff = (u8*)(ciaset->content.content0+ciaset->content.CCIContentOffsets[i]);
			ctr_sha(ContentBuff,ciaset->content.ContentSize[i],ciaset->content.ContentHash[i],CTR_SHA_256);
			if(ciaset->content.EncryptContents) {
				ciaset->content.ContentType[i] |= Encrypted;
				CryptContent(ContentBuff,ContentBuff,ciaset->content.ContentSize[i],ciaset->tik.TitleKey,ciaset->content.ContentIndex[i],ENC);
			}
			WriteBuffer(ContentBuff,ciaset->content.ContentSize[i],ciaset->content.ContentOffset[i]+ciaset->CIA_Sections.ContentOffset,ciaset->out);
		}
		free(usrset->Content0.buffer);
		usrset->Content0.buffer = NULL;
		usrset->Content0.size = 0;
	}

	
	return 0;
}

int WriteTMDToFile(cia_settings *ciaset)
{
	WriteBuffer(ciaset->CIA_Sections.TitleMetaData.buffer,ciaset->CIA_Sections.TitleMetaData.size,ciaset->CIA_Sections.TitleMetaDataOffset,ciaset->out);
	return 0;
}

int CryptContent(u8 *EncBuffer,u8 *DecBuffer,u64 size,u8 *title_key, u16 index, u8 mode)
{
	//generating IV
	u8 iv[16];
	memset(&iv,0x0,16);
	iv[0] = (index >> 8) & 0xff;
	iv[1] = index & 0xff;
	//Crypting content
	ctr_aes_context ctx;
	memset(&ctx,0x0,sizeof(ctr_aes_context));
	ctr_init_aes_cbc(&ctx,title_key,iv,mode);
	if(mode == ENC) ctr_aes_cbc(&ctx,DecBuffer,EncBuffer,size,ENC);
	else ctr_aes_cbc(&ctx,EncBuffer,DecBuffer,size,DEC);
	return 0;
}