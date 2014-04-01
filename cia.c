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
int GetCIADataFromNcch(cia_settings *ciaset, ncch_hdr *NcchHdr, extended_hdr *ExHeader);
int GetMetaRegion(cia_settings *ciaset, extended_hdr *ExHeader, u8 *ExeFs);
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
	ciaset->out = fopen(usrset->common.outFileName,"wb");
	if(!ciaset->out){
		fprintf(stderr,"[CIA ERROR] Failed to create \"%s\"\n",usrset->common.outFileName);
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
	if(set->content.contentFilePtrs){
		for(u32 i = 1; i < set->content.contentCount; i++){
			fclose(set->content.contentFilePtrs[i]);
		}
		free(set->content.contentFilePtrs);
	}
	free(set->ciaSections.certChain.buffer);
	free(set->ciaSections.tik.buffer);
	free(set->ciaSections.tmd.buffer);
	free(set->ciaSections.meta.buffer);

	memset(set,0,sizeof(cia_settings));

	free(set);
}

int get_CIASettings(cia_settings *ciaset, user_settings *usrset)
{
	int result = 0;

	// Transfering data from usrset
	result = GetSettingsFromUsrset(ciaset,usrset);

	if(usrset->common.workingFileType == infile_ncch){
		result = GetSettingsFromNcch0(ciaset,0);
		if(result) return result;
		result = GetContentFilePtrs(ciaset,usrset);
		if(result) return result;
	}

	else if(usrset->common.workingFileType == infile_srl){
		result = GetSettingsFromSrl(ciaset);
		if(result) return result;
	}

	else if(usrset->common.workingFileType == infile_ncsd){
		result = GetSettingsFromCci(ciaset);
		if(result) return result;
	}
	

	return 0;
}

int GetSettingsFromUsrset(cia_settings *ciaset, user_settings *usrset)
{
	// General Stuff
	ciaset->keys = &usrset->common.keys;
	ciaset->inFile = usrset->common.workingFile.buffer;
	ciaset->inFileSize = usrset->common.workingFile.size;
	u32_to_u8(ciaset->tmd.titleType,TYPE_CTR,BE);
	ciaset->content.encryptCia = usrset->cia.encryptCia;
	ciaset->content.IsDlc = usrset->cia.DlcContent;
	if(ciaset->keys->aes.commonKey[ciaset->keys->aes.currentCommonKey] == NULL && ciaset->content.encryptCia){
		fprintf(stderr,"[CIA WARNING] Common Key could not be loaded, CIA will not be encrypted\n");
		ciaset->content.encryptCia = false;
	}
	
	ciaset->cert.caCrlVersion = 0;
	ciaset->cert.signerCrlVersion = 0;

	for(int i = 0; i < 3; i++){
		ciaset->common.titleVersion[i] = usrset->cia.titleVersion[i];
	}

	ciaset->content.overrideSaveDataSize = usrset->cia.overideSaveDataSize;

	// Random Number generator
	u8 hash[0x20];
	if(usrset->common.rsfPath)
		ctr_sha(usrset->common.rsfPath,strlen(usrset->common.rsfPath),hash,CTR_SHA_256);
	else
		ctr_sha(ciaset->inFile,(rand() % 0x200),hash,CTR_SHA_256);

	// Ticket Data
	memcpy(ciaset->tik.ticketId,(hash+0x8),8);
	if(usrset->cia.randomTitleKey)
		memcpy(ciaset->common.titleKey,(hash+0x10),16);
	else
		memset(ciaset->common.titleKey,0,16);

	ciaset->tik.formatVersion = 1;

	int result = GenCertChildIssuer(ciaset->tik.issuer,ciaset->keys->certs.xsCert);
	if(result) return result;
	
	// Tmd Stuff
	if(usrset->cia.contentId[0] > 0xffffffff){
		ciaset->content.contentId[0] = u8_to_u32(hash,BE);
	}
	else 
		ciaset->content.contentId[0] = usrset->cia.contentId[0];
	ciaset->tmd.formatVersion = 1;
	result = GenCertChildIssuer(ciaset->tmd.issuer,ciaset->keys->certs.cpCert);
	return 0;
}

int GetSettingsFromNcch0(cia_settings *ciaset, u32 ncch0_offset)
{
	/* Sanity Checks */
	if(!ciaset->inFile) 
		return CIA_NO_NCCH0;

	u8 *ncch0 = (u8*)(ciaset->inFile+ncch0_offset);

	if(!IsNCCH(NULL,ncch0)){
		fprintf(stderr,"[CIA ERROR] Content0 is not NCCH\n");
		return CIA_INVALID_NCCH0;
	}

	/* Get Ncch0 Header */
	ncch_hdr *hdr = NULL;
	hdr = GetNCCH_CommonHDR(hdr,NULL,ncch0);
	if(IsCfa(hdr)){
		ciaset->content.IsCfa = true;
	}

	ciaset->content.contentOffset[0] = 0;
	ciaset->content.contentSize[0] = GetNCCH_MediaSize(hdr)*GetNCCH_MediaUnitSize(hdr);
	ciaset->content.totalContentSize = ciaset->content.contentSize[0];

	/* Get Ncch0 Import Context */
	ncch_struct *ncch_ctx = malloc(sizeof(ncch_struct));
	if(!ncch_ctx){ 
		fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); 
		return MEM_ERROR; 
	}
	memset(ncch_ctx,0x0,sizeof(ncch_struct));
	GetCXIStruct(ncch_ctx,hdr);

	/* Verify Ncch0 (Sig&Hash Checks) */
	int result = VerifyNCCH(ncch0,ciaset->keys,false);
	if(result == UNABLE_TO_LOAD_NCCH_KEY){
		ciaset->content.keyNotFound = true;
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
	endian_memcpy(ciaset->common.titleId,hdr->titleId,8,LE);


	/* Getting ExeFs/ExHeader */
	u8 *ExeFs = malloc(ncch_ctx->exefsSize);
	if(!ExeFs){ fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); return MEM_ERROR; }
	extended_hdr *ExHeader = malloc(ncch_ctx->exhdrSize);
	if(!ExHeader){ fprintf(stderr,"[CIA ERROR] MEM ERROR\n"); free(ExeFs); return MEM_ERROR; }

	if(!(ciaset->content.IsCfa||ciaset->content.keyNotFound)) GetNCCHSection(ExeFs, ncch_ctx->exefsSize, 0, ncch0, ncch_ctx, ciaset->keys, ncch_exefs);
	if(!(ciaset->content.IsCfa||ciaset->content.keyNotFound)) GetNCCHSection((u8*)ExHeader, ncch_ctx->exhdrSize, 0, ncch0, ncch_ctx, ciaset->keys, ncch_exhdr);
	
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

int GetCIADataFromNcch(cia_settings *ciaset, ncch_hdr *NcchHdr, extended_hdr *ExHeader)
{
	u16 Category = u8_to_u16((ciaset->common.titleId+2),BE);
	if(IsPatch(Category)||ciaset->content.IsCfa||ciaset->content.keyNotFound) u32_to_u8(ciaset->tmd.savedataSize,0,LE);
	else u32_to_u8(ciaset->tmd.savedataSize,(u32)GetSaveDataSize_frm_exhdr(ExHeader),LE);
	if(ciaset->content.overrideSaveDataSize){
		u64 size = 0;
		GetSaveDataSizeFromString(&size,ciaset->content.overrideSaveDataSize);
		u32_to_u8(ciaset->tmd.savedataSize,(u32)size,LE);
	}
	
	if(ciaset->content.IsCfa||ciaset->content.keyNotFound){
		if(ciaset->common.titleVersion[0] == 0xffff){ // '-major' wasn't set
			if(ciaset->content.IsCfa){ // Is a CFA and can be decrypted
				fprintf(stderr,"[CIA ERROR] Invalid major version. Use \"-major\" option.\n");
				return CIA_BAD_VERSION;
			}
			else // CXI which cannot be decrypted
				ciaset->common.titleVersion[0] = 0;
		}
	}
	else{ // Is a CXI and can be decrypted
		if(ciaset->common.titleVersion[0] != 0xffff){ // '-major' was set
			fprintf(stderr,"[CIA ERROR] Option \"-major\" cannot be applied for cxi.\n");
			return CIA_BAD_VERSION;
		}
		// Setting remaster ver
		ciaset->common.titleVersion[0] = GetRemasterVersion_frm_exhdr(ExHeader);
	}

	u16 version = SetupVersion(ciaset->common.titleVersion[0],ciaset->common.titleVersion[1],ciaset->common.titleVersion[2]);
	ciaset->tik.version = version;
	ciaset->tmd.version = version;
	return 0;
}

int GetMetaRegion(cia_settings *ciaset, extended_hdr *ExHeader, u8 *ExeFs)
{
	if(ciaset->content.IsCfa || ciaset->content.keyNotFound) return 0;
	ciaset->ciaSections.meta.size = sizeof(cia_metadata) + GetExeFsSectionSize("icon",ExeFs);
	ciaset->ciaSections.meta.buffer = malloc(ciaset->ciaSections.meta.size);
	if(!ciaset->ciaSections.meta.buffer){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR; 
	}
	cia_metadata *hdr = (cia_metadata*)ciaset->ciaSections.meta.buffer;
	memset(hdr,0,sizeof(cia_metadata));
	GetDependencyList_frm_exhdr(hdr->dependencyList,ExHeader);
	GetCoreVersion_frm_exhdr(hdr->coreVersion,ExHeader);
	if(DoesExeFsSectionExist("icon",ExeFs)){
		u8 *IconDestPos = (ciaset->ciaSections.meta.buffer + sizeof(cia_metadata));
		memcpy(IconDestPos,GetExeFsSection("icon",ExeFs),GetExeFsSectionSize("icon",ExeFs));
		//memdump(stdout,"Icon: ",IconDestPos,0x10);
	}
	return 0;
}

int GetContentFilePtrs(cia_settings *ciaset, user_settings *usrset)
{
	ciaset->content.contentFilePtrs = malloc(sizeof(FILE*)*CIA_MAX_CONTENT);
	if(!ciaset->content.contentFilePtrs){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n"); 
		return MEM_ERROR; 
	}
	memset(ciaset->content.contentFilePtrs,0,sizeof(FILE*)*CIA_MAX_CONTENT);
	int j = 1;
	ncch_hdr *hdr = malloc(sizeof(ncch_hdr));
	for(int i = 1; i < CIA_MAX_CONTENT; i++){
		if(usrset->common.contentPath[i]){
			ciaset->content.contentFilePtrs[j] = fopen(usrset->common.contentPath[i],"rb");
			if(!ciaset->content.contentFilePtrs[j]){ 
				fprintf(stderr,"[CIA ERROR] Failed to open \"%s\"\n",usrset->common.contentPath[i]); 
				return FAILED_TO_OPEN_FILE; 
			}
			if(usrset->cia.contentId[i] == 0x100000000){
				u8 hash[0x20];
				ctr_sha(usrset->common.contentPath[i],strlen(usrset->common.contentPath[i]),hash,CTR_SHA_256);
				ciaset->content.contentId[j]  = u8_to_u32(hash,BE);
			}
			else 
				ciaset->content.contentId[j] = (u32)usrset->cia.contentId[i];
			ciaset->content.contentIndex[j] = (u16)i;

			// Get Data from ncch HDR
			GetNCCH_CommonHDR(hdr,ciaset->content.contentFilePtrs[j],NULL);

			// Get TitleID
			memcpy(ciaset->content.contentTitleId[j],hdr->titleId,8);
			
			// Get Size
			ciaset->content.contentSize[j] =  GetNCCH_MediaSize(hdr)*GetNCCH_MediaUnitSize(hdr);
			ciaset->content.contentOffset[j] = ciaset->content.totalContentSize,0x40;
			
			ciaset->content.totalContentSize += ciaset->content.contentSize[j];
			

			// Finish get next content
			j++;
		}
	}
	free(hdr);
	ciaset->content.contentCount = j;

	// Check Conflicting IDs
	for(int i = 0; i < ciaset->content.contentCount; i++){
		for(j = i+1; j < ciaset->content.contentCount; j++){
			if(ciaset->content.contentId[j] == ciaset->content.contentId[i]){
				fprintf(stderr,"[CIA ERROR] CIA Content %d and %d, have conflicting IDs\n",ciaset->content.contentIndex[j],ciaset->content.contentIndex[i]);
				return CIA_CONFILCTING_CONTENT_IDS;
			}
		}
	}
	return 0;
}

int GetSettingsFromSrl(cia_settings *ciaset)
{
	SRL_Header *hdr = (SRL_Header*)ciaset->inFile;
	if(!hdr || ciaset->inFileSize < sizeof(SRL_Header)) {
		fprintf(stderr,"[CIA ERROR] Invalid TWL SRL File\n");
		return FAILED_TO_IMPORT_FILE;
	}
	
	// Check if TWL SRL File
	if(u8_to_u16(&hdr->title_id[6],LE) != 0x0003){
		fprintf(stderr,"[CIA ERROR] Invalid TWL SRL File\n");
		return FAILED_TO_IMPORT_FILE;
	}

	// Generate and store Converted TitleID
	u64_to_u8(ciaset->common.titleId,ConvertTwlIdToCtrId(u8_to_u64(hdr->title_id,LE)),BE);
	//memdump(stdout,"SRL TID: ",ciaset->TitleID,8);

	// Get TWL Flag
	ciaset->tmd.twlFlag = ((hdr->reserved_flags[3] & 6) >> 1);

	// Get Remaster Version
	u16 version = SetupVersion(hdr->rom_version,ciaset->common.titleVersion[1],0);
	ciaset->tik.version = version;
	ciaset->tmd.version = version;

	// Get SaveDataSize (Public and Private)
	memcpy(ciaset->tmd.savedataSize,hdr->pub_save_data_size,4);
	memcpy(ciaset->tmd.privSavedataSize,hdr->priv_save_data_size,4);

	// Setting CIA Content Settings
	ciaset->content.contentCount = 1;
	ciaset->content.contentOffset[0] = 0;
	ciaset->content.contentSize[0] = ciaset->inFileSize;
	ciaset->content.totalContentSize = ciaset->inFileSize;

	return 0;
}



int GetSettingsFromCci(cia_settings *ciaset)
{
	int result = 0;

	if(!IsCci(ciaset->inFile)){
		fprintf(stderr,"[CIA ERROR] Invalid CCI file\n");
		return FAILED_TO_IMPORT_FILE;
	}
	
	u32 ncch0_offset = GetPartitionOffset(ciaset->inFile,0);
	if(!ncch0_offset){
		fprintf(stderr,"[CIA ERROR] Invalid CCI file (invalid ncch0)\n");
		return FAILED_TO_IMPORT_FILE;
	}

	result = GetSettingsFromNcch0(ciaset, ncch0_offset);
	if(result){
		fprintf(stderr,"Import of Ncch 0 failed(%d)\n",result);	
		return result;
	}
	ciaset->content.contentCount = 1;
	ciaset->content.cciContentOffsets[0] = ncch0_offset;
	ncch_hdr *hdr = malloc(sizeof(ncch_hdr));
	for(int i = 1; i < 8; i++){
		if(GetPartitionSize(ciaset->inFile,i)){
			ciaset->content.cciContentOffsets[ciaset->content.contentCount] = GetPartitionOffset(ciaset->inFile,i);

			// Get Data from ncch HDR
			GetNCCH_CommonHDR(hdr,NULL,GetPartition(ciaset->inFile,i));
			
			// Get Size
			ciaset->content.contentSize[ciaset->content.contentCount] =  GetPartitionSize(ciaset->inFile,i);
			ciaset->content.contentOffset[ciaset->content.contentCount] = ciaset->content.totalContentSize;
			
			ciaset->content.totalContentSize += ciaset->content.contentSize[ciaset->content.contentCount];
			
			// Get ID
			u8 hash[0x20];
			ctr_sha((u8*)hdr,0x200,hash,CTR_SHA_256);
			ciaset->content.contentId[ciaset->content.contentCount] = u8_to_u32(hash,BE);

			// Get Index
			ciaset->content.contentIndex[ciaset->content.contentCount] = i;

			// Increment Content Count
			ciaset->content.contentCount++;
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
	ciaset->ciaSections.certChain.size = GetCertSize(ciaset->keys->certs.caCert) + GetCertSize(ciaset->keys->certs.xsCert) + GetCertSize(ciaset->keys->certs.cpCert);
	ciaset->ciaSections.certChain.buffer = malloc(ciaset->ciaSections.certChain.size);
	if(!ciaset->ciaSections.certChain.buffer) {
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR; 
	}
	memcpy(ciaset->ciaSections.certChain.buffer,ciaset->keys->certs.caCert,GetCertSize(ciaset->keys->certs.caCert));
	memcpy((ciaset->ciaSections.certChain.buffer+GetCertSize(ciaset->keys->certs.caCert)),ciaset->keys->certs.xsCert,GetCertSize(ciaset->keys->certs.xsCert));
	memcpy((ciaset->ciaSections.certChain.buffer+GetCertSize(ciaset->keys->certs.caCert)+GetCertSize(ciaset->keys->certs.xsCert)),ciaset->keys->certs.cpCert,GetCertSize(ciaset->keys->certs.cpCert));
	return 0;
}

int BuildCIA_Header(cia_settings *ciaset)
{
	// Allocating memory for header
	ciaset->ciaSections.ciaHdr.size = sizeof(cia_hdr);
	ciaset->ciaSections.ciaHdr.buffer = malloc(ciaset->ciaSections.ciaHdr.size);
	if(!ciaset->ciaSections.ciaHdr.buffer){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	
	cia_hdr *hdr = (cia_hdr*)ciaset->ciaSections.ciaHdr.buffer;

	// Clearing 
	memset(hdr,0,sizeof(cia_hdr));

	// Predict TMD Size
	ciaset->ciaSections.tmd.size = PredictTMDSize(ciaset->content.contentCount);

	// Setting Data
	u32_to_u8(hdr->hdrSize,sizeof(cia_hdr),LE);
	u16_to_u8(hdr->type,0x0,LE);
	u16_to_u8(hdr->version,0x0,LE);
	u32_to_u8(hdr->certChainSize,ciaset->ciaSections.certChain.size,LE);
	u32_to_u8(hdr->tikSize,ciaset->ciaSections.tik.size,LE);
	u32_to_u8(hdr->tmdSize,ciaset->ciaSections.tmd.size,LE);
	u32_to_u8(hdr->metaSize,ciaset->ciaSections.meta.size,LE);
	u64_to_u8(hdr->contentSize,ciaset->content.totalContentSize,LE);

	// Recording Offsets
	ciaset->ciaSections.certChainOffset = align_value(sizeof(cia_hdr),0x40);
	ciaset->ciaSections.tikOffset = align_value(ciaset->ciaSections.certChainOffset+ciaset->ciaSections.certChain.size,0x40);
	ciaset->ciaSections.tmdOffset = align_value(ciaset->ciaSections.tikOffset+ciaset->ciaSections.tik.size,0x40);
	ciaset->ciaSections.contentOffset = align_value(ciaset->ciaSections.tmdOffset+ciaset->ciaSections.tmd.size,0x40);
	ciaset->ciaSections.metaOffset = align_value(ciaset->ciaSections.contentOffset+ciaset->content.totalContentSize,0x40);
	
	for(int i = 0; i < ciaset->content.contentCount; i++){
		// This works by treating the 0x2000 byte index array as an array of 2048 u32 values
		
		// Used for determining which u32 chunk to write the value to
		u16 section = ciaset->content.contentIndex[i]/32;
		
		// Calculating the value added to the u32
		u32 value = 1 << (0x1F-ciaset->content.contentIndex[i]);

		// Retrieving current u32 block
		u32 cur_content_index_section = u8_to_u32(hdr->contentIndex+(sizeof(u32)*section),BE);
		
		// Adding value to block
		cur_content_index_section += value;
		
		// Returning block
		u32_to_u8(hdr->contentIndex+(sizeof(u32)*section),cur_content_index_section,BE);
	}
	return 0;
}

int WriteCurrentSectionstoFile(cia_settings *ciaset)
{
	WriteBuffer(ciaset->ciaSections.ciaHdr.buffer,ciaset->ciaSections.ciaHdr.size,0,ciaset->out);
	WriteBuffer(ciaset->ciaSections.certChain.buffer,ciaset->ciaSections.certChain.size,ciaset->ciaSections.certChainOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.tik.buffer,ciaset->ciaSections.tik.size,ciaset->ciaSections.tikOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.meta.buffer,ciaset->ciaSections.meta.size,ciaset->ciaSections.metaOffset,ciaset->out);
	return 0;
}

int WriteContentsToFile(cia_settings *ciaset, user_settings *usrset) // re-implement so it's one for loop
{
	u8 *content0 = ciaset->inFile;
	if(usrset->common.workingFileType == infile_ncsd) content0 = (u8*)(ciaset->inFile+ciaset->content.cciContentOffsets[0]);

	ctr_sha(content0,ciaset->content.contentSize[0],ciaset->content.contentHash[0],CTR_SHA_256);
	if(ciaset->content.encryptCia) {
		ciaset->content.contentFlags[0] |= content_Encrypted;
		CryptContent(content0,content0,ciaset->content.contentSize[0],ciaset->common.titleKey,ciaset->content.contentIndex[0],ENC);
	}
	WriteBuffer(content0,ciaset->content.contentSize[0],ciaset->content.contentOffset[0]+ciaset->ciaSections.contentOffset,ciaset->out);
	
	// Free Buffer if Not CCI, as the rest of the content are in this image
	if(usrset->common.workingFileType != infile_ncsd){
		free(usrset->common.workingFile.buffer);
		usrset->common.workingFile.buffer = NULL;
		usrset->common.workingFile.size = 0;
	}

	// Add additional contents, recreating them with their new TitleID
	if(usrset->common.workingFileType == infile_ncch){
		u8 TitleId[8];
		endian_memcpy(TitleId,ciaset->common.titleId,8,LE);
		for(int i = 1; i < ciaset->content.contentCount; i++){
			u8 *content = RetargetNCCH(ciaset->content.contentFilePtrs[i],ciaset->content.contentSize[i],ciaset->content.contentTitleId[i],TitleId,ciaset->keys);
			if(!content){
				fprintf(stderr,"[CIA ERROR] Could not import content %d to CIA\n",i);
				return FAILED_TO_IMPORT_FILE;
			}
			ctr_sha(content,ciaset->content.contentSize[i],ciaset->content.contentHash[i],CTR_SHA_256);
			if(ciaset->content.IsDlc)
				ciaset->content.contentFlags[i] |= content_Optional;
			if(ciaset->content.encryptCia) {
				ciaset->content.contentFlags[i] |= content_Encrypted;
				CryptContent(content,content,ciaset->content.contentSize[i],ciaset->common.titleKey,ciaset->content.contentIndex[i],ENC);
			}
			WriteBuffer(content,ciaset->content.contentSize[i],ciaset->content.contentOffset[i]+ciaset->ciaSections.contentOffset,ciaset->out);
			free(content);
		}
	}
	else if(usrset->common.workingFileType == infile_ncsd){ // This makes the assumption the CCI is valid
		for(int i = 1; i < ciaset->content.contentCount; i++){
			u8 *content = (u8*)(ciaset->inFile+ciaset->content.cciContentOffsets[i]);
			ctr_sha(content,ciaset->content.contentSize[i],ciaset->content.contentHash[i],CTR_SHA_256);
			if(ciaset->content.encryptCia) {
				ciaset->content.contentFlags[i] |= content_Encrypted;
				CryptContent(content,content,ciaset->content.contentSize[i],ciaset->common.titleKey,ciaset->content.contentIndex[i],ENC);
			}
			WriteBuffer(content,ciaset->content.contentSize[i],ciaset->content.contentOffset[i]+ciaset->ciaSections.contentOffset,ciaset->out);
		}
		free(usrset->common.workingFile.buffer);
		usrset->common.workingFile.buffer = NULL;
		usrset->common.workingFile.size = 0;
	}

	
	return 0;
}

int WriteTMDToFile(cia_settings *ciaset)
{
	WriteBuffer(ciaset->ciaSections.tmd.buffer,ciaset->ciaSections.tmd.size,ciaset->ciaSections.tmdOffset,ciaset->out);
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