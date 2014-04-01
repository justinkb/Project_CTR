#include "lib.h"
#include "ncch.h"
#include "exheader.h"
#include "ncsd.h"

// Private Prototypes

/* RSA Crypto */
int SignCCI(u8 *Signature, u8 *NCSD_HDR);
int CheckCCISignature(u8 *Signature, u8 *NCSD_HDR);

/* cci_settings tools */
void init_CCISettings(cci_settings *set);
int get_CCISettings(cci_settings *cciset, user_settings *usrset);
void free_CCISettings(cci_settings *set);

/* CCI Data Gen/Write */
int BuildNCSDHeader(cci_settings *cciset, user_settings *usrset);
int BuildCardInfoHeader(cci_settings *cciset, user_settings *usrset);
int WriteCCI_HDR_ToFile(cci_settings *cciset);
int WriteCCI_Content_ToFile(cci_settings *cciset,user_settings *usrset);
int WriteCCI_DummyBytes(cci_settings *cciset);

/* Get Data from Content Files */
int CheckContent0(cci_settings *cciset, user_settings *usrset);
int GetDataFromContent0(cci_settings *cciset, user_settings *usrset);
int GetContentFP(cci_settings *cciset, user_settings *usrset);

/* Get Data from YAML Settings */
int GetNCSDFlags(cci_settings *cciset, rsf_settings *yaml);
int GetMediaSize(cci_settings *cciset, user_settings *usrset);
u64 GetUnusedSize(u64 MediaSize, u8 CardType);
int GetWriteableAddress(cci_settings *cciset, user_settings *usrset);
int GetCardInfoBitmask(cci_settings *cciset, user_settings *usrset);

int CheckMediaSize(cci_settings *cciset);

static InternalCCI_Context ctx;

// Code
int build_CCI(user_settings *usrset)
{
	int result = 0;

	// Init Settings
	cci_settings *cciset = malloc(sizeof(cci_settings));
	if(!cciset) {fprintf(stderr,"[CCI ERROR] MEM ERROR\n"); return MEM_ERROR;}
	init_CCISettings(cciset);
	
	// Get Settings
	result = get_CCISettings(cciset,usrset);
	if(result) goto finish;

	// Create Output File
	cciset->out = fopen(usrset->common.outFileName,"wb");
	if(!cciset->out){
		fprintf(stderr,"[CCI ERROR] Failed to create '%s'\n",usrset->common.outFileName);
		result = FAILED_TO_CREATE_OUTFILE;
		goto finish;
	}
	
	// Generate NCSD Header and Additional Header
	result = BuildNCSDHeader(cciset,usrset);
	if(result) 
		goto finish;
	BuildCardInfoHeader(cciset,usrset);
	
	// Write to File
	WriteCCI_HDR_ToFile(cciset);
	result = WriteCCI_Content_ToFile(cciset,usrset);
	if(result) 
		goto finish;
	
	// Fill out file if necessary 
	if(cciset->fillOutCci) 
		WriteCCI_DummyBytes(cciset);
	
	// Close output file
finish:
	if(result != FAILED_TO_CREATE_OUTFILE && cciset->out) fclose(cciset->out);
	free_CCISettings(cciset);
	return result;
}


int SignCCI(u8 *Signature, u8 *NCSD_HDR)
{
	return ctr_sig(NCSD_HDR,sizeof(cci_hdr),Signature,ctx.keys->rsa.cciCfaPub,ctx.keys->rsa.cciCfaPvt,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckCCISignature(u8 *Signature, u8 *NCSD_HDR)
{
	return ctr_sig(NCSD_HDR,sizeof(cci_hdr),Signature,ctx.keys->rsa.cciCfaPub,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
}

void init_CCISettings(cci_settings *set)
{
	memset(set,0,sizeof(cci_settings));
	memset(&ctx,0,sizeof(InternalCCI_Context));
}

int get_CCISettings(cci_settings *cciset, user_settings *usrset)
{
	ctx.keys = &usrset->common.keys;
	int result = 0;

	/* Importing Data from Content */
	result = CheckContent0(cciset,usrset);
	if(result) return result;

	result = GetDataFromContent0(cciset,usrset);
	if(result) return result;

	result = GetContentFP(cciset,usrset);
	if(result) return result;

	

	/* Getting Data from YAML */
	result = GetNCSDFlags(cciset,&usrset->common.rsfSet);
	if(result) return result;

	result = GetMediaSize(cciset,usrset);
	if(result) return result;

	result = CheckMediaSize(cciset);
	if(result) return result;

	/** Card Info Header Data **/
	result = GetWriteableAddress(cciset,usrset);
	if(result) return result;

	result = GetCardInfoBitmask(cciset,usrset);
	if(result) return result;
	
	/* All Done */
	return 0;
}

void free_CCISettings(cci_settings *set)
{
	if(set->content){
		for(int i = 1; i < 8; i++) {
			if(set->content[i]) fclose(set->content[i]);
		}
		free(set->content);
	}
	free(set);
}

int BuildNCSDHeader(cci_settings *cciset, user_settings *usrset)
{
	memcpy((u8*)ctx.cciHdr.magic,"NCSD",4);
	u32_to_u8((u8*)ctx.cciHdr.mediaSize,(cciset->mediaSize/cciset->mediaUnit),LE); 
	memcpy((u8*)ctx.cciHdr.titleId,cciset->mediaId,8);
	for(int i = 0; i < 8; i++){
		u32_to_u8((u8*)ctx.cciHdr.offset_sizeTable[i].offset,(cciset->contentOffset[i]/cciset->mediaUnit),LE);
		u32_to_u8((u8*)ctx.cciHdr.offset_sizeTable[i].size,(cciset->contentSize[i]/cciset->mediaUnit),LE);
		memcpy((u8*)ctx.cciHdr.partitionIdTable[i],cciset->contentTitleId[i],8);
	}
	memcpy((u8*)ctx.cciHdr.partitionFlags,cciset->flags,8);
	if(SignCCI(ctx.signature,(u8*)&ctx.cciHdr) != Good){
		fprintf(stderr,"[CCI ERROR] Failed to sign CCI\n");
		return CCI_SIG_FAIL;
	}
	return 0;
}

int BuildCardInfoHeader(cci_settings *cciset, user_settings *usrset)
{
	u32_to_u8((u8*)ctx.cardinfo.writable_address,(cciset->writableAddress/cciset->mediaUnit),LE); 
	u32_to_u8((u8*)ctx.cardinfo.card_info_bitmask,cciset->cardInfoBitmask,BE);
	u32_to_u8((u8*)ctx.cardinfo.media_size_used,cciset->cciTotalSize,LE); 
	memcpy((u8*)ctx.cardinfo.ncch_0_title_id,cciset->contentTitleId[0],8);
	memcpy((u8*)ctx.cardinfo.initial_data,cciset->initialData,0x30);
	memcpy((u8*)ctx.cardinfo.ncch_0_header,cciset->ncchHdr,0x100);
	memcpy((u8*)ctx.devcardinfo.TitleKey,cciset->titleKey,0x10);
	return 0;
}

int WriteCCI_HDR_ToFile(cci_settings *cciset)
{
	WriteBuffer(ctx.signature,0x100,0,cciset->out);
	WriteBuffer((u8*)&ctx.cciHdr,sizeof(cci_hdr),0x100,cciset->out);
	WriteBuffer((u8*)&ctx.cardinfo,sizeof(cardinfo_hdr),0x200,cciset->out);
	WriteBuffer((u8*)&ctx.devcardinfo,sizeof(devcardinfo_hdr),0x1200,cciset->out);
	return 0;
}

int WriteCCI_Content_ToFile(cci_settings *cciset,user_settings *usrset)
{
	// Write Content 0
	WriteBuffer(cciset->ncch0,cciset->contentSize[0],cciset->contentOffset[0],cciset->out);
	free(usrset->common.workingFile.buffer);
	usrset->common.workingFile.buffer = NULL;
	usrset->common.workingFile.size = 0;
	
	// Add additional contents, recreating them with their new TitleID
	for(int i = 1; i < 8; i++){
		if(cciset->content[i]){
			u8 *ncch = RetargetNCCH(cciset->content[i],cciset->contentSize[i],cciset->contentTitleId[i],cciset->mediaId,ctx.keys);
			if(!ncch){
				fprintf(stderr,"[CCI ERROR] Could not import content %d to CCI\n",i);
				return FAILED_TO_IMPORT_FILE;
			}
			WriteBuffer(ncch,cciset->contentSize[i],cciset->contentOffset[i],cciset->out);
			free(ncch);
		}
	}
	return 0;
}

int WriteCCI_DummyBytes(cci_settings *cciset)
{
	// Seeking end of CCI Data
	fseek_64(cciset->out,cciset->cciTotalSize,SEEK_SET);

	// Determining Size of Dummy Bytes
	u64 len = cciset->mediaSize - cciset->cciTotalSize;
	
	// Creating Buffer of Dummy Bytes
	u8 *dummy_bytes = malloc(cciset->mediaUnit);
	memset(dummy_bytes,0xff,cciset->mediaUnit);
	
	// Writing Dummy Bytes to file
	for(u64 i = 0; i < len; i += cciset->mediaUnit){
		fwrite(&dummy_bytes,cciset->mediaUnit,1,cciset->out);
	}
	
	return 0;
}

int GetContentFP(cci_settings *cciset, user_settings *usrset)
{
	cciset->content = malloc(sizeof(FILE*)*8);
	if(!cciset->content){
		fprintf(stderr,"[CCI ERROR] MEM ERROR\n");
		return MEM_ERROR;
	}
	memset(cciset->content,0,sizeof(FILE*)*8);
	
	for(int i = 1; i < 8; i++){
		if(usrset->common.contentPath[i]){
			cciset->content[i] = fopen(usrset->common.contentPath[i],"rb");
			if(!cciset->content[i]){ // Checking if file could be opened
				fprintf(stderr,"[CCI ERROR] Failed to open '%s'\n",usrset->common.contentPath[i]);
				return FAILED_TO_OPEN_FILE;
			}
			if(!IsNCCH(cciset->content[i],NULL)){ // Checking if NCCH
				fprintf(stderr,"[CCI ERROR] Content '%s' is invalid\n",usrset->common.contentPath[i]);
				return NCSD_INVALID_NCCH0;
			}
			
			// Getting NCCH Header
			ncch_hdr *hdr = malloc(sizeof(ncch_hdr));
			GetNCCH_CommonHDR(hdr,cciset->content[i],NULL);
			
			if(GetNCCH_MediaUnitSize(hdr) != cciset->mediaUnit){ // Checking if Media Unit Size matches CCI
				fprintf(stderr,"[CCI ERROR] Content '%s' is invalid\n",usrset->common.contentPath[i]);
				return NCSD_INVALID_NCCH0;
			}
			
			memcpy(&cciset->contentTitleId[i],cciset->mediaId,8); // Set TitleID
			 
			// Modify TitleID Accordingly
			u16 tmp = u8_to_u16(&hdr->titleId[6],LE);
			tmp |= (i+4);
			u16_to_u8(&cciset->contentTitleId[i][6],tmp,LE);
			
			cciset->contentSize[i] =  GetNCCH_MediaSize(hdr)*cciset->mediaUnit;
			cciset->contentOffset[i] = cciset->cciTotalSize;
			
			cciset->cciTotalSize += cciset->contentSize[i];
			
			free(hdr);
		}
	}
	return 0;
}

int CheckContent0(cci_settings *cciset, user_settings *usrset)
{
	if(!usrset->common.workingFile.buffer) 
		return NCSD_NO_NCCH0;
	cciset->ncch0 = usrset->common.workingFile.buffer;
	cciset->ncch0_FileLen = usrset->common.workingFile.size;
	
	if(!IsNCCH(NULL,cciset->ncch0)) 
		return NCSD_INVALID_NCCH0;
	
	return 0;
}

int GetDataFromContent0(cci_settings *cciset, user_settings *usrset)
{
	cciset->cciTotalSize = 0x4000;
	
	ncch_hdr *hdr;
	
	hdr = GetNCCH_CommonHDR(NULL,NULL,cciset->ncch0);
	
	cciset->ncchHdr = hdr;
	
	u16 ncch_format_ver = u8_to_u16(hdr->formatVersion,LE);
	if(ncch_format_ver != 0 && ncch_format_ver != 2){
		fprintf(stderr,"[CCI ERROR] NCCH type %d Not Supported\n",ncch_format_ver);
		return FAILED_TO_IMPORT_FILE;
	}

	//memdump(stdout,"ncch0 head: ",(cciset->ncch0+0x100),0x100);
	//memdump(stdout,"ncch0 head: ",(u8*)(hdr),0x100);
	
	memcpy(cciset->mediaId,hdr->titleId,8);
	memcpy(&cciset->contentTitleId[0],hdr->titleId,8);
	if(usrset->cci.useSDKStockData){
		memcpy(cciset->initialData,stock_initial_data,0x30);
		memcpy(cciset->titleKey,stock_title_key,0x10);
	}
	else{
		u8 Hash[0x40];
		ctr_sha(cciset->ncch0,0x80,Hash,CTR_SHA_256);
		ctr_sha((cciset->ncch0+0x80),0x80,(Hash+0x20),CTR_SHA_256);
		memcpy(cciset->initialData,Hash,0x2C);
		//memcpy(cciset->titleKey,(Hash+0x30),0x10); // Might Remove
	}
	
	
	cciset->flags[MediaUnitSize] = hdr->flags[ContentUnitSize];
	cciset->mediaUnit = GetNCCH_MediaUnitSize(hdr);
	
	cciset->contentSize[0] = (u64)(GetNCCH_MediaSize(hdr) * cciset->mediaUnit);
	cciset->contentOffset[0] = cciset->cciTotalSize;
	
	cciset->cciTotalSize += cciset->contentSize[0];
	return 0;
}

int GetMediaSize(cci_settings *cciset, user_settings *usrset)
{
	char *MediaSizeStr = usrset->common.rsfSet.BasicInfo.MediaSize;
	if(!MediaSizeStr) cciset->mediaSize = (u64)GB*2;
	else{
		if(strcasecmp(MediaSizeStr,"128MB") == 0) cciset->mediaSize = (u64)MB*128;
		else if(strcasecmp(MediaSizeStr,"256MB") == 0) cciset->mediaSize = (u64)MB*256;
		else if(strcasecmp(MediaSizeStr,"512MB") == 0) cciset->mediaSize = (u64)MB*512;
		else if(strcasecmp(MediaSizeStr,"1GB") == 0) cciset->mediaSize = (u64)GB*1;
		else if(strcasecmp(MediaSizeStr,"2GB") == 0) cciset->mediaSize = (u64)GB*2;
		else if(strcasecmp(MediaSizeStr,"4GB") == 0) cciset->mediaSize = (u64)GB*4;
		else if(strcasecmp(MediaSizeStr,"8GB") == 0) cciset->mediaSize = (u64)GB*8;
		else if(strcasecmp(MediaSizeStr,"16GB") == 0) cciset->mediaSize = (u64)GB*16;
		else if(strcasecmp(MediaSizeStr,"32GB") == 0) cciset->mediaSize = (u64)GB*32;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid MediaSize: %s\n",MediaSizeStr);
			return INVALID_YAML_OPT;
		}
	}
	
	if(usrset->common.rsfSet.BasicInfo.MediaFootPadding != -1) cciset->fillOutCci = usrset->common.rsfSet.BasicInfo.MediaFootPadding;
	
	return 0;
}

u64 GetUnusedSize(u64 MediaSize, u8 CardType)
{
	if(CardType == CARD1){
		switch(MediaSize){
			case (u64)MB*128: return (u64)2621440;
			case (u64)MB*256: return (u64)5242880;
			case (u64)MB*512: return (u64)10485760;
			case (u64)GB*1: return (u64)73924608;
			case (u64)GB*2: return (u64)147324928;
			case (u64)GB*4: return (u64)294649856;
			case (u64)GB*8: return (u64)587202560;
			default: return (u64)((MediaSize/MB)*0x11800); // Aprox
		}
	}
	else if(CardType == CARD2){
		switch(MediaSize){
			case (u64)MB*512: return (u64)37224448;
			case (u64)GB*1: return (u64)73924608;
			case (u64)GB*2: return (u64)147324928;
			case (u64)GB*4: return (u64)294649856;
			case (u64)GB*8: return (u64)587202560;
			default: return (u64)((MediaSize/MB)*0x11800); // Aprox
		}
	}
	return 0;
}

int GetNCSDFlags(cci_settings *cciset, rsf_settings *yaml)
{
	/* BackupWriteWaitTime */
	cciset->flags[FW6x_BackupWriteWaitTime] = 0;
	if(yaml->CardInfo.BackupWriteWaitTime){
		u32 WaitTime = strtoul(yaml->CardInfo.BackupWriteWaitTime,NULL,0);
		if(WaitTime > 255){
			fprintf(stderr,"[CCI ERROR] Invalid Card BackupWriteWaitTime (%d) : must 0-255\n",WaitTime);
			return EXHDR_BAD_YAML_OPT;
		}
		cciset->flags[FW6x_BackupWriteWaitTime] = (u8)WaitTime;
	}

	/* FW6x SaveCrypto */
	cciset->flags[FW6x_SaveCryptoFlag] = 1;

	/* MediaType */
	if(!yaml->CardInfo.MediaType) cciset->flags[MediaTypeIndex] = CARD1;
	else{
		if(strcasecmp(yaml->CardInfo.MediaType,"Card1") == 0) cciset->flags[MediaTypeIndex] = CARD1;
		else if(strcasecmp(yaml->CardInfo.MediaType,"Card2") == 0) cciset->flags[MediaTypeIndex] = CARD2;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid MediaType: %s\n",yaml->CardInfo.MediaType);
			return INVALID_YAML_OPT;
		}
	}

	/* Platform */
	cciset->flags[MediaPlatformIndex] = CTR;
	/*
	if(!yaml->TitleInfo.Platform) cciset->flags[MediaPlatformIndex] = CTR;
	else{
		if(strcasecmp(yaml->TitleInfo.Platform,"ctr") == 0) cciset->flags[MediaPlatformIndex] = CTR;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid Platform: %s\n",yaml->TitleInfo.Platform);
			return INVALID_YAML_OPT;
		}
	}
	*/

	/* CardDevice */
	if(!yaml->CardInfo.CardDevice) cciset->flags[CardDeviceFlag] = CARD_DEVICE_NONE;
	else{
		if(strcmp(yaml->CardInfo.CardDevice,"NorFlash") == 0) {
			cciset->flags[CardDeviceFlag] = CARD_DEVICE_NOR_FLASH;
			if(cciset->flags[MediaTypeIndex] == CARD2){
				fprintf(stderr,"[CCI WARNING] 'CardDevice: NorFlash' is invalid on Card2\n");
				cciset->flags[CardDeviceFlag] = CARD_DEVICE_NONE;
			}
		}
		else if(strcmp(yaml->CardInfo.CardDevice,"None") == 0) cciset->flags[CardDeviceFlag] = CARD_DEVICE_NONE;
		else if(strcmp(yaml->CardInfo.CardDevice,"BT") == 0) cciset->flags[CardDeviceFlag] = CARD_DEVICE_BT;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid CardDevice: %s\n",yaml->CardInfo.CardDevice);
			return INVALID_YAML_OPT;
		}
	}
	return 0;
}

int GetWriteableAddress(cci_settings *cciset, user_settings *usrset)
{
	int result = GetSaveDataSize_rsf(&cciset->savedataSize,usrset);
	if(result) return result;

	char *WriteableAddressStr = usrset->common.rsfSet.CardInfo.WritableAddress;;
	
	cciset->writableAddress = -1;
	if(cciset->flags[MediaTypeIndex] != CARD2) return 0; // Can only be set for Card2 Media
	
	if(WriteableAddressStr){
		if(strncmp(WriteableAddressStr,"0x",2) != 0){
			fprintf(stderr,"[CCI ERROR] WritableAddress requires a Hexadecimal value\n");
			return INVALID_YAML_OPT;
		}	
		cciset->writableAddress = strtoul((WriteableAddressStr+2),NULL,16);
	}
	if(cciset->writableAddress == -1){ // If not set manually or is max size
		if ((cciset->mediaSize / 2) < cciset->savedataSize){ // If SaveData size is greater than half the MediaSize
			u64 SavedataSize = cciset->savedataSize / KB;
			fprintf(stderr,"[CCI ERROR] Too large SavedataSize %luK\n",SavedataSize);
			return SAVE_DATA_TOO_LARGE;
		}
		if (cciset->savedataSize > (u64)(2047*MB)){ // Limit set by Nintendo
			u64 SavedataSize = cciset->savedataSize / KB;
			fprintf(stderr,"[CCI ERROR] Too large SavedataSize %luK\n",SavedataSize);
			return SAVE_DATA_TOO_LARGE;
		}
		u64 UnusedSize = GetUnusedSize(cciset->mediaSize,cciset->flags[MediaTypeIndex]); // Need to look into this
		cciset->writableAddress = cciset->mediaSize - UnusedSize - cciset->savedataSize;
	}
	return 0;
}

int GetCardInfoBitmask(cci_settings *cciset, user_settings *usrset)
{
	char *str = usrset->common.rsfSet.CardInfo.CardType;
	if(!str) cciset->cardInfoBitmask |= 0;
	else{
		if(strcasecmp(str,"s1") == 0) cciset->cardInfoBitmask |= 0;
		else if(strcasecmp(str,"s2") == 0) cciset->cardInfoBitmask |= 0x20;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid CardType: %s\n",str);
			return INVALID_YAML_OPT;
		}
	}
	
	str = usrset->common.rsfSet.CardInfo.CryptoType;
	if(!str) cciset->cardInfoBitmask |= (3*0x40);
	else{
		int Value = strtol(str,NULL,10);
		if(Value < 0 || Value > 3) {
			fprintf(stderr,"[CCI ERROR] Invalid CryptoType: %s\n",str);
			return INVALID_YAML_OPT;
		}
		if(Value != 3){
			fprintf(stderr,"[CCI WARNING] Card crypto type = '%d'\n",Value);
		}
		cciset->cardInfoBitmask |= (Value*0x40);
	}
	
	return 0;
}

int CheckMediaSize(cci_settings *cciset)
{
	if(cciset->cciTotalSize > cciset->mediaSize){
		char *MediaSizeStr = NULL;
		switch(cciset->mediaSize){
			case (u64)128*MB: MediaSizeStr = " '128MB'"; break;
			case (u64)256*MB: MediaSizeStr = " '256MB'"; break;
			case (u64)512*MB: MediaSizeStr = " '512MB'"; break;
			case (u64)1*GB: MediaSizeStr = " '1GB'"; break;
			case (u64)2*GB: MediaSizeStr = " '2GB'"; break;
			case (u64)4*GB: MediaSizeStr = " '4GB'"; break;
			case (u64)8*GB: MediaSizeStr = " '8GB'"; break;
			case (u64)16*GB: MediaSizeStr = " '16GB'"; break;
			case (u64)32*GB: MediaSizeStr = " '32GB'"; break;
			default:  MediaSizeStr = ""; break;
		}
		fprintf(stderr,"[CCI ERROR] MediaSize%s is too Small\n",MediaSizeStr);
		return INVALID_YAML_OPT;
	}
	return 0;
}

bool IsCci(u8 *ncsd)
{
	cci_hdr *hdr = (cci_hdr*)(ncsd+0x100);
	if(!hdr) return false;
	if(memcmp(hdr->magic,"NCSD",4)!=0) return false;
	if(hdr->partitionFlags[MediaPlatformIndex] != CTR) return false;
	if(hdr->partitionFlags[MediaTypeIndex] != CARD1 && hdr->partitionFlags[MediaTypeIndex] != CARD2) return false;
	return true;
}

u8* GetPartition(u8 *ncsd, u8 index)
{
	return (u8*)(ncsd+GetPartitionOffset(ncsd,index));
}


u64 GetPartitionOffset(u8 *ncsd, u8 index)
{
	cci_hdr *hdr = (cci_hdr*)(ncsd+0x100);
	u32 media_size = 0x200*pow(2,hdr->partitionFlags[MediaUnitSize]);
	u32 offset = u8_to_u64(hdr->offset_sizeTable[index].offset,LE);
	return offset*media_size;
}

u64 GetPartitionSize(u8 *ncsd, u8 index)
{
	cci_hdr *hdr = (cci_hdr*)(ncsd+0x100);
	u32 media_size = 0x200*pow(2,hdr->partitionFlags[MediaUnitSize]);
	u32 size = u8_to_u64(hdr->offset_sizeTable[index].size,LE);
	return size*media_size;
}
