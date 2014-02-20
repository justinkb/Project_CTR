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
	cciset->out = fopen(usrset->outfile,"wb");
	if(!cciset->out){
		fprintf(stderr,"[CCI ERROR] Failed to create '%s'\n",usrset->outfile);
		result = FAILED_TO_CREATE_OUTFILE;
		goto finish;
	}
	
	// Generate NCSD Header and Additional Header
	result = BuildNCSDHeader(cciset,usrset);
	if(result) goto finish;
	BuildCardInfoHeader(cciset,usrset);
	
	// Write to File
	WriteCCI_HDR_ToFile(cciset);
	result = WriteCCI_Content_ToFile(cciset,usrset);
	if(result) goto finish;
	
	// Fill out file if necessary 
	if(cciset->MediaFootPadding) WriteCCI_DummyBytes(cciset);
	
	// Close output file
finish:
	if(result != FAILED_TO_CREATE_OUTFILE && cciset->out) fclose(cciset->out);
	free_CCISettings(cciset);
	return result;
}


int SignCCI(u8 *Signature, u8 *NCSD_HDR)
{
	return ctr_sig(NCSD_HDR,sizeof(NCSD_Header),Signature,ctx.keys->rsa.CCI_Pub,ctx.keys->rsa.CCI_Priv,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckCCISignature(u8 *Signature, u8 *NCSD_HDR)
{
	return ctr_sig(NCSD_HDR,sizeof(NCSD_Header),Signature,ctx.keys->rsa.CCI_Pub,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
}

void init_CCISettings(cci_settings *set)
{
	memset(set,0,sizeof(cci_settings));
	memset(&ctx,0,sizeof(InternalCCI_Context));
}

int get_CCISettings(cci_settings *cciset, user_settings *usrset)
{
	ctx.keys = &usrset->keys;
	int result = 0;

	/* Importing Data from Content */
	result = CheckContent0(cciset,usrset);
	if(result) return result;

	result = GetDataFromContent0(cciset,usrset);
	if(result) return result;

	result = GetContentFP(cciset,usrset);
	if(result) return result;

	

	/* Getting Data from YAML */
	result = GetNCSDFlags(cciset,&usrset->yaml_set);
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
	memcpy((u8*)ctx.commonHDR.magic,"NCSD",4);
	u32_to_u8((u8*)ctx.commonHDR.media_size,(cciset->MediaSize/cciset->MediaUnitSize),LE); 
	memcpy((u8*)ctx.commonHDR.title_id,cciset->MediaID,8);
	for(int i = 0; i < 8; i++){
		u32_to_u8((u8*)ctx.commonHDR.offsetsize_table[i].offset,(cciset->ContentOffset[i]/cciset->MediaUnitSize),LE);
		u32_to_u8((u8*)ctx.commonHDR.offsetsize_table[i].size,(cciset->ContentSize[i]/cciset->MediaUnitSize),LE);
		memcpy((u8*)ctx.commonHDR.partition_id_table[i],cciset->ContentTitleID[i],8);
	}
	memcpy((u8*)ctx.commonHDR.partition_flags,cciset->NCSD_Flags,8);
	if(SignCCI(ctx.Signature,(u8*)&ctx.commonHDR) != Good){
		fprintf(stderr,"[CCI ERROR] Failed to sign CCI\n");
		return CCI_SIG_FAIL;
	}
	return 0;
}

int BuildCardInfoHeader(cci_settings *cciset, user_settings *usrset)
{
	u32_to_u8((u8*)ctx.CardInfoHDR.writable_address,(cciset->WritableAddress/cciset->MediaUnitSize),LE); 
	u32_to_u8((u8*)ctx.CardInfoHDR.card_info_bitmask,cciset->CardInfoBitmask,BE);
	u32_to_u8((u8*)ctx.CardInfoHDR.media_size_used,cciset->TotalContentSize,LE); 
	memcpy((u8*)ctx.CardInfoHDR.ncch_0_title_id,cciset->ContentTitleID[0],8);
	memcpy((u8*)ctx.CardInfoHDR.initial_data,cciset->InitialData,0x30);
	if(!(usrset->OmitImportedNcchHdr && !usrset->IsBuildingNCCH0)) 
		memcpy((u8*)ctx.CardInfoHDR.ncch_0_header,cciset->NCCH_HDR,0x100);
	memcpy((u8*)ctx.DevCardInfoHDR.TitleKey,cciset->TitleKey,0x10);
	return 0;
}

int WriteCCI_HDR_ToFile(cci_settings *cciset)
{
	WriteBuffer(ctx.Signature,0x100,0,cciset->out);
	WriteBuffer((u8*)&ctx.commonHDR,sizeof(NCSD_Header),0x100,cciset->out);
	WriteBuffer((u8*)&ctx.CardInfoHDR,sizeof(CardInfo_Header),0x200,cciset->out);
	WriteBuffer((u8*)&ctx.DevCardInfoHDR,sizeof(Dev_CardInfo_Header),0x1200,cciset->out);
	return 0;
}

int WriteCCI_Content_ToFile(cci_settings *cciset,user_settings *usrset)
{
	// Write Content 0
	WriteBuffer(cciset->ncch0,cciset->ContentSize[0],cciset->ContentOffset[0],cciset->out);
	free(usrset->Content0.buffer);
	usrset->Content0.buffer = NULL;
	usrset->Content0.size = 0;
	
	// Add additional contents, recreating them with their new TitleID
	for(int i = 1; i < 8; i++){
		if(cciset->content[i]){
			u8 *ContentBuff = RetargetNCCH(cciset->content[i],cciset->ContentSize[i],cciset->ContentTitleID[i],cciset->MediaID,ctx.keys);
			if(!ContentBuff){
				fprintf(stderr,"[CCI ERROR] Could not import content %d to CCI\n",i);
				return FAILED_TO_IMPORT_FILE;
			}
			WriteBuffer(ContentBuff,cciset->ContentSize[i],cciset->ContentOffset[i],cciset->out);
			free(ContentBuff);
		}
	}
	return 0;
}

int WriteCCI_DummyBytes(cci_settings *cciset)
{
	// Seeking end of CCI Data
	fseek_64(cciset->out,cciset->TotalContentSize,SEEK_SET);

	// Determining Size of Dummy Bytes
	u64 len = cciset->MediaSize - cciset->TotalContentSize;
	
	// Creating Buffer of Dummy Bytes
	u8 dummy_bytes[cciset->MediaUnitSize];
	memset(&dummy_bytes,0xff,cciset->MediaUnitSize);
	
	// Writing Dummy Bytes to file
	for(u64 i = 0; i < len; i += cciset->MediaUnitSize){
		fwrite(&dummy_bytes,cciset->MediaUnitSize,1,cciset->out);
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
		if(usrset->ContentPath[i]){
			cciset->content[i] = fopen(usrset->ContentPath[i],"rb");
			if(!cciset->content[i]){ // Checking if file could be opened
				fprintf(stderr,"[CCI ERROR] Failed to create '%s'\n",usrset->outfile);
				return FAILED_TO_OPEN_FILE;
			}
			if(!IsNCCH(cciset->content[i],NULL)){ // Checking if NCCH
				fprintf(stderr,"[CCI ERROR] Content '%s' is invalid\n",usrset->ContentPath[i]);
				return NCSD_INVALID_NCCH0;
			}
			
			// Getting NCCH Header
			NCCH_Header *hdr = malloc(sizeof(NCCH_Header));;
			GetNCCH_CommonHDR(hdr,cciset->content[i],NULL);
			
			if(GetNCCH_MediaUnitSize(hdr) != cciset->MediaUnitSize){ // Checking if Media Unit Size matches CCI
				fprintf(stderr,"[CCI ERROR] Content '%s' is invalid\n",usrset->ContentPath[i]);
				return NCSD_INVALID_NCCH0;
			}
			
			memcpy(&cciset->ContentTitleID[i],cciset->MediaID,8); // Set TitleID
			 
			// Modify TitleID Accordingly
			u16 tmp = u8_to_u16(&hdr->title_id[6],LE);
			tmp |= (i+4);
			u16_to_u8(&cciset->ContentTitleID[i][6],tmp,LE);
			
			cciset->ContentSize[i] =  GetNCCH_MediaSize(hdr)*cciset->MediaUnitSize;
			cciset->ContentOffset[i] = cciset->TotalContentSize;
			
			cciset->TotalContentSize += cciset->ContentSize[i];
			
			free(hdr);
		}
	}
	return 0;
}

int CheckContent0(cci_settings *cciset, user_settings *usrset)
{
	if(!usrset->Content0.size) 
		return NCSD_NO_NCCH0;
	cciset->ncch0 = usrset->Content0.buffer;
	cciset->ncch0_FileLen = usrset->Content0.size;
	
	if(!IsNCCH(NULL,cciset->ncch0)) 
		return NCSD_INVALID_NCCH0;
	
	return 0;
}

int GetDataFromContent0(cci_settings *cciset, user_settings *usrset)
{
	cciset->TotalContentSize = 0x4000;
	
	NCCH_Header *hdr;
	
	hdr = GetNCCH_CommonHDR(NULL,NULL,cciset->ncch0);
	
	cciset->NCCH_HDR = hdr;
	
	u16 ncch_format_ver = u8_to_u16(hdr->version,LE);
	if(ncch_format_ver != 0 && ncch_format_ver != 2){
		fprintf(stderr,"[CCI ERROR] NCCH type %d Not Supported\n",ncch_format_ver);
		return FAILED_TO_IMPORT_FILE;
	}

	//memdump(stdout,"ncch0 head: ",(cciset->ncch0+0x100),0x100);
	//memdump(stdout,"ncch0 head: ",(u8*)(hdr),0x100);
	
	memcpy(cciset->MediaID,hdr->title_id,8);
	memcpy(&cciset->ContentTitleID[0],hdr->title_id,8);
	if(usrset->GenSDKCardInfoHeader){
		memcpy(cciset->InitialData,Stock_InitialData,0x30);
		memcpy(cciset->TitleKey,Stock_TitleKey,0x10);
	}
	else{
		u8 Hash[0x40];
		ctr_sha(cciset->ncch0,0x80,Hash,CTR_SHA_256);
		ctr_sha((cciset->ncch0+0x80),0x80,(Hash+0x20),CTR_SHA_256);
		memcpy(cciset->InitialData,Hash,0x2C);
		//memcpy(cciset->TitleKey,(Hash+0x30),0x10); // Might Remove
	}
	
	
	cciset->NCSD_Flags[MediaUnitSize] = hdr->flags[ContentUnitSize];
	cciset->MediaUnitSize = GetNCCH_MediaUnitSize(hdr);
	
	cciset->ContentSize[0] = (u64)(GetNCCH_MediaSize(hdr) * cciset->MediaUnitSize);
	cciset->ContentOffset[0] = cciset->TotalContentSize;
	
	cciset->TotalContentSize += cciset->ContentSize[0];
	return 0;
}

int GetMediaSize(cci_settings *cciset, user_settings *usrset)
{
	char *MediaSizeStr = usrset->yaml_set.BasicInfo.MediaSize;
	if(!MediaSizeStr) cciset->MediaSize = (u64)GB*2;
	else{
		if(strcasecmp(MediaSizeStr,"128MB") == 0) cciset->MediaSize = (u64)MB*128;
		else if(strcasecmp(MediaSizeStr,"256MB") == 0) cciset->MediaSize = (u64)MB*256;
		else if(strcasecmp(MediaSizeStr,"512MB") == 0) cciset->MediaSize = (u64)MB*512;
		else if(strcasecmp(MediaSizeStr,"1GB") == 0) cciset->MediaSize = (u64)GB*1;
		else if(strcasecmp(MediaSizeStr,"2GB") == 0) cciset->MediaSize = (u64)GB*2;
		else if(strcasecmp(MediaSizeStr,"4GB") == 0) cciset->MediaSize = (u64)GB*4;
		else if(strcasecmp(MediaSizeStr,"8GB") == 0) cciset->MediaSize = (u64)GB*8;
		else if(strcasecmp(MediaSizeStr,"16GB") == 0) cciset->MediaSize = (u64)GB*16;
		else if(strcasecmp(MediaSizeStr,"32GB") == 0) cciset->MediaSize = (u64)GB*32;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid MediaSize: %s\n",MediaSizeStr);
			return INVALID_YAML_OPT;
		}
	}
	
	if(usrset->yaml_set.BasicInfo.MediaFootPadding != -1) cciset->MediaFootPadding = usrset->yaml_set.BasicInfo.MediaFootPadding;
	
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
	cciset->NCSD_Flags[FW6x_BackupWriteWaitTime] = 0;
	if(yaml->CardInfo.BackupWriteWaitTime){
		u32 WaitTime = strtoul(yaml->CardInfo.BackupWriteWaitTime,NULL,0);
		if(WaitTime > 255){
			fprintf(stderr,"[CCI ERROR] Invalid Card BackupWriteWaitTime (%d) : must 0-255\n",WaitTime);
			return EXHDR_BAD_YAML_OPT;
		}
		cciset->NCSD_Flags[FW6x_BackupWriteWaitTime] = (u8)WaitTime;
	}

	/* FW6x SaveCrypto */
	cciset->NCSD_Flags[FW6x_SaveCryptoFlag] = 1;

	/* MediaType */
	if(!yaml->CardInfo.MediaType) cciset->NCSD_Flags[MediaTypeIndex] = CARD1;
	else{
		if(strcasecmp(yaml->CardInfo.MediaType,"Card1") == 0) cciset->NCSD_Flags[MediaTypeIndex] = CARD1;
		else if(strcasecmp(yaml->CardInfo.MediaType,"Card2") == 0) cciset->NCSD_Flags[MediaTypeIndex] = CARD2;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid MediaType: %s\n",yaml->CardInfo.MediaType);
			return INVALID_YAML_OPT;
		}
	}

	/* Platform */
	if(!yaml->TitleInfo.Platform) cciset->NCSD_Flags[MediaPlatformIndex] = CTR;
	else{
		if(strcasecmp(yaml->TitleInfo.Platform,"ctr") == 0) cciset->NCSD_Flags[MediaPlatformIndex] = CTR;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid Platform: %s\n",yaml->TitleInfo.Platform);
			return INVALID_YAML_OPT;
		}
	}

	/* CardDevice */
	if(!yaml->CardInfo.CardDevice) cciset->NCSD_Flags[CardDeviceFlag] = CARD_DEVICE_NONE;
	else{
		if(strcmp(yaml->CardInfo.CardDevice,"NorFlash") == 0) {
			cciset->NCSD_Flags[CardDeviceFlag] = CARD_DEVICE_NOR_FLASH;
			if(cciset->NCSD_Flags[MediaTypeIndex] == CARD2){
				fprintf(stderr,"[CCI WARNING] 'CardDevice: NorFlash' is invalid on Card2\n");
				cciset->NCSD_Flags[CardDeviceFlag] = CARD_DEVICE_NONE;
			}
		}
		else if(strcmp(yaml->CardInfo.CardDevice,"None") == 0) cciset->NCSD_Flags[CardDeviceFlag] = CARD_DEVICE_NONE;
		else if(strcmp(yaml->CardInfo.CardDevice,"BT") == 0) cciset->NCSD_Flags[CardDeviceFlag] = CARD_DEVICE_BT;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid CardDevice: %s\n",yaml->CardInfo.CardDevice);
			return INVALID_YAML_OPT;
		}
	}
	return 0;
}

int GetWriteableAddress(cci_settings *cciset, user_settings *usrset)
{
	int result = GetSaveDataSize_yaml(&cciset->SaveDataSize,usrset);
	if(result) return result;

	char *WriteableAddressStr = usrset->yaml_set.CardInfo.WritableAddress;;
	
	cciset->WritableAddress = -1;
	if(cciset->NCSD_Flags[MediaTypeIndex] != CARD2) return 0; // Can only be set for Card2 Media
	
	if(WriteableAddressStr){
		if(strncmp(WriteableAddressStr,"0x",2) != 0){
			fprintf(stderr,"[CCI ERROR] WritableAddress requires a Hexadecimal value\n");
			return INVALID_YAML_OPT;
		}	
		cciset->WritableAddress = strtoul((WriteableAddressStr+2),NULL,16);
	}
	if(cciset->WritableAddress == -1){ // If not set manually or is max size
		if ((cciset->MediaSize / 2) < cciset->SaveDataSize){ // If SaveData size is greater than half the MediaSize
			u64 saveDataSize = cciset->SaveDataSize / KB;
			fprintf(stderr,"[CCI ERROR] Too large SaveDataSize %luK\n",saveDataSize);
			return SAVE_DATA_TOO_LARGE;
		}
		if (cciset->SaveDataSize > (u64)(2047*MB)){ // Limit set by Nintendo
			u64 saveDataSize = cciset->SaveDataSize / KB;
			fprintf(stderr,"[CCI ERROR] Too large SaveDataSize %luK\n",saveDataSize);
			return SAVE_DATA_TOO_LARGE;
		}
		u64 UnusedSize = GetUnusedSize(cciset->MediaSize,cciset->NCSD_Flags[MediaTypeIndex]); // Need to look into this
		cciset->WritableAddress = cciset->MediaSize - UnusedSize - cciset->SaveDataSize;
	}
	return 0;
}

int GetCardInfoBitmask(cci_settings *cciset, user_settings *usrset)
{
	char *str = usrset->yaml_set.CardInfo.CardType;
	if(!str) cciset->CardInfoBitmask |= 0;
	else{
		if(strcasecmp(str,"s1") == 0) cciset->CardInfoBitmask |= 0;
		else if(strcasecmp(str,"s2") == 0) cciset->CardInfoBitmask |= 0x20;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid CardType: %s\n",str);
			return INVALID_YAML_OPT;
		}
	}
	
	str = usrset->yaml_set.CardInfo.CryptoType;
	if(!str) cciset->CardInfoBitmask |= (3*0x40);
	else{
		int Value = strtol(str,NULL,10);
		if(Value < 0 || Value > 3) {
			fprintf(stderr,"[CCI ERROR] Invalid CryptoType: %s\n",str);
			return INVALID_YAML_OPT;
		}
		if(Value != 3){
			fprintf(stderr,"[CCI WARNING] Card crypto type = '%d'\n",Value);
		}
		cciset->CardInfoBitmask |= (Value*0x40);
	}
	
	return 0;
}

int CheckMediaSize(cci_settings *cciset)
{
	if(cciset->TotalContentSize > cciset->MediaSize){
		char *MediaSizeStr = NULL;
		switch(cciset->MediaSize){
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
	NCSD_Header *hdr = (NCSD_Header*)(ncsd+0x100);
	if(!hdr) return false;
	if(memcmp(hdr->magic,"NCSD",4)!=0) return false;
	if(hdr->partition_flags[MediaPlatformIndex] != CTR) return false;
	if(hdr->partition_flags[MediaTypeIndex] != CARD1 && hdr->partition_flags[MediaTypeIndex] != CARD2) return false;
	return true;
}

u8* GetPartition(u8 *ncsd, u8 index)
{
	return (u8*)(ncsd+GetPartitionOffset(ncsd,index));
}


u64 GetPartitionOffset(u8 *ncsd, u8 index)
{
	NCSD_Header *hdr = (NCSD_Header*)(ncsd+0x100);
	u32 media_size = 0x200*pow(2,hdr->partition_flags[MediaUnitSize]);
	u32 offset = u8_to_u64(hdr->offsetsize_table[index].offset,LE);
	return offset*media_size;
}

u64 GetPartitionSize(u8 *ncsd, u8 index)
{
	NCSD_Header *hdr = (NCSD_Header*)(ncsd+0x100);
	u32 media_size = 0x200*pow(2,hdr->partition_flags[MediaUnitSize]);
	u32 size = u8_to_u64(hdr->offsetsize_table[index].size,LE);
	return size*media_size;
}
