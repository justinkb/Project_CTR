#include "lib.h"
#include "ncch.h"
#include "exheader.h"

#include "titleid.h"
#include "polarssl\base64.h"

#ifndef RETAIL_FSIGN
#include "accessdesc_sig.h" // For AccessDesc Presets
#endif

/* Prototypes */
void init_ExHeaderSettings(exheader_settings *exhdrset);
void free_ExHeaderSettings(exheader_settings *exhdrset);
int get_ExHeaderSettingsFromNcchset(exheader_settings *exhdrset, ncch_settings *ncchset);
int get_ExHeaderSettingsFromYaml(exheader_settings *exhdrset);

void AdjustBooleans(desc_settings *yaml);
int get_ExHeaderCodeSetInfo(exhdr_CodeSetInfo *CodeSetInfo, desc_settings *yaml);
int get_ExHeaderDependencyList(u8 *DependencyList, desc_settings *yaml);
int get_ExHeaderSystemInfo(exhdr_SystemInfo *SystemInfo, desc_settings *yaml);
int get_ExHeaderARM11SystemLocalInfo(exhdr_ARM11SystemLocalCapabilities *arm11, desc_settings *yaml);
int get_ExHeaderARM11KernelInfo(exhdr_ARM11KernelCapabilities *arm11, desc_settings *yaml);
int get_ExHeaderARM9AccessControlInfo(exhdr_ARM9AccessControlInfo *arm9, desc_settings *yaml);

int set_AccessDesc(exheader_settings *exhdrset, ncch_settings *ncchset);

/* ExHeader Signature Functions */
int SignAccessDesc(ExtendedHeader_Struct *ExHdr, keys_struct *keys)
{
	u8 *AccessDesc = (u8*) &ExHdr->AccessDescriptor.ncchpubkeymodulus;
	u8 *Signature = (u8*) &ExHdr->AccessDescriptor.signature;
	return ctr_sig(AccessDesc,0x300,Signature,keys->rsa.AccessDesc_Pub,keys->rsa.AccessDesc_Priv,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckAccessDescSignature(ExtendedHeader_Struct *ExHdr, keys_struct *keys)
{
	u8 *AccessDesc = (u8*) &ExHdr->AccessDescriptor.ncchpubkeymodulus;
	u8 *Signature = (u8*) &ExHdr->AccessDescriptor.signature;
	return ctr_sig(AccessDesc,0x300,Signature,keys->rsa.AccessDesc_Pub,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
}

/* ExHeader Build Functions */
int BuildExHeader(ncch_settings *ncchset)
{
	int result = 0;

	exheader_settings *exhdrset = malloc(sizeof(exheader_settings));
	if(!exhdrset) {fprintf(stderr,"[EXHEADER ERROR] MEM ERROR\n"); return MEM_ERROR;}
	init_ExHeaderSettings(exhdrset);

	// Get Settings
	result = get_ExHeaderSettingsFromNcchset(exhdrset,ncchset);
	if(result) goto finish;

	result = get_ExHeaderSettingsFromYaml(exhdrset);
	if(result) goto finish;

	result = set_AccessDesc(exhdrset,ncchset);
	if(result) goto finish;

	memcpy(&exhdrset->ExHdr->ARM11SystemLocalCapabilities.Flags,&exhdrset->ExHdr->AccessDescriptor.ARM11SystemLocalCapabilities.Flags,0x1f8);

finish:
	if(result) fprintf(stderr,"[EXHEADER ERROR] Failed to create ExHeader\n");
	free_ExHeaderSettings(exhdrset);
	return result;
}


void init_ExHeaderSettings(exheader_settings *exhdrset)
{
	memset(exhdrset,0,sizeof(exheader_settings));
}

void free_ExHeaderSettings(exheader_settings *exhdrset)
{
	free(exhdrset);
}

int get_ExHeaderSettingsFromNcchset(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	/* Transfer settings */
	exhdrset->keys = ncchset->keys;
	exhdrset->yaml = ncchset->yaml_set;

	/* Creating Output Buffer */
	ncchset->Sections.ExHeader.size = 0x800;
	ncchset->Sections.ExHeader.buffer = malloc(ncchset->Sections.ExHeader.size);
	if(!ncchset->Sections.ExHeader.buffer) {fprintf(stderr,"[EXHEADER ERROR] MEM ERROR\n"); return MEM_ERROR;}
	memset(ncchset->Sections.ExHeader.buffer,0,ncchset->Sections.ExHeader.size);
	
	/* Import ExHeader template */
	if(ncchset->ComponentFilePtrs.exheader_size){ 
		u32 import_size = min_u64(0x400,ncchset->ComponentFilePtrs.exheader_size);
		ReadFile_64(ncchset->Sections.ExHeader.buffer,import_size,0,ncchset->ComponentFilePtrs.exheader);
	}

	/* Create ExHeader Struct for output */
	exhdrset->ExHdr = (ExtendedHeader_Struct*)ncchset->Sections.ExHeader.buffer;

	/* Set Code Info if Code Section was built not imported */
	if(ncchset->Options.IsBuildingCodeSection){
		/* BSS Size */
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.BssSize,ncchset->CodeDetails.BSS_Size,LE);
		/* Data */
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.DataSectionInfo.Address,ncchset->CodeDetails.DataAddress,LE);
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.DataSectionInfo.CodeSize,ncchset->CodeDetails.DataSize,LE);
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.DataSectionInfo.NumMaxPages,ncchset->CodeDetails.DataMaxPages,LE);
		/* RO */
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.ReadOnlySectionInfo.Address,ncchset->CodeDetails.ROAddress,LE);
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.ReadOnlySectionInfo.CodeSize,ncchset->CodeDetails.ROSize,LE);
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.ReadOnlySectionInfo.NumMaxPages,ncchset->CodeDetails.ROMaxPages,LE);
		/* Text */
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.TextSectionInfo.Address,ncchset->CodeDetails.TextAddress,LE);
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.TextSectionInfo.CodeSize,ncchset->CodeDetails.TextSize,LE);
		u32_to_u8(exhdrset->ExHdr->CodeSetInfo.TextSectionInfo.NumMaxPages,ncchset->CodeDetails.TextMaxPages,LE);
	}

	/* Set Simple Flags */
	if(ncchset->Options.CompressCode)
		exhdrset->ExHdr->CodeSetInfo.Flags.flag |= ExeFsCodeCompress;
	if(ncchset->Options.UseOnSD)
		exhdrset->ExHdr->CodeSetInfo.Flags.flag |= RetailSDAppFlag;

	return 0;
}

int get_ExHeaderSettingsFromYaml(exheader_settings *exhdrset)
{
	AdjustBooleans(exhdrset->yaml);

	int result = 0;
	result = get_ExHeaderCodeSetInfo(&exhdrset->ExHdr->CodeSetInfo, exhdrset->yaml);
	if(result) goto finish;

	result = get_ExHeaderDependencyList((u8*)&exhdrset->ExHdr->DependencyList[0], exhdrset->yaml);
	if(result) goto finish;

	result = get_ExHeaderSystemInfo(&exhdrset->ExHdr->SystemInfo, exhdrset->yaml);
	if(result) goto finish;

	result = get_ExHeaderARM11SystemLocalInfo(&exhdrset->ExHdr->ARM11SystemLocalCapabilities, exhdrset->yaml);
	if(result) goto finish;

	result = get_ExHeaderARM11KernelInfo(&exhdrset->ExHdr->ARM11KernelCapabilities, exhdrset->yaml);
	if(result) goto finish;

	result = get_ExHeaderARM9AccessControlInfo(&exhdrset->ExHdr->ARM9AccessControlInfo, exhdrset->yaml);
	if(result) goto finish;

finish:
	return result;
}

void AdjustBooleans(desc_settings *yaml)
{
	if(yaml->DefaultSpec.AccessControlInfo.DisableDebug == -1) yaml->DefaultSpec.AccessControlInfo.DisableDebug = 0;
	if(yaml->DefaultSpec.AccessControlInfo.EnableForceDebug == -1) yaml->DefaultSpec.AccessControlInfo.EnableForceDebug = 0;
	if(yaml->DefaultSpec.AccessControlInfo.CanWriteSharedPage == -1) yaml->DefaultSpec.AccessControlInfo.CanWriteSharedPage = 0;
	if(yaml->DefaultSpec.AccessControlInfo.CanUsePrivilegedPriority == -1) yaml->DefaultSpec.AccessControlInfo.CanUsePrivilegedPriority = 0;
	if(yaml->DefaultSpec.AccessControlInfo.CanUseNonAlphabetAndNumber == -1) yaml->DefaultSpec.AccessControlInfo.CanUseNonAlphabetAndNumber = 0;
	if(yaml->DefaultSpec.AccessControlInfo.PermitMainFunctionArgument == -1) yaml->DefaultSpec.AccessControlInfo.PermitMainFunctionArgument = 0;
	if(yaml->DefaultSpec.AccessControlInfo.CanShareDeviceMemory == -1) yaml->DefaultSpec.AccessControlInfo.CanShareDeviceMemory = 0;
	if(yaml->DefaultSpec.AccessControlInfo.UseOtherVariationSaveData == -1) yaml->DefaultSpec.AccessControlInfo.UseOtherVariationSaveData = 0;
	if(yaml->DefaultSpec.AccessControlInfo.UseExtSaveData == -1) yaml->DefaultSpec.AccessControlInfo.UseExtSaveData = 0;
	if(yaml->DefaultSpec.AccessControlInfo.RunnableOnSleep == -1) yaml->DefaultSpec.AccessControlInfo.RunnableOnSleep = 0;
	if(yaml->DefaultSpec.AccessControlInfo.SpecialMemoryArrange == -1) yaml->DefaultSpec.AccessControlInfo.SpecialMemoryArrange = 0;
}

int get_ExHeaderCodeSetInfo(exhdr_CodeSetInfo *CodeSetInfo, desc_settings *yaml)
{
	/* Name */
	if(yaml->DefaultSpec.BasicInfo.Title){
		if(strlen(yaml->DefaultSpec.BasicInfo.Title) > 8){
			fprintf(stderr,"[EXHEADER ERROR] Parameter Too Long 'BasicInfo/Title'\n");
			return EXHDR_BAD_YAML_OPT;
		}
		strcpy((char*)CodeSetInfo->Name,yaml->DefaultSpec.BasicInfo.Title);
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: 'BasicInfo/Title'\n");
	}
	/* Stack Size */
	if(yaml->DefaultSpec.SystemControlInfo.StackSize){
		u32 StackSize = strtoul(yaml->DefaultSpec.SystemControlInfo.StackSize,NULL,0);
		u32_to_u8(CodeSetInfo->StackSize,StackSize,LE);
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: 'SystemControlInfo/StackSize'\n");
	}
	/* Remaster Version */
	if(yaml->DefaultSpec.SystemControlInfo.RemasterVersion){
		u16 RemasterVersion = strtol(yaml->DefaultSpec.SystemControlInfo.RemasterVersion,NULL,0);
		u16_to_u8(CodeSetInfo->Flags.remasterVersion,RemasterVersion,LE);
	}
	else{
		u16_to_u8(CodeSetInfo->Flags.remasterVersion,0,LE);
	}
	return 0;
}

int get_ExHeaderDependencyList(u8 *DependencyList, desc_settings *yaml)
{
	if(yaml->DefaultSpec.SystemControlInfo.DependencyNum > 0x30){
		fprintf(stderr,"[EXHEADER ERROR] Too Many Dependency IDs\n");
		return EXHDR_BAD_YAML_OPT;
	}
	for(int i = 0; i < yaml->DefaultSpec.SystemControlInfo.DependencyNum; i++){
		u8 *pos = (DependencyList + 0x8*i);
		u64 TitleID = strtoull(yaml->DefaultSpec.SystemControlInfo.Dependency[i],NULL,0);
		u64_to_u8(pos,TitleID,LE);
	}
	return 0;
}

int get_ExHeaderSystemInfo(exhdr_SystemInfo *SystemInfo, desc_settings *yaml)
{
	/* SaveDataSize */
	if(yaml->DefaultSpec.Rom.SaveDataSize){
		u64 SaveDataSize = strtoull(yaml->DefaultSpec.Rom.SaveDataSize,NULL,10);
		if(strstr(yaml->DefaultSpec.Rom.SaveDataSize,"K")){
			char *str = strstr(yaml->DefaultSpec.Rom.SaveDataSize,"K");
			if(strcmp(str,"K") == 0 || strcmp(str,"KB") == 0 ){
				SaveDataSize = SaveDataSize*KB;
			}
		}
		else if(strstr(yaml->DefaultSpec.Rom.SaveDataSize,"M")){
			char *str = strstr(yaml->DefaultSpec.Rom.SaveDataSize,"M");
			if(strcmp(str,"M") == 0 || strcmp(str,"MB") == 0 ){
				SaveDataSize = SaveDataSize*MB;
			}
		}
		else if(strstr(yaml->DefaultSpec.Rom.SaveDataSize,"G")){
			char *str = strstr(yaml->DefaultSpec.Rom.SaveDataSize,"G");
			if(strcmp(str,"G") == 0 || strcmp(str,"GB") == 0 ){
				SaveDataSize = SaveDataSize*GB;
			}
		}
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid save data size format.\n");
			return EXHDR_BAD_YAML_OPT;
		}
		if((SaveDataSize & 65536) != 0){
			fprintf(stderr,"[EXHEADER ERROR] Save data size must be aligned to 64K.\n");
			return EXHDR_BAD_YAML_OPT;
		}
		u64_to_u8(SystemInfo->SaveDataSize,SaveDataSize,LE);
	}
	else{
		u64_to_u8(SystemInfo->SaveDataSize,0,LE);
	}
	/* Jump Id */
	if(yaml->DefaultSpec.SystemControlInfo.JumpId){
		u64 JumpId = strtoull(yaml->DefaultSpec.SystemControlInfo.JumpId,NULL,0);
		u64_to_u8(SystemInfo->JumpId,JumpId,LE);
	}
	else{
		u64 JumpId = 0;
		int result = GetProgramID(&JumpId,yaml,false); 
		if(result) return result;
		u64_to_u8(SystemInfo->JumpId,JumpId,LE);
	}
	return 0;
}

int get_ExHeaderARM11SystemLocalInfo(exhdr_ARM11SystemLocalCapabilities *arm11, desc_settings *yaml)
{
	/* Program Id */
	u64 ProgramId = 0;
	int result = GetProgramID(&ProgramId,yaml,true); 
	if(result) return result;
	u64_to_u8(arm11->ProgramId,ProgramId,LE);
	return 0;
	/* Flags */
	//u32_to_u8(
}

int get_ExHeaderARM11KernelInfo(exhdr_ARM11KernelCapabilities *arm11, desc_settings *yaml)
{
	return 0;
}

int get_ExHeaderARM9AccessControlInfo(exhdr_ARM9AccessControlInfo *arm9, desc_settings *yaml)
{
	return 0;
}

int set_AccessDesc(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	switch(ncchset->Options.accessdesc){
		case auto_gen :
			/* Set RSA Keys */
			memcpy(ncchset->CxiRsaKey.PrivK,exhdrset->keys->rsa.CFA_Priv,0x100);
			memcpy(ncchset->CxiRsaKey.PubK,exhdrset->keys->rsa.CFA_Pub,0x100);
			memcpy(&exhdrset->ExHdr->AccessDescriptor.ncchpubkeymodulus,exhdrset->keys->rsa.CFA_Pub,0x100);
			/* Copy Data From ExHeader */
			memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM11SystemLocalCapabilities,&exhdrset->ExHdr->ARM11SystemLocalCapabilities,sizeof(exhdr_ARM11SystemLocalCapabilities));
			memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM11KernelCapabilities,&exhdrset->ExHdr->ARM11KernelCapabilities,sizeof(exhdr_ARM11KernelCapabilities));
			memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM9AccessControlInfo,&exhdrset->ExHdr->ARM9AccessControlInfo,sizeof(exhdr_ARM9AccessControlInfo));
			/* Sign AccessDesc */
			return SignAccessDesc(exhdrset->ExHdr,exhdrset->keys);
#ifndef RETAIL_FSIGN
		case app :
			memcpy(ncchset->CxiRsaKey.PrivK,(u8*)App_HdrPrivK,0x100);
			memcpy(ncchset->CxiRsaKey.PubK,(u8*)App_HdrPubK,0x100);
			memcpy(&exhdrset->ExHdr->AccessDescriptor.signature,(u8*)App_AcexData,0x400);
			return 0;
		case demo :
			memcpy(ncchset->CxiRsaKey.PrivK,(u8*)Demo_HdrPrivK,0x100);
			memcpy(ncchset->CxiRsaKey.PubK,(u8*)Demo_HdrPubK,0x100);
			memcpy(&exhdrset->ExHdr->AccessDescriptor.signature,(u8*)Demo_AcexData,0x400);
			return 0;
		case dlp :
			memcpy(ncchset->CxiRsaKey.PrivK,(u8*)Dlp_HdrPrivK,0x100);
			memcpy(ncchset->CxiRsaKey.PubK,(u8*)Dlp_HdrPubK,0x100);
			memcpy(&exhdrset->ExHdr->AccessDescriptor.signature,(u8*)Dlp_AcexData,0x400);
			return 0;
		case use_desc_file:
			/* Yaml Option Sanity Checks */
			if(!exhdrset->yaml->CommonHeaderKey.Found){
				fprintf(stderr,"[EXHEADER ERROR] Desc Section 'CommonHeaderKey' not found\n");
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			if(!exhdrset->yaml->CommonHeaderKey.D){
				fprintf(stderr,"[EXHEADER ERROR] 'CommonHeaderKey/D' not found\n");
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			if(strlen(exhdrset->yaml->CommonHeaderKey.D) != 350){
				fprintf(stderr,"[EXHEADER ERROR] 'CommonHeaderKey/D' has invalid length (%d)\n",strlen(exhdrset->yaml->CommonHeaderKey.D));
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			if(!exhdrset->yaml->CommonHeaderKey.Modulus){
				fprintf(stderr,"[EXHEADER ERROR] 'CommonHeaderKey/Modulus' not found\n");
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			if(strlen(exhdrset->yaml->CommonHeaderKey.Modulus) != 350){
				fprintf(stderr,"[EXHEADER ERROR] 'CommonHeaderKey/Modulus' has invalid length (%d)\n",strlen(exhdrset->yaml->CommonHeaderKey.Modulus));
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			if(!exhdrset->yaml->AccessControlDescriptor.AccCtlDescSign){
				fprintf(stderr,"[EXHEADER ERROR] 'AccessControlDescriptor/Signature' not found\n");
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			if(strlen(exhdrset->yaml->AccessControlDescriptor.AccCtlDescSign) != 350){
				fprintf(stderr,"[EXHEADER ERROR] 'AccessControlDescriptor/Signature' has invalid length (%d)\n",strlen(exhdrset->yaml->AccessControlDescriptor.AccCtlDescSign));
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			if(!exhdrset->yaml->AccessControlDescriptor.AccCtlDescBin){
				fprintf(stderr,"[EXHEADER ERROR] 'AccessControlDescriptor/Descriptor' not found\n");
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			if(strlen(exhdrset->yaml->AccessControlDescriptor.AccCtlDescBin) != 696){
				fprintf(stderr,"[EXHEADER ERROR] 'AccessControlDescriptor/Descriptor' has invalid length (%d)\n",strlen(exhdrset->yaml->AccessControlDescriptor.AccCtlDescBin));
				return COMMON_HEADER_KEY_NOT_FOUND;
			}
			/* Set RSA Keys */
			int result = 0;
			u32 out = 0x500;
			u8 *tmp = malloc(0x500);
			result = base64_decode(tmp,&out,(const u8*)exhdrset->yaml->CommonHeaderKey.Modulus,strlen(exhdrset->yaml->CommonHeaderKey.Modulus));
			if(result) goto finish;
			memcpy(ncchset->CxiRsaKey.PubK,tmp,0x100);
			out = 0x500;
			result = base64_decode(tmp,&out,(const u8*)exhdrset->yaml->CommonHeaderKey.D,strlen(exhdrset->yaml->CommonHeaderKey.D));
			if(result) goto finish;
			memcpy(ncchset->CxiRsaKey.PrivK,tmp,0x100);
			/* Set AccessDesc */
			out = 0x500;
			result = base64_decode(tmp,&out,(const u8*)exhdrset->yaml->AccessControlDescriptor.AccCtlDescSign,strlen(exhdrset->yaml->AccessControlDescriptor.AccCtlDescSign));
			if(result) goto finish;
			memcpy(exhdrset->ExHdr->AccessDescriptor.signature,tmp,0x100);
			memcpy(exhdrset->ExHdr->AccessDescriptor.ncchpubkeymodulus,ncchset->CxiRsaKey.PubK,0x100);
			out = 0x500;
			result = base64_decode(tmp,&out,(const u8*)exhdrset->yaml->AccessControlDescriptor.AccCtlDescBin,strlen(exhdrset->yaml->AccessControlDescriptor.AccCtlDescBin));
			if(result) goto finish;
			memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM11SystemLocalCapabilities,tmp,0x200);
finish:
			free(tmp);
			return result;			
#endif
	}
	return 0;
}

/* ExHeader Binary Print Functions */
void exhdr_Print_ServiceAccessControl(ExtendedHeader_Struct *hdr)
{
	printf("[+] Service Access Control\n");
	for(int i = 0; i < 32; i ++){
		char *SVC_Handle = (char*)hdr->ARM11SystemLocalCapabilities.ServiceAccessControl[i];
		if(SVC_Handle[0] == 0) break;
		printf("%.8s\n",hdr->ARM11SystemLocalCapabilities.ServiceAccessControl[i]);
	}
}

/* ExHeader Binary Read Functions */
u8* GetAccessDescSig_frm_exhdr(ExtendedHeader_Struct *hdr)
{
	if(!hdr) return NULL;
	return hdr->AccessDescriptor.signature ;
}

u8* GetNcchHdrPubKey_frm_exhdr(ExtendedHeader_Struct *hdr)
{
	if(!hdr) return NULL;
	return hdr->AccessDescriptor.ncchpubkeymodulus;
}

u8* GetAccessDesc_frm_exhdr(ExtendedHeader_Struct *hdr)
{
	if(!hdr) return NULL;
	return hdr->AccessDescriptor.ncchpubkeymodulus;
}

u16 GetRemasterVersion_frm_exhdr(ExtendedHeader_Struct *hdr)
{
	return u8_to_u16(hdr->CodeSetInfo.Flags.remasterVersion,LE);
}

u64 GetSaveDataSize_frm_exhdr(ExtendedHeader_Struct *hdr)
{
	return u8_to_u64(hdr->SystemInfo.SaveDataSize,LE);
}

int GetCoreVersion_frm_exhdr(u8 *Dest, ExtendedHeader_Struct *hdr)
{
	return (int) memcpy(Dest,hdr->ARM11SystemLocalCapabilities.Flags,4);
}

int GetDependancyList_frm_exhdr(u8 *Dest,ExtendedHeader_Struct *hdr)
{
	if(!Dest) return -1;
	for(int i = 0; i < 0x30; i++){
		memcpy(Dest,hdr->DependencyList,0x30*8);
	}
	return 0;
}

/* ExHeader Settings Read from Yaml */
int GetSaveDataSize_yaml(u64 *SaveDataSize, user_settings *usrset)
{	

	if(usrset->yaml_set.DefaultSpec.Rom.SaveDataSize){
		*SaveDataSize = strtoull(usrset->yaml_set.DefaultSpec.Rom.SaveDataSize,NULL,10);
		if(strstr(usrset->yaml_set.DefaultSpec.Rom.SaveDataSize,"K")){
			char *str = strstr(usrset->yaml_set.DefaultSpec.Rom.SaveDataSize,"K");
			if(strcmp(str,"K") == 0 || strcmp(str,"KB") == 0 ){
				*SaveDataSize = *SaveDataSize*KB;
			}
		}
		else if(strstr(usrset->yaml_set.DefaultSpec.Rom.SaveDataSize,"M")){
			char *str = strstr(usrset->yaml_set.DefaultSpec.Rom.SaveDataSize,"M");
			if(strcmp(str,"M") == 0 || strcmp(str,"MB") == 0 ){
				*SaveDataSize = *SaveDataSize*MB;
			}
		}
		else if(strstr(usrset->yaml_set.DefaultSpec.Rom.SaveDataSize,"G")){
			char *str = strstr(usrset->yaml_set.DefaultSpec.Rom.SaveDataSize,"G");
			if(strcmp(str,"G") == 0 || strcmp(str,"GB") == 0 ){
				*SaveDataSize = *SaveDataSize*GB;
			}
		}
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid save data size format.\n");
			return EXHDR_BAD_YAML_OPT;
		}
		if((*SaveDataSize & 65536) != 0){
			fprintf(stderr,"[EXHEADER ERROR] Save data size must be aligned to 64K.\n");
			return EXHDR_BAD_YAML_OPT;
		}
	}
	else{
		*SaveDataSize = 0;
	}
	return 0;
}

int GetRemasterVersion_yaml(u16 *RemasterVersion, user_settings *usrset)
{
	char *Str = usrset->yaml_set.DefaultSpec.SystemControlInfo.RemasterVersion;
	if(!Str){
		*RemasterVersion = 0;
		return 0;
	}
	*RemasterVersion = strtol(Str,NULL,0);
	return 0;
}