#include "lib.h"
#include "ncch.h"
#include "exheader.h"

#include "titleid.h"
#include "polarssl/base64.h"

#include "accessdesc_sig.h" // For AccessDesc Presets

/* Prototypes */
void init_ExHeaderSettings(exheader_settings *exhdrset);
void free_ExHeaderSettings(exheader_settings *exhdrset);
int get_ExHeaderSettingsFromNcchset(exheader_settings *exhdrset, ncch_settings *ncchset);
int get_ExHeaderSettingsFromYaml(exheader_settings *exhdrset);

int get_ExHeaderCodeSetInfo(exhdr_CodeSetInfo *CodeSetInfo, rsf_settings *yaml);
int get_ExHeaderDependencyList(u8 *DependencyList, rsf_settings *yaml);
int get_ExHeaderSystemInfo(exhdr_SystemInfo *SystemInfo, rsf_settings *yaml);
int get_ExHeaderARM11SystemLocalInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml, bool UseAccessDescPreset);
int SetARM11SystemLocalInfoFlags(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml);
int GetAppType(int *AppType, rsf_settings *yaml);
int SetARM11ResLimitDesc(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml);
int SetARM11StorageInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml);
int SetARM11StorageInfoSystemSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml);
int SetARM11StorageInfoExtSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml);
int SetARM11StorageInfoOtherUserSaveData(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml);
bool CheckCondiditionsForNewAccessibleSaveDataIds(rsf_settings *yaml);
int SetARM11StorageInfoAccessibleSaveDataIds(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml);
int SetARM11ServiceAccessControl(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml);
int get_ExHeaderARM11KernelInfo(exhdr_ARM11KernelCapabilities *arm11, rsf_settings *yaml);
int SetARM11KernelDescSysCallControl(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
int GetARM11SysCalls(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
void EnableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall);
void DisableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall);
int SetARM11KernelDescInteruptNumList(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
int GetARM11Interupts(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
void EnableInterupt(ARM11KernelCapabilityDescriptor *desc, int Interrupt, int i);
int SetARM11KernelDescAddressMapping(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
int GetARM11IOMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
int GetARM11StaticMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
bool IsEndAddress(u32 Address);
bool IsStartAddress(u32 Address);
u32 GetIOMappingDesc(u32 Address);
u32 GetStaticMappingDesc(u32 Address, bool IsReadOnly);
u32 GetMappingDesc(u32 Address, u32 PrefixVal, s32 numPrefixBits, bool IsRO);
int SetARM11KernelDescOtherCapabilities(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
int SetARM11KernelDescHandleTableSize(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
int SetARM11KernelDescReleaseKernelVersion(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml);
void SetARM11KernelDescValue(ARM11KernelCapabilityDescriptor *desc, u16 Index, u32 Value);
void SetARM11KernelDescBitmask(ARM11KernelCapabilityDescriptor *desc, u32 Bitmask);
void AllocateARM11KernelDescMemory(ARM11KernelCapabilityDescriptor *desc, u16 Num);
u32 GetDescPrefixMask(int numPrefixBits);
u32 GetDescPrefixBits(int numPrefixBits, u32 PrefixVal);
int get_ExHeaderARM9AccessControlInfo(exhdr_ARM9AccessControlInfo *arm9, rsf_settings *yaml);
int set_AccessDesc(exheader_settings *exhdrset, ncch_settings *ncchset);
int accessdesc_SignWithKey(exheader_settings *exhdrset, ncch_settings *ncchset);
int accessdesc_GetSignFromRsf(exheader_settings *exhdrset, ncch_settings *ncchset);
int accessdesc_GetSignFromPreset(exheader_settings *exhdrset, ncch_settings *ncchset);

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

	exhdrset->ExHdr->AccessDescriptor.ARM11SystemLocalCapabilities.Flags[6] = 5;

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
	exhdrset->UseAccessDescPreset = ncchset->keys->AccessDescSign.PresetType != not_preset;

	/* Creating Output Buffer */
	ncchset->Sections.ExHeader.size = 0x800;
	ncchset->Sections.ExHeader.buffer = malloc(ncchset->Sections.ExHeader.size);
	if(!ncchset->Sections.ExHeader.buffer) {fprintf(stderr,"[EXHEADER ERROR] MEM ERROR\n"); return MEM_ERROR;}
	memset(ncchset->Sections.ExHeader.buffer,0,ncchset->Sections.ExHeader.size);
	
	/* Import ExHeader Code Section template */
	if(ncchset->ComponentFilePtrs.exheader_size){ 
		u32 import_size = 0x30; min_u64(0x30,ncchset->ComponentFilePtrs.exheader_size);
		u32 import_offset = 0x10;
		if((import_size+import_offset) > ncchset->ComponentFilePtrs.exheader_size){
			fprintf(stderr,"[EXHEADER ERROR] Exheader Template is too small\n");
		}
		ReadFile_64((ncchset->Sections.ExHeader.buffer+import_offset),import_size,import_offset,ncchset->ComponentFilePtrs.exheader);
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
	if(!ncchset->Options.UseRomFS) // Move this later
		exhdrset->ExHdr->ARM11SystemLocalCapabilities.StorageInfo.OtherAttributes |= 1 << attribute_NOT_USE_ROMFS;

	return 0;
}

int get_ExHeaderSettingsFromYaml(exheader_settings *exhdrset)
{
	int result = 0;
	result = get_ExHeaderCodeSetInfo(&exhdrset->ExHdr->CodeSetInfo, exhdrset->yaml);
	if(result) goto finish;

	if(!exhdrset->UseAccessDescPreset){
		result = get_ExHeaderDependencyList((u8*)&exhdrset->ExHdr->DependencyList[0], exhdrset->yaml);
		if(result) goto finish;
	}

	result = get_ExHeaderSystemInfo(&exhdrset->ExHdr->SystemInfo, exhdrset->yaml);
	if(result) goto finish;

	result = get_ExHeaderARM11SystemLocalInfo(&exhdrset->ExHdr->ARM11SystemLocalCapabilities, exhdrset->yaml, exhdrset->UseAccessDescPreset);
	if(result) goto finish;

	if(!exhdrset->UseAccessDescPreset){
		result = get_ExHeaderARM11KernelInfo(&exhdrset->ExHdr->ARM11KernelCapabilities, exhdrset->yaml);
		if(result) goto finish;

		result = get_ExHeaderARM9AccessControlInfo(&exhdrset->ExHdr->ARM9AccessControlInfo, exhdrset->yaml);
		if(result) goto finish;
	}

finish:
	return result;
}

int get_ExHeaderCodeSetInfo(exhdr_CodeSetInfo *CodeSetInfo, rsf_settings *yaml)
{
	/* Name */
	if(yaml->BasicInfo.Title){
		if(strlen(yaml->BasicInfo.Title) > 8){
			fprintf(stderr,"[EXHEADER ERROR] Parameter Too Long 'BasicInfo/Title'\n");
			return EXHDR_BAD_YAML_OPT;
		}
		strcpy((char*)CodeSetInfo->Name,yaml->BasicInfo.Title);
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: 'BasicInfo/Title'\n");
		return EXHDR_BAD_YAML_OPT;
	}
	/* Stack Size */
	if(yaml->SystemControlInfo.StackSize){
		u32 StackSize = strtoul(yaml->SystemControlInfo.StackSize,NULL,0);
		u32_to_u8(CodeSetInfo->StackSize,StackSize,LE);
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: 'SystemControlInfo/StackSize'\n");
		return EXHDR_BAD_YAML_OPT;
	}
	/* Remaster Version */
	if(yaml->SystemControlInfo.RemasterVersion){
		u16 RemasterVersion = strtol(yaml->SystemControlInfo.RemasterVersion,NULL,0);
		u16_to_u8(CodeSetInfo->Flags.remasterVersion,RemasterVersion,LE);
	}
	else{
		u16_to_u8(CodeSetInfo->Flags.remasterVersion,0,LE);
	}
	return 0;
}

int get_ExHeaderDependencyList(u8 *DependencyList, rsf_settings *yaml)
{
	if(yaml->SystemControlInfo.DependencyNum > 0x30){
		fprintf(stderr,"[EXHEADER ERROR] Too Many Dependency IDs\n");
		return EXHDR_BAD_YAML_OPT;
	}
	for(int i = 0; i < yaml->SystemControlInfo.DependencyNum; i++){
		u8 *pos = (DependencyList + 0x8*i);
		u64 TitleID = strtoull(yaml->SystemControlInfo.Dependency[i],NULL,0);
		u64_to_u8(pos,TitleID,LE);
	}
	return 0;
}

int get_ExHeaderSystemInfo(exhdr_SystemInfo *SystemInfo, rsf_settings *yaml)
{
	/* SaveDataSize */
	if(yaml->Rom.SaveDataSize){
		u64 SaveDataSize = strtoull(yaml->Rom.SaveDataSize,NULL,10);
		if(strstr(yaml->Rom.SaveDataSize,"K")){
			char *str = strstr(yaml->Rom.SaveDataSize,"K");
			if(strcmp(str,"K") == 0 || strcmp(str,"KB") == 0 ){
				SaveDataSize *= KB;
			}
		}
		else if(strstr(yaml->Rom.SaveDataSize,"M")){
			char *str = strstr(yaml->Rom.SaveDataSize,"M");
			if(strcmp(str,"M") == 0 || strcmp(str,"MB") == 0 ){
				SaveDataSize *= MB;
			}
		}
		else if(strstr(yaml->Rom.SaveDataSize,"G")){
			char *str = strstr(yaml->Rom.SaveDataSize,"G");
			if(strcmp(str,"G") == 0 || strcmp(str,"GB") == 0 ){
				SaveDataSize *= GB;
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
	if(yaml->SystemControlInfo.JumpId){
		u64 JumpId = strtoull(yaml->SystemControlInfo.JumpId,NULL,0);
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

int get_ExHeaderARM11SystemLocalInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml, bool UseAccessDescPreset)
{
	/* Program Id */
	u64 ProgramId = 0;
	int result = GetProgramID(&ProgramId,yaml,true); 
	if(result) return result;
	u64_to_u8(arm11->ProgramId,ProgramId,LE);
	
	if(!UseAccessDescPreset){
		/* Flags */
		result = SetARM11SystemLocalInfoFlags(arm11, yaml);
		if(result) return result;

		/* Resource Limit Descriptors */
		result = SetARM11ResLimitDesc(arm11, yaml);
		if(result) return result;
	}

	/* Storage Info */
	result = SetARM11StorageInfo(arm11, yaml);
	if(result) return result;

	if(!UseAccessDescPreset){
		/* Service Access Control */
		result = SetARM11ServiceAccessControl(arm11, yaml);
		if(result) return result;

		/* Resource Limit Category */
		if(yaml->AccessControlInfo.ResourceLimitCategory){
			if(strcasecmp(yaml->AccessControlInfo.ResourceLimitCategory,"application") == 0) arm11->ResourceLimitCategory = resrc_limit_APPLICATION;
			else if(strcasecmp(yaml->AccessControlInfo.ResourceLimitCategory,"sysapplet") == 0) arm11->ResourceLimitCategory = resrc_limit_SYS_APPLET;
			else if(strcasecmp(yaml->AccessControlInfo.ResourceLimitCategory,"libapplet") == 0) arm11->ResourceLimitCategory = resrc_limit_LIB_APPLET;
			else if(strcasecmp(yaml->AccessControlInfo.ResourceLimitCategory,"other") == 0) arm11->ResourceLimitCategory = resrc_limit_OTHER;
		}
	}
	/* Finish */
	return 0;
}

int SetARM11SystemLocalInfoFlags(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml)
{
	/* Core Version */
	if(yaml->AccessControlInfo.CoreVersion){
		u32 Version = strtoul(yaml->AccessControlInfo.CoreVersion,NULL,0);
		u32_to_u8(&arm11->Flags[0],Version,LE);
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: 'AccessControlInfo/CoreVersion'\n");
		return EXHDR_BAD_YAML_OPT;
	}

	/* Byte[6] */
	u8 AffinityMask = 0;
	u8 IdealProcessor = 0;
	u8 SystemMode = 0;
	if(yaml->AccessControlInfo.AffinityMask){
		AffinityMask = strtol(yaml->AccessControlInfo.AffinityMask,NULL,0);
		if(AffinityMask > 1){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected AffinityMask: %d. Expected range: 0x0 - 0x1\n",AffinityMask);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	if(yaml->AccessControlInfo.IdealProcessor){
		IdealProcessor = strtol(yaml->AccessControlInfo.IdealProcessor,NULL,0);
		if(IdealProcessor > 1){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected IdealProcessor: %d. Expected range: 0x0 - 0x1\n",IdealProcessor);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	if(yaml->AccessControlInfo.SystemMode){
		SystemMode = strtol(yaml->AccessControlInfo.SystemMode,NULL,0);
		if(SystemMode > 15){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected SystemMode: 0x%x. Expected range: 0x0 - 0xf\n",SystemMode);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	arm11->Flags[6] = (u8)(SystemMode << 4 | AffinityMask << 2 | IdealProcessor);

	/* Thread Priority */
	if(yaml->AccessControlInfo.Priority){
		u8 Priority = strtoul(yaml->AccessControlInfo.Priority,NULL,0);
		int ProccessType = 0;
		GetAppType(&ProccessType,yaml);
		if(ProccessType == processtype_APPLICATION || ProccessType == processtype_DEFAULT){
			Priority += 32;
		}
		if(Priority > 127){
			fprintf(stderr,"[EXHEADER ERROR] Invalid Priority: %d\n",Priority);
			return EXHDR_BAD_YAML_OPT;
		}
		arm11->Flags[7] = Priority;
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: 'AccessControlInfo/Priority'\n");
		return EXHDR_BAD_YAML_OPT;
	}

	return 0;
}

int GetAppType(int *AppType, rsf_settings *yaml)
{
	*AppType = processtype_DEFAULT;
	if(yaml->SystemControlInfo.AppType){
		if(strcasecmp(yaml->SystemControlInfo.AppType,"application") == 0) *AppType = processtype_APPLICATION;
		else if(strcasecmp(yaml->SystemControlInfo.AppType,"system") == 0) *AppType = processtype_SYSTEM;
	}
	return 0;
}

int SetARM11ResLimitDesc(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml)
{
	for(int i = 0; i < 16; i++){
		if(i == 0){
			/* MaxCpu */
			// N's makerom actually reads this from the pre-made accessdesc. Damn cheaters. But we can improvise
			if(yaml->AccessControlInfo.MaxCpu){
				arm11->ResourceLimitDescriptor[i][0] = strtol(yaml->AccessControlInfo.MaxCpu,NULL,0);
			}
		}
	}
	
	return 0;
}

int SetARM11StorageInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml)
{
	if(yaml->AccessControlInfo.UseExtendedSaveDataAccessControl || yaml->AccessControlInfo.AccessibleSaveDataIds){
		/* Accessible SaveData IDs */
		if(!CheckCondiditionsForNewAccessibleSaveDataIds(yaml))
			return EXHDR_BAD_YAML_OPT;
		SetARM11StorageInfoAccessibleSaveDataIds(arm11,yaml);
	}
	else{
		/* Extdata Id */
		int ret = SetARM11StorageInfoExtSaveDataId(arm11,yaml);
		if(ret) return ret;
		/* OtherUserSaveData */
		SetARM11StorageInfoOtherUserSaveData(arm11,yaml);
	}

	/* System Savedata Id */
	SetARM11StorageInfoSystemSaveDataId(arm11,yaml);	

	/* FileSystem Access Info */
	u32 AccessInfo = 0;
	for(int i = 0; i < yaml->AccessControlInfo.FileSystemAccessNum; i++){
		if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CategorySystemApplication") == 0)
			AccessInfo |= 1 << fsaccess_CATEGORY_SYSTEM_APPLICATION;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CategoryHardwareCheck") == 0)
			AccessInfo |= 1 << fsaccess_CATEGORY_HARDWARE_CHECK;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CategoryFileSystemTool") == 0)
			AccessInfo |= 1 << fsaccess_CATEGORY_FILE_SYSTEM_TOOL;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"Debug") == 0)
			AccessInfo |= 1 << fsaccess_DEBUG;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"TwlCardBackup") == 0)
			AccessInfo |= 1 << fsaccess_TWL_CARD_BACKUP;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"TwlNandData") == 0)
			AccessInfo |= 1 << fsaccess_TWL_NAND_DATA;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"Boss") == 0)
			AccessInfo |= 1 << fsaccess_BOSS;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"DirectSdmc") == 0)
			AccessInfo |= 1 << fsaccess_DIRECT_SDMC;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"Core") == 0)
			AccessInfo |= 1 << fsaccess_CORE;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CtrNandRo") == 0)
			AccessInfo |= 1 << fsaccess_CTR_NAND_RO;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CtrNandRw") == 0)
			AccessInfo |= 1 << fsaccess_CTR_NAND_RW;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CtrNandRoWrite") == 0)
			AccessInfo |= 1 << fsaccess_CTR_NAND_RO_WRITE;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CategorySystemSettings") == 0)
			AccessInfo |= 1 << fsaccess_CATEGORY_SYSTEM_SETTINGS;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CardBoard") == 0)
			AccessInfo |= 1 << fsaccess_CARD_BOARD;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"ExportImportIvs") == 0)
			AccessInfo |= 1 << fsaccess_EXPORT_IMPORT_IVS;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"DirectSdmcWrite") == 0)
			AccessInfo |= 1 << fsaccess_DIRECT_SDMC_WRITE;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"SwitchCleanup") == 0)
			AccessInfo |= 1 << fsaccess_SWITCH_CLEANUP;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"SaveDataMove") == 0)
			AccessInfo |= 1 << fsaccess_SAVE_DATA_MOVE;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"Shop") == 0)
			AccessInfo |= 1 << fsaccess_SHOP;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"Shell") == 0)
			AccessInfo |= 1 << fsaccess_SHELL;
		else if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"CategoryHomeMenu") == 0)
			AccessInfo |= 1 << fsaccess_CATEGORY_HOME_MENU;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid FileSystemAccess Name: '%s'\n",yaml->AccessControlInfo.FileSystemAccess[i]);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	u32_to_u8(arm11->StorageInfo.AccessInfo,AccessInfo,LE);
	return 0;
}

int SetARM11StorageInfoSystemSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml)
{
	if(yaml->AccessControlInfo.SystemSaveDataId1){
		u32 SaveId = strtoul(yaml->AccessControlInfo.SystemSaveDataId1,NULL,0);
		u32_to_u8(arm11->StorageInfo.SystemSaveDataId,SaveId,LE);
	}
	if(yaml->AccessControlInfo.SystemSaveDataId2){
		u32 SaveId = strtoul(yaml->AccessControlInfo.SystemSaveDataId2,NULL,0);
		u32_to_u8(&arm11->StorageInfo.SystemSaveDataId[4],SaveId,LE);
	}
	return 0;
}

int SetARM11StorageInfoExtSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml)
{
	if(yaml->AccessControlInfo.ExtSaveDataId){
		if(!yaml->AccessControlInfo.UseExtSaveData){
			fprintf(stderr,"[EXHEADER ERROR] Failed to set ExtSaveDataId. UseExtSaveData must be true.\n");
			return EXHDR_BAD_YAML_OPT;
		}
		u64 ExtdataId = strtoull(yaml->AccessControlInfo.ExtSaveDataId,NULL,0);
		u64_to_u8(arm11->StorageInfo.ExtSaveDataId,ExtdataId,LE);
	}
	return 0;
}

int SetARM11StorageInfoOtherUserSaveData(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml)
{
	u64 Value = 0; 
	if(yaml->AccessControlInfo.OtherUserSaveDataId1)
		Value = 0xffffff & strtoul(yaml->AccessControlInfo.OtherUserSaveDataId1,NULL,0);
	Value = Value << 20;
	if(yaml->AccessControlInfo.OtherUserSaveDataId2)
		Value |= 0xffffff & strtoul(yaml->AccessControlInfo.OtherUserSaveDataId2,NULL,0);
	Value = Value << 20;
	if(yaml->AccessControlInfo.OtherUserSaveDataId3)
		Value |= 0xffffff & strtoul(yaml->AccessControlInfo.OtherUserSaveDataId3,NULL,0);

	/* UseOtherVariationSaveData Flag */
	if(yaml->AccessControlInfo.UseOtherVariationSaveData){
		Value |= 0x1000000000000000;
	}
	u64_to_u8(arm11->StorageInfo.StorageAccessableUniqueIds,Value,LE);
	return 0;
}

bool CheckCondiditionsForNewAccessibleSaveDataIds(rsf_settings *yaml)
{
	if(!yaml->AccessControlInfo.UseExtendedSaveDataAccessControl){
		if(yaml->AccessControlInfo.AccessibleSaveDataIds)
			fprintf(stderr,"[EXHEADER ERROR] AccessibleSaveDataIds is unavailable if UseExtendedSaveDataAccessControl is false.\n");
		return false;
	}

	/*
	if(yaml->AccessControlInfo.AccessibleSaveDataIdsNum == 0){
		fprintf(stderr,"[EXHEADER ERROR] AccessibleSaveDataIds must be specified if UseExtendedSaveDataAccessControl is true.\n");
		return false;
	}
	*/

	if(yaml->AccessControlInfo.AccessibleSaveDataIdsNum > 6){
		fprintf(stderr,"[EXHEADER ERROR] Too many UniqueId in \"AccessibleSaveDataIds\".\n");
		return false;
	}

	if(yaml->AccessControlInfo.UseExtSaveData){
		fprintf(stderr,"[EXHEADER ERROR] UseExtSaveData must be false if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	if (yaml->AccessControlInfo.ExtSaveDataId){
		fprintf(stderr,"[EXHEADER ERROR] ExtSaveDataId is unavailable if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	if (yaml->AccessControlInfo.OtherUserSaveDataId1){
		if(strtoul(yaml->AccessControlInfo.OtherUserSaveDataId1,NULL,0) > 0){
			fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId1 must be 0 if AccessibleSaveDataIds is specified.\n");
			return false;
		}
	}
	if (yaml->AccessControlInfo.OtherUserSaveDataId2){
		if(strtoul(yaml->AccessControlInfo.OtherUserSaveDataId2,NULL,0) > 0){
			fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId2 must be 0 if AccessibleSaveDataIds is specified.\n");
			return false;
		}
	}
	if (yaml->AccessControlInfo.OtherUserSaveDataId3){
		if(strtoul(yaml->AccessControlInfo.OtherUserSaveDataId3,NULL,0) > 0){
			fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId3 must be 0 if AccessibleSaveDataIds is specified.\n");
			return false;
		}
	}
	return true;
}

int SetARM11StorageInfoAccessibleSaveDataIds(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml)
{
	u64 RegionExtSaveDataId = 0;
	u64 RegionOtherUseSaveData = 0;

	if(yaml->AccessControlInfo.AccessibleSaveDataIdsNum > 0){
		u32 Max = yaml->AccessControlInfo.AccessibleSaveDataIdsNum < 3 ? yaml->AccessControlInfo.AccessibleSaveDataIdsNum : 3;
		for(int i = 0; i < Max; i++){
			u32 UniqueID = 0xffffff & strtoul(yaml->AccessControlInfo.AccessibleSaveDataIds[i],NULL,0);
			RegionOtherUseSaveData = RegionOtherUseSaveData << 20;
			RegionOtherUseSaveData |= UniqueID;
		}
	}
	if(yaml->AccessControlInfo.AccessibleSaveDataIdsNum > 3){
		for(int i = 3; i < yaml->AccessControlInfo.AccessibleSaveDataIdsNum; i++){
			u32 UniqueID = 0xffffff & strtoul(yaml->AccessControlInfo.AccessibleSaveDataIds[i],NULL,0);
			RegionExtSaveDataId = RegionExtSaveDataId << 20;
			RegionExtSaveDataId |= UniqueID;
		}
	}

	arm11->StorageInfo.OtherAttributes |= 1 << attribute_USE_EXTENDED_SAVEDATA_ACCESS_CONTROL;

	/* UseOtherVariationSaveData Flag */
	if(yaml->AccessControlInfo.UseOtherVariationSaveData){
		RegionOtherUseSaveData |= 0x1000000000000000;
	}

	u64_to_u8(arm11->StorageInfo.ExtSaveDataId,RegionExtSaveDataId,LE);
	u64_to_u8(arm11->StorageInfo.StorageAccessableUniqueIds,RegionOtherUseSaveData,LE);
	return 0;
}

int SetARM11ServiceAccessControl(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *yaml)
{
	if(yaml->AccessControlInfo.ServiceAccessControl){
		if(yaml->AccessControlInfo.ServiceAccessControlNum > 32){
			fprintf(stderr,"[EXHEADER ERROR] Too Many Service Names, maximum is 32\n");
			return EXHDR_BAD_YAML_OPT;
		}
		for(int i = 0; i < yaml->AccessControlInfo.ServiceAccessControlNum; i++){
			int svc_handle_len = strlen(yaml->AccessControlInfo.ServiceAccessControl[i]);
			if(svc_handle_len > 8){
				fprintf(stderr,"[EXHEADER ERROR] Service Name: \"%s\" is too long\n",yaml->AccessControlInfo.ServiceAccessControl[i]);
				return EXHDR_BAD_YAML_OPT;
			}
			memcpy(arm11->ServiceAccessControl[i],yaml->AccessControlInfo.ServiceAccessControl[i],svc_handle_len);
		}
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: \"AccessControlInfo/ServiceAccessControl\"\n");
		return EXHDR_BAD_YAML_OPT;
	}
	return 0;
}

int get_ExHeaderARM11KernelInfo(exhdr_ARM11KernelCapabilities *arm11, rsf_settings *yaml)
{
	int result = 0;
	ARM11KernelCapabilityDescriptor desc[6];
	memset(&desc,0,sizeof(ARM11KernelCapabilityDescriptor)*6);

	/* Get Descriptors */
	result = SetARM11KernelDescSysCallControl(&desc[0],yaml);
	if(result) goto finish;
	result = SetARM11KernelDescInteruptNumList(&desc[1],yaml);
	if(result) goto finish;
	result = SetARM11KernelDescAddressMapping(&desc[2],yaml);
	if(result) goto finish;
	result = SetARM11KernelDescOtherCapabilities(&desc[3],yaml);
	if(result) goto finish;
	result = SetARM11KernelDescHandleTableSize(&desc[4],yaml);
	if(result) goto finish;
	result = SetARM11KernelDescReleaseKernelVersion(&desc[5],yaml);

	/* Write Descriptors To Exheader */
	u16 TotalDesc = 0;
	for(int i = 0; i < 6; i++){
		TotalDesc += desc[i].num;
	}
	if(TotalDesc >= 28){
		fprintf(stderr,"[EXHEADER ERROR] Too many Kernel Capabilities.\n");
		result = EXHDR_BAD_YAML_OPT;
		goto finish;
	}
	u16 DescIndex = 0;
	for(int i = 0; i < 6; i++){
		for(int j = 0; j < desc[i].num; j++){
			u32_to_u8(arm11->descriptors[DescIndex],desc[i].Data[j],LE);
			DescIndex++;
		}
	}

	/* Fill Remaining Descriptors with 0xffffffff */ 
	for(int i = DescIndex; i < 28; i++){
		u32_to_u8(arm11->descriptors[i],0xffffffff,LE);
	}

finish:
	for(int i = 0; i < 6; i++){
		free(desc[i].Data);
	}
	return result;
}

int SetARM11KernelDescSysCallControl(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	int ret = 0;

	// Create Temporary Descriptor
	ARM11KernelCapabilityDescriptor tmp;
	memset(&tmp,0,sizeof(ARM11KernelCapabilityDescriptor));

	AllocateARM11KernelDescMemory(&tmp,8);
	for(int i = 0; i < 8; i++)
		SetARM11KernelDescValue(&tmp,i,desc_SysCallControl | (i << 24));

	// Get SysCalls
	ret = GetARM11SysCalls(&tmp,yaml);
	if(ret) goto finish;

	// Count Active Syscall Descs
	u16 ActiveSysCallDesc = 0;
	for(int i = 0; i < 8; i++)
		if((tmp.Data[i] & 0x00ffffff) != 0) 
			ActiveSysCallDesc++;
	
	// Transfer Active Syscall Descs to out Descriptor
	AllocateARM11KernelDescMemory(desc,ActiveSysCallDesc);
	u16 SysCallDescPos = 0;
	for(int i = 0; i < 8; i++){
		if((tmp.Data[i] & 0x00ffffff) != 0) {
			SetARM11KernelDescValue(desc,SysCallDescPos,tmp.Data[i]);
			SysCallDescPos++;
		}
	}

finish:
	// Free data in Temporary Descriptor
	free(tmp.Data);
	return ret;
}

int GetARM11SysCalls(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	if(!yaml->AccessControlInfo.SystemCallAccess){
		fprintf(stderr,"[EXHEADER ERROR] Parameter not found: 'AccessControlInfo/SystemCallAccess'\n");
		return EXHDR_BAD_YAML_OPT;
	}
	for(int i = 0; i < yaml->AccessControlInfo.SystemCallAccessNum; i++){
		int SysCall = strtoul(yaml->AccessControlInfo.SystemCallAccess[i],NULL,0);
		if(SysCall > 184){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected Syscall: 0x%02x. Expected Range: 0x00 - 0xB8\n",SysCall);
			return EXHDR_BAD_YAML_OPT;
		}
		EnableSystemCall(desc,SysCall);
	}

	return 0;
}

void EnableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall)
{
	int num = SysCall / 24;
	int num1 = SysCall % 24;
	desc->Data[num] |= 1 << (num1 & 31);
}

void DisableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall)
{
	int num = SysCall / 24;
	int num1 = SysCall % 24;
	desc->Data[num] = desc->Data[num] & ~(1 << (num1 & 31));
}

int SetARM11KernelDescInteruptNumList(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{	
	int ret = 0;

	// Create Temporary Descriptor
	ARM11KernelCapabilityDescriptor tmp;
	memset(&tmp,0,sizeof(ARM11KernelCapabilityDescriptor));

	AllocateARM11KernelDescMemory(&tmp,8);

	// Get Interupts
	ret = GetARM11Interupts(&tmp,yaml);
	if(ret) goto finish;

	// Count Active Interupt Descs
	u16 ActiveInteruptDesc = 0;
	for(int i = 0; i < 8; i++)
		if(tmp.Data[i]) 
			ActiveInteruptDesc++;
	
	// Transfer Active Interupt Descs to output Descriptor
	AllocateARM11KernelDescMemory(desc,ActiveInteruptDesc);
	u16 InteruptDescPos = 0;
	for(int i = 0; i < 8; i++){
		if(tmp.Data[i]) {
			SetARM11KernelDescValue(desc,InteruptDescPos,(tmp.Data[i] & 0x0fffffff) | desc_InteruptNumList);
			InteruptDescPos++;
		}
	}

finish:
	// Free data in Temporary Descriptor
	free(tmp.Data);
	return ret;
}

int GetARM11Interupts(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	if(!yaml->AccessControlInfo.InterruptNumbers){
		return 0;
	}
	if(yaml->AccessControlInfo.InterruptNumbersNum > 32){
		fprintf(stderr,"[EXHEADER ERROR] Too many Interupts. Maximum is 32\n");
		return EXHDR_BAD_YAML_OPT;
	}
	for(int i = 0; i < yaml->AccessControlInfo.InterruptNumbersNum; i++){
		int Interrupt = strtoul(yaml->AccessControlInfo.InterruptNumbers[i],NULL,0);
		if(Interrupt > 0x7f){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected Interupt: 0x%02x. Expected Range: 0x00 - 0x7f\n",Interrupt);
			return EXHDR_BAD_YAML_OPT;
		}
		EnableInterupt(desc,Interrupt,i);
	}

	return 0;
}

void EnableInterupt(ARM11KernelCapabilityDescriptor *desc, int Interrupt, int i)
{
	int num = i / 4;
	if(num*4 == i) desc->Data[num] |= 0xffffffff;
	desc->Data[num] = desc->Data[num] << 7;
	desc->Data[num] |= Interrupt;
}

int SetARM11KernelDescAddressMapping(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	int ret = 0;
	// Create Temporary Descriptors
	ARM11KernelCapabilityDescriptor io_tmp;
	memset(&io_tmp,0,sizeof(ARM11KernelCapabilityDescriptor));
	ARM11KernelCapabilityDescriptor static_tmp;
	memset(&static_tmp,0,sizeof(ARM11KernelCapabilityDescriptor));

	// Getting IO Mapping
	ret = GetARM11IOMappings(&io_tmp,yaml);
	if(ret) goto finish;

	// Getting Static Mapping
	ret = GetARM11StaticMappings(&static_tmp,yaml);
	if(ret) goto finish;


	// Creating Output Descriptor and Combining the two MemMap Descriptors
	AllocateARM11KernelDescMemory(desc,io_tmp.num+static_tmp.num);
	u16 MemMapDescPos = 0;
	for(int i = 0; i < io_tmp.num; i++){
		SetARM11KernelDescValue(desc,MemMapDescPos,io_tmp.Data[i]);
		MemMapDescPos++;
	}
	for(int i = 0; i < static_tmp.num; i++){
		SetARM11KernelDescValue(desc,MemMapDescPos,static_tmp.Data[i]);
		MemMapDescPos++;
	}

finish:
	free(io_tmp.Data);
	free(static_tmp.Data);
	return ret;
}

int GetARM11IOMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	if(!yaml->AccessControlInfo.IORegisterMapping)
		return 0;

	AllocateARM11KernelDescMemory(desc,yaml->AccessControlInfo.IORegisterMappingNum*2);
	u16 DescUsed = 0;
	for(int i = 0; i < yaml->AccessControlInfo.IORegisterMappingNum; i++){
		if(strlen(yaml->AccessControlInfo.IORegisterMapping[i])){
			// Parse Address String
			char *AddressStartStr = yaml->AccessControlInfo.IORegisterMapping[i];
			char *AddressEndStr = strstr(AddressStartStr,"-");
			if(AddressEndStr){
				if(strlen(AddressEndStr) > 1) // if not just '-'
					AddressEndStr = (AddressEndStr+1); // Setting the str to the expected start of address string
				else 
					AddressEndStr = NULL;
			}


			u32 AddressStart = strtoul(AddressStartStr,NULL,16);
			if(!IsStartAddress(AddressStart)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x is not valid mapping start address.\n",AddressStart);
				return EXHDR_BAD_YAML_OPT;
			}
			if(!AddressEndStr){ // No End Addr Was Specified
				SetARM11KernelDescValue(desc,DescUsed,GetIOMappingDesc(AddressStart));
				DescUsed++;
				goto skip;
			}

			u32 AddressEnd = strtoul(AddressEndStr,NULL,16);
			if(!IsEndAddress(AddressEnd)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x is not valid mapping end address.\n",AddressEnd);
				return EXHDR_BAD_YAML_OPT;
			}

			u32 DescStartAddr = GetStaticMappingDesc(AddressStart,false);
			u32 DescEndAddr = GetStaticMappingDesc(AddressEnd+0x1000,false);
			if(DescStartAddr != DescEndAddr){
				SetARM11KernelDescValue(desc,DescUsed,DescStartAddr);
				SetARM11KernelDescValue(desc,DescUsed+1,DescEndAddr);
				DescUsed += 2;
				goto skip;
			}
			else{
				SetARM11KernelDescValue(desc,DescUsed,GetIOMappingDesc(AddressStart));
				DescUsed++;
				goto skip;
			}
		}

		skip: ;
	}
	desc->num = DescUsed;
	return 0;
}

int GetARM11StaticMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	if(!yaml->AccessControlInfo.MemoryMapping)
		return 0;

	AllocateARM11KernelDescMemory(desc,yaml->AccessControlInfo.MemoryMappingNum*2);
	u16 DescUsed = 0;
	for(int i = 0; i < yaml->AccessControlInfo.MemoryMappingNum; i++){
		if(strlen(yaml->AccessControlInfo.MemoryMapping[i])){
			char *AddressStartStr = yaml->AccessControlInfo.MemoryMapping[i];
			char *AddressEndStr = strstr(AddressStartStr,"-");
			char *ROFlagStr = strstr(AddressStartStr,":");
			bool IsRO = false; 
			if(ROFlagStr)
				IsRO = strcasecmp(ROFlagStr,":r") == 0 ? true : false;

			if(AddressEndStr){
				if(strlen(AddressEndStr) > 1) {
					AddressEndStr = (AddressEndStr+1);
					if(AddressEndStr == ROFlagStr)
						AddressEndStr = NULL;
				}
				else 
					AddressEndStr = NULL;
			}
			u32 AddressStart = strtoul(AddressStartStr,NULL,16);
			if(!IsStartAddress(AddressStart)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x (%s) is not valid mapping start address.\n",AddressStart,AddressStartStr);
				return EXHDR_BAD_YAML_OPT;
			}
			if(!AddressEndStr){ // No End Addr Was Specified
				SetARM11KernelDescValue(desc,DescUsed,GetStaticMappingDesc(AddressStart,IsRO));
				SetARM11KernelDescValue(desc,DescUsed+1,GetStaticMappingDesc(AddressStart+0x1000, true));
				DescUsed += 2;
				goto skip;
			}

			u32 AddressEnd = strtoul(AddressEndStr,NULL,16);
			if(!IsEndAddress(AddressEnd)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x (%s) is not valid mapping end address.\n",AddressEnd,AddressEndStr);
				return EXHDR_BAD_YAML_OPT;
			}

			u32 DescStartAddr = GetStaticMappingDesc(AddressStart,IsRO);
			u32 DescEndAddr = GetStaticMappingDesc(AddressEnd+0x1000,true);
			if(DescStartAddr != DescEndAddr){
				SetARM11KernelDescValue(desc,DescUsed,DescStartAddr);
				SetARM11KernelDescValue(desc,DescUsed+1,DescEndAddr);
				DescUsed += 2;
				goto skip;
			}
			else{
				SetARM11KernelDescValue(desc,DescUsed,GetStaticMappingDesc(AddressStart,IsRO));
				SetARM11KernelDescValue(desc,DescUsed+1,GetStaticMappingDesc(AddressStart+0x1000, true));
				DescUsed += 2;
				goto skip;
			}
		}

		skip: ;
	}
	desc->num = DescUsed;
	return 0;
}

bool IsEndAddress(u32 Address)
{
	return (Address & 0x0fff) == 0x0fff;
}

bool IsStartAddress(u32 Address)
{
	return (Address & 0x0fff) == 0;
}

u32 GetIOMappingDesc(u32 Address)
{
	return GetMappingDesc(Address,0xFFE,0xC,false);
}

u32 GetStaticMappingDesc(u32 Address, bool IsReadOnly)
{
	return GetMappingDesc(Address,0x7FC,0xB,IsReadOnly);
}

u32 GetMappingDesc(u32 Address, u32 PrefixVal, s32 numPrefixBits, bool IsRO)
{
	u32 PrefixMask = GetDescPrefixMask(numPrefixBits);
	u32 PrefixBits = GetDescPrefixBits(numPrefixBits,PrefixVal);
	u32 Desc = (Address >> 12 & ~PrefixMask) | PrefixBits;
	if (IsRO)
		Desc |= 0x100000;
	return Desc;
}

int SetARM11KernelDescOtherCapabilities(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	u32 OtherCapabilities = 0;
	
	if(!yaml->AccessControlInfo.DisableDebug)
		OtherCapabilities |= 1 << othcap_PERMIT_DEBUG;
	if(yaml->AccessControlInfo.EnableForceDebug)
		OtherCapabilities |= 1 << othcap_FORCE_DEBUG;
	if(yaml->AccessControlInfo.CanUseNonAlphabetAndNumber)
		OtherCapabilities |= 1 << othcap_CAN_USE_NON_ALPHABET_AND_NUMBER;
	if(yaml->AccessControlInfo.CanWriteSharedPage)
		OtherCapabilities |= 1 << othcap_CAN_WRITE_SHARED_PAGE;
	if(yaml->AccessControlInfo.CanUsePrivilegedPriority)
		OtherCapabilities |= 1 << othcap_CAN_USE_PRIVILEGE_PRIORITY;
	if(yaml->AccessControlInfo.PermitMainFunctionArgument)
		OtherCapabilities |= 1 << othcap_PERMIT_MAIN_FUNCTION_ARGUMENT;
	if(yaml->AccessControlInfo.CanShareDeviceMemory)
		OtherCapabilities |= 1 << othcap_CAN_SHARE_DEVICE_MEMORY;
	if(yaml->AccessControlInfo.RunnableOnSleep)
		OtherCapabilities |= 1 << othcap_RUNNABLE_ON_SLEEP;
	if(yaml->AccessControlInfo.SpecialMemoryArrange)
		OtherCapabilities |= 1 << othcap_SPECIAL_MEMORY_ARRANGE;

	if(yaml->AccessControlInfo.MemoryType){
		u32 MemType = 0; 
		if(strcasecmp(yaml->AccessControlInfo.MemoryType,"application") == 0)
			MemType = memtype_APPLICATION;
		else if(strcasecmp(yaml->AccessControlInfo.MemoryType,"system") == 0)
			MemType = memtype_SYSTEM;
		else if(strcasecmp(yaml->AccessControlInfo.MemoryType,"base") == 0)
			MemType = memtype_BASE;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid memory type: '%s'\n",yaml->AccessControlInfo.MemoryType);
			return EXHDR_BAD_YAML_OPT;
		}
		OtherCapabilities = (OtherCapabilities & 0xffffff0f) | MemType << 8;
	}

	if(OtherCapabilities){
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_OtherCapabilities);
		SetARM11KernelDescValue(desc,0,OtherCapabilities);
	}
	return 0;
}

int SetARM11KernelDescHandleTableSize(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	if(yaml->AccessControlInfo.HandleTableSize){
		u16 HandleTableSize = strtoul(yaml->AccessControlInfo.HandleTableSize,NULL,0);
		if(HandleTableSize > 1023){
			fprintf(stderr,"[EXHEADER ERROR] Too large handle table size\n");
			return EXHDR_BAD_YAML_OPT;
		}
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_HandleTableSize);
		SetARM11KernelDescValue(desc,0,HandleTableSize);
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: 'AccessControlInfo/HandleTableSize'\n");
		return EXHDR_BAD_YAML_OPT;
	}	
	return 0;
}

int SetARM11KernelDescReleaseKernelVersion(ARM11KernelCapabilityDescriptor *desc, rsf_settings *yaml)
{
	if(yaml->AccessControlInfo.ReleaseKernelMajor && yaml->AccessControlInfo.ReleaseKernelMinor){
		u32 releaseKernelMajor = strtoul(yaml->AccessControlInfo.ReleaseKernelMajor,NULL,0);
		u32 releaseKernelMinor = strtoul(yaml->AccessControlInfo.ReleaseKernelMinor,NULL,0);
		if (releaseKernelMajor > 255 || releaseKernelMinor > 255){
			fprintf(stderr,"[EXHEADER ERROR] Invalid release kernel version");
		}
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_KernelReleaseVersion);
		SetARM11KernelDescValue(desc,0,(releaseKernelMajor << 8 | releaseKernelMinor));
	}
	return 0;
}

void SetARM11KernelDescValue(ARM11KernelCapabilityDescriptor *desc, u16 Index, u32 Value)
{
	if(Index >= desc->num) return;
	desc->Data[Index] |= Value; 
}

void SetARM11KernelDescBitmask(ARM11KernelCapabilityDescriptor *desc, u32 Bitmask)
{
	for(int i = 0; i < desc->num; i++)
		SetARM11KernelDescValue(desc,i,Bitmask);
}

void AllocateARM11KernelDescMemory(ARM11KernelCapabilityDescriptor *desc, u16 Num)
{
	if(Num == 0) return;
	desc->num = Num;
	desc->Data = malloc(sizeof(u32)*Num);
	memset(desc->Data,0,sizeof(u32)*Num);
	return;
}

u32 GetDescPrefixMask(int numPrefixBits)
{
	return (u32)(~((1 << (32 - (numPrefixBits & 31))) - 1));
}

u32 GetDescPrefixBits(int numPrefixBits, u32 PrefixVal)
{
	return PrefixVal << (32 - (numPrefixBits & 31));
}

int get_ExHeaderARM9AccessControlInfo(exhdr_ARM9AccessControlInfo *arm9, rsf_settings *yaml)
{
	u32 Arm9AccessControl = 0;
	for(int i = 0; i < yaml->AccessControlInfo.IoAccessControlNum; i++){
		if(strcmp(yaml->AccessControlInfo.IoAccessControl[i],"FsMountNand") == 0)
			Arm9AccessControl |= 1 << arm9cap_FS_MOUNT_NAND;
		else if(strcmp(yaml->AccessControlInfo.IoAccessControl[i],"FsMountNandRoWrite") == 0)
			Arm9AccessControl |= 1 << arm9cap_FS_MOUNT_NAND_RO_WRITE;
		else if(strcmp(yaml->AccessControlInfo.IoAccessControl[i],"FsMountTwln") == 0)
			Arm9AccessControl |= 1 << arm9cap_FS_MOUNT_TWLN;
		else if(strcmp(yaml->AccessControlInfo.IoAccessControl[i],"FsMountWnand") == 0)
			Arm9AccessControl |= 1 << arm9cap_FS_MOUNT_WNAND;
		else if(strcmp(yaml->AccessControlInfo.IoAccessControl[i],"FsMountCardSpi") == 0)
			Arm9AccessControl |= 1 << arm9cap_FS_MOUNT_CARD_SPI;
		else if(strcmp(yaml->AccessControlInfo.IoAccessControl[i],"UseSdif3") == 0)
			Arm9AccessControl |= 1 << arm9cap_USE_SDIF3;
		else if(strcmp(yaml->AccessControlInfo.IoAccessControl[i],"CreateSeed") == 0)
			Arm9AccessControl |= 1 << arm9cap_CREATE_SEED;
		else if(strcmp(yaml->AccessControlInfo.IoAccessControl[i],"UseCardSpi") == 0)
			Arm9AccessControl |= 1 << arm9cap_USE_CARD_SPI;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid IoAccessControl Name: '%s'\n",yaml->AccessControlInfo.IoAccessControl[i]);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	
	for(int i = 0; i < yaml->AccessControlInfo.FileSystemAccessNum; i++){
		if(strcmp(yaml->AccessControlInfo.FileSystemAccess[i],"DirectSdmc") == 0)
			Arm9AccessControl |= 1 << arm9cap_USE_DIRECT_SDMC;
	}

	if(yaml->Option.UseOnSD)
		Arm9AccessControl |= 1 << arm9cap_SD_APPLICATION;

	u32_to_u8(arm9->descriptors,Arm9AccessControl,LE);

	if(yaml->AccessControlInfo.DescVersion){
		arm9->descriptors[15] = strtol(yaml->AccessControlInfo.DescVersion,NULL,0);
	}
	else{
		fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: 'AccessControlInfo/DescVersion'\n");
		return EXHDR_BAD_YAML_OPT;
	}

	return 0;
}



int set_AccessDesc(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	if(ncchset->keys->AccessDescSign.PresetType == not_preset){
		if(ncchset->yaml_set->CommonHeaderKey.Found)
			return accessdesc_GetSignFromRsf(exhdrset,ncchset);
		else if(!ncchset->keys->rsa.RequiresPresignedDesc)
			return accessdesc_SignWithKey(exhdrset,ncchset);
		else{
			fprintf(stderr,"[EXHEADER ERROR] Current keyset cannot sign AccessDesc, please appropriatly setup RSF, or specify a preset with -accessdesc\n");
			return CANNOT_SIGN_ACCESSDESC;
		}
	}
	return accessdesc_GetSignFromPreset(exhdrset,ncchset);
}

int accessdesc_SignWithKey(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	/* Set RSA Keys */
	memcpy(ncchset->CxiRsaKey.PrivK,exhdrset->keys->rsa.CFA_Priv,0x100);
	memcpy(ncchset->CxiRsaKey.PubK,exhdrset->keys->rsa.CFA_Pub,0x100);
	memcpy(&exhdrset->ExHdr->AccessDescriptor.ncchpubkeymodulus,exhdrset->keys->rsa.CFA_Pub,0x100);
	/* Copy Data From ExHeader */
	memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM11SystemLocalCapabilities,&exhdrset->ExHdr->ARM11SystemLocalCapabilities,sizeof(exhdr_ARM11SystemLocalCapabilities));
	u8 *byte6 = &exhdrset->ExHdr->AccessDescriptor.ARM11SystemLocalCapabilities.Flags[6];
	u8 SystemMode = (*byte6>>4)&0xF;
	u8 AffinityMask = (*byte6>>2)&0x3;
	u8 IdealProcessor = ((*byte6>>0)&0x3)+1;
	*byte6 = (u8)(SystemMode << 4 | AffinityMask << 2 | IdealProcessor);
	
	memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM11KernelCapabilities,&exhdrset->ExHdr->ARM11KernelCapabilities,sizeof(exhdr_ARM11KernelCapabilities));
	memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM9AccessControlInfo,&exhdrset->ExHdr->ARM9AccessControlInfo,sizeof(exhdr_ARM9AccessControlInfo));
	/* Sign AccessDesc */
	return SignAccessDesc(exhdrset->ExHdr,exhdrset->keys);
}

int accessdesc_GetSignFromRsf(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	/* Yaml Option Sanity Checks */
	if(!exhdrset->yaml->CommonHeaderKey.Found){
		fprintf(stderr,"[EXHEADER ERROR] RSF Section 'CommonHeaderKey' not found\n");
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
	if(!exhdrset->yaml->CommonHeaderKey.AccCtlDescSign){
		fprintf(stderr,"[EXHEADER ERROR] 'CommonHeaderKey/Signature' not found\n");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(strlen(exhdrset->yaml->CommonHeaderKey.AccCtlDescSign) != 350){
		fprintf(stderr,"[EXHEADER ERROR] 'CommonHeaderKey/Signature' has invalid length (%d)\n",strlen(exhdrset->yaml->CommonHeaderKey.AccCtlDescSign));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(!exhdrset->yaml->CommonHeaderKey.AccCtlDescBin){
		fprintf(stderr,"[EXHEADER ERROR] 'CommonHeaderKey/Descriptor' not found\n");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(strlen(exhdrset->yaml->CommonHeaderKey.AccCtlDescBin) != 695){
		fprintf(stderr,"[EXHEADER ERROR] 'CommonHeaderKey/Descriptor' has invalid length (%d)\n",strlen(exhdrset->yaml->CommonHeaderKey.AccCtlDescBin));
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
	result = base64_decode(tmp,&out,(const u8*)exhdrset->yaml->CommonHeaderKey.AccCtlDescSign,strlen(exhdrset->yaml->CommonHeaderKey.AccCtlDescSign));
	if(result) goto finish;
	memcpy(exhdrset->ExHdr->AccessDescriptor.signature,tmp,0x100);
	memcpy(exhdrset->ExHdr->AccessDescriptor.ncchpubkeymodulus,ncchset->CxiRsaKey.PubK,0x100);
	out = 0x500;
	result = base64_decode(tmp,&out,(const u8*)exhdrset->yaml->CommonHeaderKey.AccCtlDescBin,strlen(exhdrset->yaml->CommonHeaderKey.AccCtlDescBin));
	if(result) goto finish;
	memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM11SystemLocalCapabilities,tmp,0x200);
finish:
	free(tmp);
	return result;	
}

int accessdesc_GetSignFromPreset(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	u8 *AccessDescSig = NULL;
	u8 *AccessDescData = NULL;
	u8 *DepList = NULL;

	u8 *CXI_Pubk = NULL;
	u8 *CXI_Privk = NULL;

	if(ncchset->keys->AccessDescSign.PresetType == app){
		switch(ncchset->keys->AccessDescSign.TargetFirmware){
			case 1:
				AccessDescSig = (u8*)App_sdk1_AcexSig;
				AccessDescData = (u8*)App_sdk1_AcexData;
				DepList = (u8*)sdk1_dep_list;
				CXI_Pubk = (u8*)App_sdk1_HdrPubK;
				CXI_Privk = (u8*)App_sdk1_HdrPrivK;
				break;
			case 2:
				AccessDescSig = (u8*)App_sdk2_AcexSig;
				AccessDescData = (u8*)App_sdk2_AcexData;
				DepList = (u8*)sdk2_dep_list;
				CXI_Pubk = (u8*)App_sdk2_HdrPubK;
				CXI_Privk = (u8*)App_sdk2_HdrPrivK;
				break;
			case 4:
			case 5:
				AccessDescSig = (u8*)App_sdk4_AcexSig;
				AccessDescData = (u8*)App_sdk4_AcexData;
				DepList = (u8*)sdk4_dep_list;
				CXI_Pubk = (u8*)App_sdk4_HdrPubK;
				CXI_Privk = (u8*)App_sdk4_HdrPrivK;
				break;
			case 7:
				AccessDescSig = NULL;
				AccessDescData = (u8*)App_sdk7_AcexData;
				DepList = (u8*)sdk7_dep_list;
				CXI_Pubk = NULL;
				CXI_Privk = NULL;
				break;
			
		}
	}
	else if(ncchset->keys->AccessDescSign.PresetType == dlp){
		switch(ncchset->keys->AccessDescSign.TargetFirmware){
			case 1:
				AccessDescSig = (u8*)Dlp_sdk1_AcexSig;
				AccessDescData = (u8*)Dlp_sdk1_AcexData;
				DepList = (u8*)sdk1_dep_list;
				CXI_Pubk = (u8*)Dlp_sdk1_HdrPubK;
				CXI_Privk = (u8*)Dlp_sdk1_HdrPrivK;
				break;
			case 2:
				AccessDescSig = (u8*)Dlp_sdk2_AcexSig;
				AccessDescData = (u8*)Dlp_sdk2_AcexData;
				DepList = (u8*)sdk2_dep_list;
				CXI_Pubk = (u8*)Dlp_sdk2_HdrPubK;
				CXI_Privk = (u8*)Dlp_sdk2_HdrPrivK;
				break;
			case 4:
			case 5:
				AccessDescSig = (u8*)Dlp_sdk4_AcexSig;
				AccessDescData = (u8*)Dlp_sdk4_AcexData;
				DepList = (u8*)sdk4_dep_list;
				CXI_Pubk = (u8*)Dlp_sdk4_HdrPubK;
				CXI_Privk = (u8*)Dlp_sdk4_HdrPrivK;
				break;
		}
	}
	else if(ncchset->keys->AccessDescSign.PresetType == demo){
		switch(ncchset->keys->AccessDescSign.TargetFirmware){
			case 4:
			case 5:
				AccessDescSig = (u8*)Demo_sdk4_AcexSig;
				AccessDescData = (u8*)Demo_sdk4_AcexData;
				DepList = (u8*)sdk4_dep_list;
				CXI_Pubk = (u8*)Demo_sdk4_HdrPubK;
				CXI_Privk = (u8*)Demo_sdk4_HdrPrivK;
				break;
		}
	}

	// Error Checking
	if(!AccessDescData || !DepList){
		fprintf(stderr,"[EXHEADER ERROR] AccessDesc preset is unavailable, please configure RSF file\n");
		return CANNOT_SIGN_ACCESSDESC;
	}

	if((!CXI_Pubk || !CXI_Privk || !AccessDescSig) && ncchset->keys->rsa.RequiresPresignedDesc){
		fprintf(stderr,"[EXHEADER ERROR] This AccessDesc preset needs to be signed, the current keyset is incapable of doing so. Please configure RSF file with the appropriate signature data.\n");
		return CANNOT_SIGN_ACCESSDESC;
	}
	
	// Setting data in Exheader
	// Dependency List
	memcpy(exhdrset->ExHdr->DependencyList,DepList,0x180);

	// ARM11 Local Capabilities
	exhdr_ARM11SystemLocalCapabilities *arm11local = (exhdr_ARM11SystemLocalCapabilities*)(AccessDescData);
	// Backing Up Non Preset Details
	u8 ProgramID[8];
	memcpy(ProgramID,exhdrset->ExHdr->ARM11SystemLocalCapabilities.ProgramId,8);
	exhdr_StorageInfo StorageInfoBackup;
	memcpy(&StorageInfoBackup,&exhdrset->ExHdr->ARM11SystemLocalCapabilities.StorageInfo,sizeof(exhdr_StorageInfo));
	
	// Setting Preset Data
	memcpy(&exhdrset->ExHdr->ARM11SystemLocalCapabilities,arm11local,sizeof(exhdr_ARM11SystemLocalCapabilities));

	// Restoring Non Preset Data
	memcpy(exhdrset->ExHdr->ARM11SystemLocalCapabilities.ProgramId,ProgramID,8);
	memcpy(&exhdrset->ExHdr->ARM11SystemLocalCapabilities.StorageInfo,&StorageInfoBackup,sizeof(exhdr_StorageInfo));

	// Adjusting flags to prevent errors
	u8 *byte6 = &exhdrset->ExHdr->ARM11SystemLocalCapabilities.Flags[6];
	u8 SystemMode = (*byte6>>4)&0xF;
	u8 AffinityMask = (*byte6>>2)&0x3;
	u8 IdealProcessor = ((*byte6>>0)&0x3)-1;
	*byte6 = (u8)(SystemMode << 4 | AffinityMask << 2 | IdealProcessor);
	exhdrset->ExHdr->ARM11SystemLocalCapabilities.Flags[7] = 0x30;

	// ARM11 Kernel Capabilities
	exhdr_ARM11KernelCapabilities *arm11kernel = (exhdr_ARM11KernelCapabilities*)(AccessDescData+sizeof(exhdr_ARM11SystemLocalCapabilities));
	memcpy(&exhdrset->ExHdr->ARM11KernelCapabilities,arm11kernel,(sizeof(exhdr_ARM11KernelCapabilities)));

	// ARM9 Access Control
	exhdr_ARM9AccessControlInfo *arm9 = (exhdr_ARM9AccessControlInfo*)(AccessDescData+sizeof(exhdr_ARM11SystemLocalCapabilities)+sizeof(exhdr_ARM11KernelCapabilities));
	memcpy(&exhdrset->ExHdr->ARM9AccessControlInfo,arm9,(sizeof(exhdr_ARM9AccessControlInfo)));

	// Setting AccessDesc Area
	// Signing normally if possible
	if(!ncchset->keys->rsa.RequiresPresignedDesc) 
		return accessdesc_SignWithKey(exhdrset,ncchset);

	// Otherwise set static data & ncch hdr sig info
	memcpy(ncchset->CxiRsaKey.PubK,CXI_Pubk,0x100);
	memcpy(ncchset->CxiRsaKey.PrivK,CXI_Privk,0x100);
	memcpy(&exhdrset->ExHdr->AccessDescriptor.signature,AccessDescSig,0x100);
	memcpy(&exhdrset->ExHdr->AccessDescriptor.ncchpubkeymodulus,CXI_Pubk,0x100);
	memcpy(&exhdrset->ExHdr->AccessDescriptor.ARM11SystemLocalCapabilities,AccessDescData,0x200);

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

	if(usrset->yaml_set.Rom.SaveDataSize){
		*SaveDataSize = strtoull(usrset->yaml_set.Rom.SaveDataSize,NULL,10);
		if(strstr(usrset->yaml_set.Rom.SaveDataSize,"K")){
			char *str = strstr(usrset->yaml_set.Rom.SaveDataSize,"K");
			if(strcmp(str,"K") == 0 || strcmp(str,"KB") == 0 ){
				*SaveDataSize = *SaveDataSize*KB;
			}
		}
		else if(strstr(usrset->yaml_set.Rom.SaveDataSize,"M")){
			char *str = strstr(usrset->yaml_set.Rom.SaveDataSize,"M");
			if(strcmp(str,"M") == 0 || strcmp(str,"MB") == 0 ){
				*SaveDataSize = *SaveDataSize*MB;
			}
		}
		else if(strstr(usrset->yaml_set.Rom.SaveDataSize,"G")){
			char *str = strstr(usrset->yaml_set.Rom.SaveDataSize,"G");
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
	char *Str = usrset->yaml_set.SystemControlInfo.RemasterVersion;
	if(!Str){
		*RemasterVersion = 0;
		return 0;
	}
	*RemasterVersion = strtol(Str,NULL,0);
	return 0;
}
