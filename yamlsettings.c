#include "lib.h"
#include "yamlsettings.h"

void RsfSettingTransferSingle(char **src, char **dst, char **dmp);
void RsfSettingTransferMultiple(char ***src, u32 *src_num, char ***dst, u32 *dst_num, char ***dmp, u32 *dmp_num);

int MergeSpecData(desc_settings *out, desc_settings *desc, rsf_settings *rsf)
{
	// Setup
	memcpy(out,desc,sizeof(desc_settings)); // Using desc as base, then adding rsf settings
	rsf_settings *rsf_dst = &out->DefaultSpec;
	rsf_settings *rsf_src = rsf;
	rsf_settings *rsf_dmp = &desc->DefaultSpec; // for unneeded ptrs which need freeing
	memset(rsf_dmp,0,sizeof(rsf_settings));
	
	// Booleans
	if(rsf_src->Option.NoPadding != -1) rsf_dst->Option.NoPadding = rsf_src->Option.NoPadding;
	if(rsf_src->Option.AllowUnalignedSection != -1) rsf_dst->Option.AllowUnalignedSection = rsf_src->Option.AllowUnalignedSection;
	if(rsf_src->Option.EnableCrypt != -1) rsf_dst->Option.EnableCrypt = rsf_src->Option.EnableCrypt;
	if(rsf_src->Option.EnableCompress != -1) rsf_dst->Option.EnableCompress = rsf_src->Option.EnableCompress;
	if(rsf_src->Option.FreeProductCode != -1) rsf_dst->Option.FreeProductCode = rsf_src->Option.FreeProductCode;
	if(rsf_src->Option.UseOnSD != -1) rsf_dst->Option.UseOnSD = rsf_src->Option.UseOnSD;
	
	if(rsf_src->AccessControlInfo.DisableDebug != -1) rsf_dst->AccessControlInfo.DisableDebug = rsf_src->AccessControlInfo.DisableDebug;
	if(rsf_src->AccessControlInfo.EnableForceDebug != -1) rsf_dst->AccessControlInfo.EnableForceDebug = rsf_src->AccessControlInfo.EnableForceDebug;
	if(rsf_src->AccessControlInfo.CanWriteSharedPage != -1) rsf_dst->AccessControlInfo.CanWriteSharedPage = rsf_src->AccessControlInfo.CanWriteSharedPage;
	if(rsf_src->AccessControlInfo.CanUsePrivilegedPriority != -1) rsf_dst->AccessControlInfo.CanUsePrivilegedPriority = rsf_src->AccessControlInfo.CanUsePrivilegedPriority;
	if(rsf_src->AccessControlInfo.CanUseNonAlphabetAndNumber != -1) rsf_dst->AccessControlInfo.CanUseNonAlphabetAndNumber = rsf_src->AccessControlInfo.CanUseNonAlphabetAndNumber;
	if(rsf_src->AccessControlInfo.PermitMainFunctionArgument != -1) rsf_dst->AccessControlInfo.PermitMainFunctionArgument = rsf_src->AccessControlInfo.PermitMainFunctionArgument;
	if(rsf_src->AccessControlInfo.CanShareDeviceMemory != -1) rsf_dst->AccessControlInfo.CanShareDeviceMemory = rsf_src->AccessControlInfo.CanShareDeviceMemory;
	if(rsf_src->AccessControlInfo.UseOtherVariationSaveData != -1) rsf_dst->AccessControlInfo.UseOtherVariationSaveData = rsf_src->AccessControlInfo.UseOtherVariationSaveData;
	if(rsf_src->AccessControlInfo.UseExtSaveData != -1) rsf_dst->AccessControlInfo.UseExtSaveData = rsf_src->AccessControlInfo.UseExtSaveData;
	if(rsf_src->AccessControlInfo.RunnableOnSleep != -1) rsf_dst->AccessControlInfo.RunnableOnSleep = rsf_src->AccessControlInfo.RunnableOnSleep;
	if(rsf_src->AccessControlInfo.SpecialMemoryArrange != -1) rsf_dst->AccessControlInfo.SpecialMemoryArrange = rsf_src->AccessControlInfo.SpecialMemoryArrange;
	
	if(rsf_src->BasicInfo.MediaFootPadding != -1) rsf_dst->BasicInfo.MediaFootPadding = rsf_src->BasicInfo.MediaFootPadding;
	
	// Strings
	//Option
	RsfSettingTransferSingle(&rsf_src->Option.PageSize,&rsf_dst->Option.PageSize,&rsf_dmp->Option.PageSize);
	RsfSettingTransferMultiple(&rsf_src->Option.AppendSystemCall,&rsf_src->Option.AppendSystemCallNum,&rsf_dst->Option.AppendSystemCall,&rsf_dst->Option.AppendSystemCallNum,&rsf_dmp->Option.AppendSystemCall,&rsf_dmp->Option.AppendSystemCallNum);

	//AccessControlInfo
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.ProgramId,&rsf_dst->AccessControlInfo.ProgramId,&rsf_dmp->AccessControlInfo.ProgramId);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.IdealProcessor,&rsf_dst->AccessControlInfo.IdealProcessor,&rsf_dmp->AccessControlInfo.IdealProcessor);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.Priority,&rsf_dst->AccessControlInfo.Priority,&rsf_dmp->AccessControlInfo.Priority);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.MemoryType,&rsf_dst->AccessControlInfo.MemoryType,&rsf_dmp->AccessControlInfo.MemoryType);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.SystemMode,&rsf_dst->AccessControlInfo.SystemMode,&rsf_dmp->AccessControlInfo.SystemMode);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.FirmwareVersion,&rsf_dst->AccessControlInfo.FirmwareVersion,&rsf_dmp->AccessControlInfo.FirmwareVersion);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.CoreVersion,&rsf_dst->AccessControlInfo.CoreVersion,&rsf_dmp->AccessControlInfo.CoreVersion);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.HandleTableSize,&rsf_dst->AccessControlInfo.HandleTableSize,&rsf_dmp->AccessControlInfo.HandleTableSize);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.SystemSaveDataId1,&rsf_dst->AccessControlInfo.SystemSaveDataId1,&rsf_dmp->AccessControlInfo.SystemSaveDataId1);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.SystemSaveDataId2,&rsf_dst->AccessControlInfo.SystemSaveDataId2,&rsf_dmp->AccessControlInfo.SystemSaveDataId2);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.OtherUserSaveDataId1,&rsf_dst->AccessControlInfo.OtherUserSaveDataId1,&rsf_dmp->AccessControlInfo.OtherUserSaveDataId1);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.OtherUserSaveDataId2,&rsf_dst->AccessControlInfo.OtherUserSaveDataId2,&rsf_dmp->AccessControlInfo.OtherUserSaveDataId2);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.OtherUserSaveDataId3,&rsf_dst->AccessControlInfo.OtherUserSaveDataId3,&rsf_dmp->AccessControlInfo.OtherUserSaveDataId3);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.ExtSaveDataId,&rsf_dst->AccessControlInfo.ExtSaveDataId,&rsf_dmp->AccessControlInfo.ExtSaveDataId);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.ExtSaveDataNumber,&rsf_dst->AccessControlInfo.ExtSaveDataNumber,&rsf_dmp->AccessControlInfo.ExtSaveDataNumber);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.SystemMode,&rsf_dst->AccessControlInfo.SystemMode,&rsf_dmp->AccessControlInfo.SystemMode);
	RsfSettingTransferSingle(&rsf_src->AccessControlInfo.AffinityMask,&rsf_dst->AccessControlInfo.AffinityMask,&rsf_dmp->AccessControlInfo.AffinityMask);
	RsfSettingTransferMultiple(&rsf_src->AccessControlInfo.MemoryMapping,&rsf_src->AccessControlInfo.MemoryMappingNum,&rsf_dst->AccessControlInfo.MemoryMapping,&rsf_dst->AccessControlInfo.MemoryMappingNum,&rsf_dmp->AccessControlInfo.MemoryMapping,&rsf_dmp->AccessControlInfo.MemoryMappingNum);
	RsfSettingTransferMultiple(&rsf_src->AccessControlInfo.IORegisterMapping,&rsf_src->AccessControlInfo.IORegisterMappingNum,&rsf_dst->AccessControlInfo.IORegisterMapping,&rsf_dst->AccessControlInfo.IORegisterMappingNum,&rsf_dmp->AccessControlInfo.IORegisterMapping,&rsf_dmp->AccessControlInfo.IORegisterMappingNum);
	RsfSettingTransferMultiple(&rsf_src->AccessControlInfo.FileSystemAccess,&rsf_src->AccessControlInfo.FileSystemAccessNum,&rsf_dst->AccessControlInfo.FileSystemAccess,&rsf_dst->AccessControlInfo.FileSystemAccessNum,&rsf_dmp->AccessControlInfo.FileSystemAccess,&rsf_dmp->AccessControlInfo.FileSystemAccessNum);
	RsfSettingTransferMultiple(&rsf_src->AccessControlInfo.IoAccessControl,&rsf_src->AccessControlInfo.IoAccessControlNum,&rsf_dst->AccessControlInfo.IoAccessControl,&rsf_dst->AccessControlInfo.IoAccessControlNum,&rsf_dmp->AccessControlInfo.IoAccessControl,&rsf_dmp->AccessControlInfo.IoAccessControlNum);
	RsfSettingTransferMultiple(&rsf_src->AccessControlInfo.InterruptNumbers,&rsf_src->AccessControlInfo.InterruptNumbersNum,&rsf_dst->AccessControlInfo.InterruptNumbers,&rsf_dst->AccessControlInfo.InterruptNumbersNum,&rsf_dmp->AccessControlInfo.InterruptNumbers,&rsf_dmp->AccessControlInfo.InterruptNumbersNum);
	RsfSettingTransferMultiple(&rsf_src->AccessControlInfo.SystemCallAccess,&rsf_src->AccessControlInfo.SystemCallAccessNum,&rsf_dst->AccessControlInfo.SystemCallAccess,&rsf_dst->AccessControlInfo.SystemCallAccessNum,&rsf_dmp->AccessControlInfo.SystemCallAccess,&rsf_dmp->AccessControlInfo.SystemCallAccessNum);
	RsfSettingTransferMultiple(&rsf_src->AccessControlInfo.ServiceAccessControl,&rsf_src->AccessControlInfo.ServiceAccessControlNum,&rsf_dst->AccessControlInfo.ServiceAccessControl,&rsf_dst->AccessControlInfo.ServiceAccessControlNum,&rsf_dmp->AccessControlInfo.ServiceAccessControl,&rsf_dmp->AccessControlInfo.ServiceAccessControlNum);
	RsfSettingTransferMultiple(&rsf_src->AccessControlInfo.StorageId,&rsf_src->AccessControlInfo.StorageIdNum,&rsf_dst->AccessControlInfo.StorageId,&rsf_dst->AccessControlInfo.StorageIdNum,&rsf_dmp->AccessControlInfo.StorageId,&rsf_dmp->AccessControlInfo.StorageIdNum);
	
	
	//SystemControlInfo
	RsfSettingTransferSingle(&rsf_src->SystemControlInfo.StackSize,&rsf_dst->SystemControlInfo.StackSize,&rsf_dmp->SystemControlInfo.StackSize);
	RsfSettingTransferSingle(&rsf_src->SystemControlInfo.AppType,&rsf_dst->SystemControlInfo.AppType,&rsf_dmp->SystemControlInfo.AppType);
	RsfSettingTransferSingle(&rsf_src->SystemControlInfo.RemasterVersion,&rsf_dst->SystemControlInfo.RemasterVersion,&rsf_dmp->SystemControlInfo.RemasterVersion);
	RsfSettingTransferSingle(&rsf_src->SystemControlInfo.JumpId,&rsf_dst->SystemControlInfo.JumpId,&rsf_dmp->SystemControlInfo.JumpId);
	RsfSettingTransferMultiple(&rsf_src->SystemControlInfo.Dependency,&rsf_src->SystemControlInfo.DependencyNum,&rsf_dst->SystemControlInfo.Dependency,&rsf_dst->SystemControlInfo.DependencyNum,&rsf_dmp->SystemControlInfo.Dependency,&rsf_dmp->SystemControlInfo.DependencyNum);
	
	//BasicInfo
	RsfSettingTransferSingle(&rsf_src->BasicInfo.Title,&rsf_dst->BasicInfo.Title,&rsf_dmp->BasicInfo.Title);
	RsfSettingTransferSingle(&rsf_src->BasicInfo.CompanyCode,&rsf_dst->BasicInfo.CompanyCode,&rsf_dmp->BasicInfo.CompanyCode);
	RsfSettingTransferSingle(&rsf_src->BasicInfo.ProductCode,&rsf_dst->BasicInfo.ProductCode,&rsf_dmp->BasicInfo.ProductCode);
	RsfSettingTransferSingle(&rsf_src->BasicInfo.MediaSize,&rsf_dst->BasicInfo.MediaSize,&rsf_dmp->BasicInfo.MediaSize);
	RsfSettingTransferSingle(&rsf_src->BasicInfo.ContentType,&rsf_dst->BasicInfo.ContentType,&rsf_dmp->BasicInfo.ContentType);
	RsfSettingTransferSingle(&rsf_src->BasicInfo.Logo,&rsf_dst->BasicInfo.Logo,&rsf_dmp->BasicInfo.Logo);
	RsfSettingTransferSingle(&rsf_src->BasicInfo.BackupMemoryType,&rsf_dst->BasicInfo.BackupMemoryType,&rsf_dmp->BasicInfo.BackupMemoryType);
	RsfSettingTransferSingle(&rsf_src->BasicInfo.InitialCode,&rsf_dst->BasicInfo.InitialCode,&rsf_dmp->BasicInfo.InitialCode);

	//Rom
	RsfSettingTransferSingle(&rsf_src->Rom.HostRoot,&rsf_dst->Rom.HostRoot,&rsf_dmp->Rom.HostRoot);
	RsfSettingTransferSingle(&rsf_src->Rom.Padding,&rsf_dst->Rom.Padding,&rsf_dmp->Rom.Padding);
	RsfSettingTransferSingle(&rsf_src->Rom.SaveDataSize,&rsf_dst->Rom.SaveDataSize,&rsf_dmp->Rom.SaveDataSize);
	RsfSettingTransferMultiple(&rsf_src->Rom.DefaultReject,&rsf_src->Rom.DefaultRejectNum,&rsf_dst->Rom.DefaultReject,&rsf_dst->Rom.DefaultRejectNum,&rsf_dmp->Rom.DefaultReject,&rsf_dmp->Rom.DefaultRejectNum);
	RsfSettingTransferMultiple(&rsf_src->Rom.Reject,&rsf_src->Rom.RejectNum,&rsf_dst->Rom.Reject,&rsf_dst->Rom.RejectNum,&rsf_dmp->Rom.Reject,&rsf_dmp->Rom.RejectNum);
	RsfSettingTransferMultiple(&rsf_src->Rom.Include,&rsf_src->Rom.IncludeNum,&rsf_dst->Rom.Include,&rsf_dst->Rom.IncludeNum,&rsf_dmp->Rom.Include,&rsf_dmp->Rom.IncludeNum);
	RsfSettingTransferMultiple(&rsf_src->Rom.File,&rsf_src->Rom.FileNum,&rsf_dst->Rom.File,&rsf_dst->Rom.FileNum,&rsf_dmp->Rom.File,&rsf_dmp->Rom.FileNum);
	
	//ExeFs
	RsfSettingTransferMultiple(&rsf_src->ExeFs.Text,&rsf_src->ExeFs.TextNum,&rsf_dst->ExeFs.Text,&rsf_dst->ExeFs.TextNum,&rsf_dmp->ExeFs.Text,&rsf_dmp->ExeFs.TextNum);
	RsfSettingTransferMultiple(&rsf_src->ExeFs.ReadOnly,&rsf_src->ExeFs.ReadOnlyNum,&rsf_dst->ExeFs.ReadOnly,&rsf_dst->ExeFs.ReadOnlyNum,&rsf_dmp->ExeFs.ReadOnly,&rsf_dmp->ExeFs.ReadOnlyNum);
	RsfSettingTransferMultiple(&rsf_src->ExeFs.ReadWrite,&rsf_src->ExeFs.ReadWriteNum,&rsf_dst->ExeFs.ReadWrite,&rsf_dst->ExeFs.ReadWriteNum,&rsf_dmp->ExeFs.ReadWrite,&rsf_dmp->ExeFs.ReadWriteNum);
	
	//PlainRegion
	RsfSettingTransferMultiple(&rsf_src->PlainRegion,&rsf_src->PlainRegionNum,&rsf_dst->PlainRegion,&rsf_dst->PlainRegionNum,&rsf_dmp->PlainRegion,&rsf_dmp->PlainRegionNum);
	
	//TitleInfo
	RsfSettingTransferSingle(&rsf_src->TitleInfo.Platform,&rsf_dst->TitleInfo.Platform,&rsf_dmp->TitleInfo.Platform);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.Category,&rsf_dst->TitleInfo.Category,&rsf_dmp->TitleInfo.Category);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.UniqueId,&rsf_dst->TitleInfo.UniqueId,&rsf_dmp->TitleInfo.UniqueId);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.Version,&rsf_dst->TitleInfo.Version,&rsf_dmp->TitleInfo.Version);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.ContentsIndex,&rsf_dst->TitleInfo.ContentsIndex,&rsf_dmp->TitleInfo.ContentsIndex);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.Variation,&rsf_dst->TitleInfo.Variation,&rsf_dmp->TitleInfo.Variation);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.Use,&rsf_dst->TitleInfo.Use,&rsf_dmp->TitleInfo.Use);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.ChildIndex,&rsf_dst->TitleInfo.ChildIndex,&rsf_dmp->TitleInfo.ChildIndex);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.DemoIndex,&rsf_dst->TitleInfo.DemoIndex,&rsf_dmp->TitleInfo.DemoIndex);
	RsfSettingTransferSingle(&rsf_src->TitleInfo.TargetCategory,&rsf_dst->TitleInfo.TargetCategory,&rsf_dmp->TitleInfo.TargetCategory);
	RsfSettingTransferMultiple(&rsf_src->TitleInfo.CategoryFlags,&rsf_src->TitleInfo.CategoryFlagsNum,&rsf_dst->TitleInfo.CategoryFlags,&rsf_dst->TitleInfo.CategoryFlagsNum,&rsf_dmp->TitleInfo.CategoryFlags,&rsf_dmp->TitleInfo.CategoryFlagsNum);

	//CardInfo
	RsfSettingTransferSingle(&rsf_src->CardInfo.WritableAddress,&rsf_dst->CardInfo.WritableAddress,&rsf_dmp->CardInfo.WritableAddress);
	RsfSettingTransferSingle(&rsf_src->CardInfo.CardType,&rsf_dst->CardInfo.CardType,&rsf_dmp->CardInfo.CardType);
	RsfSettingTransferSingle(&rsf_src->CardInfo.CryptoType,&rsf_dst->CardInfo.CryptoType,&rsf_dmp->CardInfo.CryptoType);
	RsfSettingTransferSingle(&rsf_src->CardInfo.CardDevice,&rsf_dst->CardInfo.CardDevice,&rsf_dmp->CardInfo.CardDevice);
	RsfSettingTransferSingle(&rsf_src->CardInfo.MediaType,&rsf_dst->CardInfo.MediaType,&rsf_dmp->CardInfo.MediaType);

	free_RsfSettings(rsf_dmp);

	memset(desc,0,sizeof(desc_settings));
	memset(rsf,0,sizeof(rsf_settings));
	
	return 0;
}
	
void RsfSettingTransferSingle(char **src, char **dst, char **dmp)
{
	if(*src){ // RSF Setting was set
		if(*dst) *dmp = *dst; // DESC was also set, so send ptr to dump
		else *dmp = NULL;
		*dst = *src; // Set DESC Ptr to RSF's ptr
		*src = NULL; // Setting to NULL Just in case
	}
	else{
		*dmp = NULL;
	}
}

void RsfSettingTransferMultiple(char ***src, u32 *src_num, char ***dst, u32 *dst_num, char ***dmp, u32 *dmp_num)
{
	if(*src){
		if(*dst){
			*dmp = *dst;
			*dmp_num = *dst_num;
		}
		else{
			*dmp = NULL;
			*dmp_num = 0;
		}
		*dst = *src;
		*dst_num = *src_num;
		*src = NULL;
		*src_num = 0;
	}
	else{
		*dmp = NULL;
		*dmp_num = 0;
	}
}

void EvaluateRSF(rsf_settings *rsf, ctr_yaml_context *ctx)
{
	u32 start_level = ctx->Level-1;
	
	/* Check Group Key for Validity */
	CHECK_Group:
	//printf("RSF Found: %s\n",GetYamlString(ctx));
	if(cmpYamlValue("Option",ctx)) {FinishEvent(ctx); GET_Option(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("AccessControlInfo",ctx)) {FinishEvent(ctx); GET_AccessControlInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("SystemControlInfo",ctx)) {FinishEvent(ctx); GET_SystemControlInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("BasicInfo",ctx)) {FinishEvent(ctx); GET_BasicInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("Rom",ctx)) {FinishEvent(ctx); GET_Rom(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("ExeFs",ctx)) {FinishEvent(ctx); GET_ExeFs(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("PlainRegion",ctx)) {FinishEvent(ctx); GET_PlainRegion(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("TitleInfo",ctx)) {FinishEvent(ctx); GET_TitleInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("CardInfo",ctx)) {FinishEvent(ctx); GET_CardInfo(ctx,rsf); goto GET_NextGroup;}
		
	// If not recognised escape:
	fprintf(stderr,"[-] Unrecognised Key: '%s'\n",GetYamlString(ctx)); 
	FinishEvent(ctx); 
	ctx->error = YAML_BAD_GROUP_HEADER; 
	return;
		
	/* Get Next Group and call check */
	GET_NextGroup:
	// If done return
	if(ctx->done || ctx->error) return;
	
	// Recursively getting events until done or has value
	if(!ctx->event.type) GetEvent(ctx);
	if(ctx->Level <= start_level) return; // No longer in RSF Domain
	while(!EventIsScalar(ctx)){
		if(ctx->done || ctx->error) return;
		if(ctx->Level <= start_level) return; // No longer in RSF Domain
		FinishEvent(ctx);
		GetEvent(ctx);		
	}
	goto CHECK_Group;
}

void EvaluateDESC(desc_settings *desc, ctr_yaml_context *ctx)
{
	/* Check Group Key for Validity */
	CHECK_Group:
	//printf("%s\n",GetYamlString(ctx));
	if(cmpYamlValue("AccessControlDescriptor",ctx)) {FinishEvent(ctx); GET_AccessControlDescriptor(ctx,desc); goto GET_NextGroup;}
	else if(cmpYamlValue("CommonHeaderKey",ctx)) {FinishEvent(ctx); GET_CommonHeaderKey(ctx,desc); goto GET_NextGroup;}
	else if(cmpYamlValue("DefaultSpec",ctx)) {
		FinishEvent(ctx); 
		if(!CheckMappingEvent(ctx)) return;
		GetEvent(ctx);
		EvaluateRSF(&desc->DefaultSpec,ctx); 
		goto GET_NextGroup;
	}
		
	// If not recognised escape:
	fprintf(stderr,"[-] Unrecognised Key: '%s' (DESC)\n",GetYamlString(ctx)); 
	FinishEvent(ctx); 
	ctx->error = YAML_BAD_GROUP_HEADER; 
	return;
		
	/* Get Next Group and call check */
	GET_NextGroup:
	// If done return
	if(ctx->done || ctx->error) return;
	
	// Recursively getting events until done or has value
	if(!ctx->event.type) GetEvent(ctx);
	while(!EventIsScalar(ctx)){
		if(ctx->done || ctx->error) return;
		FinishEvent(ctx);
		GetEvent(ctx);		
	}
	goto CHECK_Group;
}

void GET_Option(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("NoPadding",ctx)) rsf->Option.NoPadding = SetBoolYAMLValue("NoPadding",ctx);
		else if(cmpYamlValue("AllowUnalignedSection",ctx)) rsf->Option.AllowUnalignedSection = SetBoolYAMLValue("AllowUnalignedSection",ctx);
		else if(cmpYamlValue("EnableCrypt",ctx)) rsf->Option.EnableCrypt = SetBoolYAMLValue("EnableCrypt",ctx);
		else if(cmpYamlValue("EnableCompress",ctx)) rsf->Option.EnableCompress = SetBoolYAMLValue("EnableCompress",ctx);
		else if(cmpYamlValue("FreeProductCode",ctx)) rsf->Option.FreeProductCode = SetBoolYAMLValue("FreeProductCode",ctx);
		else if(cmpYamlValue("UseOnSD",ctx)) rsf->Option.UseOnSD = SetBoolYAMLValue("UseOnSD",ctx);
		else if(cmpYamlValue("PageSize",ctx)) SetSimpleYAMLValue(&rsf->Option.PageSize,"PageSize",ctx,0);
		else if(cmpYamlValue("AppendSystemCall",ctx)) rsf->Option.AppendSystemCallNum = SetYAMLSequence(&rsf->Option.AppendSystemCall,"AppendSystemCall",ctx);
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_AccessControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("DisableDebug",ctx)) rsf->AccessControlInfo.DisableDebug = SetBoolYAMLValue("DisableDebug",ctx);
		else if(cmpYamlValue("EnableForceDebug",ctx)) rsf->AccessControlInfo.EnableForceDebug = SetBoolYAMLValue("EnableForceDebug",ctx);
		else if(cmpYamlValue("CanWriteSharedPage",ctx)) rsf->AccessControlInfo.CanWriteSharedPage = SetBoolYAMLValue("CanWriteSharedPage",ctx);
		else if(cmpYamlValue("CanUsePrivilegedPriority",ctx)) rsf->AccessControlInfo.CanUsePrivilegedPriority = SetBoolYAMLValue("CanUsePrivilegedPriority",ctx);
		else if(cmpYamlValue("CanUseNonAlphabetAndNumber",ctx)) rsf->AccessControlInfo.CanUseNonAlphabetAndNumber = SetBoolYAMLValue("CanUseNonAlphabetAndNumber",ctx);
		else if(cmpYamlValue("PermitMainFunctionArgument",ctx)) rsf->AccessControlInfo.PermitMainFunctionArgument = SetBoolYAMLValue("PermitMainFunctionArgument",ctx);
		else if(cmpYamlValue("CanShareDeviceMemory",ctx)) rsf->AccessControlInfo.CanShareDeviceMemory = SetBoolYAMLValue("CanShareDeviceMemory",ctx);
		else if(cmpYamlValue("UseOtherVariationSaveData",ctx)) rsf->AccessControlInfo.UseOtherVariationSaveData = SetBoolYAMLValue("UseOtherVariationSaveData",ctx);
		else if(cmpYamlValue("UseExtSaveData",ctx)) rsf->AccessControlInfo.UseExtSaveData = SetBoolYAMLValue("UseExtSaveData",ctx);
		else if(cmpYamlValue("RunnableOnSleep",ctx)) rsf->AccessControlInfo.RunnableOnSleep = SetBoolYAMLValue("RunnableOnSleep",ctx);
		else if(cmpYamlValue("SpecialMemoryArrange",ctx)) rsf->AccessControlInfo.SpecialMemoryArrange = SetBoolYAMLValue("SpecialMemoryArrange",ctx);
		
		
		else if(cmpYamlValue("ProgramId",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ProgramId,"ProgramId",ctx,0); 
		else if(cmpYamlValue("IdealProcessor",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.IdealProcessor,"IdealProcessor",ctx,0); 
		else if(cmpYamlValue("Priority",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.Priority,"Priority",ctx,0); 
		else if(cmpYamlValue("MemoryType",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.MemoryType,"MemoryType",ctx,0); 
		else if(cmpYamlValue("SystemMode",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemMode,"SystemMode",ctx,0); 
		else if(cmpYamlValue("FirmwareVersion",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.FirmwareVersion,"FirmwareVersion",ctx,0); 
		else if(cmpYamlValue("CoreVersion",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.CoreVersion,"CoreVersion",ctx,0); 
		else if(cmpYamlValue("HandleTableSize",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.HandleTableSize,"HandleTableSize",ctx,0); 
		else if(cmpYamlValue("SystemSaveDataId1",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemSaveDataId1,"SystemSaveDataId1",ctx,0); 
		else if(cmpYamlValue("SystemSaveDataId2",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemSaveDataId2,"SystemSaveDataId2",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId1",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId1,"OtherUserSaveDataId1",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId2",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId2,"OtherUserSaveDataId2",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId3",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId3,"OtherUserSaveDataId3",ctx,0); 
		else if(cmpYamlValue("ExtSaveDataId",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ExtSaveDataId,"ExtSaveDataId",ctx,0); 
		else if(cmpYamlValue("ExtSaveDataNumber",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ExtSaveDataNumber,"ExtSaveDataNumber",ctx,0); 
		else if(cmpYamlValue("AffinityMask",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.AffinityMask,"AffinityMask",ctx,0); 
		
		
		else if(cmpYamlValue("MemoryMapping",ctx)) rsf->AccessControlInfo.MemoryMappingNum = SetYAMLSequence(&rsf->AccessControlInfo.MemoryMapping,"MemoryMapping",ctx);
		else if(cmpYamlValue("IORegisterMapping",ctx)) rsf->AccessControlInfo.IORegisterMappingNum = SetYAMLSequence(&rsf->AccessControlInfo.IORegisterMapping,"IORegisterMapping",ctx);
		else if(cmpYamlValue("FileSystemAccess",ctx)) rsf->AccessControlInfo.FileSystemAccessNum = SetYAMLSequence(&rsf->AccessControlInfo.FileSystemAccess,"FileSystemAccess",ctx);
		else if(cmpYamlValue("IoAccessControl",ctx)) rsf->AccessControlInfo.IoAccessControlNum = SetYAMLSequence(&rsf->AccessControlInfo.IoAccessControl,"IoAccessControl",ctx);
		else if(cmpYamlValue("InterruptNumbers",ctx)) rsf->AccessControlInfo.InterruptNumbersNum = SetYAMLSequence(&rsf->AccessControlInfo.InterruptNumbers,"InterruptNumbers",ctx);
		else if(cmpYamlValue("SystemCallAccess",ctx)) rsf->AccessControlInfo.SystemCallAccessNum = SetYAMLSequenceFromMapping(&rsf->AccessControlInfo.SystemCallAccess,"SystemCallAccess",ctx,false);
		else if(cmpYamlValue("ServiceAccessControl",ctx)) rsf->AccessControlInfo.ServiceAccessControlNum = SetYAMLSequence(&rsf->AccessControlInfo.ServiceAccessControl,"ServiceAccessControl",ctx);
		else if(cmpYamlValue("StorageId",ctx)) rsf->AccessControlInfo.StorageIdNum = SetYAMLSequence(&rsf->AccessControlInfo.StorageId,"StorageId",ctx);
		
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_SystemControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("AppType",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.AppType,"AppType",ctx,0);
		else if(cmpYamlValue("StackSize",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.StackSize,"StackSize",ctx,0);
		else if(cmpYamlValue("RemasterVersion",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.RemasterVersion,"RemasterVersion",ctx,0);
		else if(cmpYamlValue("JumpId",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.JumpId,"JumpId",ctx,0);
		else if(cmpYamlValue("Dependency",ctx)) rsf->SystemControlInfo.DependencyNum = SetYAMLSequenceFromMapping(&rsf->SystemControlInfo.Dependency,"Dependency",ctx,false);
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_BasicInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("MediaFootPadding",ctx)) rsf->BasicInfo.MediaFootPadding = SetBoolYAMLValue("MediaFootPadding",ctx);
		else if(cmpYamlValue("Title",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.Title,"Title",ctx,0);
		else if(cmpYamlValue("CompanyCode",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.CompanyCode,"CompanyCode",ctx,0);
		else if(cmpYamlValue("ProductCode",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.ProductCode,"ProductCode",ctx,0);
		else if(cmpYamlValue("MediaSize",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.MediaSize,"MediaSize",ctx,0);
		else if(cmpYamlValue("ContentType",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.ContentType,"ContentType",ctx,0);
		else if(cmpYamlValue("Logo",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.Logo,"Logo",ctx,0);
		else if(cmpYamlValue("BackupMemoryType",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.BackupMemoryType,"BackupMemoryType",ctx,0);
		else if(cmpYamlValue("InitialCode",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.InitialCode,"InitialCode",ctx,0);
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_Rom(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("HostRoot",ctx)) SetSimpleYAMLValue(&rsf->Rom.HostRoot,"HostRoot",ctx,0);
		else if(cmpYamlValue("Padding",ctx)) SetSimpleYAMLValue(&rsf->Rom.Padding,"Padding",ctx,0);
		else if(cmpYamlValue("SaveDataSize",ctx)) SetSimpleYAMLValue(&rsf->Rom.SaveDataSize,"SaveDataSize",ctx,0);
		
		else if(cmpYamlValue("DefaultReject",ctx)) rsf->Rom.DefaultRejectNum = SetYAMLSequence(&rsf->Rom.DefaultReject,"DefaultReject",ctx);
		else if(cmpYamlValue("Reject",ctx)) rsf->Rom.RejectNum = SetYAMLSequence(&rsf->Rom.Reject,"Reject",ctx);
		else if(cmpYamlValue("Include",ctx)) rsf->Rom.IncludeNum = SetYAMLSequence(&rsf->Rom.Include,"Include",ctx);
		else if(cmpYamlValue("File",ctx)) rsf->Rom.FileNum = SetYAMLSequence(&rsf->Rom.File,"File",ctx);
		
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_ExeFs(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("Text",ctx)) rsf->ExeFs.TextNum = SetYAMLSequence(&rsf->ExeFs.Text,"Text",ctx);
		else if(cmpYamlValue("ReadOnly",ctx)) rsf->ExeFs.ReadOnlyNum = SetYAMLSequence(&rsf->ExeFs.ReadOnly,"ReadOnly",ctx);
		else if(cmpYamlValue("ReadWrite",ctx)) rsf->ExeFs.ReadWriteNum = SetYAMLSequence(&rsf->ExeFs.ReadWrite,"ReadWrite",ctx);
		
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_PlainRegion(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	rsf->PlainRegionNum = SetYAMLSequence(&rsf->PlainRegion,"PlainRegion",ctx);
}

void GET_TitleInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("Platform",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Platform,"Platform",ctx,0);
		else if(cmpYamlValue("Category",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Category,"Category",ctx,0);
		else if(cmpYamlValue("UniqueId",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.UniqueId,"UniqueId",ctx,0);
		else if(cmpYamlValue("Version",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Version,"Version",ctx,0);
		else if(cmpYamlValue("ContentsIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.ContentsIndex,"ContentsIndex",ctx,0);
		else if(cmpYamlValue("Variation",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Variation,"Variation",ctx,0);
		else if(cmpYamlValue("Use",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Use,"Use",ctx,0);
		else if(cmpYamlValue("ChildIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.ChildIndex,"ChildIndex",ctx,0);
		else if(cmpYamlValue("DemoIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.DemoIndex,"DemoIndex",ctx,0);
		else if(cmpYamlValue("TargetCategory",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.TargetCategory,"TargetCategory",ctx,0);
		
		else if(cmpYamlValue("CategoryFlags",ctx)) rsf->TitleInfo.CategoryFlagsNum = SetYAMLSequence(&rsf->TitleInfo.CategoryFlags,"CategoryFlags",ctx);
		
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_CardInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("WritableAddress",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.WritableAddress,"WritableAddress",ctx,0);
		else if(cmpYamlValue("CardType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CardType,"CardType",ctx,0);
		else if(cmpYamlValue("CryptoType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CryptoType,"CryptoType",ctx,0);
		else if(cmpYamlValue("CardDevice",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CardDevice,"CardDevice",ctx,0);
		else if(cmpYamlValue("MediaType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.MediaType,"MediaType",ctx,0);
		
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_AccessControlDescriptor(ctr_yaml_context *ctx, desc_settings *desc)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	
	u32 InitLevel = ctx->Level;
	
	/* Checking each child */
	GetEvent(ctx);
	desc->AccessControlDescriptor.Found = true;
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		else if(cmpYamlValue("RunnableOnSleep",ctx)) desc->AccessControlDescriptor.RunnableOnSleep = SetBoolYAMLValue("RunnableOnSleep",ctx);
		else if(cmpYamlValue("SpecialMemoryArrange",ctx)) desc->AccessControlDescriptor.SpecialMemoryArrange = SetBoolYAMLValue("SpecialMemoryArrange",ctx);
		else if(cmpYamlValue("AutoGen",ctx)) desc->AccessControlDescriptor.AutoGen = SetBoolYAMLValue("AutoGen",ctx);
		
		else if(cmpYamlValue("ProgramId",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.ProgramIdDesc,"ProgramId",ctx,0); 
		else if(cmpYamlValue("Priority",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.PriorityDesc,"Priority",ctx,0); 
		else if(cmpYamlValue("AffinityMask",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.AffinityMaskDesc,"AffinityMask",ctx,0); 
		else if(cmpYamlValue("IdealProcessor",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.IdealProcessorDesc,"IdealProcessor",ctx,0); 
		else if(cmpYamlValue("FirmwareVersion",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.FirmwareVersionDesc,"FirmwareVersion",ctx,0); 
		else if(cmpYamlValue("HandleTableSize",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.HandleTableSizeDesc,"HandleTableSize",ctx,0); 
		else if(cmpYamlValue("MemoryType",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.MemoryTypeDesc,"MemoryType",ctx,0); 
		else if(cmpYamlValue("SystemMode",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.SystemModeDesc,"SystemMode",ctx,0); 
		else if(cmpYamlValue("DescVersion",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.DescVersionDesc,"DescVersion",ctx,0); 
		else if(cmpYamlValue("Signature",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.AccCtlDescSign,"Signature",ctx,0); 
		else if(cmpYamlValue("Descriptor",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.AccCtlDescBin,"Descriptor",ctx,0);
		else if(cmpYamlValue("CryptoKey",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.CryptoKey,"CryptoKey",ctx,0); 
		else if(cmpYamlValue("ResourceLimitCategory",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.ResourceLimitCategory,"ResourceLimitCategory",ctx,0); 		
		else if(cmpYamlValue("ReleaseKernelMajor",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.ReleaseKernelMajor,"ReleaseKernelMajor",ctx,0);
		else if(cmpYamlValue("ReleaseKernelMinor",ctx)) SetSimpleYAMLValue(&desc->AccessControlDescriptor.ReleaseKernelMinor,"ReleaseKernelMinor",ctx,0); 
		
		
		else if(cmpYamlValue("ServiceAccessControl",ctx)) desc->AccessControlDescriptor.ServiceAccessControlDescNum = SetYAMLSequence(&desc->AccessControlDescriptor.ServiceAccessControlDesc,"ServiceAccessControl",ctx);
		else if(cmpYamlValue("MemoryMapping",ctx)) desc->AccessControlDescriptor.MemoryMappingDescNum = SetYAMLSequence(&desc->AccessControlDescriptor.MemoryMappingDesc,"MemoryMapping",ctx);
		else if(cmpYamlValue("IORegisterMapping",ctx)) desc->AccessControlDescriptor.IORegisterMappingDescNum = SetYAMLSequence(&desc->AccessControlDescriptor.IORegisterMappingDesc,"IORegisterMapping",ctx);
		else if(cmpYamlValue("Arm9AccessControl",ctx)) desc->AccessControlDescriptor.Arm9AccessControlDescNum = SetYAMLSequence(&desc->AccessControlDescriptor.Arm9AccessControlDesc,"Arm9AccessControl",ctx);
		else if(cmpYamlValue("EnableInterruptNumbers",ctx)) desc->AccessControlDescriptor.EnableInterruptNumbersNum = SetYAMLSequence(&desc->AccessControlDescriptor.EnableInterruptNumbers,"EnableInterruptNumbers",ctx);
		else if(cmpYamlValue("EnableSystemCalls",ctx)) desc->AccessControlDescriptor.EnableSystemCallsNum = SetYAMLSequenceFromMapping(&desc->AccessControlDescriptor.EnableSystemCalls,"EnableSystemCalls",ctx,false);
		else if(cmpYamlValue("StorageId",ctx)) desc->AccessControlDescriptor.StorageIdDescNum = SetYAMLSequence(&desc->AccessControlDescriptor.StorageIdDesc,"StorageId",ctx);


		// These keys while not caught by makerom, are ignored
		else if(cmpYamlValue("DisableDebug",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("EnableForceDebug",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("CanWriteSharedPage",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("CanUsePrivilegedPriority",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("CanUseNonAlphabetAndNumber",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("PermitMainFunctionArgument",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("CanShareDeviceMemory",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("CoreVersion",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("FileSystemAccess",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("IoAccessControl",ctx)) SkipYAMLGroup(ctx);
		else if(cmpYamlValue("SystemSaveDataId1",ctx)) SkipYAMLGroup(ctx); 
		else if(cmpYamlValue("SystemSaveDataId2",ctx)) SkipYAMLGroup(ctx);
		// Ignored Values End
		
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	
	FinishEvent(ctx);
}

void GET_CommonHeaderKey(ctr_yaml_context *ctx, desc_settings *desc)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	desc->CommonHeaderKey.Found = true;
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("D",ctx)) SetSimpleYAMLValue(&desc->CommonHeaderKey.D,"D",ctx,0); 
		else if(cmpYamlValue("P",ctx)) SetSimpleYAMLValue(&desc->CommonHeaderKey.P,"P",ctx,0); 
		else if(cmpYamlValue("Q",ctx)) SetSimpleYAMLValue(&desc->CommonHeaderKey.Q,"Q",ctx,0); 
		else if(cmpYamlValue("DP",ctx)) SetSimpleYAMLValue(&desc->CommonHeaderKey.DP,"DP",ctx,0); 
		else if(cmpYamlValue("DQ",ctx)) SetSimpleYAMLValue(&desc->CommonHeaderKey.DQ,"DQ",ctx,0); 
		else if(cmpYamlValue("InverseQ",ctx)) SetSimpleYAMLValue(&desc->CommonHeaderKey.InverseQ,"InverseQ",ctx,0); 
		else if(cmpYamlValue("Modulus",ctx)) SetSimpleYAMLValue(&desc->CommonHeaderKey.Modulus,"Modulus",ctx,0); 
		else if(cmpYamlValue("Exponent",ctx)) SetSimpleYAMLValue(&desc->CommonHeaderKey.Exponent,"Exponent",ctx,0); 
		
		else{
			fprintf(stderr,"[-] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}