#include "lib.h"

// Private Prototypes
void DisplayHelp(char *app_name);
void SetDefaults(user_settings *set);
int SetArgument(int argc, int i, char *argv[], user_settings *set);
int CheckArgumentCombination(user_settings *set);
void PrintNeedsArgument(char *arg);
void PrintArgumentInvalid(char *arg);
void PrintNeedsParam(char *arg);
void PrintNoNeedParam(char *arg);

int ParseArgs(int argc, char *argv[], user_settings *usr_settings)
{
	if(argv == NULL || usr_settings == NULL)
		return USR_PTR_PASS_FAIL;
		
	if(argc < 2){
		DisplayHelp(argv[0]);
		return USR_HELP;
	}
		
	// Detecting Help Requried
	for(int i = 1; i < argc; i++){
		if(strcmp(argv[i],"-help") == 0){
			DisplayHelp(argv[0]);
			return USR_HELP;
		}
	}
	
	// Allocating Memory for Content Path Ptrs
	usr_settings->ContentPath = malloc(CIA_MAX_CONTENT*sizeof(char*));
	if(usr_settings->ContentPath == NULL){
		fprintf(stderr,"[SETTING ERROR] MEM ERROR\n");
		return USR_MEM_ERROR;
	}
	memset(usr_settings->ContentPath,0,CIA_MAX_CONTENT*sizeof(char*));
	
	// Setting Defaults
	SetDefaults(usr_settings);
	
	// Initialise Keys
	InitKeys(&usr_settings->keys);
	
	// Reading Arguments
	int set_result;
	int i = 1;
	while(i < argc){
		set_result = SetArgument(argc,i,argv,usr_settings);
		if(set_result < 1){
			fprintf(stderr,"[RESULT] Invalid arguments, see '%s -help'\n",argv[0]);
			return set_result;
		}
		i += set_result;
	}
	
	set_result = CheckArgumentCombination(usr_settings);
	if(set_result) return set_result;
	
	if(!usr_settings->outfile){
		char *source_path = NULL;
		if(usr_settings->IsBuildingNCCH0) source_path = usr_settings->rsf_path;
		else if(usr_settings->ConvertCci) source_path = usr_settings->CciPath;
		else if(usr_settings->Content0IsSrl) source_path = usr_settings->SrlPath;
		else source_path = usr_settings->ContentPath[0];
		u16 outfile_len = strlen(source_path) + 3;
		usr_settings->outfile = malloc(outfile_len);
		if(!usr_settings->outfile){
			fprintf(stderr,"[SETTING ERROR] MEM ERROR\n");
			return USR_MEM_ERROR;
		}
		usr_settings->outfile_mallocd = true;
		append_filextention(usr_settings->outfile,outfile_len,source_path,(char*)&output_extention[usr_settings->out_format-1]);
	}
	return 0;
}

void SetDefaults(user_settings *set)
{
	// Build NCCH Info
	set->IsBuildingNCCH0 = true;
	#ifdef RETAIL_FSIGN
	set->accessdesc = auto_gen;
	#else
	set->accessdesc = use_spec_file;
	#endif
	set->include_exefs_logo = false;
	set->out_format = CXI;
	set->build_ncch_type = format_not_set;

	// Content0 Info
	set->Content0IsNcch = true;
	set->ConvertCci = false;
	set->Content0IsSrl = false;

	set->Version[0] = 0xffff;

	// CCI Info
	set->GenSDKCardInfoHeader = false;
	set->OmitImportedNcchHdr = false;

	// CIA Info
	set->EncryptContents = false;
	set->RandomTitleKey = false;
	for(int i = 0; i < CIA_MAX_CONTENT; i++){
		set->ContentID[i] = 0x100000000;
	}
}

int SetArgument(int argc, int i, char *argv[], user_settings *set)
{
	bool IsLastArg = (i >= (argc -1));
	bool HasParam = false;
	if(!IsLastArg){
		if(argv[i+1][0] != '-') HasParam = true;
	}
	
	if(strcmp(argv[i],"-elf") == 0){
		if(!HasParam){
			PrintNeedsParam("-elf");
			return USR_ARG_REQ_PARAM;
		}
		set->elf_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-rsf") == 0){
		if(!HasParam){
			PrintNeedsParam("-rsf");
			return USR_ARG_REQ_PARAM;
		}
		set->rsf_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-icon") == 0){
		if(!HasParam){
			PrintNeedsParam("-icon");
			return USR_ARG_REQ_PARAM;
		}
		set->icon_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-banner") == 0){
		if(!HasParam){
			PrintNeedsParam("-banner");
			return USR_ARG_REQ_PARAM;
		}
		set->banner_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-logo") == 0){
		if(!HasParam){
			PrintNeedsParam("-logo");
			return USR_ARG_REQ_PARAM;
		}
		set->logo_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-o") == 0){
		if(!HasParam){
			PrintNeedsParam("-o");
			return USR_ARG_REQ_PARAM;
		}
		set->outfile = argv[i+1];
		set->outfile_mallocd = false;
		return 2;
	}
	#ifdef PRIVATE_BUILD
	else if(strcmp(argv[i],"-exheader") == 0){
		if(!HasParam){
			PrintNeedsParam("-exheader");
			return USR_ARG_REQ_PARAM;
		}
		set->exheader_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-code") == 0){
		if(!HasParam){
			PrintNeedsParam("-code");
			return USR_ARG_REQ_PARAM;
		}
		set->exefs_code_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-romfs") == 0){
		if(!HasParam){
			PrintNeedsParam("-romfs");
			return USR_ARG_REQ_PARAM;
		}
		set->romfs_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-plain-region") == 0){
		if(!HasParam){
			PrintNeedsParam("-plain-region");
			return USR_ARG_REQ_PARAM;
		}
		set->plain_region_path = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-cci") == 0){
		if(!HasParam){
			PrintNeedsParam("-cci");
			return USR_ARG_REQ_PARAM;
		}
		set->ConvertCci = true;
		set->Content0IsSrl = false;
		set->Content0IsNcch = false;
		set->IsBuildingNCCH0 = false;
		set->out_format = CIA;
		set->CciPath = argv[i+1];
		return 2;
	}
	else if(strcmp(argv[i],"-srl") == 0){
		if(!HasParam){
			PrintNeedsParam("-srl");
			return USR_ARG_REQ_PARAM;
		}
		set->ConvertCci = false;
		set->Content0IsSrl = true;
		set->Content0IsNcch = false;
		set->IsBuildingNCCH0 = false;
		set->out_format = CIA;
		set->SrlPath = argv[i+1];
		return 2;

	}
	else if(strcmp(argv[i],"-devcardcci") == 0){
		if(HasParam){
			PrintNoNeedParam("-devcardcci");
			return USR_BAD_ARG;
		}
		set->GenSDKCardInfoHeader = true;
		return 1;
	}
	else if(strcmp(argv[i],"-omitncchhdr") == 0){
		if(HasParam){
			PrintNoNeedParam("-omitncchhdr");
			return USR_BAD_ARG;
		}
		set->OmitImportedNcchHdr = true;
		return 1;
	}
	#endif
	else if(strcmp(argv[i],"-f") == 0){
		if(!HasParam){
			PrintNeedsParam("-f");
			return USR_ARG_REQ_PARAM;
		}
		if(strcasecmp(argv[i+1],"cxi") == 0 || strcasecmp(argv[i+1],"exec") == 0 ) set->out_format = CXI;
		else if(strcasecmp(argv[i+1],"cfa") == 0 || strcasecmp(argv[i+1],"data") == 0 ) set->out_format = CFA;
		else if(strcasecmp(argv[i+1],"cci") == 0 || strcasecmp(argv[i+1],"card") == 0 ) set->out_format = CCI;
		else if(strcasecmp(argv[i+1],"cia") == 0) set->out_format = CIA;
		else {
			fprintf(stderr,"[-] Invalid output format '%s'\n",argv[i+1]);
			return USR_BAD_ARG;
		}		
		return 2;
	}
	else if(strcmp(argv[i],"-ncch") == 0){
		if(!HasParam){
			PrintNeedsParam("-ncch");
			return USR_ARG_REQ_PARAM;
		}
		if(strcasecmp(argv[i+1],"cxi") == 0) set->build_ncch_type = CXI;
		else if(strcasecmp(argv[i+1],"cfa") == 0) set->build_ncch_type = CFA;
		else {
			fprintf(stderr,"[-] Invalid ncch type '%s'\n",argv[i+1]);
			return USR_BAD_ARG;
		}		
		return 2;
	}
	#ifdef RETAIL_FSIGN
	else if(strcmp(argv[i],"-sysfixedkey") == 0){
		if(!HasParam){
			PrintNeedsParam("-sysfixedkey");
			return USR_ARG_REQ_PARAM;
		}
		if(strlen(argv[i+1]) != 32) {
			fprintf(stderr,"[ERROR] Invalid SystemFixedKey '%s'\n",argv[i+1]);
			return USR_BAD_ARG;
		}
		u8 *key = malloc(16);
		if(!key){
			fprintf(stderr,"[ERROR] MEM ERROR\n");
			return USR_MEM_ERROR;
		}
		char_to_u8_array(key,argv[i+1],16,BE,16);
		SetSystemFixedKey(&set->keys,key);
		free(key);
		return 2;
	}
	else if(strcmp(argv[i],"-commonkey") == 0){
		if(!HasParam){
			PrintNeedsParam("-commonkey");
			return USR_ARG_REQ_PARAM;
		}
		if(strlen(argv[i+1]) != 32) {
			fprintf(stderr,"[ERROR] Invalid CommonKey '%s'\n",argv[i+1]);
			return USR_BAD_ARG;
		}
		u8 *key = malloc(16);
		if(!key){
			fprintf(stderr,"[ERROR] MEM ERROR\n");
			return USR_MEM_ERROR;
		}
		char_to_u8_array(key,argv[i+1],16,BE,16);

		if(i+2 < argc){
			u8 id = strtol(argv[i+2],NULL,10);
			SetCommonKey(&set->keys,key,id);
			SetCurrentCommonKey(&set->keys,id);
		}
		else SetCommonKey(&set->keys,key,0);
		SetCurrentCommonKey(&set->keys,0);
		free(key);
		return 2;
	}
	#endif
	else if(strcmp(argv[i],"-accessdesc") == 0){
		if(!HasParam){
			PrintNeedsParam("-accessdesc");
			return USR_ARG_REQ_PARAM;
		}
		
		if(strcasecmp(argv[i+1],"UseRsf") == 0) set->accessdesc = use_spec_file;
		else if(strcasecmp(argv[i+1],"AutoGen") == 0 || strcasecmp(argv[i+1],"Auto") == 0) set->accessdesc = auto_gen;
#ifndef RETAIL_FSIGN
		else if(strcasecmp(argv[i+1],"App") == 0) set->accessdesc = app;
		else if(strcasecmp(argv[i+1],"Demo") == 0) set->accessdesc = demo;
		else if(strcasecmp(argv[i+1],"DlpChild") == 0 || strcasecmp(argv[i+1],"Dlp") == 0) set->accessdesc = dlp;
#endif
		else{
			fprintf(stderr,"[-] Accessdesc pre-set '%s' not recognised\n",argv[i+1]);
			return USR_BAD_ARG;
		}
		return 2;
	}
	
	else if(strcmp(argv[i],"-exefslogo") == 0){
		if(HasParam){
			PrintNoNeedParam("-exefslogo");
			return USR_BAD_ARG;
		}
		set->include_exefs_logo = true;
		return 1;
	}
	else if(strcmp(argv[i],"-rand") == 0){
		if(HasParam){
			PrintNoNeedParam("-rand");
			return USR_BAD_ARG;
		}
		set->RandomTitleKey = true;
		return 1;
	}
	else if(strcmp(argv[i],"-encryptcia") == 0){
		if(HasParam){
			PrintNoNeedParam("-encryptcia");
			return USR_BAD_ARG;
		}
		set->EncryptContents = true;
		return 1;
	}
	else if(strcmp(argv[i],"-major") == 0){
		if(!HasParam){
			PrintNeedsParam("-major");
			return USR_ARG_REQ_PARAM;
		}
		u32 tmp = strtoul(argv[i+1],NULL,10);
		set->Version[0] = tmp > 63 ? 63 : tmp;
		return 2;
	}
	else if(strcmp(argv[i],"-minor") == 0){
		if(!HasParam){
			PrintNeedsParam("-minor");
			return USR_ARG_REQ_PARAM;
		}
		u32 tmp = strtoul(argv[i+1],NULL,10);
		set->Version[1] = tmp > 63 ? 63 : tmp;
		return 2;
	}
	else if(strcmp(argv[i],"-micro") == 0){
		if(!HasParam){
			PrintNeedsParam("-micro");
			return USR_ARG_REQ_PARAM;
		}
		u32 tmp = strtoul(argv[i+1],NULL,10);
		set->Version[2] = tmp > 15 ? 15 : tmp;
		return 2;
	}

	else if(strcmp(argv[i],"-content") == 0){
		if(!HasParam){
			PrintNeedsParam("-content");
			return USR_ARG_REQ_PARAM;
		}
		char *pos = strstr(argv[i+1],":");
		if(!pos){
			fprintf(stderr,"[SETTING ERROR] Bad argument '%s %s', correct format:\n",argv[i],argv[i+1]);
			fprintf(stderr,"	-content <CONTENT PATH>:<INDEX>\n");
			fprintf(stderr,"  If generating a CIA, then use the format:\n");
			fprintf(stderr,"	-content <CONTENT PATH>:<INDEX>:<ID>\n");
			return USR_BAD_ARG;
		}		
		if(strlen(pos) < 2){
			fprintf(stderr,"[SETTING ERROR] Bad argument '%s %s', correct format:\n",argv[i],argv[i+1]);
			fprintf(stderr,"	-content <CONTENT PATH>:<INDEX>\n");
			fprintf(stderr,"  If generating a CIA, then use the format:\n");
			fprintf(stderr,"	-content <CONTENT PATH>:<INDEX>:<ID>\n");
			return USR_BAD_ARG;
		}

		/* Getting Content Index */
		u16 content_index = strtol((char*)(pos+1),NULL,10);

		/* Storing Content Filepath */
		u32 path_len = (u32)(pos-argv[i+1])+1;
		
		if(content_index == 0) set->IsBuildingNCCH0 = false;
		if(set->ContentPath[content_index] != NULL){
			fprintf(stderr,"[SETTING ERROR] Content %d is already specified\n",content_index);
			return USR_BAD_ARG;
		}
		set->ContentPath[content_index] = malloc(path_len);
		if(set->ContentPath[content_index] == NULL){
			fprintf(stderr,"[SETTING ERROR] MEM ERROR\n");
			return USR_MEM_ERROR;
		}
		memset(set->ContentPath[content_index],0,path_len);
		strncpy(set->ContentPath[content_index],argv[i+1],path_len-1);	

		/* Get ContentID for CIA gen */
		char *pos2 = strstr(pos+1,":"); 
		if(pos2) {
			set->ContentID[content_index] = strtoul((pos2+1),NULL,16);
		}
		
		/* Return Next Arg Pos*/
		return 2;
	}
	/*
	else if(strncmp(argv[i],"-D",2) == 0){
		fprintf(stderr,"[WARNING] -DNAME=VALUE not implemented yet\n");
	}
	*/

	// If not a valid argument
	fprintf(stderr,"[SETTING ERROR] Unrecognised argument '%s'\n",argv[i]);
	return USR_UNK_ARG;
}

int CheckArgumentCombination(user_settings *set)
{
	for(int i = 0; i < CIA_MAX_CONTENT; i++){
		if( i > CCI_MAX_CONTENT-1 && set->ContentPath[i] && set->out_format == CCI){
			fprintf(stderr,"[SETTING ERROR] Content indexes > 7 are invalid for CCI\n");
			return USR_BAD_ARG;
		}
		if(set->ContentPath[i] && (set->out_format == CXI || set->out_format == CFA)){
			fprintf(stderr,"[SETTING ERROR] You cannot specify content while outputting CXI/CFA files\n");
			return USR_BAD_ARG;
		}
	}
	if((set->out_format == CXI || set->out_format == CFA) && set->build_ncch_type > 0){
		fprintf(stderr,"[SETTING ERROR] Arguments '-f cxi|cfa' and '-ncch cxi|cfa' are invalid\n");
		return USR_BAD_ARG;
	}
	if(set->build_ncch_type > 0 && !set->IsBuildingNCCH0){
		fprintf(stderr,"[SETTING ERROR] Arguments '-content %s:0' and '-ncch cxi|cfa' cannot be used together\n",set->ContentPath[0]);
		return USR_BAD_ARG;
	}

	if(set->elf_path && set->exefs_code_path){
		fprintf(stderr,"[SETTING ERROR] Arguments '-elf' and '-code' cannot be used together\n");
		return USR_BAD_ARG;
	}

	// Setting set->build_ncch_type if it isn't already set
	if(set->IsBuildingNCCH0 && set->build_ncch_type == 0){
		if(set->out_format == CCI || set->out_format == CIA) set->build_ncch_type = CXI;
		else set->build_ncch_type = set->out_format;
	}

	bool buildCXI = (set->out_format == CXI || set->build_ncch_type == CXI) && set->IsBuildingNCCH0;
	bool buildCFA = (set->out_format == CFA || set->build_ncch_type == CFA) && set->IsBuildingNCCH0;
	// Detecting Required Arguments
	if(buildCXI && !set->elf_path && !set->exefs_code_path){
		PrintNeedsArgument("-elf");
		return USR_BAD_ARG;
	}
	if((buildCXI || buildCFA) && !set->rsf_path){
		PrintNeedsArgument("-rsf");
		return USR_BAD_ARG;
	}
	if(buildCXI && !set->exheader_path && set->exefs_code_path){
		PrintNeedsArgument("-exheader");
		return USR_BAD_ARG;
	}

	// Reporting bad arguments
	if(!buildCXI && set->elf_path){
		PrintArgumentInvalid("-elf");
		return USR_BAD_ARG;
	}
	if(!buildCXI && set->exefs_code_path){
		PrintArgumentInvalid("-code");
		return USR_BAD_ARG;
	}
	if(!buildCXI && set->exheader_path){
		PrintArgumentInvalid("-exheader");
		return USR_BAD_ARG;
	}
	if(!buildCXI && set->plain_region_path){
		PrintArgumentInvalid("-plain-region");
		return USR_BAD_ARG;
	}
	if(!buildCXI && set->include_exefs_logo){
		PrintArgumentInvalid("-exefslogo");
		return USR_BAD_ARG;
	}
	if(!set->IsBuildingNCCH0 && set->romfs_path){
		PrintArgumentInvalid("-romfs");
		return USR_BAD_ARG;
	}

	return 0;
}

void InvalidateRSFBooleans(rsf_settings *rsf_set)
{
	rsf_set->Option.NoPadding = -1;
	rsf_set->Option.AllowUnalignedSection = -1;
	rsf_set->Option.EnableCrypt = -1;
	rsf_set->Option.EnableCompress = -1;
	rsf_set->Option.FreeProductCode = -1;
	rsf_set->Option.UseOnSD = -1;

	rsf_set->AccessControlInfo.DisableDebug = -1;
	rsf_set->AccessControlInfo.EnableForceDebug = -1;
	rsf_set->AccessControlInfo.CanWriteSharedPage = -1;
	rsf_set->AccessControlInfo.CanUsePrivilegedPriority = -1;
	rsf_set->AccessControlInfo.CanUseNonAlphabetAndNumber = -1;
	rsf_set->AccessControlInfo.PermitMainFunctionArgument = -1;
	rsf_set->AccessControlInfo.CanShareDeviceMemory = -1;
	rsf_set->AccessControlInfo.UseOtherVariationSaveData = -1;
	rsf_set->AccessControlInfo.UseExtSaveData = -1;
	rsf_set->AccessControlInfo.UseExtendedSaveDataAccessControl = -1;
	rsf_set->AccessControlInfo.RunnableOnSleep = -1;
	rsf_set->AccessControlInfo.SpecialMemoryArrange = -1;
	
	rsf_set->BasicInfo.MediaFootPadding = -1;
}

void init_UserSettings(user_settings *usr_settings)
{
	memset(usr_settings,0,sizeof(user_settings));
}

void free_YamlSettings(yaml_settings *set)
{
	// Option
	free(set->Option.PageSize);
	
	// RomFs
	free(set->RomFs.HostRoot);
	free_StringCollection(set->RomFs.DefaultReject,set->RomFs.DefaultRejectNum);
	free_StringCollection(set->RomFs.Reject,set->RomFs.RejectNum);
	free_StringCollection(set->RomFs.Include,set->RomFs.IncludeNum);
	free_StringCollection(set->RomFs.File,set->RomFs.FileNum);

	// ExeFs
	free(set->ExeFs.StackSize);
	free_StringCollection(set->ExeFs.Text,set->ExeFs.TextNum);
	free_StringCollection(set->ExeFs.ReadOnly,set->ExeFs.ReadOnlyNum);
	free_StringCollection(set->ExeFs.ReadWrite,set->ExeFs.ReadWriteNum);
	
	// Plain Region
	free_StringCollection(set->PlainRegion,set->PlainRegionNum);

	// BasicInfo
	free(set->BasicInfo.Title);
	free(set->BasicInfo.CompanyCode);
	free(set->BasicInfo.ProductCode);
	free(set->BasicInfo.ContentType);
	free(set->BasicInfo.Logo);
	free(set->BasicInfo.RemasterVersion);

	// TitleInfo
	free(set->TitleInfo.Category);
	free(set->TitleInfo.ChildIndex);
	free(set->TitleInfo.ContentsIndex);
	free(set->TitleInfo.DataTitleIndex);
	free(set->TitleInfo.DemoIndex);
	free(set->TitleInfo.Version);
	free(set->TitleInfo.TargetCategory);
	free(set->TitleInfo.UniqueId);
	free_StringCollection(set->TitleInfo.CategoryFlags,set->TitleInfo.CategoryFlagsNum);

	// CardInfo
	free(set->CardInfo.BackupWriteWaitTime);
	free(set->CardInfo.CardDevice);
	free(set->CardInfo.CardType);
	free(set->CardInfo.CryptoType);
	free(set->CardInfo.MediaSize);
	free(set->CardInfo.MediaType);
	free(set->CardInfo.WritableAddress);

	// SystemInfo
	free(set->SystemInfo.JumpId);
	free(set->SystemInfo.SaveDataSize);

	// Dependency
	free_StringCollection(set->Dependency,set->DependencyNum);

	// ARM11SystemLocalCapabilities
	free(set->ARM11SystemLocalCapabilities.AppType);
	free(set->ARM11SystemLocalCapabilities.MaxCpu);
	free(set->ARM11SystemLocalCapabilities.CoreVersion);
	free(set->ARM11SystemLocalCapabilities.IdealProcessor);
	free(set->ARM11SystemLocalCapabilities.Priority);
	free(set->ARM11SystemLocalCapabilities.AffinityMask);
	free(set->ARM11SystemLocalCapabilities.SystemMode);
	free(set->ARM11SystemLocalCapabilities.ResourceLimitCategory);

	free_StringCollection(set->ARM11SystemLocalCapabilities.ServiceAccessControl,set->ARM11SystemLocalCapabilities.ServiceAccessControlNum);

	// ARM11KernelCapabilities
	free(set->ARM11KernelCapabilities.MemoryType);
	free(set->ARM11KernelCapabilities.HandleTableSize);
	free(set->ARM11KernelCapabilities.ReleaseKernelMajor);
	free(set->ARM11KernelCapabilities.ReleaseKernelMinor);
	free(set->ARM11KernelCapabilities.StorageInfo.SystemSaveDataId1);
	free(set->ARM11KernelCapabilities.StorageInfo.SystemSaveDataId2);
	free(set->ARM11KernelCapabilities.StorageInfo.OtherUserSaveDataId1);
	free(set->ARM11KernelCapabilities.StorageInfo.OtherUserSaveDataId2);
	free(set->ARM11KernelCapabilities.StorageInfo.OtherUserSaveDataId3);
	free(set->ARM11KernelCapabilities.StorageInfo.ExtSaveDataId);

	free_StringCollection(set->ARM11KernelCapabilities.MemoryMapping,set->ARM11KernelCapabilities.MemoryMappingNum);
	free_StringCollection(set->ARM11KernelCapabilities.IORegisterMapping,set->ARM11KernelCapabilities.IORegisterMappingNum);
	free_StringCollection(set->ARM11KernelCapabilities.FileSystemAccess,set->ARM11KernelCapabilities.FileSystemAccessNum);
	free_StringCollection(set->ARM11KernelCapabilities.InterruptNumbers,set->ARM11KernelCapabilities.InterruptNumbersNum);
	free_StringCollection(set->ARM11KernelCapabilities.SystemCallAccess,set->ARM11KernelCapabilities.SystemCallAccessNum);
	free_StringCollection(set->ARM11KernelCapabilities.StorageInfo.AccessibleSaveDataIds,set->ARM11KernelCapabilities.StorageInfo.AccessibleSaveDataIdsNum);
	
	// ARM9AccessControlInfo
	free(set->ARM9AccessControlInfo.DescVersion);
	free_StringCollection(set->ARM9AccessControlInfo.IoAccessControl,set->ARM9AccessControlInfo.IoAccessControlNum);

	// CommonHeaderKey
	free(set->CommonHeaderKey.D);
	free(set->CommonHeaderKey.Modulus);
	free(set->CommonHeaderKey.Exponent);
	free(set->CommonHeaderKey.AccCtlDescSign);
	free(set->CommonHeaderKey.AccCtlDescBin);
}

void free_StringCollection(char **Collection, u32 StringNum)
{
	for(int i = 0; i < StringNum; i++)
		free(Collection[i]);
	free(Collection);
}

void free_RsfSettings(rsf_settings *set)
{
	//Option
	free(set->Option.PageSize);
	for(u32 i = 0; i < set->Option.AppendSystemCallNum; i++){
		free(set->Option.AppendSystemCall[i]);
	}
	free(set->Option.AppendSystemCall);

	//AccessControlInfo
	free(set->AccessControlInfo.ProgramId);
	free(set->AccessControlInfo.IdealProcessor);
	free(set->AccessControlInfo.Priority);
	free(set->AccessControlInfo.MemoryType);
	free(set->AccessControlInfo.SystemMode);
	free(set->AccessControlInfo.CoreVersion);
	free(set->AccessControlInfo.HandleTableSize);
	free(set->AccessControlInfo.SystemSaveDataId1);
	free(set->AccessControlInfo.SystemSaveDataId2);
	free(set->AccessControlInfo.OtherUserSaveDataId1);
	free(set->AccessControlInfo.OtherUserSaveDataId2);
	free(set->AccessControlInfo.OtherUserSaveDataId3);
	free(set->AccessControlInfo.ExtSaveDataId);
	free(set->AccessControlInfo.SystemMode);	
	free(set->AccessControlInfo.AffinityMask);
	free(set->AccessControlInfo.DescVersion);
	free(set->AccessControlInfo.CryptoKey);
	free(set->AccessControlInfo.ResourceLimitCategory);
	free(set->AccessControlInfo.ReleaseKernelMajor);
	free(set->AccessControlInfo.ReleaseKernelMinor);
	free(set->AccessControlInfo.MaxCpu);

	for(u32 i = 0; i < set->AccessControlInfo.MemoryMappingNum; i++){
		free(set->AccessControlInfo.MemoryMapping[i]);
	}
	free(set->AccessControlInfo.MemoryMapping);
	
	for(u32 i = 0; i < set->AccessControlInfo.IORegisterMappingNum; i++){
		free(set->AccessControlInfo.IORegisterMapping[i]);
	}
	free(set->AccessControlInfo.IORegisterMapping);
	
	for(u32 i = 0; i < set->AccessControlInfo.FileSystemAccessNum; i++){
		free(set->AccessControlInfo.FileSystemAccess[i]);
	}
	free(set->AccessControlInfo.FileSystemAccess);
	
	for(u32 i = 0; i < set->AccessControlInfo.IoAccessControlNum; i++){
		free(set->AccessControlInfo.IoAccessControl[i]);
	}
	free(set->AccessControlInfo.IoAccessControl);
	
	for(u32 i = 0; i < set->AccessControlInfo.InterruptNumbersNum; i++){
		free(set->AccessControlInfo.InterruptNumbers[i]);
	}
	free(set->AccessControlInfo.InterruptNumbers);
	
	for(u32 i = 0; i < set->AccessControlInfo.SystemCallAccessNum; i++){
		free(set->AccessControlInfo.SystemCallAccess[i]);
	}
	free(set->AccessControlInfo.SystemCallAccess);
	
	for(u32 i = 0; i < set->AccessControlInfo.ServiceAccessControlNum; i++){
		free(set->AccessControlInfo.ServiceAccessControl[i]);
	}
	free(set->AccessControlInfo.ServiceAccessControl);
	
	for(u32 i = 0; i < set->AccessControlInfo.StorageIdNum; i++){
		free(set->AccessControlInfo.StorageId[i]);
	}
	free(set->AccessControlInfo.StorageId);

	for(u32 i = 0; i < set->AccessControlInfo.AccessibleSaveDataIdsNum; i++){
		free(set->AccessControlInfo.AccessibleSaveDataIds[i]);
	}
	free(set->AccessControlInfo.AccessibleSaveDataIds);
	
	//SystemControlInfo
	free(set->SystemControlInfo.AppType);
	free(set->SystemControlInfo.StackSize);
	free(set->SystemControlInfo.RemasterVersion);
	free(set->SystemControlInfo.JumpId);
	
	for(u32 i = 0; i < set->SystemControlInfo.DependencyNum; i++){
		free(set->SystemControlInfo.Dependency[i]);
	}
	free(set->SystemControlInfo.Dependency);
	
	//BasicInfo
	free(set->BasicInfo.Title);
	free(set->BasicInfo.CompanyCode);
	free(set->BasicInfo.ProductCode);
	free(set->BasicInfo.MediaSize);
	free(set->BasicInfo.ContentType);
	free(set->BasicInfo.Logo);
	free(set->BasicInfo.BackupMemoryType);
	free(set->BasicInfo.InitialCode);
	
	//Rom
	free(set->Rom.HostRoot);
	free(set->Rom.Padding);
	free(set->Rom.SaveDataSize);
	
	for(u32 i = 0; i < set->Rom.DefaultRejectNum; i++){
		free(set->Rom.DefaultReject[i]);
	}
	free(set->Rom.DefaultReject);
	
	for(u32 i = 0; i < set->Rom.RejectNum; i++){
		free(set->Rom.Reject[i]);
	}
	free(set->Rom.Reject);
	
	for(u32 i = 0; i < set->Rom.IncludeNum; i++){
		free(set->Rom.Include[i]);
	}
	free(set->Rom.Include);
	
	for(u32 i = 0; i < set->Rom.FileNum; i++){
		free(set->Rom.File[i]);
	}
	free(set->Rom.File);
	
	//ExeFs
	for(u32 i = 0; i < set->ExeFs.TextNum; i++){
		free(set->ExeFs.Text[i]);
	}
	free(set->ExeFs.Text);
	
	for(u32 i = 0; i < set->ExeFs.ReadOnlyNum; i++){
		free(set->ExeFs.ReadOnly[i]);
	}
	free(set->ExeFs.ReadOnly);
	
	for(u32 i = 0; i < set->ExeFs.ReadWriteNum; i++){
		free(set->ExeFs.ReadWrite[i]);
	}
	free(set->ExeFs.ReadWrite);
	
	//PlainRegion
	for(u32 i = 0; i < set->PlainRegionNum; i++){
		free(set->PlainRegion[i]);
	}
	free(set->PlainRegion);
	
	//TitleInfo
	free(set->TitleInfo.Platform);
	free(set->TitleInfo.Category);
	free(set->TitleInfo.UniqueId);
	free(set->TitleInfo.Version);
	free(set->TitleInfo.ContentsIndex);
	free(set->TitleInfo.Variation);
	free(set->TitleInfo.Use);
	free(set->TitleInfo.ChildIndex);
	free(set->TitleInfo.DemoIndex);
	free(set->TitleInfo.TargetCategory);
	
	for(u32 i = 0; i < set->TitleInfo.CategoryFlagsNum; i++){
		free(set->TitleInfo.CategoryFlags[i]);
	}
	free(set->TitleInfo.CategoryFlags);
	
	//CardInfo
	free(set->CardInfo.WritableAddress);
	free(set->CardInfo.CardType);
	free(set->CardInfo.CryptoType);
	free(set->CardInfo.CardDevice);
	free(set->CardInfo.MediaType);
	free(set->CardInfo.BackupWriteWaitTime);

	//CommonHeaderKey
	free(set->CommonHeaderKey.D);
	free(set->CommonHeaderKey.P);
	free(set->CommonHeaderKey.Q);
	free(set->CommonHeaderKey.DP);
	free(set->CommonHeaderKey.DQ);
	free(set->CommonHeaderKey.InverseQ);
	free(set->CommonHeaderKey.Modulus);
	free(set->CommonHeaderKey.Exponent);
	free(set->CommonHeaderKey.AccCtlDescSign);
	free(set->CommonHeaderKey.AccCtlDescBin);
}

void free_UserSettings(user_settings *usr_settings)
{
	// Free Content Paths
	if(usr_settings->ContentPath){
		for(int i = 0; i < CIA_MAX_CONTENT; i++){
			free(usr_settings->ContentPath[i]);
		}
		free(usr_settings->ContentPath);
	}
	
	// Free Spec File Setting
	free_RsfSettings(&usr_settings->yaml_set);
	
	// Free Key Data
	FreeKeys(&usr_settings->keys);
	
	// Free Content0
	free(usr_settings->Content0.buffer);
		
	// Free outfile path, if malloc'd
	if(usr_settings->outfile_mallocd) free(usr_settings->outfile);
	
	// Clear settings
	init_UserSettings(usr_settings);
	
	// Free
	free(usr_settings);
}

void PrintNeedsArgument(char *arg)
{
	fprintf(stderr,"[SETTING ERROR] Argument '%s' is required\n",arg);
}

void PrintArgumentInvalid(char *arg)
{
	fprintf(stderr,"[SETTING ERROR] Argument '%s' is invalid\n",arg);
}

void PrintNeedsParam(char *arg)
{
	fprintf(stderr,"[SETTING ERROR] '%s' requires a parameter\n",arg);
}

void PrintNoNeedParam(char *arg)
{
	fprintf(stderr,"[SETTING ERROR] '%s' does not take a parameter\n",arg);
}

void DisplayHelp(char *app_name)
{
	printf("CTR MAKEROM %d.%d",MAKEROM_VER_MAJOR,MAKEROM_VER_MINOR);
#ifdef PRIVATE_BUILD
	printf(" PRIVATE BUILD");
#endif
	printf("\n(C) 3DSGuy 2014\n");
	printf("Usage: %s [options... ]\n",app_name);
	printf("Option          Parameter           Explanation\n");
	printf("Global Options:\n");
	printf(" -help                              Display this text\n");
	printf(" -rsf           <rsf path>          RSF File\n");
	printf(" -f             <out format>        Output Format (cxi|cfa|cci|cia)\n");
	printf(" -o             <outfile>           Output File\n");
	//printf(" -DNAME=VALUE                       Substitute values in Spec files\n");
	printf("NCCH Options:\n");
	printf(" -ncch0         <ncch format>       NCCH Format (cxi|cfa)\n");
	printf(" -desc          <desc path>         DESC File\n");
	printf(" -elf           <elf path>          ELF File\n");
	printf(" -icon          <icon path>         Icon File\n");
	printf(" -banner        <banner path>       Banner File\n");
	printf(" -logo          <logo path>         Logo File\n");
	printf(" -exefslogo                         Include Logo in ExeFs\n");
	printf(" -accessdesc    <accessdesc type>   (AutoGen|UseRsf)\n");
#ifdef RETAIL_FSIGN
	printf(" -sysfixedkey   <32 hex chars>      Specify SystemFixed Key\n");	
#endif
#ifdef PRIVATE_BUILD
	printf(" -code          <code path>         Specify ExeFs code File\n");
	printf(" -exheader      <exhdr path>        ExHeader Template File\n");
	printf(" -plain-region  <pln region path>   PlainRegion File\n");
	printf(" -romfs         <romfs path>        RomFS File\n");	
#endif
	printf("CCI Options:\n");
#ifdef PRIVATE_BUILD
	printf(" -devcardcci                        Use SDK CardInfo Method\n");
	printf(" -omitncchhdr                       Omit NCCH Hdr for imported NCCH0\n");
#endif
	printf(" -content <filepath>:<index>        Specify content files\n");
	printf("CIA Options:\n");
#ifdef PRIVATE_BUILD
	printf(" -cci           <cci path>          Convert CCI to CIA\n");
	printf(" -srl           <srl path>          Use TWL SRL as Content0\n");
#endif
	printf(" -content <filepath>:<index>:<id>   Specify content files\n");
	printf(" -major         <version major>     Specify Title Version Major\n");
	printf(" -minor         <version minor>     Specify Title Version Minor\n");
	printf(" -micro         <version micro>     Specify Title Version Micro\n");
	printf(" -rand                              Use a random title key\n");
	printf(" -encryptcia                        Encrypt CIA Contents\n");
#ifdef RETAIL_FSIGN
	printf(" -commonkey    <32 hex chars> <id>  Specify commonkey and index\n");
#endif
}
