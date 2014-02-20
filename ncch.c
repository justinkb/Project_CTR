#include "lib.h"
#include "ncch.h"
#include "exheader.h"
#include "elf.h"
#include "exefs.h"
#include "romfs.h"
#include "titleid.h"
#include "logo_data.h"

// Private Prototypes
int SignCFA(u8 *Signature, u8 *CFA_HDR, keys_struct *keys);
int CheckCFASignature(u8 *Signature, u8 *CFA_HDR, keys_struct *keys);
int SignCXI(u8 *Signature, u8 *CXI_HDR, u8 *PubK, u8 *PrivK);
int CheckCXISignature(u8 *Signature, u8 *CXI_HDR, u8 *PubK);

void init_NCCHSettings(ncch_settings *set);
void free_NCCHSettings(ncch_settings *set);
int get_NCCHSettings(ncch_settings *ncchset, user_settings *usrset);
int SetBasicOptions(ncch_settings *ncchset, user_settings *usrset);
int CreateInputFilePtrs(ncch_settings *ncchset, user_settings *usrset);
int ImportNonCodeExeFsSections(ncch_settings *ncchset);	
int ImportLogo(ncch_settings *ncchset);

int SetCommonHeaderBasicData(ncch_settings *ncchset, NCCH_Header *hdr);
int SetCommonHeaderSectionData(ncch_settings *ncchset, NCCH_Header *hdr);
bool IsValidProductCode(char *ProductCode, bool FreeProductCode);

int BuildCommonHeader(ncch_settings *ncchset);
int EncryptNCCHSections(ncch_settings *ncchset);
int WriteNCCHSectionsToBuffer(ncch_settings *ncchset);

// Code

int SignCFA(u8 *Signature, u8 *CFA_HDR, keys_struct *keys)
{
	return ctr_sig(CFA_HDR,sizeof(NCCH_Header),Signature,keys->rsa.CFA_Pub,keys->rsa.CFA_Priv,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckCFASignature(u8 *Signature, u8 *CFA_HDR, keys_struct *keys)
{
	return ctr_sig(CFA_HDR,sizeof(NCCH_Header),Signature,keys->rsa.CFA_Pub,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
}

int SignCXI(u8 *Signature, u8 *CXI_HDR, u8 *PubK, u8 *PrivK)
{
	return ctr_sig(CXI_HDR,sizeof(NCCH_Header),Signature,PubK,PrivK,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckCXISignature(u8 *Signature, u8 *CXI_HDR, u8 *PubK)
{
	int result = ctr_sig(CXI_HDR,sizeof(NCCH_Header),Signature,PubK,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
	return result;
}

// NCCH Build Functions

int build_NCCH(user_settings *usrset)
{
	int result;

	// Init Settings
	ncch_settings *ncchset = malloc(sizeof(ncch_settings));
	if(!ncchset) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
	init_NCCHSettings(ncchset);

	// Get Settings
	result = get_NCCHSettings(ncchset,usrset);
	if(result) goto finish;

	// Build ExeFs Code Section
	result = BuildExeFsCode(ncchset);
	if(result) goto finish;

#ifdef ELF_DEBUG
	FILE *code = fopen("code.bin","wb");
	fwrite(ncchset->ExeFs_Sections.Code.buffer,ncchset->ExeFs_Sections.Code.size,1,code);
	fclose(code);
	u8 hash[0x20];
	ctr_sha(ncchset->ExeFs_Sections.Code.buffer,ncchset->ExeFs_Sections.Code.size,hash,CTR_SHA_256);
	printf("BSS Size:  0x%x\n",ncchset->CodeDetails.BSS_Size);
	printf("Code Size: 0x%x\n",ncchset->ExeFs_Sections.Code.size);
	memdump(stdout,"Code Hash: ",hash,0x20);
#endif
	
	// Build ExHeader
	result = BuildExHeader(ncchset);
	if(result) goto finish;
	
	
	// Build ExeFs/RomFs
	result = BuildExeFs(ncchset);
	if(result) goto finish;
	result = BuildRomFs(ncchset);
	if(result) goto finish;
	
	// Final Steps
	result = BuildCommonHeader(ncchset);
	if(result) goto finish;
	result = EncryptNCCHSections(ncchset);
	if(result) goto finish;
	result = WriteNCCHSectionsToBuffer(ncchset);
	if(result) goto finish;
finish:
	if(result) fprintf(stderr,"[NCCH ERROR] NCCH Build Process Failed\n");
	free_NCCHSettings(ncchset);
	return result;
}

void init_NCCHSettings(ncch_settings *set)
{
	memset(set,0,sizeof(ncch_settings));
}

void free_NCCHSettings(ncch_settings *set)
{
	if(set->CxiRsaKey.PrivK) free(set->CxiRsaKey.PrivK);
	if(set->CxiRsaKey.PubK) free(set->CxiRsaKey.PubK);

	if(set->ComponentFilePtrs.elf) fclose(set->ComponentFilePtrs.elf);
	if(set->ComponentFilePtrs.banner) fclose(set->ComponentFilePtrs.banner);
	if(set->ComponentFilePtrs.icon) fclose(set->ComponentFilePtrs.icon);
	if(set->ComponentFilePtrs.logo) fclose(set->ComponentFilePtrs.logo);
	if(set->ComponentFilePtrs.code) fclose(set->ComponentFilePtrs.code);
	if(set->ComponentFilePtrs.exheader) fclose(set->ComponentFilePtrs.exheader);
	if(set->ComponentFilePtrs.romfs) fclose(set->ComponentFilePtrs.romfs);
	if(set->ComponentFilePtrs.plainregion) fclose(set->ComponentFilePtrs.plainregion);

	if(set->ExeFs_Sections.Code.size) free(set->ExeFs_Sections.Code.buffer);
	if(set->ExeFs_Sections.Banner.size) free(set->ExeFs_Sections.Banner.buffer);
	if(set->ExeFs_Sections.Icon.size) free(set->ExeFs_Sections.Icon.buffer);

	if(set->Sections.CommonHeader.size) free(set->Sections.CommonHeader.buffer);
	if(set->Sections.ExHeader.size) free(set->Sections.ExHeader.buffer);
	if(set->Sections.Logo.size) free(set->Sections.Logo.buffer);
	if(set->Sections.PlainRegion.size) free(set->Sections.PlainRegion.buffer);
	if(set->Sections.ExeFs.size) free(set->Sections.ExeFs.buffer);
	if(set->Sections.RomFs.size) free(set->Sections.RomFs.buffer);

	memset(set,0,sizeof(ncch_settings));

	free(set);
}

int get_NCCHSettings(ncch_settings *ncchset, user_settings *usrset)
{
	int result = 0;
	ncchset->out = &usrset->Content0;
	ncchset->yaml_set = &usrset->yaml_set;
	ncchset->keys = &usrset->keys;

	result = SetBasicOptions(ncchset,usrset);
	if(result) return result;
	result = CreateInputFilePtrs(ncchset,usrset);
	if(result) return result;
	result = ImportNonCodeExeFsSections(ncchset);
	if(result) return result;
	result = ImportLogo(ncchset);
	if(result) return result;
	

	return 0;
}

int SetBasicOptions(ncch_settings *ncchset, user_settings *usrset)
{
	int result = 0;

	/* Options */
	ncchset->Options.MediaSize = 0x200;

	ncchset->Options.IncludeExeFsLogo = usrset->include_exefs_logo;
	
	if(usrset->yaml_set.Option.EnableCompress != -1) ncchset->Options.CompressCode = usrset->yaml_set.Option.EnableCompress;
	else ncchset->Options.CompressCode = true;

	if(usrset->yaml_set.Option.UseOnSD != -1) ncchset->Options.UseOnSD = usrset->yaml_set.Option.UseOnSD;
	else ncchset->Options.UseOnSD = false;
	usrset->yaml_set.Option.UseOnSD = ncchset->Options.UseOnSD;

	if(usrset->yaml_set.Option.EnableCrypt != -1) ncchset->Options.Encrypt = usrset->yaml_set.Option.EnableCrypt;
	else ncchset->Options.Encrypt = true;

	if(usrset->yaml_set.Option.FreeProductCode != -1) ncchset->Options.FreeProductCode = usrset->yaml_set.Option.FreeProductCode;
	else ncchset->Options.FreeProductCode = false;

	ncchset->Options.IsCfa = (usrset->build_ncch_type == CFA);
	
	ncchset->Options.IsBuildingCodeSection = (usrset->elf_path != NULL);

	ncchset->Options.UseRomFS = ((ncchset->yaml_set->Rom.HostRoot && strlen(ncchset->yaml_set->Rom.HostRoot) > 0) || usrset->romfs_path);
	
	if(ncchset->Options.IsCfa && !ncchset->Options.UseRomFS){
		fprintf(stderr,"[NCCH ERROR] 'Rom/HostRoot' must be set\n");
		return NCCH_BAD_YAML_SET;
	}

	ncchset->Options.accessdesc = usrset->accessdesc;

	ncchset->CxiRsaKey.PrivK = malloc(0x100);
	ncchset->CxiRsaKey.PubK = malloc(0x100);

	return result;
}

int CreateInputFilePtrs(ncch_settings *ncchset, user_settings *usrset)
{
	if(usrset->elf_path){
		ncchset->ComponentFilePtrs.elf_size = GetFileSize_u64(usrset->elf_path);
		ncchset->ComponentFilePtrs.elf = fopen(usrset->elf_path,"rb");
		if(!ncchset->ComponentFilePtrs.elf){
			fprintf(stderr,"[NCCH ERROR] Failed to open elf file '%s'\n",usrset->elf_path);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->banner_path){
		ncchset->ComponentFilePtrs.banner_size = GetFileSize_u64(usrset->banner_path);
		ncchset->ComponentFilePtrs.banner = fopen(usrset->banner_path,"rb");
		if(!ncchset->ComponentFilePtrs.banner){
			fprintf(stderr,"[NCCH ERROR] Failed to open banner file '%s'\n",usrset->banner_path);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->icon_path){
		ncchset->ComponentFilePtrs.icon_size = GetFileSize_u64(usrset->icon_path);
		ncchset->ComponentFilePtrs.icon = fopen(usrset->icon_path,"rb");
		if(!ncchset->ComponentFilePtrs.icon){
			fprintf(stderr,"[NCCH ERROR] Failed to open icon file '%s'\n",usrset->icon_path);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->logo_path){
		ncchset->ComponentFilePtrs.logo_size = GetFileSize_u64(usrset->logo_path);
		ncchset->ComponentFilePtrs.logo = fopen(usrset->logo_path,"rb");
		if(!ncchset->ComponentFilePtrs.logo){
			fprintf(stderr,"[NCCH ERROR] Failed to open logo file '%s'\n",usrset->logo_path);
			return FAILED_TO_IMPORT_FILE;
		}
	}

	if(usrset->exefs_code_path){
		ncchset->ComponentFilePtrs.code_size = GetFileSize_u64(usrset->exefs_code_path);
		ncchset->ComponentFilePtrs.code = fopen(usrset->exefs_code_path,"rb");
		if(!ncchset->ComponentFilePtrs.code){
			fprintf(stderr,"[NCCH ERROR] Failed to open ExeFs Code file '%s'\n",usrset->exefs_code_path);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->exheader_path){
		ncchset->ComponentFilePtrs.exheader_size = GetFileSize_u64(usrset->exheader_path);
		ncchset->ComponentFilePtrs.exheader = fopen(usrset->exheader_path,"rb");
		if(!ncchset->ComponentFilePtrs.exheader){
			fprintf(stderr,"[NCCH ERROR] Failed to open ExHeader file '%s'\n",usrset->exheader_path);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->romfs_path){
		ncchset->ComponentFilePtrs.romfs_size = GetFileSize_u64(usrset->romfs_path);
		ncchset->ComponentFilePtrs.romfs = fopen(usrset->romfs_path,"rb");
		if(!ncchset->ComponentFilePtrs.romfs){
			fprintf(stderr,"[NCCH ERROR] Failed to open RomFs file '%s'\n",usrset->romfs_path);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->plain_region_path){
		ncchset->ComponentFilePtrs.plainregion_size = GetFileSize_u64(usrset->plain_region_path);
		ncchset->ComponentFilePtrs.plainregion = fopen(usrset->plain_region_path,"rb");
		if(!ncchset->ComponentFilePtrs.plainregion){
			fprintf(stderr,"[NCCH ERROR] Failed to open PlainRegion file '%s'\n",usrset->plain_region_path);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	return 0;
}

int ImportNonCodeExeFsSections(ncch_settings *ncchset)
{
	if(ncchset->ComponentFilePtrs.banner){
		ncchset->ExeFs_Sections.Banner.size = ncchset->ComponentFilePtrs.banner_size;
		ncchset->ExeFs_Sections.Banner.buffer = malloc(ncchset->ExeFs_Sections.Banner.size);
		if(!ncchset->ExeFs_Sections.Banner.buffer) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
		ReadFile_64(ncchset->ExeFs_Sections.Banner.buffer,ncchset->ExeFs_Sections.Banner.size,0,ncchset->ComponentFilePtrs.banner);
	}
	if(ncchset->ComponentFilePtrs.icon){
		ncchset->ExeFs_Sections.Icon.size = ncchset->ComponentFilePtrs.icon_size;
		ncchset->ExeFs_Sections.Icon.buffer = malloc(ncchset->ExeFs_Sections.Icon.size);
		if(!ncchset->ExeFs_Sections.Icon.buffer) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
		ReadFile_64(ncchset->ExeFs_Sections.Icon.buffer,ncchset->ExeFs_Sections.Icon.size,0,ncchset->ComponentFilePtrs.icon);
	}
	return 0;
}

int ImportLogo(ncch_settings *ncchset)
{
	if(ncchset->ComponentFilePtrs.logo){
		ncchset->Sections.Logo.size = ncchset->ComponentFilePtrs.logo_size;
		ncchset->Sections.Logo.buffer = malloc(ncchset->Sections.Logo.size);
		if(!ncchset->Sections.Logo.buffer) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
		ReadFile_64(ncchset->Sections.Logo.buffer,ncchset->Sections.Logo.size,0,ncchset->ComponentFilePtrs.logo);
	}
	else if(ncchset->yaml_set->BasicInfo.Logo){
		if(strcasecmp(ncchset->yaml_set->BasicInfo.Logo,"nintendo") == 0){
			ncchset->Sections.Logo.size = 0x2000;
			ncchset->Sections.Logo.buffer = malloc(ncchset->Sections.Logo.size);
			if(!ncchset->Sections.Logo.buffer) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
			memcpy(ncchset->Sections.Logo.buffer,Nintendo_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->yaml_set->BasicInfo.Logo,"licensed") == 0){
			ncchset->Sections.Logo.size = 0x2000;
			ncchset->Sections.Logo.buffer = malloc(ncchset->Sections.Logo.size);
			if(!ncchset->Sections.Logo.buffer) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
			memcpy(ncchset->Sections.Logo.buffer,Nintendo_LicensedBy_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->yaml_set->BasicInfo.Logo,"distributed") == 0){
			ncchset->Sections.Logo.size = 0x2000;
			ncchset->Sections.Logo.buffer = malloc(ncchset->Sections.Logo.size);
			if(!ncchset->Sections.Logo.buffer) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
			memcpy(ncchset->Sections.Logo.buffer,Nintendo_DistributedBy_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->yaml_set->BasicInfo.Logo,"ique") == 0){
			ncchset->Sections.Logo.size = 0x2000;
			ncchset->Sections.Logo.buffer = malloc(ncchset->Sections.Logo.size);
			if(!ncchset->Sections.Logo.buffer) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
			memcpy(ncchset->Sections.Logo.buffer,iQue_with_ISBN_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->yaml_set->BasicInfo.Logo,"iqueforsystem") == 0){
			ncchset->Sections.Logo.size = 0x2000;
			ncchset->Sections.Logo.buffer = malloc(ncchset->Sections.Logo.size);
			if(!ncchset->Sections.Logo.buffer) {fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
			memcpy(ncchset->Sections.Logo.buffer,iQue_without_ISBN_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->yaml_set->BasicInfo.Logo,"none") != 0){
			fprintf(stderr,"[NCCH ERROR] Invalid logo name\n");
			return NCCH_BAD_YAML_SET;
		}
	}
	return 0;
}

int SetCommonHeaderBasicData(ncch_settings *ncchset, NCCH_Header *hdr)
{
	/* NCCH Format Version */
	u16_to_u8(hdr->version,0x2,LE);
	
	/* Setting ProgramId/TitleId */
	u64 ProgramId = 0;
	int result = GetProgramID(&ProgramId,ncchset->yaml_set,false); 
	if(result) return result;

	u64_to_u8(hdr->program_id,ProgramId,LE);
	u64_to_u8(hdr->title_id,ProgramId,LE);

	/* Get Product Code and Maker Code */
	if(ncchset->yaml_set->BasicInfo.ProductCode){
		if(!IsValidProductCode((char*)ncchset->yaml_set->BasicInfo.ProductCode,ncchset->Options.FreeProductCode)){
			fprintf(stderr,"[NCCH ERROR] Invalid Product Code\n");
			return NCCH_BAD_YAML_SET;
		}
		memcpy(hdr->product_code,ncchset->yaml_set->BasicInfo.ProductCode,strlen((char*)ncchset->yaml_set->BasicInfo.ProductCode));
	}
	else memcpy(hdr->product_code,"CTR-P-CTAP",10);

	if(ncchset->yaml_set->BasicInfo.CompanyCode){
		if(strlen((char*)ncchset->yaml_set->BasicInfo.CompanyCode) != 2){
			fprintf(stderr,"[NCCH ERROR] Company code length must be 2\n");
			return NCCH_BAD_YAML_SET;
		}
		memcpy(hdr->maker_code,ncchset->yaml_set->BasicInfo.CompanyCode,2);
	}
	else memcpy(hdr->maker_code,"00",2);

	/* Set ContentUnitSize */
	hdr->flags[ContentUnitSize] = 0;

	/* Setting ContentPlatform */
	if(ncchset->yaml_set->TitleInfo.Platform){
		if(strcasecmp(ncchset->yaml_set->TitleInfo.Platform,"ctr") == 0) hdr->flags[ContentPlatform] = 1;
		else{
			fprintf(stderr,"[NCCH ERROR] Invalid Platform: %s\n",ncchset->yaml_set->TitleInfo.Platform);
			return NCCH_BAD_YAML_SET;
		}
	}
	else
		hdr->flags[ContentPlatform] = 1; // CTR

	/* Setting OtherFlag */
	hdr->flags[OtherFlag] = FixedCryptoKey;
	if(!ncchset->Options.Encrypt) hdr->flags[OtherFlag] |= NoCrypto;
	if(!ncchset->Sections.RomFs.size) hdr->flags[OtherFlag] |= NoMountRomFs;


	/* Setting ContentType */
	hdr->flags[ContentType] = 0;
	if(ncchset->Sections.RomFs.size) hdr->flags[ContentType] |= RomFS;
	if(ncchset->Sections.ExeFs.size) hdr->flags[ContentType] |= ExeFS;
	if(ncchset->yaml_set->BasicInfo.ContentType){
		if(strcmp(ncchset->yaml_set->BasicInfo.ContentType,"Application") == 0) hdr->flags[ContentType] |= 0;
		else if(strcmp(ncchset->yaml_set->BasicInfo.ContentType,"SystemUpdate") == 0) hdr->flags[ContentType] |= SystemUpdate;
		else if(strcmp(ncchset->yaml_set->BasicInfo.ContentType,"Manual") == 0) hdr->flags[ContentType] |= Manual;
		else if(strcmp(ncchset->yaml_set->BasicInfo.ContentType,"Child") == 0) hdr->flags[ContentType] |= Child;
		else if(strcmp(ncchset->yaml_set->BasicInfo.ContentType,"Trial") == 0) hdr->flags[ContentType] |= Trial;
		else{
			fprintf(stderr,"[NCCH ERROR] Invalid ContentType '%s'\n",ncchset->yaml_set->BasicInfo.ContentType);
			return NCCH_BAD_YAML_SET;
		}
	}

	return 0;
}

int SetCommonHeaderSectionData(ncch_settings *ncchset, NCCH_Header *hdr)
{
	/* Set Sizes/Hashes to Hdr */
	u32 ExHeaderSize = (u32) ncchset->Sections.ExHeader.size - 0x400;
	u32 LogoSize = (u32) (ncchset->Sections.Logo.size/ncchset->Options.MediaSize);
	u32 PlainRegionSize = (u32) (ncchset->Sections.PlainRegion.size/ncchset->Options.MediaSize);
	u32 ExeFsSize = (u32) (ncchset->Sections.ExeFs.size/ncchset->Options.MediaSize);
	u32 ExeFsHashSize = (u32) ExeFsSize? ncchset->Options.MediaSize/ncchset->Options.MediaSize : 0;
	u32 RomFsSize = (u32) (ncchset->Sections.RomFs.size/ncchset->Options.MediaSize);
	u32 RomFsHashSize = (u32) RomFsSize? ncchset->Options.MediaSize/ncchset->Options.MediaSize : 0;

	u32_to_u8(hdr->extended_header_size,ExHeaderSize,LE);
	if(ExHeaderSize) ctr_sha(ncchset->Sections.ExHeader.buffer,ExHeaderSize,hdr->extended_header_sha_256_hash,CTR_SHA_256);

	u32_to_u8(hdr->logo_region_size,LogoSize,LE);
	if(LogoSize) ctr_sha(ncchset->Sections.Logo.buffer,ncchset->Sections.Logo.size,hdr->logo_sha_256_hash,CTR_SHA_256);

	u32_to_u8(hdr->plain_region_size,PlainRegionSize,LE);

	u32_to_u8(hdr->exefs_size,ExeFsSize,LE);
	u32_to_u8(hdr->exefs_hash_size,ExeFsHashSize,LE);
	if(ExeFsSize) ctr_sha(ncchset->Sections.ExeFs.buffer,ncchset->Options.MediaSize,hdr->exefs_sha_256_hash,CTR_SHA_256);

	u32_to_u8(hdr->romfs_size,RomFsSize,LE);
	u32_to_u8(hdr->romfs_hash_size,RomFsHashSize,LE);
	if(RomFsSize) ctr_sha(ncchset->Sections.RomFs.buffer,ncchset->Options.MediaSize,hdr->romfs_sha_256_hash,CTR_SHA_256);


	/* Get Section Offsets */
	u32 size = 1;
	if (ExHeaderSize)
		size += 4;

	if (LogoSize){
		u32_to_u8(hdr->logo_region_offset,size,LE);
		ncchset->Sections.LogoOffset = size*ncchset->Options.MediaSize;
		size += LogoSize;
	}

	if(PlainRegionSize){
		u32_to_u8(hdr->plain_region_offset,size,LE);
		ncchset->Sections.PlainRegionOffset = size*ncchset->Options.MediaSize;
		size += PlainRegionSize;
	}

	if (ExeFsSize){
		u32_to_u8(hdr->exefs_offset,size,LE);
		ncchset->Sections.ExeFsOffset = size*ncchset->Options.MediaSize;
		size += ExeFsSize;
	}

	if (RomFsSize){
		u32_to_u8(hdr->romfs_offset,size,LE);
		ncchset->Sections.RomFsOffset = size*ncchset->Options.MediaSize;
		size += RomFsSize;
	}

	u32_to_u8(hdr->content_size,size,LE);

	ncchset->Sections.TotalContentSize = size * ncchset->Options.MediaSize;

	return 0;
}

bool IsValidProductCode(char *ProductCode, bool FreeProductCode)
{
	if(strlen(ProductCode) > 16) return false;

	if(FreeProductCode)
		return true;

	if(strlen(ProductCode) < 10) return false;
	if(strncmp(ProductCode,"CTR-",4) != 0) return false;
	if(ProductCode[5] != '-') return false;
	if(!isdigit(ProductCode[4]) && !isupper(ProductCode[4])) return false;
	for(int i = 6; i < 10; i++){
		if(!isdigit(ProductCode[i]) && !isupper(ProductCode[i])) return false;
	}

	return true;
}

int BuildCommonHeader(ncch_settings *ncchset)
{
	int result = 0;

	// Initialising Header
	ncchset->Sections.CommonHeader.size = 0x100 + sizeof(NCCH_Header);
	ncchset->Sections.CommonHeader.buffer = malloc(ncchset->Sections.CommonHeader.size);
	if(!ncchset->Sections.CommonHeader.buffer) { fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR; }
	memset(ncchset->Sections.CommonHeader.buffer,0,ncchset->Sections.CommonHeader.size);

	// Creating Ptrs
	u8 *sig = ncchset->Sections.CommonHeader.buffer;
	NCCH_Header *hdr = (NCCH_Header*)(ncchset->Sections.CommonHeader.buffer+0x100);

	// Setting Data in Hdr
	memcpy(hdr->magic,"NCCH",4);
	
	result = SetCommonHeaderBasicData(ncchset,hdr);
	if(result) return result;

	result = SetCommonHeaderSectionData(ncchset,hdr);
	if(result) return result;


	// Signing Hdr
	int sig_result = Good;
	if(ncchset->Options.IsCfa) sig_result = SignCFA(sig,(u8*)hdr,ncchset->keys);
	else sig_result = SignCXI(sig,(u8*)hdr,ncchset->CxiRsaKey.PubK,ncchset->CxiRsaKey.PrivK);
	if(sig_result != Good){
		fprintf(stderr,"[NCCH ERROR] Failed to sign %s header\n",ncchset->Options.IsCfa ? "CFA" : "CXI");
		return sig_result;
	}

	return 0;
}

int EncryptNCCHSections(ncch_settings *ncchset)
{
	if(!ncchset->Options.Encrypt) return 0;

	/* Getting NCCH_STRUCT */
	NCCH_Header *hdr = GetNCCH_CommonHDR(NULL,NULL,ncchset->Sections.CommonHeader.buffer);
	NCCH_STRUCT *ncch = malloc(sizeof(NCCH_STRUCT));
	if(!ncch) { fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
	memset(ncch,0,sizeof(NCCH_STRUCT));
	GetCXIStruct(ncch,hdr);

	u8 *ncch_key = GetNCCHKey(hdr,ncchset->keys);

	if(ncchset->Sections.ExHeader.size)
		CryptNCCHSection(ncchset->Sections.ExHeader.buffer,ncchset->Sections.ExHeader.size,0,ncch,ncch_key,ncch_ExHeader);

	if(ncchset->Sections.ExeFs.size)
		CryptNCCHSection(ncchset->Sections.ExeFs.buffer,ncchset->Sections.ExeFs.size,0,ncch,ncch_key,ncch_exefs);

	if(ncchset->Sections.RomFs.size)
		CryptNCCHSection(ncchset->Sections.RomFs.buffer,ncchset->Sections.RomFs.size,0,ncch,ncch_key,ncch_romfs);

	return 0;
}

int WriteNCCHSectionsToBuffer(ncch_settings *ncchset)
{
	/* Allocating Memory for NCCH, and clearing */
	ncchset->out->size = ncchset->Sections.TotalContentSize;
	ncchset->out->buffer = malloc(ncchset->out->size);
	if(!ncchset->out->buffer) { fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR;}
	memset(ncchset->out->buffer,0,ncchset->out->size);

	/* Copy Header+Sig */
	memcpy(ncchset->out->buffer,ncchset->Sections.CommonHeader.buffer,ncchset->Sections.CommonHeader.size);
	
	/* Copy Exheader+AccessDesc */
	if(ncchset->Sections.ExHeader.size)
		memcpy(ncchset->out->buffer+0x200,ncchset->Sections.ExHeader.buffer,ncchset->Sections.ExHeader.size);

	/* Copy Logo */
	if(ncchset->Sections.Logo.size)
		memcpy(ncchset->out->buffer+ncchset->Sections.LogoOffset,ncchset->Sections.Logo.buffer,ncchset->Sections.Logo.size);

	/* Copy PlainRegion */
	if(ncchset->Sections.PlainRegion.size)
		memcpy(ncchset->out->buffer+ncchset->Sections.PlainRegionOffset,ncchset->Sections.PlainRegion.buffer,ncchset->Sections.PlainRegion.size);

	/* Copy ExeFs */
	if(ncchset->Sections.ExeFs.size)
		memcpy(ncchset->out->buffer+ncchset->Sections.ExeFsOffset,ncchset->Sections.ExeFs.buffer,ncchset->Sections.ExeFs.size);

	/* Copy RomFs */
	if(ncchset->Sections.RomFs.size)
		memcpy(ncchset->out->buffer+ncchset->Sections.RomFsOffset,ncchset->Sections.RomFs.buffer,ncchset->Sections.RomFs.size);

	return 0;
}

// NCCH Read Functions

int VerifyNCCH(u8 *ncch, keys_struct *keys, bool SuppressOutput)
{
	// Setup
	u8 Hash[0x20];
	u8 *hdr_sig = ncch;
	NCCH_Header* hdr = GetNCCH_CommonHDR(NULL,NULL,ncch);

	NCCH_STRUCT *ncch_ctx = malloc(sizeof(NCCH_STRUCT));
	if(!ncch_ctx){ fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); return MEM_ERROR; }
	memset(ncch_ctx,0x0,sizeof(NCCH_STRUCT));
	GetCXIStruct(ncch_ctx,hdr);

	if(IsCfa(hdr)){
		if(CheckCFASignature(hdr_sig,(u8*)hdr,keys) != Good){
#ifdef RETAIL_FSIGN
			if(!SuppressOutput) fprintf(stderr,"[NCCH WARNING] CFA Sigcheck Failed\n");
#else
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] CFA Sigcheck Failed\n");
			free(ncch_ctx);
			return NCCH_HDR_SIG_BAD;
#endif
		}
		if(!ncch_ctx->romfs_size){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] CFA is corrupt\n");
			free(ncch_ctx);
			return NO_ROMFS_IN_CFA;
		}
		u8 *RomFs = malloc(ncch_ctx->romfs_hash_src_size);
		if(!RomFs){ 
			fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); 
			free(ncch_ctx);
			return MEM_ERROR; 
		}
		int ret = GetNCCHSection(RomFs,ncch_ctx->romfs_hash_src_size,0,ncch,ncch_ctx,keys,ncch_romfs);
		if(ret != 0 && ret != UNABLE_TO_LOAD_NCCH_KEY){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] CFA is corrupt\n");
			free(ncch_ctx);
			free(RomFs);
			return CXI_CORRUPT;
		}
		else if(ret == UNABLE_TO_LOAD_NCCH_KEY){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key.\n");
			free(ncch_ctx);
			free(RomFs);
			return UNABLE_TO_LOAD_NCCH_KEY;
		}

		ctr_sha(RomFs,ncch_ctx->romfs_hash_src_size,Hash,CTR_SHA_256);
		free(RomFs);
		if(memcmp(Hash,hdr->romfs_sha_256_hash,0x20) != 0){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] RomFs Hashcheck Failed\n");
			free(ncch_ctx);
			return ExeFs_Hashfail;
		}
	}
	else{ // IsCxi
		// Checking for necessary sections
		if(!ncch_ctx->exheader_size){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			free(ncch_ctx);
			return NO_EXHEADER_IN_CXI;
		}
		if(!ncch_ctx->exefs_size){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			free(ncch_ctx);
			return NO_EXEFS_IN_CXI;
		}
		// Get ExHeader
		ExtendedHeader_Struct *ExHeader = malloc(ncch_ctx->exheader_size);
		if(!ExHeader){ 
			fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); 
			free(ncch_ctx);
			return MEM_ERROR; 
		}
		int ret = GetNCCHSection((u8*)ExHeader,ncch_ctx->exheader_size,0,ncch,ncch_ctx,keys,ncch_ExHeader);
		if(ret != 0 && ret != UNABLE_TO_LOAD_NCCH_KEY){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			free(ncch_ctx);
			free(ExHeader);
			return CXI_CORRUPT;
		}
		else if(ret == UNABLE_TO_LOAD_NCCH_KEY){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key.\n");
			free(ncch_ctx);
			free(ExHeader);
			return UNABLE_TO_LOAD_NCCH_KEY;
		}

		// Checking Exheader Hash to see if decryption was sucessful
		ctr_sha(ExHeader,0x400,Hash,CTR_SHA_256);
		if(memcmp(Hash,hdr->extended_header_sha_256_hash,0x20) != 0){
			//memdump(stdout,"Expected Hash: ",hdr->extended_header_sha_256_hash,0x20);
			//memdump(stdout,"Actual Hash:   ",Hash,0x20);
			//memdump(stdout,"Exheader:      ",(u8*)ExHeader,0x400);
			if(!SuppressOutput) {
				fprintf(stderr,"[NCCH ERROR] ExHeader Hashcheck Failed\n");
				fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			}
			free(ncch_ctx);
			free(ExHeader);
			return ExHeader_Hashfail;
		}

		// Checking RSA Sigs
		u8 *hdr_pubk = GetNcchHdrPubKey_frm_exhdr(ExHeader);

		if(CheckAccessDescSignature(ExHeader,keys) != 0){
#ifdef RETAIL_FSIGN
			if(!SuppressOutput) fprintf(stderr,"[NCCH WARNING] AccessDesc Sigcheck Failed\n");
#else
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] AccessDesc Sigcheck Failed\n");
			free(ncch_ctx);
			free(ExHeader);
			return ACCESSDESC_SIG_BAD;
#endif
		}
		if(CheckCXISignature(hdr_sig,(u8*)hdr,hdr_pubk) != 0){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] CXI Header Sigcheck Failed\n");
			free(ncch_ctx);
			free(ExHeader);
			return NCCH_HDR_SIG_BAD;
		}
		free(ExHeader);

		// It is assumed by this point, everything is fine
		
		/* Checking ExeFs Hash */
		u8 *ExeFs = malloc(ncch_ctx->exefs_hash_src_size);
		if(!ExeFs){ 
			fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); 
			free(ncch_ctx);
			return MEM_ERROR; 
		}
		GetNCCHSection(ExeFs,ncch_ctx->exefs_hash_src_size,0,ncch,ncch_ctx,keys,ncch_exefs);
		ctr_sha(ExeFs,ncch_ctx->exefs_hash_src_size,Hash,CTR_SHA_256);
		free(ExeFs);
		if(memcmp(Hash,hdr->exefs_sha_256_hash,0x20) != 0){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] ExeFs Hashcheck Failed\n");
			free(ncch_ctx);
			return ExeFs_Hashfail;
		}

		/* Checking RomFs hash, if present */
		if(ncch_ctx->romfs_size){
			u8 *RomFs = malloc(ncch_ctx->romfs_hash_src_size);
			if(!RomFs){ 
				fprintf(stderr,"[NCCH ERROR] MEM ERROR\n"); 
				free(ncch_ctx);
				return MEM_ERROR; 
			}
			GetNCCHSection(RomFs,ncch_ctx->romfs_hash_src_size,0,ncch,ncch_ctx,keys,ncch_romfs);
			ctr_sha(RomFs,ncch_ctx->romfs_hash_src_size,Hash,CTR_SHA_256);
			free(RomFs);
			if(memcmp(Hash,hdr->romfs_sha_256_hash,0x20) != 0){
				if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] RomFs Hashcheck Failed\n");
				free(ncch_ctx);
				return ExeFs_Hashfail;
			}
		}

		/* Checking the Logo Hash, if present */
		if(ncch_ctx->logo_size){
			u8 *logo = (ncch+ncch_ctx->logo_offset);
			ctr_sha(logo,ncch_ctx->logo_size,Hash,CTR_SHA_256);
			if(memcmp(Hash,hdr->logo_sha_256_hash,0x20) != 0){
				if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] Logo Hashcheck Failed\n");
				free(ncch_ctx);
				return Logo_Hashfail;
			}
		} 
	}
	
	free(ncch_ctx);
	return 0;
}


u8* RetargetNCCH(FILE *fp, u64 size, u8 *TitleId, u8 *ProgramId, keys_struct *keys)
{
	u8 *ncch = malloc(size);
	if(!ncch){
		fprintf(stderr,"[NCCH ERROR] MEM ERROR\n");
		return NULL;
	}
	ReadFile_64(ncch,size,0,fp); // Importing
	
	if(!IsNCCH(NULL,ncch)){
		free(ncch);
		return NULL;
	}
		
	NCCH_Header *hdr = NULL;
	hdr = GetNCCH_CommonHDR(NULL,NULL,ncch);
	
	if(!IsCfa(hdr)){
		fprintf(stderr,"[NCCH ERROR] CXI's ID cannot be modified\n"); // Not yet yet, requires AccessDesc Privk, may implement anyway later
		free(ncch);
		return NULL;
	}
	
	if((memcmp(TitleId,hdr->title_id,8) == 0) && (memcmp(ProgramId,hdr->program_id,8) == 0)) 
		return ncch;// if no modification is required don't do anything

	if(memcmp(TitleId,hdr->title_id,8) == 0){ // If TitleID Same, no crypto required, just resign.
		memcpy(hdr->program_id,ProgramId,8);
		SignCFA(ncch,(u8*)hdr,keys);
		return ncch;
	}

	ncch_key_type keytype = GetNCCHKeyType(hdr);
	u8 *key = NULL;
	
	if(keytype == KeyIsUnFixed || keytype == KeyIsUnFixed2){
		fprintf(stderr,"[NCCH ERROR] Unknown aes key\n");
		free(ncch);
		return NULL;
	}
	
	
	NCCH_STRUCT ncch_struct;
	if(keytype != NoKey){ //Decrypting if necessary
		GetCXIStruct(&ncch_struct,hdr);
		u8 *romfs = (ncch+ncch_struct.romfs_offset);
		key = GetNCCHKey(hdr,keys);
		if(key == NULL){
			fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key\n");
			free(ncch);
			return NULL;
		}
		CryptNCCHSection(romfs,ncch_struct.romfs_size,0,&ncch_struct,key,ncch_romfs);
	}
	
	
	memcpy(hdr->title_id,TitleId,8);
	memcpy(hdr->program_id,ProgramId,8);
	
	//Checking New Fixed Key Type
	keytype = GetNCCHKeyType(hdr);
	
	if(keytype != NoKey){ // Re-encrypting if necessary
		GetCXIStruct(&ncch_struct,hdr);
		u8 *romfs = (ncch+ncch_struct.romfs_offset);
		key = GetNCCHKey(hdr,keys);
		if(key == NULL){
			fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key\n");
			free(ncch);
			return NULL;
		}
		CryptNCCHSection(romfs,ncch_struct.romfs_size,0,&ncch_struct,key,ncch_romfs);
	}
	
	SignCFA(ncch,(u8*)hdr,keys);
	
	return ncch;
}


NCCH_Header* GetNCCH_CommonHDR(void *out, FILE *fp, u8 *buf)
{
	if(!fp && !buf) return NULL;
	if(fp){
		if(!out) return NULL;
		ReadFile_64(out,0x100,0x100,fp);
		return (NCCH_Header*)out;
	}
	else{
		return (NCCH_Header*)(buf+0x100);
	}
}


bool IsNCCH(FILE *fp, u8 *buf)
{
	if(!fp && !buf) return false;
	NCCH_Header *ncchHDR = NULL;
	bool result;
	if(fp) {
		ncchHDR = malloc(sizeof(NCCH_Header));
		GetNCCH_CommonHDR(ncchHDR,fp,NULL);
		result = (memcmp(ncchHDR->magic,"NCCH",4) == 0);
		free(ncchHDR);
	}
	else {
		ncchHDR = GetNCCH_CommonHDR(ncchHDR,NULL,buf);
		result = (memcmp(ncchHDR->magic,"NCCH",4) == 0);
	}
	return result;
}

bool IsCfa(NCCH_Header* hdr)
{
	return (((hdr->flags[ContentType] & RomFS) == RomFS) && ((hdr->flags[ContentType] & ExeFS) != ExeFS));
}

u32 GetNCCH_MediaUnitSize(NCCH_Header* hdr)
{
	u16 version = u8_to_u16(hdr->version,LE);
	u32 ret = 0;
	if (version == 1)
		ret = 1;
	else if (version == 2 || version == 0)
		ret = 1 << (hdr->flags[ContentUnitSize] + 9);
	return ret;
	//return 0x200*pow(2,hdr->flags[ContentUnitSize]);
}

u32 GetNCCH_MediaSize(NCCH_Header* hdr)
{
	return u8_to_u32(hdr->content_size,LE);
}

ncch_key_type GetNCCHKeyType(NCCH_Header* hdr)
{	
	// Non-Secure Key Options
	if((hdr->flags[OtherFlag] & NoCrypto) == NoCrypto) return NoKey;
	if((hdr->flags[OtherFlag] & FixedCryptoKey) == FixedCryptoKey){
		if((hdr->program_id[4] & 0x10) == 0x10) return KeyIsSystemFixed;
		else return KeyIsNormalFixed;
	}

	// Secure Key Options
	if(hdr->flags[SecureCrypto2] == 1) return KeyIsUnFixed2;
	return KeyIsUnFixed;
}

u8* GetNCCHKey(NCCH_Header* hdr, keys_struct *keys)
{
	ncch_key_type keytype = GetNCCHKeyType(hdr);
	switch(keytype){
		case NoKey: return NULL;
		case KeyIsNormalFixed: return keys->aes.NormalKey;
		case KeyIsSystemFixed:
			if(!keys->aes.SystemFixedKey) fprintf(stderr,"[NCCH WARNING] Unable to load SystemFixed Key\n");
			return keys->aes.SystemFixedKey;
		case KeyIsUnFixed:
			if(!keys->aes.UnFixedKey) fprintf(stderr,"[NCCH WARNING] Unable to load UnFixed Key\n");
			return keys->aes.UnFixedKey;
		case KeyIsUnFixed2:
			fprintf(stderr,"[NCCH WARNING] Crypto method (Secure2) not supported yet\n");
			return NULL;
	}
	return NULL;
}

int GetNCCHSection(u8 *dest, u64 dest_max_size, u64 src_pos, u8 *ncch, NCCH_STRUCT *ncch_ctx, keys_struct *keys, ncch_section section)
{
	if(!ncch) return MEM_ERROR;
	u8 *key = NULL;
	NCCH_Header* hdr = GetNCCH_CommonHDR(NULL,NULL,ncch);
	ncch_key_type keytype = GetNCCHKeyType(hdr);

	if(keytype != NoKey && (section == ncch_ExHeader || section == ncch_exefs || section == ncch_romfs)){
		key = GetNCCHKey(hdr,keys);
		if(key == NULL){
			//fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key.\n");
			return UNABLE_TO_LOAD_NCCH_KEY;
		}
	}
	//printf("detecting section type\n");
	u64 offset = 0;
	u64 size = 0;
	switch(section){
		case ncch_ExHeader:
			offset = ncch_ctx->exheader_offset;
			size = ncch_ctx->exheader_size;
			break;
		case ncch_Logo:
			offset = ncch_ctx->logo_offset;
			size = ncch_ctx->logo_size;
			break;
		case ncch_PlainRegion:
			offset = ncch_ctx->plain_region_offset;
			size = ncch_ctx->plain_region_size;
			break;
		case ncch_exefs:
			offset = ncch_ctx->exefs_offset;
			size = ncch_ctx->exefs_size;
			break;
		case ncch_romfs:
			offset = ncch_ctx->romfs_offset;
			size = ncch_ctx->romfs_size;
			break;
	}
	if(!offset || !size) return NCCH_SECTION_NOT_EXIST; 

	if(src_pos > size) return DATA_POS_DNE;

	size = min_u64(size-src_pos,dest_max_size);

	//printf("Copying data\n");
	u8 *section_pos = (ncch + offset + src_pos);
	memcpy(dest,section_pos,size);

	//printf("decrypting if needed\n");
	if(keytype != NoKey && (section == ncch_ExHeader || section == ncch_exefs || section == ncch_romfs)){ // Decrypt
		//memdump(stdout,"Key: ",key,16);
		CryptNCCHSection(dest,size,src_pos,ncch_ctx,key,section);
		//printf("no cigar\n");
	}

	return 0;
}

int GetCXIStruct(NCCH_STRUCT *ctx, NCCH_Header *header)
{
	memcpy(ctx->titleID,header->title_id,8);
	memcpy(ctx->programID,header->program_id,8);

	
	u32 media_unit = GetNCCH_MediaUnitSize(header);
	
	ctx->version = u8_to_u16(header->version,LE);
	if(!IsCfa(header)){
		ctx->exheader_offset = 0x200;
		ctx->exheader_size = u8_to_u32(header->extended_header_size,LE) + 0x400;
		ctx->logo_offset = (u64)(u8_to_u32(header->logo_region_offset,LE)*media_unit);
		ctx->logo_size = (u64)(u8_to_u32(header->logo_region_size,LE)*media_unit);
		ctx->plain_region_offset = (u64)(u8_to_u32(header->plain_region_offset,LE)*media_unit);
		ctx->plain_region_size = (u64)(u8_to_u32(header->plain_region_size,LE)*media_unit);
		ctx->exefs_offset = (u64)(u8_to_u32(header->exefs_offset,LE)*media_unit);
		ctx->exefs_size = (u64)(u8_to_u32(header->exefs_size,LE)*media_unit);
		ctx->exefs_hash_src_size = (u64)(u8_to_u32(header->exefs_hash_size,LE)*media_unit);
	}
	ctx->romfs_offset = (u64) (u8_to_u32(header->romfs_offset,LE)*media_unit);
	ctx->romfs_size = (u64) (u8_to_u32(header->romfs_size,LE)*media_unit);
	ctx->romfs_hash_src_size = (u64)(u8_to_u32(header->romfs_hash_size,LE)*media_unit);
	return 0;
}

void CryptNCCHSection(u8 *buffer, u64 size, u64 src_pos, NCCH_STRUCT *ctx, u8 key[16], u8 type)
{
	if(type < 1 || type > 3)
		return;
	u8 counter[0x10];
	ncch_get_counter(ctx,counter,type);	
	ctr_aes_context aes_ctx;
	memset(&aes_ctx,0x0,sizeof(ctr_aes_context));
	ctr_init_counter(&aes_ctx, key, counter);
	if(src_pos > 0){
		u32 carry = 0;
		carry = align_value(src_pos,0x10);
		carry = carry/0x10;
		ctr_add_counter(&aes_ctx,carry);
	}
	ctr_crypt_counter(&aes_ctx, buffer, buffer, size);
	return;
}

void ncch_get_counter(NCCH_STRUCT *ctx, u8 counter[16], u8 type)
{
	u8 *titleID = ctx->titleID;
	u32 i;
	u32 x = 0;

	memset(counter, 0, 16);

	if (ctx->version == 2 || ctx->version == 0)
	{
		for(i=0; i<8; i++)
			counter[i] = titleID[7-i];
		counter[8] = type;
	}
	else if (ctx->version == 1)
	{
		switch(type){
			case ncch_ExHeader : x = ctx->exheader_offset; break;
			case ncch_exefs : x = ctx->exefs_offset; break;
			case ncch_romfs : x = ctx->romfs_offset; break;
		}
		for(i=0; i<8; i++)
			counter[i] = titleID[i];
		for(i=0; i<4; i++)
			counter[12+i] = x>>((3-i)*8);
	}
}