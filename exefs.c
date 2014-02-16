#include "lib.h"
#include "ncch.h"
#include "exefs.h"

// Private Prototypes
u32 PredictExeFS_Size(ExeFs_BuildContext *ctx);
int GenerateExeFS_Header(ExeFs_BuildContext *ctx, u8 *outbuff);
void InitialiseExeFSContext(ExeFs_BuildContext *ctx);
void FreeExeFSContext(ExeFs_BuildContext *ctx);
int ImportDatatoExeFS(ExeFs_BuildContext *ctx, u8 *outbuff);
int ImportToExeFSContext(ExeFs_BuildContext *ctx, char *lable, u8 *buffer, u32 size);

// ExeFs Build Functions
int BuildExeFs(ncch_settings *ncchset)
{
	/* Intialising ExeFs Build Context */
	ExeFs_BuildContext *ctx = malloc(sizeof(ExeFs_BuildContext));
	if(!ctx) {fprintf(stderr,"[EXEFS ERROR] MEM ERROR\n"); return MEM_ERROR;}
	InitialiseExeFSContext(ctx);
	ctx->media_unit = ncchset->Options.MediaSize;

	/* Importing ExeFs */
	if(ncchset->ExeFs_Sections.Code.size) 
		ImportToExeFSContext(ctx,".code",ncchset->ExeFs_Sections.Code.buffer,ncchset->ExeFs_Sections.Code.size);
	if(ncchset->ExeFs_Sections.Banner.size) 
		ImportToExeFSContext(ctx,"banner",ncchset->ExeFs_Sections.Banner.buffer,ncchset->ExeFs_Sections.Banner.size);
	if(ncchset->ExeFs_Sections.Icon.size) 
		ImportToExeFSContext(ctx,"icon",ncchset->ExeFs_Sections.Icon.buffer,ncchset->ExeFs_Sections.Icon.size);
	if(ncchset->Sections.Logo.size && ncchset->Options.IncludeExeFsLogo) 
		ImportToExeFSContext(ctx,"logo",ncchset->Sections.Logo.buffer,ncchset->Sections.Logo.size);

	/* Allocating Memory for ExeFs */
	ncchset->Sections.ExeFs.size = PredictExeFS_Size(ctx);
	ncchset->Sections.ExeFs.buffer = malloc(ncchset->Sections.ExeFs.size);
	if(!ncchset->Sections.ExeFs.buffer){
		printf("[EXEFS ERROR] Could Not Allocate Memory for ExeFS\n");
		return Fail;
	}
	memset(ncchset->Sections.ExeFs.buffer,0,ncchset->Sections.ExeFs.size);

	/* Generating Header, and writing sections to buffer */
	GenerateExeFS_Header(ctx,ncchset->Sections.ExeFs.buffer);
	ImportDatatoExeFS(ctx,ncchset->Sections.ExeFs.buffer);

	/* Finish */
	FreeExeFSContext(ctx);
	return 0;
}

u32 PredictExeFS_Size(ExeFs_BuildContext *ctx)
{
	u32 exefs_size = 0x200; // Size of header
	for(int i = 0; i < ctx->section_count; i++){
		exefs_size += align_value(ctx->section_size[i],ctx->media_unit);
	}
	//exefs_size = align_value(ctx->exefs_size,ctx->media_unit);
	return exefs_size;
}

int GenerateExeFS_Header(ExeFs_BuildContext *ctx, u8 *outbuff)
{
	for(int i = 0; i < ctx->section_count; i++){
		if(i == 0)
			ctx->section_offset[i] = 0;
		else
			ctx->section_offset[i] = align_value((ctx->section_offset[i-1]+ctx->section_size[i-1]),ctx->media_unit);
		
		memcpy(ctx->file_header[i].name,ctx->lable[i],8);
		u32_to_u8(ctx->file_header[i].offset,ctx->section_offset[i],LE);
		u32_to_u8(ctx->file_header[i].size,ctx->section_size[i],LE);
		ctr_sha(ctx->section[i],ctx->section_size[i],ctx->file_hashes[9-i],CTR_SHA_256);
	}
	memcpy(outbuff,ctx->file_header,sizeof(ExeFs_FileHeader)*10);
	memcpy(outbuff+0xc0,ctx->file_hashes,0x20*10);
	return 0;
}

void InitialiseExeFSContext(ExeFs_BuildContext *ctx)
{
	memset(ctx,0,sizeof(ExeFs_BuildContext));
}

void FreeExeFSContext(ExeFs_BuildContext *ctx)
{
	/*
	if(ctx->outbuff != NULL)
		free(ctx->outbuff);
	for(int i = 0; i < 10; i++){
		if(ctx->section[i] != NULL)
			free(ctx->section[i]);
	}
	*/
	memset(ctx,0,sizeof(ExeFs_BuildContext));
	free(ctx);
}

int ImportDatatoExeFS(ExeFs_BuildContext *ctx, u8 *outbuff)
{
	for(int i = 0; i < ctx->section_count; i++){
		memcpy(outbuff+ctx->section_offset[i]+0x200,ctx->section[i],ctx->section_size[i]);
	}
	return 0;
}

int ImportToExeFSContext(ExeFs_BuildContext *ctx, char *lable, u8 *buffer, u32 size)
{
	if(ctx == NULL || lable == NULL || buffer == NULL){
		printf("[!] PTR ERROR\n");
		return PTR_ERROR;
	}
	if(ctx->section_count >= 10){
		printf("[!] Maximum ExeFS Capacity Reached\n");
		return EXEFS_MAX_REACHED;
	}
	if(strlen(lable) > 8){
		printf("[!] ExeFS Section Name: '%s' is too large\n",lable);
		return EXEFS_SECTION_NAME_ERROR;
	}	
	
	ctx->section_count++;
	ctx->section[ctx->section_count - 1] = buffer;
	ctx->section_size[ctx->section_count - 1] = size;
	strcpy(ctx->lable[ctx->section_count - 1],lable);
	return 0;
}

// ExeFs Read Functions
bool DoesExeFsSectionExist(char *section, u8 *ExeFs)
{
	ExeFs_Header *hdr = (ExeFs_Header*) ExeFs;
	for(int i = 0; i < MAX_EXEFS_SECTIONS; i++){
		if(strncmp(hdr->SectionHdr[i].name,section,8) == 0) return true;
	}
	return false;
}
u8* GetExeFsSection(char *section, u8 *ExeFs)
{
	ExeFs_Header *hdr = (ExeFs_Header*) ExeFs;
	for(int i = 0; i < MAX_EXEFS_SECTIONS; i++){
		if(strncmp(hdr->SectionHdr[i].name,section,8) == 0){ 
			u32 offset = u8_to_u32(hdr->SectionHdr[i].offset,LE) + sizeof(ExeFs_Header);
			return (u8*)(ExeFs+offset);
		}
	}
	return NULL;
}

u8* GetExeFsSectionHash(char *section, u8 *ExeFs)
{
	ExeFs_Header *hdr = (ExeFs_Header*) ExeFs;
	for(int i = 0; i < MAX_EXEFS_SECTIONS; i++){
		if(strncmp(hdr->SectionHdr[i].name,section,8) == 0){ 
			return (u8*)(hdr->SectionHashes[MAX_EXEFS_SECTIONS-1-i]);
		}
	}
	return NULL;
}

u32 GetExeFsSectionSize(char *section, u8 *ExeFs)
{
	ExeFs_Header *hdr = (ExeFs_Header*) ExeFs;
	for(int i = 0; i < MAX_EXEFS_SECTIONS; i++){
		if(strncmp(hdr->SectionHdr[i].name,section,8) == 0){ 
			return u8_to_u32(hdr->SectionHdr[i].size,LE);
		}
	}
	return 0;
}

u32 GetExeFsSectionOffset(char *section, u8 *ExeFs)
{
	ExeFs_Header *hdr = (ExeFs_Header*) ExeFs;
	for(int i = 0; i < MAX_EXEFS_SECTIONS; i++){
		if(strncmp(hdr->SectionHdr[i].name,section,8) == 0){ 
			return u8_to_u32(hdr->SectionHdr[i].offset,LE) + sizeof(ExeFs_Header);
		}
	}
	return 0;
}