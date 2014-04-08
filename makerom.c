#include "lib.h"
#include "ncch.h"
#include "ncsd.h"
#include "cia.h"

int main(int argc, char *argv[])
{
	// Setting up user settings
	user_settings *usrset = malloc(sizeof(user_settings));
	if(usrset == NULL) {fprintf(stderr,"[!] MEM ERROR\n"); return -1;}	
	init_UserSettings(usrset);
	
	int result;
	
#ifdef DEBUG
	printf("[DEBUG] Parseing Args\n");
#endif

	// Parsing command args
	result = ParseArgs(argc,argv,usrset);
	if(result < 0) goto finish;
	
#ifdef DEBUG
	printf("[DEBUG] Importing Yaml Settings\n");
#endif

	// Import RSF Settings if present
	result = GetYamlSettings(usrset);
	if(result < 0) goto finish;

	// Setup Content 0
	if(!usrset->ncch.buildNcch0){ // Import Content
		if(usrset->common.workingFileType == infile_ncch){
			FILE *ncch0 = fopen(usrset->common.contentPath[0],"rb");
			if(!ncch0) {fprintf(stderr,"[MAKEROM ERROR] Failed to open Content 0: %s\n",usrset->common.contentPath[0]); goto finish;}
			fclose(ncch0);
			usrset->common.workingFile.size = GetFileSize_u64(usrset->common.contentPath[0]);
			usrset->common.workingFile.buffer = malloc(usrset->common.workingFile.size);
			ncch0 = fopen(usrset->common.contentPath[0],"rb");
			ReadFile_64(usrset->common.workingFile.buffer, usrset->common.workingFile.size,0,ncch0);
			fclose(ncch0);
		}
		else if(usrset->common.workingFileType == infile_srl || usrset->common.workingFileType == infile_ncsd){
			FILE *fp = fopen(usrset->common.workingFilePath,"rb");
			if(!fp) {
				fprintf(stderr,"[MAKEROM ERROR] Failed to open %s: %s\n",usrset->common.workingFileType == infile_srl? "SRL":"CCI",usrset->common.workingFilePath); 
				goto finish;
			}
			fclose(fp);
			u64 size = GetFileSize_u64(usrset->common.workingFilePath);
			usrset->common.workingFile.size = align(size,0x10);
			usrset->common.workingFile.buffer = malloc(usrset->common.workingFile.size);
			fp = fopen(usrset->common.workingFilePath,"rb");
			ReadFile_64(usrset->common.workingFile.buffer,size,0,fp);
			fclose(fp);
		}
	}
	else{// Build Content 0
#ifdef DEBUG
	printf("[DEBUG] Build NCCH0\n");
#endif
		result = build_NCCH(usrset);
		if(result < 0) { 
			//fprintf(stderr,"[ERROR] %s generation failed\n",usrset->build_ncch_type == CXI? "CXI" : "CFA"); 
			fprintf(stderr,"[RESULT] Failed to build outfile\n"); 
			goto finish; 
		}	
	}
	// Make CCI
	if(usrset->common.outFormat == CCI){
#ifdef DEBUG
	printf("[DEBUG] Building CCI\n");
#endif
		result = build_CCI(usrset);
		if(result < 0) { fprintf(stderr,"[RESULT] Failed to build CCI\n"); goto finish; }
	}
	// Make CIA
	else if(usrset->common.outFormat == CIA){
#ifdef DEBUG
	printf("[DEBUG] Building CIA\n");
#endif
		result = build_CIA(usrset);
		if(result < 0) { fprintf(stderr,"[RESULT] Failed to build CIA\n"); goto finish; }
	}
	// No Container Raw CXI/CFA
	else if(usrset->common.outFormat == CXI || usrset->common.outFormat == CFA){
#ifdef DEBUG
	printf("[DEBUG] Outputting NCCH, because No Container\n");
#endif
		FILE *ncch_out = fopen(usrset->common.outFileName,"wb");
		if(!ncch_out) {
			fprintf(stderr,"[ERROR] Failed to create '%s'\n",usrset->common.outFileName); 
			fprintf(stderr,"[RESULT] Failed to build '%s'\n",usrset->common.outFormat == CXI? "CXI" : "CFA"); 
			result = FAILED_TO_CREATE_OUTFILE; 
			goto finish;
		}
		WriteBuffer(usrset->common.workingFile.buffer,usrset->common.workingFile.size,0,ncch_out);
		fclose(ncch_out);
	}
	
finish:
#ifdef DEBUG
	printf("[DEBUG] Free Context\n");
#endif
	free_UserSettings(usrset);
#ifdef DEBUG
	printf("[DEBUG] Finished returning (result=%d)\n",result);
#endif
	return result;
}