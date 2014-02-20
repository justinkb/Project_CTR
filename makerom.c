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
	
	// Parsing command args
	result = ParseArgs(argc,argv,usrset);
	if(result < 0) goto fail_finalise;
	
	// Import RSF Settings if present
	result = GetYamlSettings(usrset);
	if(result < 0) goto fail_finalise;

	// Setup Content 0
	if(!usrset->IsBuildingNCCH0){ // Import Content 0
		if(usrset->Content0IsNcch){
			FILE *ncch0 = fopen(usrset->ContentPath[0],"rb");
			if(!ncch0) {fprintf(stderr,"[MAKEROM ERROR] Failed to open Content 0: %s\n",usrset->ContentPath[0]); goto fail_finalise;}
			fclose(ncch0);
			usrset->Content0.size = GetFileSize_u64(usrset->ContentPath[0]);
			usrset->Content0.buffer = malloc(usrset->Content0.size);
			ncch0 = fopen(usrset->ContentPath[0],"rb");
			ReadFile_64(usrset->Content0.buffer, usrset->Content0.size,0,ncch0);
			fclose(ncch0);
		}
		else if(usrset->Content0IsSrl){
			FILE *srl = fopen(usrset->SrlPath,"rb");
			if(!srl) {fprintf(stderr,"[MAKEROM ERROR] Failed to open SRL: %s\n",usrset->SrlPath); goto fail_finalise;}
			fclose(srl);
			u64 size = GetFileSize_u64(usrset->SrlPath);
			usrset->Content0.size = align_value(size,0x10);
			usrset->Content0.buffer = malloc(usrset->Content0.size);
			srl = fopen(usrset->SrlPath,"rb");
			ReadFile_64(usrset->Content0.buffer,size,0,srl);
			fclose(srl);
		}
		else if(usrset->ConvertCci){
			FILE *cci = fopen(usrset->CciPath,"rb");
			if(!cci) {fprintf(stderr,"[MAKEROM ERROR] Failed to open CCI: %s\n",usrset->CciPath); goto fail_finalise;}
			fclose(cci);
			usrset->Content0.size = GetFileSize_u64(usrset->CciPath);
			usrset->Content0.buffer = malloc(usrset->Content0.size);
			cci = fopen(usrset->CciPath,"rb");
			ReadFile_64(usrset->Content0.buffer, usrset->Content0.size,0,cci);
			fclose(cci);
		}
	}
	else{// Build Content 0
		result = build_NCCH(usrset);
		if(result < 0) { 
			//fprintf(stderr,"[ERROR] %s generation failed\n",usrset->build_ncch_type == CXI? "CXI" : "CFA"); 
			fprintf(stderr,"[RESULT] Failed to build outfile\n"); 
			goto fail_finalise; 
		}	
	}
	// Make CCI
	if(usrset->out_format == CCI){
		result = build_CCI(usrset);
		if(result < 0) { fprintf(stderr,"[RESULT] Failed to build CCI\n"); goto fail_finalise; }
	}
	// Make CIA
	else if(usrset->out_format == CIA){
		result = build_CIA(usrset);
		if(result < 0) { fprintf(stderr,"[RESULT] Failed to build CIA\n"); goto fail_finalise; }
	}
	// No Container Raw CXI/CFA
	else if(usrset->out_format == CXI || usrset->out_format == CFA){
		FILE *ncch_out = fopen(usrset->outfile,"wb");
		if(!ncch_out) {
			fprintf(stderr,"[ERROR] Failed to create '%s'\n",usrset->outfile); 
			fprintf(stderr,"[RESULT] Failed to build '%s'\n",usrset->out_format == CXI? "CXI" : "CFA"); 
			result = FAILED_TO_CREATE_OUTFILE; 
			goto fail_finalise;
		}
		WriteBuffer(usrset->Content0.buffer,usrset->Content0.size,0,ncch_out);
		fclose(ncch_out);
	}
	
	free_UserSettings(usrset);
	return 0;
fail_finalise:
	free_UserSettings(usrset);
	return result;
}