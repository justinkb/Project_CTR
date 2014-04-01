#include "lib.h"
#include "ncch.h"
#include "romfs.h"

// RomFs Build Functions

int ImportRomFsBinaryFromFile(ncch_settings *ncchset);

int BuildRomFs(ncch_settings *ncchset)
{
	int result = 0;

	// If Not Using RomFS Return
	if(!ncchset->options.UseRomFS) return result;

	if(ncchset->componentFilePtrs.romfs){ // The user has specified a pre-built RomFs Binary
		result = ImportRomFsBinaryFromFile(ncchset);
		return result;
	}
	
	// Need to implement RomFs generation

	return result;
}

int ImportRomFsBinaryFromFile(ncch_settings *ncchset)
{
	ncchset->sections.romFs.size = ncchset->componentFilePtrs.romfsSize;
	ncchset->sections.romFs.buffer = malloc(ncchset->sections.romFs.size);
	if(!ncchset->sections.romFs.buffer) {fprintf(stderr,"[ROMFS ERROR] MEM ERROR\n"); return MEM_ERROR;}
	ReadFile_64(ncchset->sections.romFs.buffer,ncchset->sections.romFs.size,0,ncchset->componentFilePtrs.romfs);
	if(memcmp(ncchset->sections.romFs.buffer,"IVFC",4) != 0){
		fprintf(stderr,"[ROMFS ERROR] Invalid RomFS Binary.\n");
		return INVALID_ROMFS_FILE;
	}
	return 0;
}

// RomFs Read Functions