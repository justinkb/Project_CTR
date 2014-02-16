#include "lib.h"
#include "ncch.h"
#include "romfs.h"

// RomFs Build Functions

int ImportRomFsBinaryFromFile(ncch_settings *ncchset);

int BuildRomFs(ncch_settings *ncchset)
{
	int result = 0;
	if(ncchset->ComponentFilePtrs.romfs){ // The user has specified a pre-built RomFs Binary
		result = ImportRomFsBinaryFromFile(ncchset);
		return result;
	}
	
	// Need to implement RomFs generation

	return result;
}

int ImportRomFsBinaryFromFile(ncch_settings *ncchset)
{
	ncchset->Sections.RomFs.size = ncchset->ComponentFilePtrs.romfs_size;
	ncchset->Sections.RomFs.buffer = malloc(ncchset->Sections.RomFs.size);
	if(!ncchset->Sections.RomFs.buffer) {fprintf(stderr,"[ROMFS ERROR] MEM ERROR\n"); return MEM_ERROR;}
	ReadFile_64(ncchset->Sections.RomFs.buffer,ncchset->Sections.RomFs.size,0,ncchset->ComponentFilePtrs.romfs);
	return 0;
}

// RomFs Read Functions