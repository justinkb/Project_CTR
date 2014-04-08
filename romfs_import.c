#include "lib.h"
#include "ncch.h"
#include "romfs.h"

int PrepareImportRomFsBinaryFromFile(ncch_settings *ncchset, romfs_buildctx *ctx)
{
	ctx->ImportRomfsBinary = true;
	ctx->romfsSize = ncchset->componentFilePtrs.romfsSize;
	ctx->romfsBinary = ncchset->componentFilePtrs.romfs;

	return 0;
}

int ImportRomFsBinaryFromFile(romfs_buildctx *ctx)
{
	ReadFile_64(ctx->output,ctx->romfsSize,0,ctx->romfsBinary);
	if(memcmp(ctx->output,"IVFC",4) != 0){
		fprintf(stderr,"[ROMFS ERROR] Invalid RomFS Binary.\n");
		return INVALID_ROMFS_FILE;
	}
	return 0;
}