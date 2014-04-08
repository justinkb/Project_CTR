#include "lib.h"
#include "ncch.h"
#include "romfs.h"
#include "romfs_binary.h"
#include "romfs_import.h"

// RomFs Build Functions
int SetupRomFs(ncch_settings *ncchset, romfs_buildctx *ctx)
{
	ctx->output = NULL;
	ctx->romfsSize = 0;

	// If Not Using RomFS Return
	if(!ncchset->options.UseRomFS)
		return 0;

	int result = 0;

	if(ncchset->componentFilePtrs.romfs)// The user has specified a pre-built RomFs Binary
		result = PrepareImportRomFsBinaryFromFile(ncchset,ctx);
	
	else // Otherwise build ROMFS
		result = PrepareBuildRomFsBinary(ncchset,ctx);

	return result;
}

int BuildRomFs(romfs_buildctx *ctx)
{
	// If Not Using RomFS Return
	if(!ctx->romfsSize)
		return 0;

	int result = 0;
	
	if(ctx->ImportRomfsBinary) // The user has specified a pre-built RomFs Binary
		result = ImportRomFsBinaryFromFile(ctx);
	else // Otherwise build ROMFS
		result = BuildRomFsBinary(ctx);	

	FreeRomFsCtx(ctx);

	return result;
}

void FreeRomFsCtx(romfs_buildctx *ctx)
{
	if(ctx->romfsBinary)
		fclose(ctx->romfsBinary);
}