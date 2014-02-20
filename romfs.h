#ifndef _ROMFS_H_
#define _ROMFS_H_

typedef enum
{
	INVALID_ROMFS_FILE = -10,
} romfs_errors;

#endif

// RomFs Build Functions

int BuildRomFs(ncch_settings *ncchset);

// RomFs Read Functions