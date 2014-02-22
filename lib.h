#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <math.h>

#ifdef _WIN32
	#include <io.h>
	#include <direct.h>
	#include <windows.h>
	//#include <wchar.h>
#else
	#include <sys/stat.h>
	#include <sys/types.h>
#endif


#include "types.h"
#include "utils.h"
#include "crypto.h"
#ifdef RETAIL_FSIGN
#include "keys_retail.h"
#else
#include "keys_debug.h"
#endif
#include "accessdesc_sig.h"

#include "keyset.h"
#include "usersettings.h"
#include "libyaml/yaml.h"
#include "yaml_ctr.h"


