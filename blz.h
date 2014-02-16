#ifndef _BLZ_H_
#define _BLZ_H_

#define BLZ_NORMAL    0          // normal mode
#define BLZ_BEST      1          // best mode

u8 *BLZ_Code(u8 *raw_buffer, int raw_len, u32 *new_len, int best);

#endif
