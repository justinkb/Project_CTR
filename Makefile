# Makerom Sources
UTILS_OBJS = utils.o keyset.o titleid.o
CIA_OBJS = cia.o certs.o tik.o tmd.o
NCCH_OBJS = ncch.o exheader.o exefs.o elf.o romfs.o
NCSD_OBJS = ncsd.o  
SETTINGS_OBJS = usersettings.o yamlsettings.o
LIB_API_OBJS = crypto.o yaml_ctr.o blz.o

OBJS = makerom.o $(UTILS_OBJS) $(LIB_API_OBJS) $(SETTINGS_OBJS) $(NCSD_OBJS) $(NCCH_OBJS) $(CIA_OBJS)

# Libraries
POLAR_OBJS = polarssl/aes.o polarssl/bignum.o polarssl/rsa.o polarssl/sha1.o polarssl/sha2.o polarssl/padlock.o polarssl/md.o polarssl/md_wrap.o polarssl/md2.o polarssl/md4.o polarssl/md5.o polarssl/sha4.o polarssl/base64.o polarssl/cipher.o polarssl/cipher_wrap.o polarssl/camellia.o polarssl/des.o polarssl/blowfish.o
YAML_OBJS = libyaml/api.o libyaml/dumper.o libyaml/emitter.o libyaml/loader.o libyaml/parser.o libyaml/reader.o libyaml/scanner.o libyaml/writer.o

# Compiler Settings
LIBS = -static-libgcc -static-libstdc++
CXXFLAGS = -I.
CFLAGS = --std=c99 -Wall -I. -DMAKEROM_VER_MAJOR=$(VER_MAJOR) -DMAKEROM_VER_MINOR=$(VER_MINOR) $(MAKEROM_BUILD_FLAGS)
CC = gcc
 
# MAKEROM Build Settings
MAKEROM_BUILD_FLAGS = -DPRIVATE_BUILD #-DELF_DEBUG -DRETAIL_FSIGN -DDEBUG 
VER_MAJOR = 0
VER_MINOR = 3
OUTPUT = makerom

main: build

rebuild: clean build

build: $(OBJS) $(POLAR_OBJS) $(YAML_OBJS)
	g++ -o $(OUTPUT) $(LIBS) $(OBJS) $(POLAR_OBJS) $(YAML_OBJS)

clean:
	rm -rf $(OUTPUT) $(OBJS) $(POLAR_OBJS) $(YAML_OBJS) *.cci *.cia *.cxi *.cfa
	
# Winfail compatibility
rebuildwin: cleanwin build
cleanwin:
	del /Q objs $(OUTPUT).exe *.o polarssl\*.o libyaml\*.o *.cci *.cia *.cxi *.cfa

#Test Functions
	
ccigen_sdk:
	ctr_makerom32 -f card -rsf testdata\Application.rsf -o content_test_sdk.cci -content testdata\app_zeroskey.cxi:0 -content testdata\manual_zeroskey.cfa:1 -content testdata\dlp_zeroskey.cfa:2 -content testdata\update_zeroskey.cfa:7
	del content_test_sdk.cci.xml
	
ccigen:
	$(OUTPUT) -f card -rsf testdata\Application.rsf -o content_test.cci -content testdata\app_zeroskey.cxi:0 -content testdata\manual_zeroskey.cfa:1 -content testdata\dlp_zeroskey.cfa:2 -content testdata\update_zeroskey.cfa:7
	
ciagen_sdk:
	ctr_makecia32 -o content_test.cia -i testdata\app_zeroskey.cxi:0 -i testdata\manual_zeroskey.cfa:1 -i testdata\dlp_zeroskey.cfa:2
	
ciagen:
	$(OUTPUT) -f cia -o content_test.cia -content testdata\app_zeroskey.cxi:0 -content testdata\manual_zeroskey.cfa:1 -content testdata\dlp_zeroskey.cfa:2 -encryptcia

pyramids: 
	$(OUTPUT) -f cxi -accessdesc app -o pyramids.cxi -code pyramids\code.bin -exheader pyramids\exheader.bin -rsf pyramids\app.rsf -desc pyramids\build.desc -icon pyramids\icon.icn -banner pyramids\banner.bnr -romfs pyramids\romfs.bin
