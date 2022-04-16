# C++/C Recursive Project Makefile 
# (c) Jack
# Version 7.a (20220413)

# Project Name
PROJECT_NAME = Project_CTR

# Project Relative Paths
PROJECT_PATH = $(CURDIR)
PROJECT_PROGRAM_LOCAL_DIR = ctrtool makerom
PROJECT_DEPEND_LOCAL_DIR = libmbedtls libfmt libpolarssl libblz libyaml libnintendo-n3ds libbroadon-es 

# Determine if the root makefile has been established, and if not establish this makefile as the root makefile
ifeq ($(ROOT_PROJECT_NAME),)
	export ROOT_PROJECT_NAME = $(PROJECT_NAME)
	export ROOT_PROJECT_PATH = $(PROJECT_PATH)
	export ROOT_PROJECT_DEPENDENCY_PATH = $(ROOT_PROJECT_PATH)/deps
endif

# Detect Platform
ifeq ($(PROJECT_PLATFORM),)
	ifeq ($(OS), Windows_NT)
		export PROJECT_PLATFORM = WIN32
	else
		UNAME = $(shell uname -s)
		ifeq ($(UNAME), Darwin)
			export PROJECT_PLATFORM = MACOS
		else
			export PROJECT_PLATFORM = GNU
		endif
	endif
endif

# Detect Architecture
ifeq ($(PROJECT_PLATFORM_ARCH),)
	ifeq ($(PROJECT_PLATFORM), WIN32)
		export PROJECT_PLATFORM_ARCH = x86_64
	else ifeq ($(PROJECT_PLATFORM), GNU)
		export PROJECT_PLATFORM_ARCH = $(shell uname -m)
	else ifeq ($(PROJECT_PLATFORM), MACOS)
		export PROJECT_PLATFORM_ARCH = $(shell uname -m)
	else
		export PROJECT_PLATFORM_ARCH = x86_64
	endif
endif

# all is the default, user should specify what the default should do
#	- 'deps' for building local dependencies.
#	- 'program' for building executable programs.
all: deps progs
	
clean: clean_deps clean_progs

# Programs
.PHONY: progs
progs:
	@$(foreach prog,$(PROJECT_PROGRAM_LOCAL_DIR), cd "$(prog)" && $(MAKE) program && cd "$(PROJECT_PATH)";)

.PHONY: clean_progs
clean_progs:
	@$(foreach prog,$(PROJECT_PROGRAM_LOCAL_DIR), cd "$(prog)" && $(MAKE) clean && cd "$(PROJECT_PATH)";)

# Dependencies
.PHONY: deps
deps:
	@$(foreach lib,$(PROJECT_DEPEND_LOCAL_DIR), cd "$(ROOT_PROJECT_DEPENDENCY_PATH)/$(lib)" && $(MAKE) static_lib && cd "$(PROJECT_PATH)";)

.PHONY: clean_deps
clean_deps:
	@$(foreach lib,$(PROJECT_DEPEND_LOCAL_DIR), cd "$(ROOT_PROJECT_DEPENDENCY_PATH)/$(lib)" && $(MAKE) clean && cd "$(PROJECT_PATH)";)