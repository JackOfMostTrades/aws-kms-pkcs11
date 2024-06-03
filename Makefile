# Detect OS
UNAME_S := $(shell uname -s)

# Try to locate the AWS SDK if not specified with AWS_SDK_PATH
MACHINE := $(shell gcc -dumpmachine)
ifeq ($(AWS_SDK_PATH),)
  ifneq ($(wildcard /usr/include/aws),)
    AWS_SDK_PATH := /usr
  else ifneq ($(wildcard /usr/local/include/aws),)
    AWS_SDK_PATH := /usr/local
  else
    $(error AWS SDK not found in common include path, please specify AWS_SDK_PATH)
  endif
endif

# Try to find which subdir of the SDK has the libraries
ifneq ($(AWS_SDK_PATH),)
  ifneq ($(wildcard $(AWS_SDK_PATH)/lib/libaws-c-common.*),)
    AWS_SDK_LIB_PATH := $(addsuffix /lib,$(AWS_SDK_PATH))
  else ifneq ($(wildcard $(AWS_SDK_PATH)/lib64/libaws-c-common.*),)
    AWS_SDK_LIB_PATH := $(addsuffix /lib64,$(AWS_SDK_PATH))
  else ifneq ($(wildcard $(AWS_SDK_PATH)/lib/$(MACHINE)/libaws-c-common.*),)
    AWS_SDK_LIB_PATH := $(addsuffix /lib/$(MACHINE),$(AWS_SDK_PATH))
  else
    $(error neither lib or lib64 found in AWS SDK)
  endif
endif

# The SDK has two main sets of components, the C runtimes and the C++ runtimes,
# depending on how the SDK is built, they can be separately either static libs,
# dynamic libs, or both.
#
# Let's try to intuit this unless specified, with a bias towards static libs
# if available, as they SDK versions tend to have ABI compatibility issues
#
# Use these variables to override the mechanisms for those two sets:
#
# AWS_SDK_STATIC = y     : Force use of static libraries for both C and C++
# AWS_SDK_STATIC = n     : Force use of dynamic libraries for both C and C++
# AWS_SDK_C_STATIC = y   : Force use of static libraries for C
# AWS_SDK_C_STATIC = n   : Force use of dynamic libraries for C
# AWS_SDK_CPP_STATIC = y : Force use of static libraries for C++
# AWS_SDK_CPP_STATIC = n : Force use of dynamic libraries for C++

ifdef AWS_SDK_STATIC
  ifeq ($(AWS_SDK_STATIC),y)
    AWS_SDK_C_STATIC := y
    AWS_SDK_CPP_STATIC := y
  else ifeq ($(AWS_SDK_STATIC),n)
    AWS_SDK_C_STATIC := n
    AWS_SDK_CPP_STATIC := n
  else
    $(error Unrecognized value for AWS_SDK_STATIC, use y or n)
  endif
endif

ifndef AWS_SDK_C_STATIC
  ifneq ($(wildcard ${AWS_SDK_LIB_PATH}/libaws-c-common.a),)
    AWS_SDK_C_STATIC := y
  else ifneq ($(wildcard ${AWS_SDK_LIB_PATH}/libaws-c-common.so),)
    AWS_SDK_C_STATIC := n
  else
    $(error Cannot find either static or dynamic SDK C libraries)
  endif
endif

ifndef AWS_SDK_CPP_STATIC
  ifneq ($(wildcard ${AWS_SDK_LIB_PATH}/libaws-cpp-sdk-kms.a),)
    AWS_SDK_CPP_STATIC := y
  else ifneq ($(wildcard ${AWS_SDK_LIB_PATH}/libaws-cpp-sdk-core.so),)
    AWS_SDK_CPP_STATIC := n
  else
    $(error Cannot find either static or dynamic SDK C++ libraries)
  endif
endif

# Try to locate the pkcs11.h if location not specified with PKCS11_INC
ifeq ($(PKCS11_INC),)
  PKCS11_INC := $(shell pkg-config --cflags p11-kit-1 2>/dev/null)
  ifneq ($(PKCS11_INC),)
    PKCS11_INC := $(addsuffix /p11-kit,$(PKCS11_INC))
  else
    PKCS11_INC := $(shell pkg-config --cflags nss 2>/dev/null)
  endif
  ifeq ($(PKCS11_INC),)
    ifneq ($(wildcard /usr/include/opencryptoki),)
      PKCS11_INC := -I/usr/include/opencryptoki
    endif
  endif
  ifeq ($(PKCS11_INC),)
    $(error p11-kit or nss not found, specify PKCS11_INC)
  endif
endif

# Try to locate target install location if not specified with PKCS11_MOD_PATH
ifeq ($(PKCS11_MOD_PATH),)
  PKCS11_MOD_PATH := $(shell pkg-config --variable p11_module_path p11-kit-1 2>/dev/null)
  ifeq ($(PKCS11_MOD_PATH),)
    PKCS11_MOD_PATH := $(shell pkg-config --variable libdir nss 2>/dev/null)
    ifneq ($(PKCS11_MOD_PATH),)
      PKCS11_MOD_PATH := $(addsuffix /pkcs11,$(PKCS11_MOD_PATH))
    endif
  endif
  ifeq ($(PKCS11_MOD_PATH),)
    $(error p11-kit or nss not found, specify PKCS11_MOD_PATH)
  endif
endif

# Try to locate the json-c headers if location not specified with JSON_C_INC
ifeq ($(JSON_C_INC),)
  JSON_C_INC := $(shell pkg-config --cflags json-c 2>/dev/null)
  ifeq ($(JSON_C_INC),)
    $(error json-c not found, specify JSON_C_INC)
  endif
endif

# Try to locate the json-c libraries if location not specified with JSON_C_LIB
ifeq ($(JSON_C_LIB),)
  JSON_C_LIB := $(shell pkg-config --libs json-c 2>/dev/null)
  ifeq ($(JSON_C_LIB),)
    $(error json-c libraries not found, specify JSON_C_LIB)
  endif
endif

# Try to locate OpenSSL if not specified with OPENSSL_INC and OPENSSL_LIB
ifeq ($(OPENSSL_INC),)
  OPENSSL_INC := $(shell pkg-config --cflags openssl 2>/dev/null)
  ifeq ($(OPENSSL_INC),)
    $(error OpenSSL not found, please specify OPENSSL_INC)
  endif
endif

ifeq ($(OPENSSL_LIB),)
  OPENSSL_LIB := $(shell pkg-config --libs openssl 2>/dev/null)
  ifeq ($(OPENSSL_LIB),)
    $(error OpenSSL libraries not found, please specify OPENSSL_LIB)
  endif
endif

ifdef AWS_SDK_USE_SYSTEM_PROXY
  ifeq ($(AWS_SDK_USE_SYSTEM_PROXY),y)
    PROXY_CFLAGS := -DAWS_SDK_USE_SYSTEM_PROXY=1
  else ifeq ($(AWS_SDK_USE_SYSTEM_PROXY),n)
    PROXY_CFLAGS :=
  else
    $(error Invalid value for AWS_SDK_USE_SYSTEM_PROXY, use y or n)
  endif
endif

# Build library link list
STATIC_LIBS :=
LIBS :=

ifeq ($(AWS_SDK_CPP_STATIC),y)
  $(info Using C++ SDK static libraries)
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-cpp-sdk-kms.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-cpp-sdk-acm-pca.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-cpp-sdk-core.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-crt-cpp.a
else ifeq ($(AWS_SDK_CPP_STATIC),n)
  $(info Using C++ SDK dynamic libraries)
  LIBS += $(AWS_SDK_LIB_PATH)/libaws-cpp-sdk-core.so
  LIBS += $(AWS_SDK_LIB_PATH)/libaws-cpp-sdk-kms.so
  LIBS += $(AWS_SDK_LIB_PATH)/libaws-cpp-sdk-acm-pca.so
else
  $(error Unrecognized value for AWS_SDK_CPP_STATIC, use y or n)
endif

ifeq ($(AWS_SDK_C_STATIC),y)
  $(info Using C SDK static libraries)
  ifeq ($(UNAME_S),Linux)
    STATIC_LIBS += -Wl,--start-group
  endif
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-checksums.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-common.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-event-stream.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-auth.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-http.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-io.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-mqtt.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-cal.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-compression.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-s3.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-sdkutils.a
  STATIC_LIBS += $(AWS_SDK_LIB_PATH)/libs2n.a
  ifeq ($(UNAME_S),Linux)
    STATIC_LIBS += -Wl,--end-group
  endif
else ifeq ($(AWS_SDK_C_STATIC),n)
  $(info Using C SDK dynamic libraries)
  LIBS += $(AWS_SDK_LIB_PATH)/libaws-checksums.so
  LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-common.so
  LIBS += $(AWS_SDK_LIB_PATH)/libaws-c-event-stream.so
else
  $(error Unrecognized value for AWS_SDK_C_STATIC, use y or n)
endif

# Source files
SRC = attributes.cpp aws_kms_pkcs11.cpp certificates.cpp unsupported.cpp debug.cpp aws_kms_slot.cpp

# Additional frameworks for macOS
ifeq ($(UNAME_S),Darwin)
  MACOSX_FRAMEWORKS := -framework CoreFoundation -framework Security
endif

all: aws_kms_pkcs11.so aws_kms_pkcs11.dylib

clean:
	rm -f aws_kms_pkcs11.so aws_kms_pkcs11.dylib aws_kms_pkcs11_test aws_kms_client_test

test: aws_kms_pkcs11_test certificates_test
	./certificates_test
	AWS_KMS_PKCS11_DEBUG=1 ./aws_kms_pkcs11_test

certificates_test: certificates.cpp certificates_test.cpp
	g++ -g -fPIC -Wall -I$(AWS_SDK_PATH)/include $(PKCS11_INC) $(JSON_C_INC) $(OPENSSL_INC) $(PROXY_CFLAGS) -fno-exceptions -std=c++17 \
	    debug.cpp certificates.cpp certificates_test.cpp -o certificates_test $(STATIC_LIBS) $(LIBS) $(OPENSSL_LIB) $(JSON_C_LIB) -lcurl $(MACOSX_FRAMEWORKS) -lz

aws_kms_pkcs11_test: aws_kms_pkcs11_test.c aws_kms_pkcs11.so
	g++ -g -fPIC -Wall -I$(AWS_SDK_PATH)/include $(PKCS11_INC) $(JSON_C_INC) $(OPENSSL_INC) $(PROXY_CFLAGS) -fno-exceptions -std=c++17 \
	    aws_kms_pkcs11_test.c -o aws_kms_pkcs11_test -ldl $(OPENSSL_LIB) $(JSON_C_LIB) $(MACOSX_FRAMEWORKS) -lz

aws_kms_pkcs11.so: aws_kms_pkcs11.cpp unsupported.cpp aws_kms_slot.cpp debug.cpp attributes.cpp certificates.cpp
	g++ -shared -fPIC -Wall -I$(AWS_SDK_PATH)/include $(PKCS11_INC) $(JSON_C_INC) $(OPENSSL_INC) $(PROXY_CFLAGS) -fno-exceptions -std=c++17 $(SRC) \
	    -o aws_kms_pkcs11.so $(STATIC_LIBS) $(LIBS) $(OPENSSL_LIB) $(JSON_C_LIB) -lcurl $(MACOSX_FRAMEWORKS) -lz

aws_kms_pkcs11.dylib: aws_kms_pkcs11.cpp unsupported.cpp aws_kms_slot.cpp debug.cpp attributes.cpp certificates.cpp
	g++ -dynamiclib -fPIC -Wall -I$(AWS_SDK_PATH)/include $(PKCS11_INC) $(JSON_C_INC) $(OPENSSL_INC) $(PROXY_CFLAGS) -fno-exceptions -std=c++17 $(SRC) \
	    -o aws_kms_pkcs11.dylib $(STATIC_LIBS) $(LIBS) $(OPENSSL_LIB) $(JSON_C_LIB) -lcurl $(MACOSX_FRAMEWORKS) -lz

install: aws_kms_pkcs11.so
	cp aws_kms_pkcs11.so $(PKCS11_MOD_PATH)/

uninstall:
	rm -f $(PKCS11_MOD_PATH)/aws_kms_pkcs11.so
