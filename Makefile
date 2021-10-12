ifeq ($(AWS_SDK_PATH),)
  ifneq ($(wildcard $(HOME)/aws-sdk-cpp/include/aws),)
    AWS_SDK_PATH := $(HOME)/aws-sdk-cpp
  else ifneq ($(wildcard /usr/local/include/aws),)
    AWS_SDK_PATH := /usr/local
  endif
  # Note: we don't error here when not found, as "sudo make install" would
  # then fail as $(HOME) is then all wrong
endif

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

ifeq ($(JSON_C_INC),)
  JSON_C_INC := $(shell pkg-config --cflags json-c 2>/dev/null)
  ifeq ($(JSON_C_INC),)
    $(error json-c not found, specify JSON_C_INC)
  endif
endif

all: aws_kms_pkcs11.so

clean:
	rm -f aws_kms_pkcs11.so aws_kms_pkcs11_test aws_kms_client_test

test: aws_kms_pkcs11_test certificates_test
	./certificates_test
	AWS_KMS_PKCS11_DEBUG=1 ./aws_kms_pkcs11_test

certificates_test: certificates.cpp certificates_test.cpp
	g++ -g -Wall certificates.cpp certificates_test.cpp -o certificates_test -lcrypto

aws_kms_pkcs11_test: aws_kms_pkcs11_test.c aws_kms_pkcs11.so
	gcc -g -Wall $(PKCS11_INC) aws_kms_pkcs11_test.c -o aws_kms_pkcs11_test -ldl

aws_kms_pkcs11.so: aws_kms_pkcs11.cpp unsupported.cpp aws_kms_slot.cpp debug.cpp attributes.cpp certificates.cpp
	@if [ -z $(AWS_SDK_PATH) ]; then echo "AWS SDK not found, specify with AWS_SDK_PATH" >&2 ; exit 1; fi
	g++ -shared -fPIC -Wall -I$(AWS_SDK_PATH)/include $(PKCS11_INC) $(JSON_C_INC) -fno-exceptions -std=c++17 attributes.cpp aws_kms_pkcs11.cpp certificates.cpp unsupported.cpp debug.cpp aws_kms_slot.cpp -o aws_kms_pkcs11.so \
	    -Wl,--whole-archive \
	    $(AWS_SDK_PATH)/lib/libaws-checksums.a \
	    $(AWS_SDK_PATH)/lib/libaws-c-common.a \
	    $(AWS_SDK_PATH)/lib/libaws-c-event-stream.a \
	    $(AWS_SDK_PATH)/lib/libaws-cpp-sdk-core.so \
	    $(AWS_SDK_PATH)/lib/libaws-cpp-sdk-kms.so \
	    -Wl,--no-whole-archive -lcrypto -ljson-c -lcurl

install: aws_kms_pkcs11.so
	cp aws_kms_pkcs11.so /usr/lib/x86_64-linux-gnu/pkcs11/

uninstall:
	rm -f /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
