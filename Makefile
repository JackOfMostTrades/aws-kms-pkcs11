CFLAGS=$(shell PKG_CONFIG_PATH=$(HOME)/aws-sdk-cpp/lib/pkgconfig pkg-config --cflags aws-cpp-sdk-kms)
LDFLAGS=$(shell PKG_CONFIG_PATH=$(HOME)/aws-sdk-cpp/lib/pkgconfig pkg-config --libs --static aws-cpp-sdk-kms)

all: aws_kms_pkcs11.so

clean:
	rm -f aws_kms_pkcs11.so aws_kms_pkcs11_test aws_kms_client_test

test: aws_kms_pkcs11_test
	./aws_kms_pkcs11_test

aws_kms_pkcs11_test: aws_kms_pkcs11_test.c aws_kms_pkcs11.so
	gcc -g -Wall -I /usr/include/opencryptoki aws_kms_pkcs11_test.c -o aws_kms_pkcs11_test -ldl

aws_kms_pkcs11.so: aws_kms_pkcs11.cpp
	g++ -shared -fPIC -Wall -I /usr/include/opencryptoki $(CFLAGS) aws_kms_pkcs11.cpp -o aws_kms_pkcs11.so \
	    -Wl,--whole-archive \
	    $(HOME)/aws-sdk-cpp/lib/libaws-checksums.a \
	    $(HOME)/aws-sdk-cpp/lib/libaws-c-common.a \
	    $(HOME)/aws-sdk-cpp/lib/libaws-c-event-stream.a \
	    $(HOME)/aws-sdk-cpp/lib/libaws-cpp-sdk-core.a \
	    $(HOME)/aws-sdk-cpp/lib/libaws-cpp-sdk-kms.a \
	    -Wl,--no-whole-archive -lcrypto -ljson-c -lcurl

