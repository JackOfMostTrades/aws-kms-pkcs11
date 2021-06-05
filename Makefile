all: aws_kms_pkcs11.so

clean:
	rm -f aws_kms_pkcs11.so aws_kms_pkcs11_test aws_kms_client_test

test: aws_kms_pkcs11_test certificates_test
	./certificates_test
	AWS_KMS_PKCS11_DEBUG=1 ./aws_kms_pkcs11_test

certificates_test: certificates.cpp certificates_test.cpp
	g++ -g -Wall certificates.cpp certificates_test.cpp -o certificates_test -lcrypto

aws_kms_pkcs11_test: aws_kms_pkcs11_test.c aws_kms_pkcs11.so
	gcc -g -Wall -I /usr/include/opencryptoki aws_kms_pkcs11_test.c -o aws_kms_pkcs11_test -ldl

aws_kms_pkcs11.so: aws_kms_pkcs11.cpp unsupported.cpp aws_kms_slot.cpp debug.cpp attributes.cpp certificates.cpp
	g++ -shared -fPIC -Wall -I /usr/include/opencryptoki -I$(HOME)/aws-sdk-cpp/include -fno-exceptions -std=c++17 attributes.cpp aws_kms_pkcs11.cpp certificates.cpp unsupported.cpp debug.cpp aws_kms_slot.cpp -o aws_kms_pkcs11.so \
	    -Wl,--whole-archive \
	    $(HOME)/aws-sdk-cpp/lib/libaws-checksums.a \
	    $(HOME)/aws-sdk-cpp/lib/libaws-c-common.a \
	    $(HOME)/aws-sdk-cpp/lib/libaws-c-event-stream.a \
	    $(HOME)/aws-sdk-cpp/lib/libaws-cpp-sdk-core.a \
	    $(HOME)/aws-sdk-cpp/lib/libaws-cpp-sdk-kms.a \
	    -Wl,--no-whole-archive -lcrypto -ljson-c -lcurl

install: aws_kms_pkcs11.so
	cp aws_kms_pkcs11.so /usr/lib/x86_64-linux-gnu/pkcs11/

uninstall:
	rm -f /usr/lib/x86_64-linux-gnu/pkcs11/aws_kms_pkcs11.so
