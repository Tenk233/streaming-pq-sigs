SYMCRYPTO_SRC_COMMON = \
	mupq/common/fips202.c \
	mupq/common/sp800-185.c \
	mupq/common/nistseedexpander.c \

SYMCRYPTO_SRC = \
	$(SYMCRYPTO_SRC_COMMON) \
	common/keccakf1600.S \
	common/aes.c \
	common/aes_encrypt.S \
	common/aes_keyschedule.S \
	common/crypto_hashblocks_sha512_m3_inner32.S \
	common/crypto_hashblocks_sha512.c \
	mupq/common/sha2.c \
	common/randombytes.c

HOST_SYMCRYPTO_SRC = \
	$(SYMCRYPTO_SRC_COMMON) \
	mupq/common/keccakf1600.S \
	mupq/pqclean/common/aes.c \
	mupq/pqclean/common/sha2.c \
	mupq/pqclean/common/randombytes.c

obj/libsymcrypto.a: $(call objs,$(SYMCRYPTO_SRC))

obj/libsymcrypto-hashprof.a: CPPFLAGS+=-DPROFILE_HASHING
obj/libsymcrypto-hashprof.a: $(call hashprofobjs,$(SYMCRYPTO_SRC))

obj-host/libsymcrypto.a: $(call hostobjs,$(HOST_SYMCRYPTO_SRC))


LDLIBS += -lsymcrypto$(if $(PROFILE_HASHING),-hashprof)
LIBDEPS += obj/libsymcrypto.a obj/libsymcrypto-hashprof.a

