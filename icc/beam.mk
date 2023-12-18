#
# Run the beam static analysis tool over ICC sources
# Used to do it as part of the build, but too hard
#

BEAM		= beam_compile

BEAM_FLAGS	= --beam::prefixcc 

CC		= gcc

CFLAGS		= -I./ -I../openssl-1.0.1/include

RUN_BEAM  =	$(BEAM) $(BEAM_FLAGS) $(CC) $(CFLAGS)

all: icc.beam icclib.beam fips.beam status.beam \
	icc_rand.beam platform.beam platfsl.beam \
	icctest.beam  \
	fips-prng/SP800-90.beam fips-prng/SP800-90HMAC.beam \
	fips-prng/SP800-90HashData.beam fips-prng/SP800-90Cipher.beam \
	fips-prng/SP800-90TRNG.beam fips-prng/fips-dss-prng.beam \
	fips-prng/fips-prng-RAND.beam fips-prng/fips-prng-err.beam \
	fips-prng/ds.beam fips-prng/utils.beam

.SUFFIXES: .beam .c

.c.beam :
	echo "$<" >>beam.log
	$(RUN_BEAM) $<  2>&1 1>>beam.log

icc.beam: icc.c	

icc_rand.beam: icc_rand.c

platform.beam: platform.c
platfsl.beam: platfsl.c
icctest.beam: icctest.c


icclib.beam: icclib.c

fips.beam: fips.c

status.beam: status.c



fips-prng/ds.beam: fips-prng/ds.c
fips-prng/utils.beam: fips-prng/utils.c

fips-prng/SP800-90.beam: fips-prng/SP800-90.c

fips-prng/SP800-90HMAC.beam: fips-prng/SP800-90HMAC.c

fips-prng/SP800-90TRNG.beam: fips-prng/SP800-90TRNG.c

fips-prng/SP800-90Cipher.beam: fips-prng/SP800-90Cipher.c

fips-prng/SP800-90HashData.beam: fips-prng/SP800-90HashData.c

fips-prng/fips-dss-prng.beam: fips-prng/fips-dss-prng.c

fips-prng/fips-prng-RAND.beam: fips-prng/fips-prng-RAND.c

fips-prng/fips-prng-err.beam: fips-prng/fips-prng-err.c

clean: 
	rm *.beam fips-prng/*.beam beam.log
