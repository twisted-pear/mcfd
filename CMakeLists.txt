cmake_minimum_required (VERSION 2.6)
project (MCFD) 

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -std=c99 -D_XOPEN_SOURCE=500")

include_directories (include/spongecrypt/keccak)
include_directories (include/spongecrypt)
add_subdirectory (include)

add_subdirectory (src)

get_property (H_CRYPTO_COMMON GLOBAL PROPERTY H_CRYPTO_COMMON)
get_property (S_CRYPTO_COMMON GLOBAL PROPERTY S_CRYPTO_COMMON)

get_property (H_KECCAK GLOBAL PROPERTY H_KECCAK)
get_property (S_KECCAK GLOBAL PROPERTY S_KECCAK)

get_property (H_SPONGE GLOBAL PROPERTY H_SPONGE)
get_property (S_SPONGE GLOBAL PROPERTY S_SPONGE)

get_property (H_SPONGEWRAP GLOBAL PROPERTY H_SPONGEWRAP)
get_property (S_SPONGEWRAP GLOBAL PROPERTY S_SPONGEWRAP)

get_property (H_MCFD GLOBAL PROPERTY H_MCFD)
get_property (S_MCFD GLOBAL PROPERTY S_MCFD)

add_executable (mcfd
	${H_CRYPTO_COMMON} ${S_CRYPTO_COMMON}
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGE} ${S_SPONGE}
	${H_SPONGEWRAP} ${S_SPONGEWRAP}
	${H_MCFD} ${S_MCFD})

get_property (H_SPONGEPRG GLOBAL PROPERTY H_SPONGEPRG)
get_property (S_SPONGEPRG GLOBAL PROPERTY S_SPONGEPRG)

get_property (H_KECCAK_RNG GLOBAL PROPERTY H_KECCAK_RNG)
get_property (S_KECCAK_RNG GLOBAL PROPERTY S_KECCAK_RNG)

add_executable (keccak_rng
	${H_CRYPTO_COMMON} ${S_CRYPTO_COMMON}
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGEPRG} ${S_SPONGEPRG}
	${H_KECCAK_RNG} ${S_KECCAK_RNG})

enable_testing ()
include_directories (src/tests)
add_subdirectory (tests)
