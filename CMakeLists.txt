cmake_minimum_required (VERSION 2.8)
project (MCFD) 

if (NOT CMAKE_BUILD_TYPE)
	set (CMAKE_BUILD_TYPE Debug)
endif ()

if (CMAKE_COMPILER_IS_GNUCC)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra -Wall -pedantic -std=c11 -D_XOPEN_SOURCE=500")
	set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -Werror")
endif ()

include_directories (include/curve25519)
include_directories (include/spongecrypt)
include_directories (include/mcfd)
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

get_property (H_CURVE25519 GLOBAL PROPERTY H_CURVE25519)
get_property (S_CURVE25519 GLOBAL PROPERTY S_CURVE25519)

get_property (H_MCFD GLOBAL PROPERTY H_MCFD)
get_property (S_MCFD GLOBAL PROPERTY S_MCFD)

add_executable (mcfd
	${H_CRYPTO_COMMON} ${S_CRYPTO_COMMON}
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGE} ${S_SPONGE}
	${H_SPONGEWRAP} ${S_SPONGEWRAP}
	${H_CURVE25519} ${S_CURVE25519}
	${H_MCFD} ${S_MCFD})
target_link_libraries (mcfd seccomp)

get_property (H_SPONGEPRG GLOBAL PROPERTY H_SPONGEPRG)
get_property (S_SPONGEPRG GLOBAL PROPERTY S_SPONGEPRG)

get_property (H_KECCAK_RNG GLOBAL PROPERTY H_KECCAK_RNG)
get_property (S_KECCAK_RNG GLOBAL PROPERTY S_KECCAK_RNG)

add_executable (keccak_rng
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGEPRG} ${S_SPONGEPRG}
	${H_KECCAK_RNG} ${S_KECCAK_RNG})

get_property (H_DUPLEX GLOBAL PROPERTY H_DUPLEX)
get_property (S_DUPLEX GLOBAL PROPERTY S_DUPLEX)

get_property (S_CURVE25519_DONNA GLOBAL PROPERTY S_CURVE25519_DONNA)

get_property (H_MCFD_AUTH GLOBAL PROPERTY H_MCFD_AUTH)
get_property (S_MCFD_AUTH GLOBAL PROPERTY S_MCFD_AUTH)

get_property (H_MCFD_KDF GLOBAL PROPERTY H_MCFD_KDF)
get_property (S_MCFD_KDF GLOBAL PROPERTY S_MCFD_KDF)

get_property (H_MCFD_CIPHER GLOBAL PROPERTY H_MCFD_CIPHER)
get_property (S_MCFD_CIPHER GLOBAL PROPERTY S_MCFD_CIPHER)

include (CTest)
add_subdirectory (tests)
