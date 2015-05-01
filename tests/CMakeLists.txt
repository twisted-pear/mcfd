add_subdirectory (src)

if (CMAKE_COMPILER_IS_GNUCC)
	set_source_files_properties ( ${S_CRYPTO_COMMON} PROPERTIES
		COMPILE_FLAGS "-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_KECCAK} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_SPONGE} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_SPONGEWRAP} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_MCFD} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage -D__MCFD_PROFILE__")
	set_source_files_properties ( ${S_SPONGEPRG} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_KECCAK_RNG} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_DUPLEX} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_CURVE25519_DONNA} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_MCFD_AUTH} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_MCFD_KDF} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")
	set_source_files_properties ( ${S_MCFD_CIPHER} PROPERTIES COMPILE_FLAGS
		"-fprofile-arcs -ftest-coverage")

	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs")
endif ()

get_property (H_TEST_UNIT_MAIN GLOBAL PROPERTY H_TEST_UNIT_MAIN)
get_property (S_TEST_UNIT_MAIN GLOBAL PROPERTY S_TEST_UNIT_MAIN)
get_property (H_LIBC_WRAPPERS GLOBAL PROPERTY H_LIBC_WRAPPERS)
get_property (S_LIBC_WRAPPERS GLOBAL PROPERTY S_LIBC_WRAPPERS)
get_property (ALLOC_LINK_FLAGS GLOBAL PROPERTY
	ALLOC_LINK_FLAGS)
get_property (LIBC_WRAPPERS_LINK_FLAGS GLOBAL PROPERTY
	LIBC_WRAPPERS_LINK_FLAGS)
macro (add_unit_test module_name misc_sources)
	STRING(TOUPPER "${module_name}" _u_name)
	STRING(TOLOWER "${module_name}" _l_name)

	set (_header_name "H_${_u_name}")
	set (_source_name "S_${_u_name}")

	set (_test_name "S_TEST_UNIT_${_u_name}")
	set (_exe_name "test_unit_${_l_name}")

	get_property (${_test_name} GLOBAL PROPERTY ${_test_name})

	add_executable (${_exe_name}
		EXCLUDE_FROM_ALL
		${${_header_name}} ${${_source_name}}
		${misc_sources}
		${${_test_name}}
		${H_LIBC_WRAPPERS} ${S_LIBC_WRAPPERS}
		${H_TEST_UNIT_MAIN} ${S_TEST_UNIT_MAIN})
	target_link_libraries (${_exe_name} cmocka)
	set_target_properties (${_exe_name} PROPERTIES LINK_FLAGS
		"${ALLOC_LINK_FLAGS} ${LIBC_WRAPPERS_LINK_FLAGS}")
	set_property (TARGET ${_exe_name} APPEND PROPERTY INCLUDE_DIRECTORIES
		"${CMAKE_CURRENT_SOURCE_DIR}/src")

	add_test (build_${_exe_name} "${CMAKE_COMMAND}" --build
		${CMAKE_BINARY_DIR} --target ${_exe_name})
	add_test (run_${_exe_name} ${_exe_name})
endmacro (add_unit_test)

add_unit_test ("crypto_common" "")
add_unit_test ("keccak" "")
add_unit_test ("sponge" "")
add_unit_test ("duplex" "")
add_unit_test ("spongeprg" "")
add_unit_test ("spongewrap" "")

add_unit_test ("mcfd_auth" "${S_CRYPTO_COMMON}")
add_unit_test ("mcfd_kdf" "${S_CRYPTO_COMMON}")
add_unit_test ("mcfd_cipher" "${S_CRYPTO_COMMON}")

get_property (S_TEST_GENKAT GLOBAL PROPERTY S_TEST_GENKAT)
get_property (S_TEST_DUPLEX GLOBAL PROPERTY S_TEST_DUPLEX)
get_property (S_TEST_SPONGEPRG GLOBAL PROPERTY S_TEST_SPONGEPRG)
get_property (S_TEST_SPONGEWRAP GLOBAL PROPERTY S_TEST_SPONGEWRAP)

get_property (S_TEST_CURVE25519 GLOBAL PROPERTY S_TEST_CURVE25519)
get_property (S_TEST_CURVE25519_NONCANON GLOBAL PROPERTY
	S_TEST_CURVE25519_NONCANON)

add_executable (test_genKAT
	EXCLUDE_FROM_ALL
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGE} ${S_SPONGE}
	${H_LIBC_WRAPPERS} ${S_LIBC_WRAPPERS}
	${S_TEST_GENKAT})
target_link_libraries (test_genKAT cmocka)
set_target_properties (test_genKAT PROPERTIES LINK_FLAGS
	"${ALLOC_LINK_FLAGS}")
add_test (build_test_genKAT "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target test_genKAT)
add_test (run_test_genKAT test_genKAT)

add_executable (test_duplex
	EXCLUDE_FROM_ALL
	${H_KECCAK} ${S_KECCAK}
	${H_DUPLEX} ${S_DUPLEX}
	${H_LIBC_WRAPPERS} ${S_LIBC_WRAPPERS}
	${S_TEST_DUPLEX})
target_link_libraries (test_duplex cmocka)
set_target_properties (test_duplex PROPERTIES LINK_FLAGS
	"${ALLOC_LINK_FLAGS}")
add_test (build_test_duplex "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target test_duplex)
add_test (run_test_duplex test_duplex)

configure_file (LongMsgKAT.txt LongMsgKAT.txt COPYONLY)
configure_file (MonteCarlo.txt MonteCarlo.txt COPYONLY)
configure_file (ShortMsgKAT.txt ShortMsgKAT.txt COPYONLY)

set (TEST_RESULT_FILES
	LongMsgKAT_224.txt LongMsgKAT_256.txt LongMsgKAT_384.txt LongMsgKAT_512.txt  
	MonteCarlo_224.txt MonteCarlo_256.txt MonteCarlo_384.txt MonteCarlo_512.txt  
	ShortMsgKAT_224.txt ShortMsgKAT_256.txt ShortMsgKAT_384.txt ShortMsgKAT_512.txt
	TestDuplex.txt)

set_directory_properties (PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
	"${TEST_RESULT_FILES}")

foreach (result_file ${TEST_RESULT_FILES})
	configure_file (test_expected/${result_file}
		test_expected/${result_file} COPYONLY)
	add_test (check_${result_file} diff -q ${result_file}
		test_expected/${result_file})
endforeach (result_file)

add_executable (test_spongeprg
	EXCLUDE_FROM_ALL
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGEPRG} ${S_SPONGEPRG}
	${H_LIBC_WRAPPERS} ${S_LIBC_WRAPPERS}
	${S_TEST_SPONGEPRG})
target_link_libraries (test_spongeprg cmocka)
set_target_properties (test_spongeprg PROPERTIES LINK_FLAGS
	"${ALLOC_LINK_FLAGS}")
add_test (build_test_spongeprg "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target test_spongeprg)
add_test (run_test_spongeprg test_spongeprg)

add_executable (test_spongewrap
	EXCLUDE_FROM_ALL
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGEWRAP} ${S_SPONGEWRAP}
	${H_LIBC_WRAPPERS} ${S_LIBC_WRAPPERS}
	${S_TEST_SPONGEWRAP})
target_link_libraries (test_spongewrap cmocka)
set_target_properties (test_spongewrap PROPERTIES LINK_FLAGS
	"${ALLOC_LINK_FLAGS}")
add_test (build_test_spongewrap "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target test_spongewrap)
add_test (run_test_spongewrap test_spongewrap)

add_executable (test_curve25519
	EXCLUDE_FROM_ALL
	${S_CURVE25519_DONNA}
	${H_LIBC_WRAPPERS} ${S_LIBC_WRAPPERS}
	${S_TEST_CURVE25519})
target_link_libraries (test_curve25519 cmocka)
set_target_properties (test_curve25519 PROPERTIES LINK_FLAGS
	"${ALLOC_LINK_FLAGS}")
add_test (build_test_curve25519 "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target test_curve25519)
add_test (run_test_curve25519 test_curve25519)

add_executable (test_curve25519_noncanon
	EXCLUDE_FROM_ALL
	${S_CURVE25519_DONNA}
	${H_LIBC_WRAPPERS} ${S_LIBC_WRAPPERS}
	${S_TEST_CURVE25519_NONCANON})
target_link_libraries (test_curve25519_noncanon cmocka)
set_target_properties (test_curve25519_noncanon PROPERTIES LINK_FLAGS
	"${ALLOC_LINK_FLAGS}")
add_test (build_test_curve25519_noncanon "${CMAKE_COMMAND}" --build
	${CMAKE_BINARY_DIR} --target test_curve25519_noncanon)
add_test (run_test_curve25519_noncanon test_curve25519_noncanon)

add_executable (mcfd_test
	EXCLUDE_FROM_ALL
	${H_CRYPTO_COMMON} ${S_CRYPTO_COMMON}
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGE} ${S_SPONGE}
	${H_SPONGEWRAP} ${S_SPONGEWRAP}
	${H_CURVE25519} ${S_CURVE25519}
	${H_MCFD} ${S_MCFD})
if (USE_SECCOMP)
	target_link_libraries (mcfd_test seccomp)
endif (USE_SECCOMP)
add_test (build_mcfd_test "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target mcfd_test)

configure_file (test_end_to_end.sh test_end_to_end.sh COPYONLY)
add_test (end_to_end test_end_to_end.sh "${CMAKE_BINARY_DIR}/tests/mcfd_test" "asdf" 5000)
