add_subdirectory (src)

get_property (S_TEST_GENKAT GLOBAL PROPERTY S_TEST_GENKAT)
get_property (S_TEST_DUPLEX GLOBAL PROPERTY S_TEST_DUPLEX)
get_property (S_TEST_SPONGEWRAP GLOBAL PROPERTY S_TEST_SPONGEWRAP)
get_property (S_TEST_SPONGEPRG GLOBAL PROPERTY S_TEST_SPONGEPRG)

add_executable (keccak_test
	EXCLUDE_FROM_ALL
	${H_CRYPTO_COMMON} ${S_CRYPTO_COMMON}
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGE} ${S_SPONGE}
	${H_SPONGEWRAP} ${S_SPONGEWRAP}
	${H_SPONGEPRG} ${S_SPONGEPRG}
	${S_TEST_GENKAT}
	${S_TEST_DUPLEX}
	${S_TEST_SPONGEWRAP}
	${S_TEST_SPONGEPRG}
	"${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")

add_test (build_keccak_test "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target keccak_test)
add_test (run_keccak_test keccak_test)

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
