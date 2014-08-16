find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})

add_subdirectory (src)

get_property (S_TEST_GENKAT GLOBAL PROPERTY S_TEST_GENKAT)
get_property (S_TEST_DUPLEX GLOBAL PROPERTY S_TEST_DUPLEX)
get_property (S_TEST_SPONGEWRAP GLOBAL PROPERTY S_TEST_SPONGEWRAP)
get_property (S_TEST_SPONGEPRG GLOBAL PROPERTY S_TEST_SPONGEPRG)

add_executable (test_genKAT
	EXCLUDE_FROM_ALL
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGE} ${S_SPONGE}
	${S_TEST_GENKAT})
add_test (build_test_genKAT "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target test_genKAT)
add_test (run_test_genKAT test_genKAT)

add_executable (test_duplex
	EXCLUDE_FROM_ALL
	${H_KECCAK} ${S_KECCAK}
	${H_DUPLEX} ${S_DUPLEX}
	${S_TEST_DUPLEX})
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

add_executable (test_spongewrap
	EXCLUDE_FROM_ALL
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGEWRAP} ${S_SPONGEWRAP}
	${S_TEST_SPONGEWRAP})
add_test (build_test_spongewrap "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target test_spongewrap)
add_test (run_test_spongewrap test_spongewrap)

add_executable (test_spongeprg
	EXCLUDE_FROM_ALL
	${H_KECCAK} ${S_KECCAK}
	${H_SPONGEPRG} ${S_SPONGEPRG}
	${S_TEST_SPONGEPRG})
add_test (build_test_spongeprg "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR}
	--target test_spongeprg)
add_test (run_test_spongeprg test_spongeprg)
