set (S_MCFD_KDF
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_kdf.c")
set_property (GLOBAL APPEND PROPERTY S_MCFD_KDF
	${S_MCFD_KDF})

set_property (GLOBAL APPEND PROPERTY H_MCFD
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_auth.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_common.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_cipher.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_net.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_random.h")
set_property (GLOBAL APPEND PROPERTY S_MCFD
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_auth.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_common.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_cipher.c"
	"${S_MCFD_KDF}"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_main.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_net.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_random.c")
