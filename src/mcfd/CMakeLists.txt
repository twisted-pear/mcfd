set_property (GLOBAL APPEND PROPERTY H_MCFD
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_auth.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_common.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_crypto.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_net.h")
set_property (GLOBAL APPEND PROPERTY S_MCFD
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_auth.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_common.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_crypto.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_main.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/mcfd_net.c")
