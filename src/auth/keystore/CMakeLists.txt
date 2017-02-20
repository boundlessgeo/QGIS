SET(AUTH_KEYSTORE_SRCS
  qgskeystoremethod.cpp
  qgskeystoreedit.cpp
  qgskeystoreutils.cpp
)

SET(AUTH_KEYSTORE_HDRS
  qgskeystoremethod.h
  qgskeystoreedit.h
  qgskeystoreutils.h
)

SET(AUTH_KEYSTORE_MOC_HDRS
  qgskeystoremethod.h
  qgskeystoreedit.h
  qgskeystoreutils.h
)

SET(AUTH_KEYSTORE_UIS qgskeystoreedit.ui)

INCLUDE_DIRECTORIES (
  ../../core
  ../../core/auth
  ../../core/geometry
)
INCLUDE_DIRECTORIES (SYSTEM
  ${QCA_INCLUDE_DIR}
)
INCLUDE_DIRECTORIES (
  ../../gui
  ../../gui/auth
  ${CMAKE_CURRENT_BINARY_DIR}
)

QT4_WRAP_UI (AUTH_KEYSTORE_UIS_H ${AUTH_KEYSTORE_UIS})

QT4_WRAP_CPP(AUTH_KEYSTORE_MOC_SRCS ${AUTH_KEYSTORE_MOC_HDRS})

ADD_LIBRARY (keystoreauthmethod SHARED ${AUTH_KEYSTORE_SRCS} ${AUTH_KEYSTORE_HDRS} ${AUTH_KEYSTORE_MOC_SRCS} ${AUTH_KEYSTORE_UIS_H})

TARGET_LINK_LIBRARIES (keystoreauthmethod
  qgis_core
  qgis_gui
  advapi32
  crypt32
  ncrypt
)

INSTALL(TARGETS keystoreauthmethod
  RUNTIME DESTINATION ${QGIS_PLUGIN_DIR}
  LIBRARY DESTINATION ${QGIS_PLUGIN_DIR})
