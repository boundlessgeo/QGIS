
########################################################
# Files

SET (sslerrorsadapter_SRCS
     sslerrorsadapter.cpp
     qgskeystoreutils.cpp
)

SET (sslerrorsadapter_MOC_HDRS
     sslerrorsadapter.h
     qgskeystoreutils.h
)

########################################################
# Build

QT4_WRAP_CPP (sslerrorsadapter_MOC_SRCS  ${sslerrorsadapter_MOC_HDRS})

QT4_ADD_RESOURCES(sslerrorsadapter_RCC_SRCS ${sslerrorsadapter_RCCS})

ADD_LIBRARY (sslerrorsadapterplugin MODULE ${sslerrorsadapter_SRCS} ${sslerrorsadapter_MOC_SRCS})

INCLUDE_DIRECTORIES(
     ${CMAKE_CURRENT_BINARY_DIR}
     ../../core ../../core/geometry ../../core/raster
     ../../gui
     ..
)

INCLUDE_DIRECTORIES (SYSTEM
  ${QCA_INCLUDE_DIR}
)
INCLUDE_DIRECTORIES(
     ${QGIS_APP_HDRS}
     ${QGIS_APP_MOC_HDRS}
     ../../app
     ../../core/auth
)

TARGET_LINK_LIBRARIES(sslerrorsadapterplugin
  qgis_core
  qgis_gui
  advapi32
  crypt32
)


########################################################
# Install

INSTALL(TARGETS sslerrorsadapterplugin
  RUNTIME DESTINATION ${QGIS_PLUGIN_DIR}
  LIBRARY DESTINATION ${QGIS_PLUGIN_DIR})

