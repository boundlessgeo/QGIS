# OAuth 2 Authentication Method plugin

########################################################
# Packages
SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

OPTION(WITH_INTERNAL_O2 "Locally build o2 library as external project" ON)

IF(WITH_INTERNAL_O2)
  INCLUDE(External_O2)
ELSE()
  FIND_PACKAGE(O2 REQUIRED)
ENDIF()

########################################################
# Files

SET(OAUTH2_SRCS
  qgso2.cpp
  qgsauthoauth2config.cpp
  qgsauthoauth2method.cpp
  qgsauthoauth2edit.cpp
  qjsonwrapper/Json.cpp
)

SET(OAUTH2_HDRS
  qgso2.h
  qgsauthoauth2config.h
  qgsauthoauth2method.h
  qgsauthoauth2edit.h
  qjsonwrapper/Json.h
)

SET(OAUTH2_MOC_HDRS
  qgso2.h
  qgsauthoauth2config.h
  qgsauthoauth2method.h
  qgsauthoauth2edit.h
)

SET(OAUTH2_UIS qgsauthoauth2edit.ui)

SET(OAUTH2_RCCS oauth2_resources.qrc)

# Common includes
INCLUDE_DIRECTORIES (
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
)
INCLUDE_DIRECTORIES (SYSTEM
  ${QCA_INCLUDE_DIR}
  ${O2_INCLUDE_DIR}
)
INCLUDE_DIRECTORIES (
  ${CMAKE_SOURCE_DIR}/src/core
  ${CMAKE_SOURCE_DIR}/src/core/auth
  ${CMAKE_SOURCE_DIR}/src/core/geometry
  ${CMAKE_SOURCE_DIR}/src/auth/oauth2
  ${CMAKE_SOURCE_DIR}/src/gui
  ${CMAKE_SOURCE_DIR}/src/gui/auth
  ${CMAKE_BINARY_DIR}/src/core
  ${CMAKE_BINARY_DIR}/src/gui
  ${CMAKE_BINARY_DIR}/src/ui
  ${CMAKE_BINARY_DIR}/src/ui/auth
  ${CMAKE_BINARY_DIR}/src/auth/oauth2
)

QT4_WRAP_UI(OAUTH2_UIS_H ${OAUTH2_UIS})

QT4_WRAP_CPP(OAUTH2_MOC_SRCS ${OAUTH2_MOC_HDRS})

QT4_ADD_RESOURCES(OAUTH2_RCC_SRCS ${OAUTH2_RCCS})

ADD_LIBRARY (oauth2authmethod MODULE
  ${OAUTH2_SRCS}
  ${OAUTH2_HDRS}
  ${OAUTH2_MOC_SRCS}
  ${OAUTH2_RCC_SRCS}
  ${OAUTH2_UIS_H}
)

# For unit testing
ADD_LIBRARY (oauth2authmethod_static STATIC
  ${OAUTH2_SRCS}
  ${OAUTH2_HDRS}
  ${OAUTH2_MOC_SRCS}
  ${OAUTH2_RCC_SRCS}
  ${OAUTH2_UIS_H}
)

# Common linked libs
IF(NOT "${O2_LIBRARY_STATIC}" STREQUAL "")
  # prefer static linking, so newer o2 lib does not need separately packaged
  SET(OAUTH2_TARGET_LIBS ${O2_LIBRARY_STATIC})
ELSE()
  SET(OAUTH2_TARGET_LIBS ${O2_LIBRARY})
ENDIF()

#message(STATUS "OAUTH2_TARGET_LIBS: ${OAUTH2_TARGET_LIBS}")

SET(OAUTH2_TARGET_LIBS
  qgis_core
  qgis_gui
  ${OAUTH2_TARGET_LIBS}
)

TARGET_LINK_LIBRARIES (oauth2authmethod
  ${OAUTH2_TARGET_LIBS}
)
TARGET_LINK_LIBRARIES (oauth2authmethod_static
  ${OAUTH2_TARGET_LIBS}
)

IF(WITH_INTERNAL_O2)
  ADD_DEPENDENCIES(oauth2authmethod external_o2)
  ADD_DEPENDENCIES(oauth2authmethod_static external_o2)
ENDIF()

########################################################
# Install

# don't install static variant, as it's only for unit testing from build directory
INSTALL(TARGETS oauth2authmethod
  RUNTIME DESTINATION ${QGIS_PLUGIN_DIR}
  LIBRARY DESTINATION ${QGIS_PLUGIN_DIR}
)
