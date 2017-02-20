# Authentication method plugins
# (similar to how data provider plugin libs are structured and loaded)
# see current auth method plugins for example implementation

# core/auth/QgsAuthMethod.h is the abstract base class for the method
# gui/auth/QgsAuthMethodEdit.h is the abstract base class for the method's edit widget

# override default path where built files are put to allow running qgis without installing
SET (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${QGIS_OUTPUT_DIRECTORY}/${QGIS_PLUGIN_SUBDIR})
SET (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${QGIS_OUTPUT_DIRECTORY}/${QGIS_PLUGIN_SUBDIR})

IF (NOT MSVC)
  ADD_DEFINITIONS("-DAUTHMETHOD_EXPORT")
  IF ("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU" OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden")
  ENDIF()
ENDIF (NOT MSVC)
ADD_DEFINITIONS("\"-DAUTHMETHOD_EXPORT=${DLLEXPORT}\"")

# NOTE: the plugin's file name must follow this pattern to be found during auth method registry loading:
#       (.*)authmethod\.(so|dll)

SET(ENABLE_OAUTH2_PLUGIN FALSE CACHE BOOL "Enable OAuth2 authentication plugin")

ADD_SUBDIRECTORY(basic)
ADD_SUBDIRECTORY(identcert)
IF(ENABLE_OAUTH2_PLUGIN)
  ADD_SUBDIRECTORY(oauth2)
ENDIF(ENABLE_OAUTH2_PLUGIN)
IF (WIN32)
  ADD_SUBDIRECTORY(keystore)
ENDIF (WIN32)
ADD_SUBDIRECTORY(pkipaths)
ADD_SUBDIRECTORY(pkipkcs12)
