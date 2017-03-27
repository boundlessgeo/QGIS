# External Project for o2 Library
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copyright (c) 2017, Larry Shaffer, <lshaffer (at) boundlessgeo (dot) com>
#
# Builds a static o2 library based off of Qt5
# Official source code repository: https://github.com/pipacs/o2
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

include(ExternalProject)

# NOTE: These are temporary source code provenance endpoints, until necessary
#       commits are done upstream to support the OAuth2 plugin

set(_o2_url "https://github.com/MonsantoCo/o2/archive/o2-monsanto-features.tar.gz")
set(_o2_md5 e8cfe993e0312180423101f879db4fa7)

set(_o2_git_repo "https://github.com/MonsantoCo/o2")
set(_o2_git_branch "o2-monsanto-features")

set(_o2_prefix ${CMAKE_CURRENT_BINARY_DIR}/o2)

if(MSVC)
  # TODO: ExternalProject_Add(external_o2 ... )

  # this will probably need prefixed with build type subdirectory
  set(_o2_static_lib o2.lib)
else(UNIX)
  ExternalProject_Add(external_o2
    PREFIX ${_o2_prefix}
    #URL ${_o2_url}
    #URL_MD5 ${_o2_md5}
    GIT_REPOSITORY ${_o2_git_repo}
    GIT_TAG ${_o2_git_branch}
    CMAKE_CACHE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
    -DCMAKE_PREFIX_PATH:STRING=${CMAKE_PREFIX_PATH}
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
    -DBUILD_SHARED_LIBS:BOOL=OFF
    -Do2_WITH_QT5:BOOL=ON
    LOG_DOWNLOAD 1
    LOG_CONFIGURE 1
    LOG_BUILD 1
    LOG_INSTALL 1
  )
  set(_o2_static_lib libo2.a)
endif()

# These match variables set by FindO2.cmake
set(O2_INCLUDE_DIR ${_o2_prefix}/include/o2 CACHE INTERNAL "Path to o2 library headers" FORCE)
set(O2_LIBRARY "" CACHE INTERNAL "Path to o2 shared library" FORCE)
set(O2_LIBRARY_STATIC ${_o2_prefix}/lib/${_o2_static_lib} CACHE INTERNAL "Path to o2 static library" FORCE)
set(O2_FOUND TRUE CACHE INTERNAL "Whether O2 has been found" FORCE)

# Add a dummy static file so that linking against this works for other targets
# during their configuring, which occurs BEFORE this external project is built
execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${_o2_prefix}/lib)
execute_process(COMMAND ${CMAKE_COMMAND} -E touch ${O2_LIBRARY_STATIC})
