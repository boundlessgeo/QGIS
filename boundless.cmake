INCLUDE ("@CMAKE_BINARY_DIR@/mac/0vars.cmake")
INCLUDE ("@CMAKE_SOURCE_DIR@/cmake/MacBundleMacros.cmake")

# Global lib paths
SET (BUILD_PATH "/opt/qgis_deps")
SET (BUILD_FW "${BUILD_PATH}/Frameworks")
SET (BUILD_PYTHON "${BUILD_PATH}/python")
SET (BUILD_SITE_PKGS "${BUILD_PYTHON}/site-packages")
SET (BUILD_LIB_PATH "${BUILD_PATH}/lib")
SET (BUNDLE_LIB_PATH "@executable_path/lib")
get_filename_component(BUNDLE_CONTENTS "${QAPPDIR}/.." REALPATH)
SET (BUNDLE_MACOS "${BUNDLE_CONTENTS}/MacOS")
SET (BUNDLE_BIN "${BUNDLE_MACOS}/bin")
SET (BUNDLE_LIB "${BUNDLE_MACOS}/lib")
SET (BUNDLE_FW "${BUNDLE_CONTENTS}/Frameworks")
SET (BUNDLE_PLUGINS "${BUNDLE_CONTENTS}/Plugins")
SET (BUNDLE_RESOURCES "${BUNDLE_CONTENTS}/Resources")
SET (BUNDLE_PYTHON "${BUNDLE_RESOURCES}/python")

# TODO: pass these versions or query them somehow
SET (QT_VER "4.8.6")
SET (QT_FW "/Library/Frameworks")
SET (QWT_VER "6.0.2")
SET (QWT_FW "/usr/local/qwt-6.0.2/lib")
SET (GRASS_BUILD_PATH "${BUILD_PATH}/grass-6.4.4")
SET (G6_PREFIX_NAME "grass6")
SET (G6_PREFIX "${BUNDLE_RESOURCES}/${G6_PREFIX_NAME}")
SET (GRASS7_BUILD_PATH "${BUILD_PATH}/grass-7.0.0")
SET (G7_PREFIX_NAME "grass7")
SET (G7_PREFIX "${BUNDLE_RESOURCES}/${G6_PREFIX_NAME}")

SET (NON_MACH_CACHE)
SET (MACH_CACHE)

MESSAGE (STATUS "Starting boundless.cmake bundling...")

# Check whether the file is a Mach-O derivative
FUNCTION (IS_MACH_O ITEM OUTVAR)
  IF (EXISTS "${ITEM}")
    EXECUTE_PROCESS (COMMAND file "${ITEM}" OUTPUT_VARIABLE file_out ERROR_QUIET)
    STRING (REGEX MATCH ".*:.*Mach-O" mach_o "${file_out}")
    IF (NOT mach_o)
      # get_filename_component(item_name "${ITEM}" NAME)
      # MESSAGE (STATUS "Not a Mach-O file: ${item_name}")
      SET (${OUTVAR} FALSE PARENT_SCOPE)
    ELSE()
      SET (${OUTVAR} TRUE PARENT_SCOPE)
    ENDIF()
  ELSE()
    SET (${OUTVAR} FALSE PARENT_SCOPE)
  ENDIF ()
ENDFUNCTION (IS_MACH_O)

# Same as global INSTALLNAMETOOL_CHANGE but errors are silenced so we don't get bombarded with errors on directories
FUNCTION (INSTALLNAMETOOL_CHANGE_NO_ERR CHANGE CHANGETO CHANGEBIN)
  LIST(FIND NON_MACH_CACHE "${CHANGEBIN}" find_non_res)
  IF (find_non_res GREATER -1)
    RETURN()
  ENDIF ()

  LIST(FIND MACH_CACHE "${CHANGEBIN}" find_res)
  IF (find_res EQUAL -1)
    IS_MACH_O(${CHANGEBIN} mach_o)
    IF (NOT mach_o)
      LIST(APPEND NON_MACH_CACHE "${CHANGEBIN}")
      RETURN()
    ELSE()
      LIST(APPEND MACH_CACHE "${CHANGEBIN}")
    ENDIF ()
  ENDIF ()

  IF (EXISTS "${CHANGEBIN}" AND CHANGE AND CHANGETO)
    # ensure CHANGEBIN is writable by user, e.g. Homebrew binaries are installed non-writable
    EXECUTE_PROCESS (COMMAND chmod u+w "${CHANGEBIN}")
    EXECUTE_PROCESS (COMMAND install_name_tool -change ${CHANGE} ${CHANGETO} "${CHANGEBIN}" ERROR_QUIET)
  ENDIF ()
ENDFUNCTION (INSTALLNAMETOOL_CHANGE_NO_ERR)


# Modified version of global GET_INSTALL_NAME
FUNCTION (INSTALL_NAME LIBFILE OUTVAR)
  IF (EXISTS "${LIBFILE}")
    EXECUTE_PROCESS (COMMAND otool -D "${LIBFILE}" OUTPUT_VARIABLE iname_out ERROR_QUIET)

    STRING (REGEX MATCH "not an object file" not_mach_obj "${iname_out}")
    IF (not_mach_obj)
      get_filename_component(lib_name "${LIBFILE}" NAME)
      MESSAGE (STATUS "Obj tool - not a Mach-O file: ${lib_name}")
      SET ("" out)
    ELSE()
      # Extract second line of output which contains the lib id
      STRING (REGEX REPLACE ".*:\n" "" iname "${iname_out}")
      # Make sure there is an actual install name
      STRING (COMPARE EQUAL "${iname}" "" result)
      IF (result)
        #get_filename_component(file_name "${LIBFILE}" NAME)
        #MESSAGE (STATUS "No install name for ${file_name}")
        SET ("" out)
      ELSE()
        STRING (STRIP ${iname} out)
      ENDIF()
    ENDIF()
    SET (${OUTVAR} ${out} PARENT_SCOPE)
  ELSE ()
    SET (${OUTVAR} "" PARENT_SCOPE)
  ENDIF ()
ENDFUNCTION (INSTALL_NAME)

# Ensure IDs are correct
FUNCTION (INSTALLNAMETOOL_SET_ID ID LIBRARY)
  IF (EXISTS "${LIBRARY}" AND ID)
    EXECUTE_PROCESS (COMMAND chmod u+w "${LIBRARY}")
    EXECUTE_PROCESS (COMMAND install_name_tool -id ${ID} "${LIBRARY}")
  ENDIF ()
ENDFUNCTION (INSTALLNAMETOOL_SET_ID)

# Ensure bundled dylibs all point to the right place. Based on global UPDATEQGISPATHS fn.
FUNCTION (UPDATELOCALPATHS LIBFROM LIBTO)
  # Update the lib path for dylibs in /lib
  FILE (GLOB files "${QLIBDIR}/*")
  FOREACH (file ${files})
    INSTALLNAMETOOL_CHANGE_NO_ERR(${LIBFROM} ${LIBTO} ${file})
  ENDFOREACH()

  # Update the lib path for bins in /bin
  FILE (GLOB files "${QLIBDIR}/../bin/*")
  FOREACH (file ${files})
    INSTALLNAMETOOL_CHANGE_NO_ERR(${LIBFROM} ${LIBTO} ${file})
  ENDFOREACH()

  # Update the lib path for dylibs in framework root
  FILE (GLOB files "${QFWDIR}/*.framework/*")
  FOREACH (file ${files})
    INSTALLNAMETOOL_CHANGE_NO_ERR(${LIBFROM} ${LIBTO} ${file})
  ENDFOREACH()

  # Update the lib path for dylibs in framework internals
  FILE (GLOB files "${QFWDIR}/*.framework/Versions/*")
  FOREACH (file ${files})
    INSTALLNAMETOOL_CHANGE_NO_ERR(${LIBFROM} ${LIBTO} ${file})
  ENDFOREACH()

ENDFUNCTION (UPDATELOCALPATHS)

# re-link libs
# TODO: figure out why wildcards don't work in COMMAND so we can get rid of this loop.
MESSAGE (STATUS "Copying dylibs to ${QLIBDIR}...")
FILE (GLOB files "${BUILD_LIB_PATH}/*.dylib")
SET (dylib_filter "lib(wx|saga).*")  # <---------------------------------------------- clear this when bundling SAGA
FOREACH (build_file ${files})
  get_filename_component(fname "${build_file}" NAME)
  STRING (REGEX MATCH "${dylib_filter}" dylib_filtered "${fname}")
  IF (NOT dylib_filtered)
    IF (NOT IS_SYMLINK ${build_file})
      EXECUTE_PROCESS (COMMAND ditto "${build_file}" "${QLIBDIR}")
    ELSE ()
      EXECUTE_PROCESS (COMMAND cp -a "${build_file}" "${QLIBDIR}")
    ENDIF ()
  ENDIF ()
ENDFOREACH ()

# Unclear why this dylib does not get copied in above loop
EXECUTE_PROCESS (COMMAND cp "${BUILD_LIB_PATH}/libgeos_c.1.dylib" "${QLIBDIR}")

# Copy OTB for processing
# MESSAGE (STATUS "Copying OTB...")
# FILE (GLOB otb_binaries "${BUILD_LIB_PATH}/../bin/otb*")
# FOREACH (bin ${otb_binaries})
#   EXECUTE_PROCESS (COMMAND ditto ${bin} "${QLIBDIR}/../bin")
# ENDFOREACH ()
# FILE (GLOB otb_libs "${BUILD_LIB_PATH}/../lib/otb/*.dylib")
# FOREACH (lib ${otb_libs})
#   IF (NOT IS_SYMLINK ${lib})
#     EXECUTE_PROCESS (COMMAND ditto ${lib} "${QLIBDIR}")
#   ENDIF ()
# ENDFOREACH ()
# FILE (GLOB otb_app_libs "${BUILD_LIB_PATH}/../lib/otb/applications/*.dylib")
# FOREACH (lib ${otb_app_libs})
#   IF (NOT IS_SYMLINK ${lib})
#     EXECUTE_PROCESS (COMMAND ditto ${lib} "${QLIBDIR}")
#   ENDIF ()
# ENDFOREACH ()

# SAGA
# MESSAGE (STATUS "Copying SAGA...")
# EXECUTE_PROCESS (COMMAND ditto "${BUILD_LIB_PATH}/../bin/saga_cmd" "${QLIBDIR}/../bin")
# FILE (GLOB saga_libs "${BUILD_LIB_PATH}/../lib/saga/*.dylib")
# FOREACH (lib ${saga_libs})
#   IF (NOT IS_SYMLINK ${lib})
#     EXECUTE_PROCESS (COMMAND ditto ${lib} "${QLIBDIR}")
#   ENDIF ()
# ENDFOREACH ()

# Copy GDAL binaries for processing
MESSAGE (STATUS "Copying gdal...")
FILE (GLOB gdal_binaries "${BUILD_LIB_PATH}/../bin/gdal*")
FOREACH (bin ${gdal_binaries})
  EXECUTE_PROCESS (COMMAND ditto ${bin} "${QLIBDIR}/../bin")
ENDFOREACH ()
FILE (GLOB ogr_binaries "${BUILD_LIB_PATH}/../bin/ogr*")
FOREACH (bin ${ogr_binaries})
  EXECUTE_PROCESS (COMMAND ditto ${bin} "${QLIBDIR}/../bin")
ENDFOREACH ()

# Needs to be in Resources, for codesigning
EXECUTE_PROCESS (COMMAND mkdir "${BUNDLE_RESOURCES}/share")
EXECUTE_PROCESS (COMMAND cp -a "${BUILD_LIB_PATH}/../share/gdal" "${BUNDLE_RESOURCES}/share/gdal")
EXECUTE_PROCESS (COMMAND cp -a "${BUILD_LIB_PATH}/../share/proj" "${BUNDLE_RESOURCES}/share/proj")
EXECUTE_PROCESS (COMMAND ln -fs "../Resources/share" "${BUNDLE_MACOS}/share")

# Copy both versions of GRASS
# Need to be in Resources, for codesigning (works on OS X 10.10, but putting code in Resources is deprecated)
MESSAGE (STATUS "Copying grass...")
EXECUTE_PROCESS (COMMAND cp -a "${GRASS_BUILD_PATH}" "${G6_PREFIX}")
EXECUTE_PROCESS (COMMAND ln -fs "../Resources/${G6_PREFIX_NAME}" "${BUNDLE_MACOS}/grass")
# copy and fix up launch script, then create sh script symlink for Processing
EXECUTE_PROCESS (COMMAND cp -a "${BUILD_PATH}/bin/grass64" "${G6_PREFIX}/")
SET (grass64_bin "${G6_PREFIX}/grass64")
FILE (READ ${grass64_bin} grass64_content)
STRING (REPLACE "${GRASS_BUILD_PATH}" "$(dirname \"$0\")" grass64_mod_content "${grass64_content}")
FILE (WRITE ${grass64_bin} "${grass64_mod_content}")
EXECUTE_PROCESS (COMMAND ln -fs "grass64" "${G6_PREFIX}/grass.sh")

# MESSAGE (STATUS "Copying grass7...")
# EXECUTE_PROCESS (COMMAND cp -a "${GRASS7_BUILD_PATH}" "${G7_PREFIX}/grass7")
# TODO: copy and fix up launch script

# re-link GRASS6
MESSAGE (STATUS "Re-linking grass libs...")
STRING (TIMESTAMP grass_start)
# get list of dylibs stripped of version numbers, then list without extension
FILE (GLOB g6_liblist RELATIVE "${G6_PREFIX}/lib" "${G6_PREFIX}/lib/lib*.dylib")
STRING (REGEX REPLACE "lib[^.;]*\\.[0-9.]*\\.dylib" "" g6_dyliblist "${g6_liblist}")
STRING (REGEX REPLACE "\\.dylib" "" g6_libs "${g6_dyliblist}")

FILE (GLOB g6_binlist "${G6_PREFIX}/bin/*")
FILE (GLOB_RECURSE driverlist "${G6_PREFIX}/driver/*")
SET (g6_driverlist)
FOREACH (driver ${driverlist})
  IF (NOT IS_DIRECTORY "${driver}")
    IS_MACH_O("${driver}" mach_o)
    IF (mach_o)
      LIST (APPEND g6_driverlist "${driver}")
    ENDIF ()
  ENDIF ()
ENDFOREACH ()
FILE (GLOB_RECURSE etclist "${G6_PREFIX}/etc/*")
SET (g6_etclist)
FOREACH (etc ${etclist})
  IF (NOT IS_DIRECTORY "${etc}")
    IS_MACH_O("${etc}" mach_o)
    IF (mach_o)
      LIST (APPEND g6_etclist "${etc}")
    ENDIF ()
  ENDIF ()
ENDFOREACH ()
FILE (GLOB qgis_gmodslist "${BUNDLE_LIB}/qgis/grass/modules/*")

# first, fix up grass libs
FOREACH (glib ${g6_libs})
  IF (glib)
    MESSAGE (STATUS "  ${glib}.dylib...")
    GET_INSTALL_NAME ("${GRASS_BUILD_PATH}/lib/${glib}.dylib" "${glib}" glib_id)
    # resolve any symlinks to versioned dylib
    SET (ver_dylib "${glib}.dylib")
    SET (dylib_path "${G6_PREFIX}/lib/${ver_dylib}")
    IF ( IS_SYMLINK "${dylib_path}" )
      get_filename_component(dylib_path "${dylib_path}" REALPATH)
      get_filename_component(ver_dylib "${dylib_path}" NAME)
    ENDIF ()
    INSTALLNAMETOOL_SET_ID ("@rpath/${ver_dylib}" "${G6_PREFIX}/lib/${glib}.dylib")

    FOREACH (dlib ${g6_dyliblist})
      IF (dlib)
        INSTALLNAMETOOL_CHANGE ("${glib_id}" "${ATLOADER}/${ver_dylib}" "${G6_PREFIX}/lib/${dlib}")
      ENDIF ()
    ENDFOREACH ()

    FOREACH (bin ${g6_binlist})
      INSTALLNAMETOOL_CHANGE ("${glib_id}" "${ATLOADER}/../lib/${ver_dylib}" "${bin}")
    ENDFOREACH ()

    FOREACH (driver ${g6_driverlist})
      get_filename_component(driver_dir "${driver}" DIRECTORY)
      FILE (RELATIVE_PATH driver_relpath "${driver_dir}" "${G6_PREFIX}/lib/${ver_dylib}")
      INSTALLNAMETOOL_CHANGE ("${glib_id}" "${ATLOADER}/${driver_relpath}" "${driver}")
    ENDFOREACH ()

    FOREACH (etc ${g6_etclist})
      get_filename_component(etc_dir "${etc}" DIRECTORY)
      FILE (RELATIVE_PATH etc_relpath "${etc_dir}" "${G6_PREFIX}/lib/${ver_dylib}")
      INSTALLNAMETOOL_CHANGE ("${glib_id}" "${ATLOADER}/${etc_relpath}" "${etc}")
    ENDFOREACH ()

    # QGIS's grass6 framework and plugins
    FILE (RELATIVE_PATH qg_fwk_relpath "${BUNDLE_FW}/qgisgrass6.framework" "${G6_PREFIX}/lib/${ver_dylib}")
    INSTALLNAMETOOL_CHANGE ("${glib_id}" "${ATLOADER}/${qg_fwk_relpath}" "${BUNDLE_FW}/qgisgrass6.framework/qgisgrass")

    FILE (GLOB plugins "${BUNDLE_PLUGINS}/qgis/libgrass*.so")
    FOREACH (plugin ${plugins})
      FILE (RELATIVE_PATH plugin_relpath "${BUNDLE_PLUGINS}/qgis" "${G6_PREFIX}/lib/${ver_dylib}")
      INSTALLNAMETOOL_CHANGE("${glib_id}" "${ATLOADER}/${plugin_relpath}" "${plugin}")
    ENDFOREACH()

    FOREACH (mod ${qgis_gmodslist})
      FILE (RELATIVE_PATH mod_relpath "${BUNDLE_LIB}/qgis/grass/modules" "${G6_PREFIX}/lib/${ver_dylib}")
      INSTALLNAMETOOL_CHANGE("${glib_id}" "${ATLOADER}/${mod_relpath}" "${mod}")
    ENDFOREACH()

  ENDIF ()
ENDFOREACH()
STRING (TIMESTAMP grass_end)
MESSAGE (STATUS "${grass_start} -> ${grass_end}")

MESSAGE (STATUS "Re-linking libs to grass...")
STRING (TIMESTAMP lib2grass_start)
# now for bundled basic libs
FOREACH (blib
  "libcairo.2"
  "libfreetype.6"
  "libgdal.1"
  "libgdal.20"
  "libgeos-3.4.2"
  "libgeos_c.1"
  "libhistory.6"
  "libintl.8"
  "libpng16.16"
  "libproj.9"
  "libreadline.6"
  "libtiff.3"
)
  MESSAGE (STATUS "  ${blib}.dylib...")
  GET_INSTALL_NAME ("${BUILD_LIB_PATH}/${blib}.dylib" "${blib}" blib_id)

  FOREACH (dlib ${g6_dyliblist})
    IF (dlib)
      FILE (RELATIVE_PATH lib_relpath "${G6_PREFIX}/lib" "${BUNDLE_LIB}/${blib}.dylib")
      INSTALLNAMETOOL_CHANGE ("${blib_id}" "${ATLOADER}/${lib_relpath}" "${G6_PREFIX}/lib/${dlib}")
    ENDIF ()
  ENDFOREACH ()

  FOREACH (bin ${g6_binlist})
    FILE (RELATIVE_PATH bin_relpath "${G6_PREFIX}/bin" "${BUNDLE_LIB}/${blib}.dylib")
    INSTALLNAMETOOL_CHANGE ("${blib_id}" "${ATLOADER}/${bin_relpath}" "${bin}")
  ENDFOREACH ()

  FOREACH (driver ${g6_driverlist})
    get_filename_component(driver_dir "${driver}" DIRECTORY)
    FILE (RELATIVE_PATH driver_relpath "${driver_dir}" "${BUNDLE_LIB}/${blib}.dylib")
    INSTALLNAMETOOL_CHANGE ("${blib_id}" "${ATLOADER}/${driver_relpath}" "${driver}")
  ENDFOREACH ()

  FOREACH (etc ${g6_etclist})
    get_filename_component(etc_dir "${etc}" DIRECTORY)
    FILE (RELATIVE_PATH etc_relpath "${etc_dir}" "${BUNDLE_LIB}/${blib}.dylib")
    INSTALLNAMETOOL_CHANGE ("${blib_id}" "${ATLOADER}/${etc_relpath}" "${etc}")
  ENDFOREACH ()

  # QGIS's grass framework and plugins, which, as of 2.8.2, only work with GRASS6
#   FILE (RELATIVE_PATH qg_fwk_relpath "${QFWDIR}/qgisgrass.framework" "${QLIBDIR}/${blib}.dylib")
#   INSTALLNAMETOOL_CHANGE ("${blib_id}" "${ATLOADER}/${qg_fwk_relpath}" "${QFWDIR}/qgisgrass.framework/qgisgrass")

  FILE (GLOB plugins "${BUNDLE_PLUGINS}/qgis/libgrass*.so")
  FOREACH (plugin ${plugins})
    FILE (RELATIVE_PATH plugin_relpath "${BUNDLE_PLUGINS}/qgis" "${BUNDLE_LIB}/${blib}.dylib")
    INSTALLNAMETOOL_CHANGE("${blib_id}" "${ATLOADER}/${plugin_relpath}" "${plugin}")
  ENDFOREACH()

  FOREACH (mod ${qgis_gmodslist})
    FILE (RELATIVE_PATH mod_relpath "${BUNDLE_LIB}/qgis/grass/modules" "${BUNDLE_LIB}/${blib}.dylib")
    INSTALLNAMETOOL_CHANGE("${blib_id}" "${ATLOADER}/${mod_relpath}" "${mod}")
  ENDFOREACH()

ENDFOREACH()
STRING (TIMESTAMP lib2grass_end)
MESSAGE (STATUS "${lib2grass_start} -> ${lib2grass_end}")


MESSAGE (STATUS "Re-linking base dylibs...")
STRING (TIMESTAMP baselibs_start)
# get list of base dylibs stripped of version numbers
FILE (GLOB liblist RELATIVE "${BUNDLE_LIB}" "${BUNDLE_LIB}/lib*.dylib")
STRING (REGEX REPLACE "lib[^.;]*\\.[0-9.]*\\.dylib" "" dyliblist "${liblist}")

FILE (GLOB bndl_bins "${BUNDLE_BIN}/*")
SET (binlist)
FOREACH (bin ${bndl_bins})
  IF (NOT IS_DIRECTORY "${bin}" AND NOT IS_SYMLINK "${bin}")
    IS_MACH_O("${bin}" mach_o)
    IF (mach_o)
      LIST (APPEND binlist "${bin}")
    ENDIF ()
  ENDIF ()
ENDFOREACH ()

FILE (GLOB bndl_fwks "${BUNDLE_FW}/*.framework/*")
SET (fwklist)
FOREACH (fwk_lib ${bndl_fwks})
  IF (NOT IS_DIRECTORY "${fwk_lib}" AND NOT IS_SYMLINK "${fwk_lib}")
    IS_MACH_O("${fwk_lib}" mach_o)
    IF (mach_o)
      LIST (APPEND fwklist "${fwk_lib}")
    ENDIF ()
  ENDIF ()
ENDFOREACH ()

FILE (GLOB bndl_fwkvs "${BUNDLE_FW}/*.framework/Versions/*")
SET (fwkvlist)
FOREACH (fwkv_lib ${bndl_fwkvs})
  IF (NOT IS_DIRECTORY "${fwkv_lib}" AND NOT IS_SYMLINK "${fwkv_lib}")
    IS_MACH_O("${fwkv_lib}" mach_o)
    IF (mach_o)
      LIST (APPEND fwkvlist "${fwkv_lib}")
    ENDIF ()
  ENDIF ()
ENDFOREACH ()

FOREACH (dylib ${dyliblist})
  IF (dylib)
    STRING (REGEX REPLACE "\\.dylib" "" lib "${dylib}")
    MESSAGE (STATUS "  ${dylib}...")
    GET_INSTALL_NAME ("${BUILD_LIB_PATH}/${dylib}" "${lib}" lib_id)
    # resolve any symlinks to versioned dylib
    SET (ver_dylib "${dylib}")
    SET (dylib_path "${BUNDLE_LIB}/${dylib}")
    IF ( IS_SYMLINK "${dylib_path}" )
      get_filename_component(dylib_path "${dylib_path}" REALPATH)
      get_filename_component(ver_dylib "${dylib_path}" NAME)
    ENDIF ()
    # No install name means nothing can link to it. Don't try to re-link.
    # TODO: add this to other routines
    STRING (COMPARE EQUAL "${lib_id}" "" missing_id)
    IF (missing_id)
      # Some things get linked without a dir. Add the loader_path to those in UPDATEQGISPATHS
      SET (lib_id "${ver_dylib}")
    ENDIF ()
    INSTALLNAMETOOL_SET_ID ("@rpath/${ver_dylib}" "${BUNDLE_LIB}/${dylib}")

    UPDATEQGISPATHS ("${lib_id}" "${ver_dylib}")

    # Update the lib path for dylibs in /lib
    FOREACH (dlib ${dyliblist})
      IF (dlib)
        INSTALLNAMETOOL_CHANGE ("${lib_id}" "${ATLOADER}/${ver_dylib}" "${BUNDLE_LIB}/${dlib}")
      ENDIF ()
    ENDFOREACH ()

    # Update the lib path for bins in /bin
    FOREACH (bin ${binlist})
      INSTALLNAMETOOL_CHANGE ("${lib_id}" "${ATLOADER}/../lib/${ver_dylib}" "${bin}")
    ENDFOREACH ()

    # Update the lib path for dylibs in framework root
    FOREACH (fwk ${fwklist})
      get_filename_component(fwk_dir "${fwk}" DIRECTORY)
      FILE (RELATIVE_PATH fwk_relpath "${fwk_dir}" "${BUNDLE_LIB}/${ver_dylib}")
      INSTALLNAMETOOL_CHANGE ("${lib_id}" "${ATLOADER}/${fwk_relpath}" "${fwk}")
    ENDFOREACH()

    # Update the lib path for dylibs in framework internals
    FOREACH (fwkv ${fwkvlist})
      get_filename_component(fwkv_dir "${fwkv}" DIRECTORY)
      FILE (RELATIVE_PATH fwkv_relpath "${fwkv_dir}" "${BUNDLE_LIB}/${ver_dylib}")
      INSTALLNAMETOOL_CHANGE ("${lib_id}" "${ATLOADER}/${fwkv_relpath}" "${fwkv}")
    ENDFOREACH()

  ENDIF ()
ENDFOREACH ()
STRING (TIMESTAMP baselibs_end)
MESSAGE (STATUS "${baselibs_start} -> ${baselibs_end}")

# FILE (GLOB_RECURSE files FOLLOW_SYMLINKS "${QLIBDIR}/*")
# FOREACH (file ${files})
#   IF (NOT IS_DIRECTORY ${file} AND NOT IS_SYMLINK ${file})
#     EXECUTE_PROCESS (COMMAND basename "${file}" OUTPUT_VARIABLE file_basename_newline)
#     # Strip newline from end of filename
#     STRING (STRIP ${file_basename_newline} file_basename)
#     MESSAGE (STATUS "Re-linking ${file_basename}...")
#     SET(bundle_file "${QLIBDIR}/${file_basename}")
#     SET(BUNDLE_ID "${BUNDLE_LIB_PATH}/${file_basename}")
#     INSTALL_NAME ("${bundle_file}" LIB_INSTALL_NAME)
#     # No install name means nothing can link to it. Don't try to re-link.
#     STRING (COMPARE NOTEQUAL "${LIB_INSTALL_NAME}" "" result)
#     IF (result)
#       INSTALLNAMETOOL_SET_ID (${BUNDLE_ID} "${bundle_file}")
#       UPDATEQGISPATHS (${LIB_INSTALL_NAME} ${file_basename})
#       UPDATELOCALPATHS (${LIB_INSTALL_NAME} ${BUNDLE_ID})
#     ELSE ()
#       # Some things get linked without a dir. Add the loader_path to those.
#       # NOTE: this may need to be moved outside and after of this conditional
#       UPDATEQGISPATHS (${file_basename} ${file_basename})
#       UPDATELOCALPATHS (${file_basename} ${BUNDLE_ID})
#     ENDIF()
#   ENDIF ()
# ENDFOREACH ()

# odd relinking of Qt core plugin
# is this just a generalized guess on Qt's part, hoping rpath will kick in?
# FIXME: was this compiled locally against a now non-existent pgsql install?
FILE (RELATIVE_PATH sql_libpq_relpath "${BUNDLE_PLUGINS}/sqldrivers" "${BUNDLE_LIB}/libpq.5.dylib")
INSTALLNAMETOOL_CHANGE("/usr/local/pgsql/lib/libpq.5.dylib" "${ATLOADER}/${sql_libpq_relpath}" "${BUNDLE_PLUGINS}/sqldrivers/libqsqlpsql.dylib")

# Setup python utils
MESSAGE (STATUS "Setting up psycopg2...")
EXECUTE_PROCESS (COMMAND cp -a "${BUILD_SITE_PKGS}/psycopg2" "${BUNDLE_PYTHON}/.")
GET_INSTALL_NAME ("${BUILD_LIB_PATH}/libpq.5.dylib" "libpq" libpq_id)
FILE (RELATIVE_PATH psy_libpq_relpath "${BUNDLE_PYTHON}/psycopg2" "${BUNDLE_LIB}/libpq.5.dylib")
INSTALLNAMETOOL_CHANGE("${libpq_id}" "${ATLOADER}/${psy_libpq_relpath}" "${BUNDLE_PYTHON}/psycopg2/_psycopg.so")

# # Until pyspatialite works with libspatialite 4.2.x, or DB Manager works with mod_spatialite
MESSAGE (STATUS "Setting up pyspatialite...")
EXECUTE_PROCESS (COMMAND cp -a "${BUILD_SITE_PKGS}/pyspatialite" "${BUNDLE_PYTHON}/.")
FOREACH (lib "libgeos-3.4.2" "libgeos_c.1" "libproj.9" "libspatialite.7" "libsqlite3.0")
  GET_INSTALL_NAME ("${BUILD_LIB_PATH}/${lib}.dylib" "${lib}" lib_id)
  FILE (RELATIVE_PATH pysp_lib_relpath "${BUNDLE_PYTHON}/pyspatialite" "${BUNDLE_LIB}/${lib}.dylib")
  INSTALLNAMETOOL_CHANGE("${lib_id}" "${ATLOADER}/${pysp_lib_relpath}" "${BUNDLE_PYTHON}/pyspatialite/_spatialite.so")
ENDFOREACH ()

MESSAGE (STATUS "Setting up osgeo...")
EXECUTE_PROCESS (COMMAND cp -a "${BUILD_SITE_PKGS}/osgeo" "${BUNDLE_PYTHON}/.")
FILE (GLOB osgeo_libs "${BUNDLE_PYTHON}/osgeo/*.so")
# For GDAL 1.x and GDL 2.x
FOREACH (osglib
  "libgdal.1"
  "libgdal.20"
  "libsqlite3.0"
)
  GET_INSTALL_NAME ("${BUILD_LIB_PATH}/${osglib}.dylib" "${osglib}" osglib_id)
  FILE (RELATIVE_PATH osglib_relpath "${BUNDLE_PYTHON}/osgeo" "${BUNDLE_LIB}/${osglib}.dylib")
  FOREACH (lib ${osgeo_libs})
    INSTALLNAMETOOL_CHANGE("${osglib_id}" "${ATLOADER}/${osglib_relpath}" "${lib}")
  ENDFOREACH ()
ENDFOREACH()

######### Fixups for codesigning #########

# update Qt and Qwt frameworks
MESSAGE (STATUS "Fixing up Qt frameworks for code-signing...")
FILE (GLOB qt_fwks "${QFWDIR}/Qt*.framework")
LIST(APPEND qt_fwks "${QFWDIR}/phonon.framework")
FOREACH (qt_fwk ${qt_fwks})
  get_filename_component(fwk_name "${qt_fwk}" NAME)
  get_filename_component(fwk_name_we "${qt_fwk}" NAME_WE)
  IF (NOT EXISTS "${qt_fwk}/Versions/Current/Resources")
    EXECUTE_PROCESS (COMMAND /bin/mkdir -p -m 755 "${qt_fwk}/Versions/Current/Resources")
  ENDIF ()
  IF (NOT EXISTS "${qt_fwk}/Resources")
    EXECUTE_PROCESS (COMMAND /bin/ln -sf "Versions/Current/Resources" "${qt_fwk}/Resources")
  ENDIF ()
  IF (NOT EXISTS "${qt_fwk}/Versions/Current/Resources/Info.plist" AND
      EXISTS "${QT_FW}/${fwk_name}/Contents/Info.plist")
    EXECUTE_PROCESS (COMMAND /bin/cp -a "${QT_FW}/${fwk_name}/Contents/Info.plist" "${qt_fwk}/Versions/Current/Resources/")
    EXECUTE_PROCESS (COMMAND /bin/chmod u+w "${qt_fwk}/Versions/Current/Resources/Info.plist")
    # this strips off any *_debug suffix in existing CFBundleExecutable name
    EXECUTE_PROCESS (COMMAND /usr/libexec/PlistBuddy -c "Set :CFBundleExecutable \"${fwk_name_we}\"" "${qt_fwk}/Versions/Current/Resources/Info.plist")
    EXECUTE_PROCESS (COMMAND /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string \"org.qt-project.${fwk_name_we}\"" "${qt_fwk}/Versions/Current/Resources/Info.plist")
    EXECUTE_PROCESS (COMMAND /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string \"${QT_VER}\"" "${qt_fwk}/Versions/Current/Resources/Info.plist")
  ENDIF ()
ENDFOREACH()

MESSAGE (STATUS "Fixing up Qwt framework for code-signing...")
SET (qwt_fwk "${QFWDIR}/qwt.framework")
IF (EXISTS "${qwt_fwk}")
  IF (NOT EXISTS "${qwt_fwk}/Versions/Current/Resources")
    EXECUTE_PROCESS (COMMAND /bin/mkdir -p -m 755 "${qwt_fwk}/Versions/Current/Resources")
  ENDIF ()
  IF (NOT EXISTS "${qwt_fwk}/Resources")
    EXECUTE_PROCESS (COMMAND /bin/ln -sf "Versions/Current/Resources" "${qwt_fwk}/Resources")
  ENDIF ()
  IF (NOT EXISTS "${qwt_fwk}/Versions/Current/Resources/Info.plist" AND
      EXISTS "${QWT_FW}/qwt.framework/Contents/Info.plist")
    EXECUTE_PROCESS (COMMAND /bin/cp -a "${QWT_FW}/qwt.framework/Contents/Info.plist" "${qwt_fwk}/Versions/Current/Resources/")
    EXECUTE_PROCESS (COMMAND /bin/chmod u+w "${qwt_fwk}/Versions/Current/Resources/Info.plist")
    EXECUTE_PROCESS (COMMAND /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string \"org.qwt-project.qwt\"" "${qwt_fwk}/Versions/Current/Resources/Info.plist")
    EXECUTE_PROCESS (COMMAND /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string \"${QWT_VER}\"" "${qwt_fwk}/Versions/Current/Resources/Info.plist")
  ENDIF ()
ENDIF ()

MESSAGE (STATUS "Fixing up grass directories for code-signing...")
# codesign evidently can't cope with directory names with periods
# fool it by setting up symlinks of same name
FOREACH (g6_etc_dir "d.polar" "db.test" "i.oif" "r.in.wms" "r.li.setup")
  STRING(REPLACE "." "_" g6_etc_dir_clean "${g6_etc_dir}")
  EXECUTE_PROCESS (COMMAND mv -f "${G6_PREFIX}/etc/${g6_etc_dir}" "${G6_PREFIX}/etc/${g6_etc_dir_clean}")
  EXECUTE_PROCESS (COMMAND /bin/ln -sf "${g6_etc_dir_clean}" "${G6_PREFIX}/etc/${g6_etc_dir}")
ENDFOREACH()
