#!/bin/bash
###########################################################################
#    quickpackage.sh
#    ---------------------
#    Date                 : November 2010
#    Copyright            : (C) 2010 by Tim Sutton
#    Email                : tim at kartoza dot com
###########################################################################
#                                                                         #
#   This program is free software; you can redistribute it and/or modify  #
#   it under the terms of the GNU General Public License as published by  #
#   the Free Software Foundation; either version 2 of the License, or     #
#   (at your option) any later version.                                   #
#                                                                         #
###########################################################################


# This script is just for if you want to run the nsis (under linux) part 
# of the package building process. Typically you should use 
#
# osgeo4w/creatensis.pl
#
# rather to do the complete package build process. However running this 
# script can be useful if you have manually tweaked the package contents 
# under osgeo4w/unpacked and want to create a new package based on that.
#
# Tim Sutton November 2010

export PATH=/cygdrive/z/DevTools/NSIS:$PATH

makensis -V3 \
-DVERSION_NAME='Wien' \
-DVERSION_NUMBER='2.8.3' \
-DBINARY_REVISION=1 \
-DVERSION_INT='2080301' \
-DQGIS_BASE='QGIS Wien' \
-DINSTALLER_NAME='QGIS-wPKI-2.8.3-1-x86.exe' \
-DDISPLAYED_NAME='QGIS 'Wien' (2.8.3)' \
-DSHORTNAME='qgis-ltr' \
-DINSTALLER_TYPE=OSGeo4W \
-DPACKAGE_FOLDER=osgeo4w/unpacked-x86 \
-DLICENSE_FILE='osgeo4w/unpacked-x86/apps/qgis-ltr/doc/LICENSE' \
-DARCH='x86' \
QGIS-Installer.nsi
