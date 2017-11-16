/***************************************************************************
    qgsauthmethodmetadata.cpp
    ---------------------
    begin                : September 1, 2015
    copyright            : (C) 2015 by Boundless Spatial, Inc. USA
    author               : Larry Shaffer
    email                : lshaffer at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/


#include "qgsauthmethodmetadata.h"


QgsAuthMethodMetadata::QgsAuthMethodMetadata( QString const &_key,
    const QString &_description,
    const QStringList &_supportedProviders,
    const int &_version,
    const QString &_library )
  : key_( _key )
  , description_( _description )
  , supportedProviders_( _supportedProviders )
  , version_( _version )
  , library_( _library )
{}

QString QgsAuthMethodMetadata::key() const
{
  return key_;
}

QString QgsAuthMethodMetadata::description() const
{
  return description_;
}

int QgsAuthMethodMetadata::version() const
{
  return version_;
}

QString QgsAuthMethodMetadata::library() const
{
  return library_;
}

QStringList QgsAuthMethodMetadata::supportedProviders() const
{
  return supportedProviders_;
}

