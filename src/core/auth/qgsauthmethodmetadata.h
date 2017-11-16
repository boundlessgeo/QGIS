/***************************************************************************
    qgsauthmethodmetadata.h
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

#ifndef QGSAUTHMETHODMETADATA_H
#define QGSAUTHMETHODMETADATA_H

#include <QString>
#include <QStringList>

#include "qgis_core.h"

/**
 * \ingroup core
 * Holds data auth method key, description, and associated shared library file information.

   The metadata class is used in a lazy load implementation in
   QgsAuthMethodRegistry.  To save memory, auth methods are only actually
   loaded via QLibrary calls if they're to be used.  (Though they're all
   iteratively loaded once to get their metadata information, and then
   unloaded when the QgsAuthMethodRegistry is created.)  QgsProviderMetadata
   supplies enough information to be able to later load the associated shared
   library object.
 * \note Culled from QgsProviderMetadata
 */
class CORE_EXPORT QgsAuthMethodMetadata
{
  public:

    /**
     * Construct an authentication method metadata container
     * \param _key Textual key of the library plugin
     * \param _description Description of the library plugin
     * \param _supportedProviders list of supported provider keys
     * \param _version version number of the method
     * \param _library File name of library plugin
     */
    QgsAuthMethodMetadata( const QString &_key, const QString &_description, const QStringList &_supportedProviders, const int &_version, const QString &_library );

    /**
     * This returns the unique key associated with the method

        This key string is used for the associative container in QgsAuthMethodRegistry
     */
    QString key() const;

    /**
     * This returns the version associated with the method

        This version is used for updating the authentication configuration
     */
    int version() const;

    /**
     * This returns descriptive text for the method

        This is used to provide a descriptive list of available data methods.
     */
    QString description() const;

    /**
     * This returns the library file name

        This is used to QLibrary calls to load the method.
     */
    QString library() const;

    /**
     * \brief supportedProviders
     * \return list of supported providers keys
     */
    QStringList supportedProviders() const;

  private:

    /// unique key for method
    QString key_;

    /// associated terse description
    QString description_;

    /// supported providers
    QStringList supportedProviders_;

    /// version
    int version_;

    /// file path
    QString library_;
};

#endif // QGSAUTHMETHODMETADATA_H
