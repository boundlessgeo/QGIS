/************************************************************************
 * This file has been generated automatically from                      *
 *                                                                      *
 * src/core/auth/qgsauthmethodmetadata.h                                *
 *                                                                      *
 * Do not edit manually ! Edit header and run scripts/sipify.pl again   *
 ************************************************************************/




class QgsAuthMethodMetadata
{
%Docstring
 Holds data auth method key, description, and associated shared library file information.

The metadata class is used in a lazy load implementation in
QgsAuthMethodRegistry.  To save memory, auth methods are only actually
loaded via QLibrary calls if they're to be used.  (Though they're all
iteratively loaded once to get their metadata information, and then
unloaded when the QgsAuthMethodRegistry is created.)  QgsProviderMetadata
supplies enough information to be able to later load the associated shared
library object.
.. note::

   Culled from QgsProviderMetadata
%End

%TypeHeaderCode
#include "qgsauthmethodmetadata.h"
%End
  public:

    QgsAuthMethodMetadata( const QString &_key, const QString &_description, const QStringList &_supportedProviders, const int &_version, const QString &_library );
%Docstring
 Construct an authentication method metadata container
 \param _key Textual key of the library plugin
 \param _description Description of the library plugin
 \param _supportedProviders list of supported provider keys
 \param _version version number of the method
 \param _library File name of library plugin
%End

    QString key() const;
%Docstring
 This returns the unique key associated with the method

This key string is used for the associative container in QgsAuthMethodRegistry
 :rtype: str
%End

    int version() const;
%Docstring
 This returns the version associated with the method

This version is used for updating the authentication configuration
 :rtype: int
%End

    QString description() const;
%Docstring
 This returns descriptive text for the method

This is used to provide a descriptive list of available data methods.
 :rtype: str
%End

    QString library() const;
%Docstring
 This returns the library file name

This is used to QLibrary calls to load the method.
 :rtype: str
%End

    QStringList supportedProviders() const;
%Docstring
 supportedProviders
 :return: list of supported providers keys
 :rtype: list of str
%End

};

/************************************************************************
 * This file has been generated automatically from                      *
 *                                                                      *
 * src/core/auth/qgsauthmethodmetadata.h                                *
 *                                                                      *
 * Do not edit manually ! Edit header and run scripts/sipify.pl again   *
 ************************************************************************/
