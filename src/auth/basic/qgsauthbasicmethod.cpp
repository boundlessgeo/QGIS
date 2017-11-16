/***************************************************************************
    qgsauthbasicmethod.cpp
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

#include "qgsauthbasicmethod.h"
#include "qgsauthbasicedit.h"

#include "qgsauthmanager.h"
#include "qgslogger.h"
#include "qgsapplication.h"

#include <QNetworkProxy>
#include <QMutexLocker>
#include <QUuid>

static const QString AUTH_METHOD_KEY = QStringLiteral( "Basic" );
static const QString AUTH_METHOD_DESCRIPTION = QStringLiteral( "Basic authentication" );
static const int AUTH_METHOD_VERSION = 2;

QgsAuthBasicMethod::QgsAuthBasicMethod( const QString authcfg ):
  QgsAuthMethod( authcfg )
{
  setVersion( AUTH_METHOD_VERSION );
  setExpansions( QgsAuthMethod::NetworkRequest | QgsAuthMethod::DataSourceUri );
  setDataProviders( QStringList()
                    << QStringLiteral( "postgres" )
                    << QStringLiteral( "db2" )
                    << QStringLiteral( "ows" )
                    << QStringLiteral( "wfs" )  // convert to lowercase
                    << QStringLiteral( "wcs" )
                    << QStringLiteral( "wms" )
                    << QStringLiteral( "proxy" ) );

}

QString QgsAuthBasicMethod::key() const
{
  return AUTH_METHOD_KEY;
}

QString QgsAuthBasicMethod::description() const
{
  return AUTH_METHOD_DESCRIPTION;
}

QString QgsAuthBasicMethod::displayDescription() const
{
  return tr( "Basic authentication" );
}

bool QgsAuthBasicMethod::updateNetworkRequest( QNetworkRequest &request,
    const QString &dataprovider )
{
  Q_UNUSED( dataprovider )
  QMutexLocker locker( mMutex );
  if ( !mConfig->isValid() )
  {
    QgsDebugMsg( QString( "Update request config FAILED for authcfg: %1: config invalid" ).arg( mAuthcfg ) );
    return false;
  }

  QString username = mConfig->config( QStringLiteral( "username" ) );
  QString password = mConfig->config( QStringLiteral( "password" ) );

  if ( !username.isEmpty() )
  {
    request.setRawHeader( "Authorization", "Basic " + QStringLiteral( "%1:%2" ).arg( username, password ).toLatin1().toBase64() );
  }
  return true;
}

bool QgsAuthBasicMethod::updateDataSourceUriItems( QStringList &connectionItems,
    const QString &dataprovider )
{
  Q_UNUSED( dataprovider )
  QMutexLocker locker( mMutex );
  if ( !mConfig->isValid() )
  {
    QgsDebugMsg( QString( "Update URI items FAILED for authcfg: %1: basic config invalid" ).arg( mAuthcfg ) );
    return false;
  }

  QString username = mConfig->config( QStringLiteral( "username" ) );
  QString password = mConfig->config( QStringLiteral( "password" ) );

  if ( username.isEmpty() )
  {
    QgsDebugMsg( QString( "Update URI items FAILED for authcfg: %1: username empty" ).arg( mAuthcfg ) );
    return false;
  }

  QString userparam = "user='" + escapeUserPass( username ) + '\'';
  int userindx = connectionItems.indexOf( QRegExp( "^user='.*" ) );
  if ( userindx != -1 )
  {
    connectionItems.replace( userindx, userparam );
  }
  else
  {
    connectionItems.append( userparam );
  }

  QString passparam = "password='" + escapeUserPass( password ) + '\'';
  int passindx = connectionItems.indexOf( QRegExp( "^password='.*" ) );
  if ( passindx != -1 )
  {
    connectionItems.replace( passindx, passparam );
  }
  else
  {
    connectionItems.append( passparam );
  }

  // add extra CAs
  QList<QSslCertificate> cas;
  cas = QgsApplication::authManager()->trustedCaCerts();
  // save CAs to temp file
  QString tempFileBase = QStringLiteral( "tmp_basic_%1.pem" );
  QString caFilePath = QgsAuthCertUtils::pemTextToTempFile(
                         tempFileBase.arg( QUuid::createUuid().toString() ),
                         QgsAuthCertUtils::certsToPemText( cas ) );
  if ( ! caFilePath.isEmpty() )
  {
    QString caparam = "sslrootcert='" + caFilePath + "'";
    int sslcaindx = connectionItems.indexOf( QRegExp( "^sslrootcert='.*" ) );
    if ( sslcaindx != -1 )
    {
      connectionItems.replace( sslcaindx, caparam );
    }
    else
    {
      connectionItems.append( caparam );
    }
  }

  return true;
}

bool QgsAuthBasicMethod::updateNetworkProxy( QNetworkProxy &proxy, const QString &dataprovider )
{
  Q_UNUSED( dataprovider )
  QMutexLocker locker( mMutex );

  if ( !mConfig->isValid() )
  {
    QgsDebugMsg( QString( "Update proxy config FAILED for authcfg: %1: config invalid" ).arg( mAuthcfg ) );
    return false;
  }

  QString username = mConfig->config( QStringLiteral( "username" ) );
  QString password = mConfig->config( QStringLiteral( "password" ) );

  if ( !username.isEmpty() )
  {
    proxy.setUser( username );
    proxy.setPassword( password );
  }
  return true;
}

void QgsAuthBasicMethod::updateMethodConfig( )
{
  QMutexLocker locker( mMutex );
  if ( mConfig->hasConfig( QStringLiteral( "oldconfigstyle" ) ) )
  {
    QgsDebugMsg( "Updating old style auth method config" );

    QStringList conflist = mConfig->config( QStringLiteral( "oldconfigstyle" ) ).split( QStringLiteral( "|||" ) );
    mConfig->setConfig( QStringLiteral( "realm" ), conflist.at( 0 ) );
    mConfig->setConfig( QStringLiteral( "username" ), conflist.at( 1 ) );
    mConfig->setConfig( QStringLiteral( "password" ), conflist.at( 2 ) );
    mConfig->removeConfig( QStringLiteral( "oldconfigstyle" ) );
  }

  // TODO: add updates as method version() increases due to config storage changes
}


QString QgsAuthBasicMethod::escapeUserPass( const QString &val, QChar delim ) const
{
  QString escaped = val;

  escaped.replace( '\\', QLatin1String( "\\\\" ) );
  escaped.replace( delim, QStringLiteral( "\\%1" ).arg( delim ) );

  return escaped;
}

//////////////////////////////////////////////
// Plugin externals
//////////////////////////////////////////////

/**
 * Required class factory to return a pointer to a newly created object
 */
QGISEXTERN QgsAuthBasicMethod *classFactory( const QString authcfg )
{
  return new QgsAuthBasicMethod( authcfg );
}

/**
 * Required key function (used to map the plugin to a data store type)
 */
QGISEXTERN QString authMethodKey()
{
  return AUTH_METHOD_KEY;
}

/**
 * Required isAuthMethod function. Used to determine if this shared library
 * is an authentication method plugin
 */
QGISEXTERN bool isAuthMethod()
{
  return true;
}

/**
 * Optional class factory to return a pointer to a newly created edit widget
 */
QGISEXTERN QgsAuthBasicEdit *editWidget( QWidget *parent )
{
  return new QgsAuthBasicEdit( parent );
}

/**
 * Required cleanup function
 */
QGISEXTERN void cleanupAuthMethod() // pass QgsAuthMethod *method, then delete method  ?
{
}
