/***************************************************************************
    qgskeystoreedit.cpp
    ---------------------
    begin                : June 13, 2016
    copyright            : (C) 2016 by Boundless Spatial, Inc. USA
    author               : Luigi Pirelli
    email                : lpirelli at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

//#ifdef Q_OS_WIN

#include <Qt>
#include <QMap>
#include <QPair>
#include <QString>
#include <QList>
#include <QSslCertificate>

#include "qgskeystoreedit.h"
#include "ui_qgskeystoreedit.h"

#include "qgsapplication.h"
#include "qgsauthcertutils.h"
#include "qgsauthmanager.h"
#include "qgslogger.h"

#include "qgskeystoreutils.h"

QgsKeyStoreEdit::QgsKeyStoreEdit( QWidget *parent )
  : QgsAuthMethodEdit( parent )
  , mValid( 0 )
{
  setupUi( this );
  populateIdentityComboBox();
}

QgsKeyStoreEdit::~QgsKeyStoreEdit()
{
}

bool QgsKeyStoreEdit::validateConfig()
{
  bool curvalid = cmbIdentityCert->currentIndex() != 0;
  if ( mValid != curvalid )
  {
    mValid = curvalid;
    emit validityChanged( curvalid );
  }

  return curvalid;
}

QgsStringMap QgsKeyStoreEdit::configMap() const
{
  QgsStringMap config;
  QString certHash = cmbIdentityCert->itemData( cmbIdentityCert->currentIndex() ).toString();
  config.insert( "certid", certHash );
  QgsDebugMsg( QString( "Cert hash link to the KeyStore: %1" ).arg( config.value( "certid" ) ) );

  bool doExport = ( chkMakeItExportable->checkState() == Qt::Checked );
  config.insert( "export",  doExport? QString("1") : QString("0") );
  QgsDebugMsg( QString( "Cert have to be exported flag: %1" ).arg( config.value( "export" ) ) );

  return config;
}

void QgsKeyStoreEdit::loadConfig( const QgsStringMap &configmap )
{
  clearConfig();

  mConfigMap = configmap;
  int indx = cmbIdentityCert->findData( mConfigMap.value( "certid" ) );
  cmbIdentityCert->setCurrentIndex( indx == -1 ? 0 : indx );

  validateConfig();
}

void QgsKeyStoreEdit::resetConfig()
{
  loadConfig( mConfigMap );
}

void QgsKeyStoreEdit::clearConfig()
{
  cmbIdentityCert->setCurrentIndex( 0 );
}

void QgsKeyStoreEdit::populateIdentityComboBox()
{
  cmbIdentityCert->addItem( tr( "Select identity..." ), "" );

  // get the list of certs stored in KeyStore
  QList< QSslCertificate > certs( KeystoreUtils::get_systemstore("MY") );
  if ( !certs.isEmpty() )
  {
    cmbIdentityCert->setIconSize( QSize( 26, 22 ) );
    QgsStringMap idents;

    Q_FOREACH ( const QSslCertificate& cert, certs )
    {
      QString org( SSL_SUBJECT_INFO( cert, QSslCertificate::Organization ) );
      if ( org.isEmpty() )
        org = tr( "Organization not defined" );

      QString ref(QgsAuthCertUtils::shaHexForCert(cert));
      idents.insert( QString( "%1 (%2)" ).arg( QgsAuthCertUtils::resolvedCertName( cert ), org ),
                     ref );
      QgsDebugMsg( QString( "Add certid = %1" ).arg( ref ) );
    }
    QgsStringMap::const_iterator it = idents.constBegin();
    for ( ; it != idents.constEnd(); ++it )
    {

      cmbIdentityCert->addItem( QgsApplication::getThemeIcon( "/mIconCertificate.svg" ),
                                it.key(), it.value() );
    }
  }
}

void QgsKeyStoreEdit::on_cmbIdentityCert_currentIndexChanged( int indx )
{
  // get hash
  QString certHash = cmbIdentityCert->itemData( indx ).toString();
  if (certHash.isNull() || certHash.isEmpty())
    return;

  // visualize or not checkbox depending if cert is exportable
  bool isCertExportable = KeystoreUtils::systemstore_cert_privatekey_is_exportable( certHash, "MY" );
  chkMakeItExportable->setVisible( !isCertExportable );

  // set exportable checkbox basing on cert (by default don't force export)
  chkMakeItExportable->setCheckState( Qt::Unchecked );
  if (!isCertExportable)
  {
    // set basing of user configuration for the saved conf
    if ( mConfigMap.value( "certid" ) == certHash )
    {
      bool toExport = (mConfigMap.value( "export" ) == QString("1"));
      chkMakeItExportable->setCheckState(( (toExport)? Qt::Checked : Qt::Unchecked ));
    }
  }

  validateConfig();
}

//#endif // Q_OS_WIN
