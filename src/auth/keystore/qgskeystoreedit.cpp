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
  QPair<QString, bool> pair = cmbIdentityCert->itemData( cmbIdentityCert->currentIndex() );
  config.insert( "certid", pair.first );
  QgsDebugMsg( QString( "Cert hash link to the KeyStore: %1" ).arg( config.value( "certid" ) ) );

  bool doExport = ( chkMakeItExportable.checkState() == Qt::Checked );
  config.insert( "export",  doExport);
  QgsDebugMsg( QString( "Cert have to be exported flag: %1" ).arg( config.value( "export" ) ) );

  return config;
}

void QgsKeyStoreEdit::loadConfig( const QgsStringMap &configmap )
{
  clearConfig();

  mConfigMap = configmap;
  int indx = cmbIdentityCert->findData( configmap.value( "certid" ) );
  cmbIdentityCert->setCurrentIndex( indx == -1 ? 0 : indx );

  // set exportable checkbox basing on user configuration
  chkMakeItExportable.setCheckState( configmap.value( "export" )? Qt::checked : Qt::Unchecked );

  // visualize or not checkbox depending if cert is exportable
  QPair<QString, bool> pair = cmbIdentityCert->itemData( cmbIdentityCert->currentIndex() );
  bool isExportable = pair.second;

  // set exportable checkbox basing on cert
  chkMakeItExportable.setVsible( !isExportable );
  if ( isExportable )
  {
      chkMakeItExportable.setCheckState( Qt::Unchecked );
  }
  else
  {
      // leave setting based on user configuration
  }

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
  QList< QPair<QSslCertificate, bool> > certsPair( get_systemstore("MY") );
  if ( !certs.isEmpty() )
  {
    cmbIdentityCert->setIconSize( QSize( 26, 22 ) );
    QMap< QString, QPair<QString, bool> > idents;

    Q_FOREACH ( const QPair<QSslCertificate, bool>& certPair, certsPair )
    {
      QSslCertificate cert = certPair.first;
      bool isExportable = certPair.second;

      QString org( SSL_SUBJECT_INFO( cert, QSslCertificate::Organization ) );
      if ( org.isEmpty() )
        org = tr( "Organization not defined" );

      QPair<QString, bool> ref(QgsAuthCertUtils::shaHexForCert(cert), isExportable);
      idents.insert( QString( "%1 (%2)" ).arg( QgsAuthCertUtils::resolvedCertName( cert ), org ),
                     ref );
      QgsDebugMsg( QString( "Add certid = %1" ).arg( QgsAuthCertUtils::shaHexForCert(cert) ) );
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
  Q_UNUSED( indx );
  validateConfig();
}

//#endif // Q_OS_WIN
