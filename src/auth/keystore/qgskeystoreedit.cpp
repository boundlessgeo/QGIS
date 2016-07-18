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
  config.insert( "certid", cmbIdentityCert->itemData( cmbIdentityCert->currentIndex() ).toString() );

  return config;
}

void QgsKeyStoreEdit::loadConfig( const QgsStringMap &configmap )
{
  clearConfig();

  mConfigMap = configmap;
  int indx = cmbIdentityCert->findData( configmap.value( "certid" ) );
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

  // TODO: get the list of certs stored in KeyStore with hash/id, symbole name and type
  QList<QSslCertificate> certs;
  certs = get_systemstore("MY");

  //QList<QSslCertificate> certs( QgsAuthManager::instance()->getCertIdentities() );
  if ( !certs.isEmpty() )
  {
    cmbIdentityCert->setIconSize( QSize( 26, 22 ) );
    QgsStringMap idents;
    Q_FOREACH ( const QSslCertificate& cert, certs )
    {
      QString org( SSL_SUBJECT_INFO( cert, QSslCertificate::Organization ) );
      if ( org.isEmpty() )
        org = tr( "Organization not defined" );
      idents.insert( QString( "%1 (%2)" ).arg( QgsAuthCertUtils::resolvedCertName( cert ), org ),
                     QgsAuthCertUtils::shaHexForCert( cert ) );
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
