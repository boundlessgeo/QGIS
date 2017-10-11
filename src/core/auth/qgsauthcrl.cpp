/***************************************************************************
  qgsauthcrl.cpp - QgsAuthCrl

 ---------------------
 begin                : 10.10.2017
 copyright            : (C) 2017 by Alessandro Pasotti
 email                : apasotti at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
#include "qgsauthcrl.h"
#include "qgslogger.h"
#include "qca.h"
#include "qgis.h"

#include <QFileInfo>
#include <QDebug>


QgsAuthCrlEntry::QgsAuthCrlEntry( const QgsAuthCrlEntry::Reason &reason, const QByteArray &serialNumber, const QDateTime &revokationDate )
  : mReason( reason )
  , mSerialNumber( serialNumber )
  , mRevokationDate( revokationDate )
{

}

QgsAuthCrlEntry::Reason QgsAuthCrlEntry::reasonFromQCAReason( const QCA::CRLEntry::Reason &reason )
{
  return ( QgsAuthCrlEntry::Reason ) reason;
}

QString QgsAuthCrlEntry::reasonAsString( const QgsAuthCrlEntry::Reason &reason ) const
{
  switch ( reason )
  {
    case KeyCompromise:
      return QObject::tr( "Private key has been compromised" );
    case CACompromise:
      return QObject::tr( "Certificate authority has been compromised" );
    case AffiliationChanged:
      return QObject::tr( "Certificate has been superseded" );
    case CessationOfOperation:
      return QObject::tr( "Cessation of operation" );
    case CertificateHold:
      return QObject::tr( "Certificate is on hold" );
    case RemoveFromCRL:
      return QObject::tr( "Certificate was previously in a CRL, but is now valid" );
    case PrivilegeWithdrawn:
      return QObject::tr( "Privilege has been withdrawn" );
    case AACompromise:
      return QObject::tr( "Attribute authority has been compromised" );
    default:
    case Unspecified:
      return QObject::tr( "Reason is unknown" );
  }
}


QgsAuthCrl::QgsAuthCrl( const QString &crlPath )
{
  if ( QCA::isSupported( "crl", QLatin1String( "qca-ossl" ) ) )
  {
    QFileInfo check_file( crlPath );
    // Check if file exists and is a file
    if ( check_file.exists() && check_file.isFile() )
    {
      QCA::CRL crl;
      QCA::ConvertResult result;
      crl = QCA::CRL::fromPEMFile( crlPath, &result, QLatin1String( "qca-ossl" ) );
      if ( result == QCA::ConvertGood )
      {
        const QList<QCA::CRLEntry> revoked( crl.revoked() );
        for ( const auto cert : revoked )
        {
          // TODO: use toHex when available (since Qt 5.9)
          mEntries.append( QgsAuthCrlEntry( QgsAuthCrlEntry::reasonFromQCAReason( cert. cert.reason() ), cert.serialNumber().toArray().toByteArray( ), cert.time( ) ) );
        }
      }
      else
      {
        QgsDebugMsgLevel( QString( "Warning %1 reading CRL file as PEM, trying with DER" ).arg( crlPath ), 4 );
        // Try DER
        if ( mEntries.isEmpty( ) )
        {
          QFile crlFile( crlPath );
          if ( crlFile.open( QIODevice::ReadOnly ) )
          {
            QByteArray crlText( crlFile.readAll( ) );
            crl = QCA::CRL::fromDER( crlText, &result, QLatin1String( "qca-ossl" ) );
            if ( result == QCA::ConvertGood )
            {
              const QList<QCA::CRLEntry> revoked( crl.revoked() );
              for ( const auto cert : revoked )
              {
                // TODO: use toHex when available (since Qt 5.9)
                mEntries.append( QgsAuthCrlEntry( QgsAuthCrlEntry::reasonFromQCAReason( cert.reason() ), cert.serialNumber().toArray().toByteArray( ), cert.time( ) ) );
              }
            }
            else
            {
              QgsDebugMsgLevel( QString( "Error %1 reading CRL as DER: %2" ).arg( result ).arg( crlPath ), 4 );
            }
          }
          else
          {
            QgsDebugMsgLevel( QString( "Error %1 reading CRL file as DER" ).arg( crlPath ), 4 );
          }
        }
      }
    }
    else
    {
      QgsDebugMsgLevel( QString( "CRL file does not exist: %1" ).arg( crlPath ), 4 );
    }
    if ( mEntries.isEmpty() )
      QgsDebugMsgLevel( QString( "Could not find any revoked certificate in CRL: %1" ).arg( crlPath ), 4 );
  }
  else
  {
    QgsDebugMsgLevel( QString( "CRL is not supported by QCA" ), 4 );
  }
}

QList<QByteArray> QgsAuthCrl::serialNumbers() const
{
  QList<QByteArray> results;
  const QList<QgsAuthCrlEntry> entries( mEntries );
  for ( const auto entry : entries )
  {
    results.append( entry.serialNumber( ) );
  }
  return results;
}


QByteArray QgsAuthCrlEntry::serialNumberAsHexArray() const
{
  QByteArray result;
  if ( mSerialNumber.toHex().size() )
  {
    QByteArray hex;
    if ( mSerialNumber.at( 0 ) == 0x00 )
      hex = mSerialNumber.mid( 1 ).toHex();
    else
      hex = mSerialNumber.toHex();
    for ( int pos = 0; pos < hex.size(); ++pos )
    {
      result.append( hex.at( pos ) );
      if ( pos % 2 && pos + 1 < hex.size() )
      {
        result.append( ':' );
      }
    }
  }
  return result;
}

const QgsAuthCrlEntry *QgsAuthCrl::certificateEntry( const QSslCertificate &certificate ) const
{
  for ( int i = 0; i < mEntries.size(); ++i )
  {
    if ( certificate.serialNumber() == mEntries.at( i ).serialNumberAsHexArray() )
    {
      return &mEntries.at( i );
    }
  }
  return nullptr;
}

bool QgsAuthCrl::isRevoked(const QSslCertificate &certificate) const
{
  const QgsAuthCrlEntry* entry = certificateEntry( certificate );
  if ( entry )
  {
    return entry->revokationDate() <= QDateTime::currentDateTime( );
  }
  return true;
}
