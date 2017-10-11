/***************************************************************************
  qgsauthcrl.h - QgsAuthCrl

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
#ifndef QGSAUTHCRL_H
#define QGSAUTHCRL_H

#include <QObject>
#include <QSslCertificate>
#include <QDateTime>

#include "qgis_core.h"
#include "qca.h"

/**
 * \ingroup core
 * \brief CRL entry from a CRL
 */
class CORE_EXPORT QgsAuthCrlEntry
{

  public:

    enum Reason
    {
      Unspecified,        ///< reason is unknown
      KeyCompromise,      ///< private key has been compromised
      CACompromise,       ///< certificate authority has been compromised
      AffiliationChanged,
      Superseded,         ///< certificate has been superseded
      CessationOfOperation,
      CertificateHold,    ///< certificate is on hold
      RemoveFromCRL,      ///< certificate was previously in a CRL, but is now valid
      PrivilegeWithdrawn,
      AACompromise        ///< attribute authority has been compromised
    };


    /**
     * \brief QgsAuthCrlEntry construct a QgsAuthCrlEntry from a \a reason a \a certificate and the \a revokationDate
     */
    QgsAuthCrlEntry( const Reason &reason, const QByteArray &serialNumber, const QDateTime &revokationDate );

    /**
     * \brief reasonFromQCAReason maps QCA \a reason enum to QgsAuthCrlEntry Reason
     * \return the reason
     */
    static Reason reasonFromQCAReason( const QCA::CRLEntry::Reason &reason );

    /**
     * \brief reasonAsString returns a textual description of the revocation \a reason
     * \return textual description of the revocation \a reason
     */
    QString reasonAsString( const Reason &reason ) const;


    /**
     * \brief Returns the reason why the certificate was put in the CRL
     * \return the reason
     */
    Reason reason() const { return mReason; }

    /**
     * \brief Returns the revokation date of the certificate
     * \return the revokation date
     */
    QDateTime revokationDate() const { return mRevokationDate; }

    /**
     * The serial number of the certificate that is the subject of this CRL entry
     * \return the certificate serial number
     */
    QByteArray serialNumber() const { return mSerialNumber; }

    /**
     * \brief serialNumberAsHexArray return the serial number as encoded hex array
     * \return the serial number encoded as hex array
     */
    QByteArray serialNumberAsHexArray( ) const;

  private:

    Reason mReason;
    QByteArray mSerialNumber;
    QDateTime mRevokationDate;

};



/**
 * \ingroup core
 * \brief CRL
 */
class CORE_EXPORT QgsAuthCrl
{
  public:

    /**
     * \brief QgsAuthCrl construct the CRL by reading it from a DER or PEM file
     * \param crlPath the CRL file path
     */
    QgsAuthCrl( const QString &crlPath );

    /**
     * \brief entries
     * \return the list of CRL entries
     */
    QList<QgsAuthCrlEntry> entries() const { return mEntries; }

    /**
     * \brief serialNumbers
     * \return the list of CRL certificates serial numbers
     */
    QList<QByteArray> serialNumbers() const;

    /**
     * \brief certificateEntry return the CRL entry for the given \a certificate,
     * a nullptr is returned if there is no such entry in the CRL
     * \param certificate to be searched
     */
    const QgsAuthCrlEntry *certificateEntry( const QSslCertificate &certificate ) const;

    /**
     * \brief isRevoked checks is the given \a certificate is revoked
     * \param certificate to be checked
     * \return false if the certificate is in the CRL and the revokation time is in the past
     */
    bool isRevoked( const QSslCertificate &certificate ) const;


  private:

    QList<QgsAuthCrlEntry> mEntries;
};

#endif // QGSAUTHCRL_H
