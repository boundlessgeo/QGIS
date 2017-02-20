/***************************************************************************
    qgskeystoreutils.cpp
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
 *
 *   Code inspired from Justin Karneges <justin@affinix.com> code get from:
 *   https://quickgit.kde.org/?p=qca.git&a=blob&h=b48d8529ccd586c2a14dfa219fae29825c1c7105&hb=eb5eeca609e9960d7afe3462b421bfe0a48b8e21&f=src%2Fqca_systemstore_win.cpp
 *   and
 *   from Jason Geffner code get from:
 *   https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf
 *                                                                         *
 ***************************************************************************/

//#ifdef Q_OS_WIN

#ifndef QT_NO_OPENSSL
#include <QSslCertificate>
#include <QSslKey>
#include <QSsl>
#endif
#include <QList>
#include <QPair>
#include <QChar>
#include <QDir>
#include <QtGlobal>
#include <QFile>

#include "qgslogger.h"
#include "qgskeystoreutils.h"
#include "qgsauthcertutils.h"

#include <windows.h>
#include <Winbase.h>
#include <wincrypt.h>
#include <tchar.h>
#include <stdio.h>


QString
get_random_string(
    const int size)
{
  const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");

  QString randomString;
  for(int i=0; i<size; ++i)
  {
    int index = std::rand() % possibleCharacters.length();
    QChar nextChar = possibleCharacters.at(index);
    randomString.append(nextChar);
  }
  return randomString;
}

bool
convert_hash_to_binary(
    const QString &certHash,
    CRYPT_HASH_BLOB &hashBlob)
{
  // reset the CRYPT_HASH_BLOB struct
  hashBlob.cbData = 0;
  if(hashBlob.pbData)
  {
    free(hashBlob.pbData);
    hashBlob.pbData = NULL;
  }

  // convert hash in binary hash useful to find certificate
  LPCTSTR pszString = certHash.toLatin1().data();
  DWORD pcchString = certHash.toLatin1().size();
  DWORD pcbBinary;
  if ( !CryptStringToBinary(
         pszString,
         pcchString,
         CRYPT_STRING_HEX,
         NULL,
         &pcbBinary,
         NULL,
         NULL))
  {
    QgsDebugMsg( QString( "Cannot convert hash to binary for hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    return false;
  }
  BYTE *pbBinary = (BYTE*) malloc(pcbBinary);
  CryptStringToBinary(
        pszString,
        pcchString,
        CRYPT_STRING_HEX,
        pbBinary,
        &pcbBinary,
        NULL,
        NULL);

  // fill the CRYPT_HASH_BLOB struct
  hashBlob.cbData = pcbBinary;
  hashBlob.pbData = pbBinary;

  return true;
}

bool
KeystoreUtils::have_systemstore(
    const QString &storeName)
{
  bool ok = false;
  HCERTSTORE hSystemStore;

  // open store
  hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
  if(hSystemStore)
    ok = true;

  // close it
  CertCloseStore(hSystemStore, 0);

  return ok;
}

QList< QSslCertificate >
KeystoreUtils::get_systemstore(
    const QString &storeName)
{
  QList<QSslCertificate> result;
  QList<QSslCertificate> certs;
  QSslCertificate cert;
  HCERTSTORE hSystemStore;

  // open store
  hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
  if(!hSystemStore)
    return result;

  // load certs
  PCCERT_CONTEXT pCertContext = NULL;
  while(1)
  {
    pCertContext = CertFindCertificateInStore(
          hSystemStore,
          X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
          0,
          CERT_FIND_ANY,
          NULL,
          pCertContext);
    if(!pCertContext)
      break;

    // transform cert in QSslCertificate format
    int size = pCertContext->cbCertEncoded;
    QByteArray der(size, 0);
    memcpy(der.data(), pCertContext->pbCertEncoded, size);

    certs = QSslCertificate::fromData(der, QSsl::Der);
    if( certs.isEmpty() )
      continue;
    cert = certs.first();

    // get printable info useful for notification purpose
    QString certInfoName = QgsAuthCertUtils::resolvedCertName( cert );

    // check if cert is RSA
    if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                szOID_RSA,
                strlen(szOID_RSA)))
    {
      QgsDebugMsg( QString( "Cert %1: is not RSA. Skipped!" ).arg( certInfoName ) );
      continue;
    }

    // add to result
    result.append( cert );
  }

  // close store
  CertCloseStore(hSystemStore, 0);

  return result;
}

QSslCertificate
KeystoreUtils::get_systemstore_cert(
    const QString &certHash,
    const QString &storeName)
{
  QSslCertificate cert;
  HCERTSTORE hSystemStore;
  CRYPT_HASH_BLOB hashBlob;

  // open store
  hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
  if(!hSystemStore)
    return cert;

  // fill the CRYPT_HASH_BLOB struct
  hashBlob.cbData = (DWORD) certHash.length();
  hashBlob.pbData = (BYTE*) malloc (certHash.length());
  memcpy(hashBlob.pbData, certHash.toStdString().c_str(), hashBlob.cbData);

  // load certs
  // can be available more than one cert with the same hash due to
  // multiple import and different name
  PCCERT_CONTEXT pCertContext = NULL;
  pCertContext = CertFindCertificateInStore(
        hSystemStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        (const void *) &hashBlob,
        NULL);
  if ( pCertContext )
  {
    int size = pCertContext->cbCertEncoded;
    QByteArray der(size, 0);
    memcpy(der.data(), pCertContext->pbCertEncoded, size);

    QList<QSslCertificate> certs = QSslCertificate::fromData(der, QSsl::Der);
    if( !certs.isEmpty() )
    {
      cert = certs.first();
    }
  }

  // close store
  if(pCertContext)
    CertFreeCertificateContext(pCertContext);
  CertCloseStore(hSystemStore, 0);

  return cert;
}

bool
KeystoreUtils::systemstore_cert_privatekey_available(
    const QString &certHash,
    const QString &storeName)
{
  bool isAvailable = false;

  // wincrypt vars
  HCERTSTORE hSystemStore = NULL;
  CRYPT_HASH_BLOB hashBlob;
  hashBlob.cbData = 0;
  hashBlob.pbData = NULL;
  PCCERT_CONTEXT pCertContext = NULL;
  DWORD dwKeySpec;
  DWORD dwKeySpecSize = sizeof(dwKeySpec);

  // open store
  QgsDebugMsgLevel( QString( "Opening KeyStore %1" ).arg( storeName ), 99);

  hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
  if(!hSystemStore)
  {
    QgsDebugMsg( QString( "Cannot open KeyStore %1" ).arg( storeName ) );
    goto terminate;
  }

  // convert hash in binary hash useful to find certificate
  QgsDebugMsgLevel( QString( "Converting hash %1 to binary" ).arg( certHash ), 99);

  if ( !convert_hash_to_binary(
         certHash,
         hashBlob) )
  {
    goto terminate;
  }

  // load cert related with the hash
  // can be available more than one cert with the same hash due to
  // multiple import and different name
  QgsDebugMsgLevel( QString( "Finding cert with hash %1 in store %2" ).arg( certHash ).arg( storeName ), 99);

  pCertContext = CertFindCertificateInStore(
        hSystemStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        (const void *) &hashBlob,
        NULL);
  if ( !pCertContext )
  {
    QgsDebugMsg( QString( "No cert found with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // check if cert is RSA
  QgsDebugMsgLevel( QString( "Checking if cert with hash %1 is RSA" ).arg( certHash ), 99);

  if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
              szOID_RSA,
              strlen(szOID_RSA)))
  {
    QgsDebugMsg( QString( "Cert with hash %1: is not RSA" ).arg( certHash ) );
    goto terminate;
  }

  // check if cert has private key
  QgsDebugMsgLevel( QString( "Checking if cert with hash %1 has private key available" ).arg( certHash ), 99);

  if (CertGetCertificateContextProperty(
        pCertContext,
        CERT_KEY_SPEC_PROP_ID,
        &dwKeySpec,
        &dwKeySpecSize))
  {
    isAvailable = true;
  }
  else
  {
    QgsDebugMsg( QString( "Cert with hash %1: has no private key available" ).arg( certHash ) );
  }

terminate:
  QgsDebugMsgLevel( QString( "Starting function cleanup" ), 99);

  // close store
  if(pCertContext)
    CertFreeCertificateContext(pCertContext);
  if (hSystemStore)
    CertCloseStore(hSystemStore, 0);

  // fee allocations
  if(hashBlob.pbData)
  {
    free(hashBlob.pbData);
    hashBlob.pbData = NULL;
    hashBlob.cbData = 0;
  }

  return isAvailable;
}

bool
KeystoreUtils::systemstore_cert_privatekey_is_exportable(
    const QString &certHash,
    const QString &storeName)
{
  bool isExportable = false;

  // wincrypt vars
  HCERTSTORE hSystemStore = NULL;
  CRYPT_HASH_BLOB hashBlob;
  hashBlob.cbData = 0;
  hashBlob.pbData = NULL;
  PCCERT_CONTEXT pCertContext = NULL;
  DWORD dwKeySpec;
  DWORD dwKeySpecSize = sizeof(dwKeySpec);
  HCRYPTPROV hProv;
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
  BOOL fCallerFreeProvOrNCryptKey;
  HCRYPTKEY hKey;
  DWORD cbData;

  // open store
  QgsDebugMsgLevel( QString( "Opening KeyStore %1" ).arg( storeName ), 99);

  hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
  if(!hSystemStore)
  {
    QgsDebugMsg( QString( "Cannot open KeyStore %1" ).arg( storeName ) );
    goto terminate;
  }

  // convert hash in binary hash useful to find certificate
  QgsDebugMsgLevel( QString( "Converting hash %1 to binary" ).arg( certHash ), 99);

  if ( !convert_hash_to_binary(
         certHash,
         hashBlob) )
  {
    goto terminate;
  }

  // load cert related with the hash
  // can be available more than one cert with the same hash due to
  // multiple import and different name
  QgsDebugMsgLevel( QString( "Finding cert with hash %1 in store %2" ).arg( certHash ).arg( storeName ), 99);

  pCertContext = CertFindCertificateInStore(
        hSystemStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        (const void *) &hashBlob,
        NULL);
  if ( !pCertContext )
  {
    QgsDebugMsg( QString( "No cert found with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // check if cert is RSA
  QgsDebugMsgLevel( QString( "Checking if cert with hash %1 is RSA" ).arg( certHash ), 99);

  if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
              szOID_RSA,
              strlen(szOID_RSA)))
  {
    QgsDebugMsg( QString( "Cert with hash %1: is not RSA" ).arg( certHash ) );
    goto terminate;
  }

  // check if cert has private key
  QgsDebugMsgLevel( QString( "Checking if cert with hash %1 has private key available" ).arg( certHash ), 99);

  if (!CertGetCertificateContextProperty(
        pCertContext,
        CERT_KEY_SPEC_PROP_ID,
        &dwKeySpec,
        &dwKeySpecSize))
  {
    QgsDebugMsg( QString( "Cert with hash %1: has no private key available" ).arg( certHash ) );
    goto terminate;
  }

  // check if private key is exportable

  // Retrieve a handle to the certificate's private key's CSP key
  // container. Precedence to a CNG handle respect CryptoAPI (CAPI)
  QgsDebugMsgLevel( QString( "Checking if cert with hash %1 has exportable private key" ).arg( certHash ), 99);

  if (!CryptAcquireCertificatePrivateKey(
        pCertContext,
        CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
        //CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
        NULL,
        &hCryptProvOrNCryptKey,
        &dwKeySpec,
        &fCallerFreeProvOrNCryptKey))
  {
    QgsDebugMsg( QString( "Cannot retrieve handles for private key for cert with hash %1. Skipped!: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // look if key is exportable, doing export!
  if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
  {
    QgsDebugMsg( QString( "Returned KeySpec in CAPI context for cert with hash %1.").arg( certHash ) );

    // Retrieve a handle to the certificate's private key
    QgsDebugMsgLevel( QString( "Retrieving private key handle for cert with hash %1" ).arg( certHash ), 99);
    hProv = hCryptProvOrNCryptKey;

    if (!CryptGetUserKey(
          hProv,
          dwKeySpec,
          &hKey))
    {
      QgsDebugMsg( QString( "Cannot retrieve handles for private key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      goto terminate;
    }

    // try to export public/private key
    QgsDebugMsgLevel( QString( "Trying to export private key for cert with hash %1" ).arg( certHash ), 99);

    if ( !CryptExportKey(
           hKey,
           0,
           PRIVATEKEYBLOB,
           0,
           NULL,
           &cbData) )
    {
      QgsDebugMsg( QString( "Private key is NOT exportable for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      isExportable = false;
    }
    else
    {
      QgsDebugMsg( QString( "Private key is exportable for cert with hash %1" ).arg( certHash ));
      isExportable = true;
    }
  }
  else
  {
    QgsDebugMsg( QString( "Returned KeySpec in CNG context for cert with hash %1.").arg( certHash ) );
    QgsDebugMsgLevel( QString( "Trying to export private key for cert with hash %1" ).arg( certHash ), 99);

    SECURITY_STATUS ss = NCryptExportKey(
          hCryptProvOrNCryptKey,
          NULL,
          LEGACY_RSAPRIVATE_BLOB,
          NULL,
          NULL,
          0,
          &cbData,
          0);
    if ( ERROR_SUCCESS != ss )
    {
      QgsDebugMsg( QString( "Private key is NOT exportable for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( ss, 0, 16 ) );
      isExportable = false;
    }
    else
    {
      QgsDebugMsg( QString( "Private key is exportable for cert with hash %1" ).arg( certHash ));
      isExportable = true;
    }
  }

terminate:
  QgsDebugMsgLevel( QString( "Starting function cleanup" ), 99);

  if (hCryptProvOrNCryptKey)
    if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
      if ( !CryptDestroyKey(hCryptProvOrNCryptKey) )
      {
        QgsDebugMsg( QString( "Cannot destroy temporary key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      }
    else
      NCryptFreeObject(hCryptProvOrNCryptKey);

  // close store
  if(pCertContext)
    CertFreeCertificateContext(pCertContext);
  if (hSystemStore)
    CertCloseStore(hSystemStore, 0);

  // fee allocations
  if(hashBlob.pbData)
  {
    free(hashBlob.pbData);
    hashBlob.pbData = NULL;
    hashBlob.cbData = 0;
  }

  return isExportable;
}


QPair<QSslCertificate, QSslKey>
KeystoreUtils::get_systemstore_cert_with_privatekey(
    const QString &certHash,
    const QString &storeName,
    const bool forceExport)
{
  HANDLE hFile = NULL;

  // QSsl section
  QSslKey privateKey = QSslKey();
  QSslCertificate localCertificate = QSslCertificate();
  QPair<QSslCertificate, QSslKey> result;
  result.first = localCertificate;
  result.second = privateKey;
  QByteArray der;
  QList<QSslCertificate> certs;
  QString wszFileName;
  QString pwd;
  std::string sTemp;
  std::wstring wsTemp;

  // qca section
  QCA::SecureArray passarray;
  QCA::ConvertResult res;
  QCA::KeyBundle bundle;

  // wincrypt section
  HCERTSTORE hSystemStore = NULL;
  PCCERT_CONTEXT pCertContext = NULL;
  BYTE *pbBinary = NULL;
  CRYPT_HASH_BLOB hashBlob;
  hashBlob.cbData = 0;
  hashBlob.pbData = NULL;
  CRYPT_DATA_BLOB cdb;
  cdb.cbData = 0;
  cdb.pbData = NULL;
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeyNew = NULL;
  SC_HANDLE hSCManager = NULL;
  SC_HANDLE hService = NULL;
  HANDLE hProcess = NULL;
  HCERTSTORE hMemoryStore = NULL;
  PCCERT_CONTEXT pCertContextNew = NULL;
  NCRYPT_PROV_HANDLE hProvider = NULL;
  BYTE *ssp = NULL;
  DWORD dwBytesNeeded = 0;


  // open store
  QgsDebugMsgLevel( QString( "Opening KeyStore %1" ).arg( storeName ), 99);

  hSystemStore = CertOpenSystemStoreA(
        0,
        storeName.toStdString().c_str());
  if(!hSystemStore)
  {
    QgsDebugMsg( QString( "Cannot open System Store %1: Wincrypt error 0x%2" ).arg( storeName ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // convert hash in binary hash useful to find certificate
  QgsDebugMsgLevel( QString( "Converting hash %1 to binary" ).arg( certHash ), 99);

  if ( !convert_hash_to_binary(
         certHash,
         hashBlob) )
  {
    goto terminate;
  }

  // load cert related with the hash
  // can be available more than one cert with the same hash due to
  // multiple import and different name
  QgsDebugMsgLevel( QString( "Finding cert with hash %1 in store %2" ).arg( certHash ).arg( storeName ), 99);

  pCertContext = CertFindCertificateInStore(
        hSystemStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        (const void *) &hashBlob,
        NULL);
  if ( !pCertContext )
  {
    QgsDebugMsg( QString( "No cert found with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // check if cert is RSA
  QgsDebugMsgLevel( QString( "Checking if cert with hash %1 is RSA" ).arg( certHash ), 99);

  if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
              szOID_RSA,
              strlen(szOID_RSA)))
  {
    QgsDebugMsg( QString( "Cert with hash %1: is not RSA" ).arg( certHash ) );
    goto terminate;
  }

  // create QSslCertificate from pCertContext
  QgsDebugMsgLevel( QString( "Creating QSslCertificate from der data for cert with hash %1" ).arg( certHash ), 99);

  der = QByteArray(pCertContext->cbCertEncoded, 0);
  memcpy(der.data(),
         pCertContext->pbCertEncoded,
         pCertContext->cbCertEncoded);

  certs = QSslCertificate::fromData(der, QSsl::Der);
  if ( (certs.size() == 0) || certs.first().isNull() )
  {
    QgsDebugMsg( QString( "Cannot create QSslCertificate cert from data for cert with hash %1" ).arg( certHash ) );
    goto terminate;
  }
  localCertificate = certs.first();
  result.first = localCertificate;

  // check if cert has private key
  QgsDebugMsgLevel( QString( "checking if cert with hash %1 has private key" ).arg( certHash ), 99);

  DWORD dwKeySpec;
  DWORD dwKeySpecSize = sizeof(dwKeySpec);

  if (!CertGetCertificateContextProperty(
        pCertContext,
        CERT_KEY_SPEC_PROP_ID,
        &dwKeySpec,
        &dwKeySpecSize))
  {
    QgsDebugMsg( QString( "Cert with hash %1 has not private key: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // Retrieve a handle to the certificate's private key's CSP key
  // container
  HCRYPTPROV hProv;
  HCRYPTPROV hProvTemp;
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
  NCRYPT_KEY_HANDLE hNKey;
  BOOL fCallerFreeProvOrNCryptKey;

  QgsDebugMsgLevel( QString( "Getting handle for cert with hash %1" ).arg( certHash ), 99);

  if (!CryptAcquireCertificatePrivateKey(
        pCertContext,
        CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
        //CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
        NULL,
        &hCryptProvOrNCryptKey,
        &dwKeySpec,
        &fCallerFreeProvOrNCryptKey))
  {
    QgsDebugMsg( QString( "Cannot retrieve handles for private key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // export keys
  hProv = hCryptProvOrNCryptKey;
  hNKey = hCryptProvOrNCryptKey;
  HCRYPTKEY hKey;
  BYTE* pbData = NULL;
  DWORD cbData = 0;

  if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
  {
    QgsDebugMsg( QString( "Returned KeySpec in CAPI context for cert with hash %1.").arg( certHash ) );

    // entering here means that key can be:
    // AT_KEYEXCHANGE: The key pair is a key exchange pair.
    // AT_SIGNATURE: The key pair is a signature pair.

    // Retrieve a handle to the certificate's private key
    QgsDebugMsgLevel( QString( "Getting handles for private key for cert with hash %1" ).arg( certHash ), 99);

    if (!CryptGetUserKey(
          hProv,
          dwKeySpec,
          &hKey))
    {
      QgsDebugMsg( QString( "Cannot retrieve handles for private key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      goto terminate;
    }

    // Export the public/private key
    // first attend in case key is exportable
    // and to retieve the lenght, then to retrieve data
    QgsDebugMsgLevel( QString( "First try to get private key size for cert with hash %1" ).arg( certHash ), 99);

    bool hasExported = CryptExportKey(
          hKey,
          0,
          PRIVATEKEYBLOB,
          0,
          NULL,
          &cbData);
    if (!hasExported && forceExport)
    {
      // Mark the certificate's private key as exportable and archivable
      // this memory structure hack derive directly from the following paper:
      // https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf
      *(ULONG_PTR*)(*(ULONG_PTR*)(*(ULONG_PTR*)
      #if defined(_M_X64)
        (hKey + 0x58) ^ 0xE35A172CD96214A0) + 0x0C)
      #elif (defined(_M_IX86) || defined(_ARM_))
        (hKey + 0x2C) ^ 0xE35A172C) + 0x08)
      #else
        #error Platform not supported
      #endif
        |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;

      // Export the public/private key
      // first to retieve the lenght, then to retrieve data
      // second attend to get the key after the memory hack
      QgsDebugMsgLevel( QString( "Second try to get private key size for cert with hash %1" ).arg( certHash ), 99);

      hasExported = CryptExportKey(
            hKey,
            0,
            PRIVATEKEYBLOB,
            0,
            NULL,
            &cbData);
    }
    // if not exported after the second attend => some error accourred
    if (!hasExported)
    {
      QgsDebugMsg( QString( "Cannot export private key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      goto terminate;
    }

    // retrieve private key
    QgsDebugMsgLevel( QString( "Exporting private key for cert with hash %1" ).arg( certHash ), 99);

    pbData = (BYTE*)malloc(cbData);
    if (!CryptExportKey(
            hKey,
            0,
            PRIVATEKEYBLOB,
            0,
            pbData,
            &cbData))
    {
      QgsDebugMsg( QString( "Cannot export private key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      goto terminate;
    }

    // Establish a temporary key container
    QgsDebugMsgLevel( QString( "Creating temporary key container for cert with hash %1" ).arg( certHash ), 99);

    if ( !CryptAcquireContext(
           &hProvTemp,
           NULL,
           NULL,
           PROV_RSA_FULL,
           CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET) )
    {
      QgsDebugMsg( QString( "Cannot create temporary KeyStore for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      goto terminate;
    }

    // Import the private key into the temporary key container
    QgsDebugMsgLevel( QString( "Importing private key in temporary container for cert with hash %1" ).arg( certHash ), 99);

    if ( !CryptImportKey(
           hProvTemp,
           pbData,
           cbData,
           0,
           CRYPT_EXPORTABLE,
           &hKeyNew) )
    {
      QgsDebugMsg( QString( "Cannot import key in temporary KeyStore for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      goto terminate;
    }
  }
  else
  {
    QgsDebugMsg( QString( "Returned KeySpec in CNG context for cert with hash %1.").arg( certHash ) );
    QgsDebugMsgLevel( QString( "First try to get private key size for cert with hash %1" ).arg( certHash ), 99);

    SECURITY_STATUS ss = NCryptExportKey(
                             hCryptProvOrNCryptKey,
                             NULL,
                             LEGACY_RSAPRIVATE_BLOB,
                             NULL,
                             NULL,
                             0,
                             &cbData,
                             0);
    if ( ERROR_SUCCESS != ss )
    {
      if (forceExport)
      {
        // TODO: enter here only if the correct SECURITY_STATUS error is received
        // that means error regarding cert that can't be exported.

        // Mark the certificate's private key as exportable and archivable

        // Retrieve a handle to the Service Control Manager
        QgsDebugMsgLevel( QString( "Opening SCManager for cert with hash %1" ).arg( certHash ), 99);

        hSCManager = OpenSCManager(
              NULL,
              NULL,
              SC_MANAGER_CONNECT);
        if (!hSCManager)
        {
           QgsDebugMsg( QString( "Cannot open Service Control Manager for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
           goto terminate;
        }

        // Retrieve a handle to the KeyIso service
        QgsDebugMsgLevel( QString( "Opening KeyIso service for cert with hash %1" ).arg( certHash ), 99);

        hService = OpenService(
              hSCManager,
              _T("KeyIso"),
              SERVICE_QUERY_STATUS);
        if (!hService)
        {
          QgsDebugMsg( QString( "Cannot open KeyIso Service for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
          goto terminate;
        }

        // Retrieve the status of the KeyIso process, including its Process ID
        QgsDebugMsgLevel( QString( "Retrieving KeyIso service status for cert with hash %1" ).arg( certHash ), 99);

        if (!QueryServiceStatusEx(
                hService,
                SC_STATUS_PROCESS_INFO,
                NULL,
                0,
                &dwBytesNeeded))
        {
          if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
          {
            QgsDebugMsg( QString( "Cannot stat KeyIso Service status for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
            goto terminate;
          }
        }
        ssp = (BYTE*)malloc(dwBytesNeeded);

        if (!QueryServiceStatusEx(
                hService,
                SC_STATUS_PROCESS_INFO,
                ssp,
                dwBytesNeeded,
                &dwBytesNeeded))
        {
          QgsDebugMsg( QString( "Cannot stat KeyIso Service status for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
          goto terminate;
        }

        // set privilege
        // ///////////////////////////////////////////////////////
        //   Note: Enabling SeDebugPrivilege adapted from sample
        //     MSDN @ http://msdn.microsoft.com/en-us/library/aa446619%28VS.85%29.aspx
        // Enable SeDebugPrivilege
        HANDLE hToken = NULL;
        TOKEN_PRIVILEGES tokenPriv;
        LUID luidDebug;
        QgsDebugMsgLevel( QString( "Getting current process token" ), 99);
        if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
           QgsDebugMsgLevel( QString( "Looking for privilege" ), 99);
           if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug))
           {
              tokenPriv.PrivilegeCount           = 1;
              tokenPriv.Privileges[0].Luid       = luidDebug;
              tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
              if(AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
              {
                if ( GetLastError() == ERROR_SUCCESS)
                {
                  QgsDebugMsg( QString( "successfully changed privilege" ) );
                }
                else
                {
                  QgsDebugMsg( QString( "FAILED TO CHANGE TOKEN PRIVILEGES: Wincrypt error 0x%1" ).arg( GetLastError(), 0, 16 ) );
                }
              }
              else
              {
                 QgsDebugMsg( QString( "FAILED TO CHANGE TOKEN PRIVILEGES: Wincrypt error 0x%1" ).arg( GetLastError(), 0, 16 ) );
              }
           }
           else
           {
             QgsDebugMsg( QString( "FAILED look for PRIVILEGES: Wincrypt error 0x%1" ).arg( GetLastError(), 0, 16 ) );
           }
        }
        else
        {
          QgsDebugMsg( QString( "Cannot get token: Wincrypt error 0x%1" ).arg( GetLastError(), 0, 16 ) );
        }
        if (hToken)
          CloseHandle(hToken);
        // Enable SeDebugPrivilege
        // ///////////////////////////////////////////////////////

        // Open a read-write handle to the process hosting the KeyIso service
        QgsDebugMsgLevel( QString( "Opening process (orw) id: %1 for cert with hash %2" ).arg(((SERVICE_STATUS_PROCESS*)ssp)->dwProcessId).arg( certHash ), 99);

        hProcess = OpenProcess(
              PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
              FALSE,
              ((SERVICE_STATUS_PROCESS*)ssp)->dwProcessId);
        if (!hProcess)
        {
          QgsDebugMsg( QString( "Cannot open process for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
          goto terminate;
        }

        // this memory structure hack derive directly from the following paper:
        // https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf

        // Prepare the structure offsets for accessing the appropriate field
        DWORD dwOffsetNKey;
        DWORD dwOffsetSrvKeyInLsass;
        DWORD dwOffsetKspKeyInLsass;
        #if defined(_M_X64)
          dwOffsetNKey = 0x10;
          dwOffsetSrvKeyInLsass = 0x28;
          dwOffsetKspKeyInLsass = 0x28;
        #elif defined(_M_IX86)
          dwOffsetNKey = 0x08;
          if (!g_fWow64Process)
          {
            dwOffsetSrvKeyInLsass = 0x18;
            dwOffsetKspKeyInLsass = 0x20;
          }
          else
          {
            dwOffsetSrvKeyInLsass = 0x28;
            dwOffsetKspKeyInLsass = 0x28;
          }
        #else
          // Platform not supported
          QgsDebugMsg( QString( "Platform not supported" ) );
          goto terminate;
        #endif

        // Mark the certificate's private key as exportable
        QgsDebugMsgLevel( QString( "Reading pKspKeyInLsass for cert with hash %1" ).arg( certHash ), 99);

        DWORD pKspKeyInLsass;
        SIZE_T sizeBytes;

        if (!ReadProcessMemory(
                hProcess,
                (void*)(*(SIZE_T*)*(DWORD*)(hNKey + dwOffsetNKey) + dwOffsetSrvKeyInLsass),
                &pKspKeyInLsass,
                sizeof(DWORD),
                &sizeBytes))
        {
          QgsDebugMsg( QString( "Cannot read pKspKeyInLsass in memory for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
          goto terminate;
        }

        QgsDebugMsgLevel( QString( "Reading ucExportable for cert with hash %1" ).arg( certHash ), 99);
        unsigned char ucExportable;
        if (!ReadProcessMemory(
                hProcess,
                (void*)(pKspKeyInLsass + dwOffsetKspKeyInLsass),
                &ucExportable,
                sizeof(unsigned char),
                &sizeBytes))
        {
          QgsDebugMsg( QString( "Cannot read ucExportable in memory for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
          goto terminate;
        }

        // do flag exportable
        QgsDebugMsgLevel( QString( "Setting cert with hash %1as exportable" ).arg( certHash ), 99);

        ucExportable |= NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        if (!WriteProcessMemory(
                hProcess,
                (void*)(pKspKeyInLsass + dwOffsetKspKeyInLsass),
                &ucExportable,
                sizeof(unsigned char),
                &sizeBytes))
        {
          QgsDebugMsg( QString( "Cannot read ucExportable in memory for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
          goto terminate;
        }

        // Export the private key
        QgsDebugMsgLevel( QString( "Second try to get private key size for cert with hash %1" ).arg( certHash ), 99);

        ss = NCryptExportKey(
                hNKey,
                NULL,
                LEGACY_RSAPRIVATE_BLOB,
                NULL,
                NULL,
                0,
                &cbData,
                0);
        if ( ERROR_SUCCESS != ss )
        {
          QgsDebugMsg( QString( "Cannot get size of private key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( ss, 0, 16 ) );
          goto terminate;
        }

        QgsDebugMsgLevel( QString( "Exporting private key for cert with hash %1" ).arg( certHash ), 99);
        pbData = (BYTE*)malloc(cbData);
        ss = NCryptExportKey(
                hNKey,
                NULL,
                LEGACY_RSAPRIVATE_BLOB,
                NULL,
                pbData,
                cbData,
                &cbData,
                0);
        if ( ERROR_SUCCESS != ss )
        {
          QgsDebugMsg( QString( "Cannot export private key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( ss, 0, 16 ) );
          goto terminate;
        }

        // Establish a temporary CNG key store provider
        QgsDebugMsgLevel( QString( "Setting temporary CNG keystore provider for cert with hash %1" ).arg( certHash ), 99);

        ss = NCryptOpenStorageProvider(
                &hProvider,
                MS_KEY_STORAGE_PROVIDER,
                0);
        if ( ERROR_SUCCESS != ss )
        {
          QgsDebugMsg( QString( "Cannot set temporary CNG keystore for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( ss, 0, 16 ) );
          goto terminate;
        }

        // Import the private key into the temporary storage provider
        QgsDebugMsgLevel( QString( "Importing private key in temporary container for cert with hash %1" ).arg( certHash ), 99);

        ss = NCryptImportKey(
                hProvider,
                NULL,
                LEGACY_RSAPRIVATE_BLOB,
                NULL,
                &hKeyNew,
                pbData,
                cbData,
                0);
        if ( ERROR_SUCCESS != ss )
        {
          QgsDebugMsg( QString( "Cannot set temporary CNG keystore for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( ss, 0, 16 ) );
          goto terminate;
        }
      }
      else
      {
        QgsDebugMsg( QString( "Cannot export private key and no forcing is set for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( ss, 0, 16 ) );
        goto terminate;
      }
    }
  }

  /***********************************************************
    * now having the key, start the process to export in a pfx
    * file container
    ************************************************************/

  // Create a temporary certificate store in memory
  QgsDebugMsgLevel( QString( "Opening memory keystore for cert with hash %1" ).arg( certHash ), 99);

  hMemoryStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        NULL,
        0,
        NULL);
  if ( !hMemoryStore )
  {
    QgsDebugMsg( QString( "Cannot open memory store for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // Add a link to the certificate to our temporary certificate store
  QgsDebugMsgLevel( QString( "Linking cert to memory keystore for cert with hash %1" ).arg( certHash ), 99);

  if ( !CertAddCertificateLinkToStore(
         hMemoryStore,
         pCertContext,
         CERT_STORE_ADD_NEW,
         &pCertContextNew) )
  {
    QgsDebugMsg( QString( "Cannot link cert context for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // Set the key container for the linked certificate to be our temporary
  // key container
  QgsDebugMsgLevel( QString( "Setting key container for linked cert with hash %1" ).arg( certHash ), 99);

  if ( !CertSetCertificateContextProperty(
         pCertContext,
         CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID,
         0,
         (void*)( (CERT_NCRYPT_KEY_SPEC == dwKeySpec) ? hNKey : hProvTemp) ))
  {
    QgsDebugMsg( QString( "Cannot set property for temporary cert related to cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // random pwd to export key...
  // and convert to wstring to API compatibility
  pwd = get_random_string(24);
  sTemp = pwd.toStdString();
  wsTemp = std::wstring(sTemp.begin(), sTemp.end());

  // Export the temporary certificate store to a PFX data blob in memory
  QgsDebugMsgLevel( QString( "Getting PFX cert size for cert with hash %1" ).arg( certHash ), 99);

  if ( !PFXExportCertStoreEx(
         hMemoryStore,
         &cdb,
         wsTemp.c_str(),
         NULL,
         EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY) )
  {
    QgsDebugMsg( QString( "Cannot get cert size for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }
  cdb.pbData = (BYTE*)malloc(cdb.cbData);

  QgsDebugMsgLevel( QString( "Exporting PFX cert for cert with hash %1" ).arg( certHash ), 99);
  if ( !PFXExportCertStoreEx(
         hMemoryStore,
         &cdb,
         wsTemp.c_str(),
         NULL,
         EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY) )
  {
    QgsDebugMsg( QString( "Cannot store cert in temporary store for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // Prepare the PFX's file name
  wszFileName = QString("%1%2%3")
      .arg( QDir::tempPath() )
      .arg( QDir::separator() )
      .arg( get_random_string(8) );

  // Write the PFX data blob to disk
  // because of nature of the filename, I can safly use
  // CreateFileA (Ascii) insteand the generic alias CreateFile
  QgsDebugMsgLevel( QString( "Opening PFX cert for cert with hash %1" ).arg( certHash ), 99);

  hFile = CreateFileA(
        wszFileName.toStdString().c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        0,
        NULL);
  if ( hFile == INVALID_HANDLE_VALUE)
  {
    QgsDebugMsg( QString( "Cannot create file handle for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  QgsDebugMsgLevel( QString( "Writing PFX cert for cert with hash %1" ).arg( certHash ), 99);
  DWORD dwBytesWritten;
  if ( !WriteFile(
         hFile,
         cdb.pbData,
         cdb.cbData,
         &dwBytesWritten,
         NULL) )
  {
    QgsDebugMsg( QString( "Cannot write temp cert for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
    goto terminate;
  }

  // close file to avoid locks
  CloseHandle(hFile);
  hFile = NULL;

  // re-read generated cert file with QCA lib...
  // I didn't find a way to directly ready using QSsl libd
  if ( !QCA::isSupported( "pkcs12" ) )
  {
    QgsDebugMsg( QString( "QCA library has no PKCS#12 support" ) );
    goto terminate;
  }

  // load the bundle
  QgsDebugMsgLevel( QString( "Loading bundle from PFX for cert with hash %1" ).arg( certHash ), 99);

  passarray = QCA::SecureArray( pwd.toUtf8() );
  bundle = QCA::KeyBundle( QCA::KeyBundle::fromFile(
                             wszFileName,
                             passarray,
                             &res,
                             QString( "qca-ossl" ) ) );
  if ( res == QCA::ErrorFile )
  {
    QgsDebugMsg( QString( "Failed to read bundle file for cert with hash %1" ).arg(certHash) );
    goto terminate;
  }
  else if ( res == QCA::ErrorPassphrase )
  {
    QgsDebugMsg( QString( "Incorrect bundle password for cert with hash %1" ).arg(certHash) );
    goto terminate;
  }
  else if ( res == QCA::ErrorDecode )
  {
    QgsDebugMsg( QString( "Failed to decode (try entering another password) for cert with hash %1" ).arg(certHash) );
    goto terminate;
  }

  if ( bundle.isNull() )
  {
    QgsDebugMsg( QString( "Bundle empty or can not be loaded for cert with hash %1" ).arg(certHash) );
    goto terminate;
  }

  // try to get QSslKey from QCA bundle
  QgsDebugMsgLevel( QString( "Generating QSsKey from bundle for cert with hash %1" ).arg( certHash ), 99);

  privateKey = QSslKey( bundle.privateKey().toRSA().toPEM().toAscii(),
                        QSsl::Rsa );

  // before to check if import was ok, remove stored certs
  QFile::remove(wszFileName);

  // check imported cert
  if ( privateKey.isNull() )
  {
    QgsDebugMsg( QString( "Cannot re-import private key for cert with hash %1" ).arg( certHash ) );
    goto terminate;
  }

  // set the definitive result
  result.second = privateKey;

terminate:
  QgsDebugMsgLevel( QString( "Starting function cleanup" ), 99);

  // close store
  if ( hFile && (hFile != INVALID_HANDLE_VALUE) )
    CloseHandle(hFile);
  if (wszFileName.isEmpty())
    // be sure that temp cert has been removed
    // if not available => return false and no exception
    QFile::remove(wszFileName);
  if (pbBinary)
    free(pbBinary);
  if (pbData)
    free(pbData);
  if (hKeyNew)
    if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
      if ( !CryptDestroyKey(hKeyNew) )
      {
        QgsDebugMsg( QString( "Cannot destroy temporary key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
      }
    else
      NCryptFreeObject(hKeyNew);
  if (ssp)
    free(ssp);
  if (cdb.pbData)
  {
    free(cdb.pbData);
    cdb.pbData = NULL;
    cdb.cbData = 0;
  }
  if (hashBlob.pbData)
  {
    free(hashBlob.pbData);
    hashBlob.pbData = NULL;
    hashBlob.cbData = 0;
  }
  if(pCertContext)
    CertFreeCertificateContext(pCertContext);
  if (hSystemStore)
    CertCloseStore(hSystemStore, 0);
  if (hProcess)
    CloseHandle(hProcess);
  if (hService)
    CloseServiceHandle(hService);
  if (hSCManager)
    CloseServiceHandle(hSCManager);
  if (hProvider)
    NCryptFreeObject(hProvider);
  if (pCertContextNew)
    CertDeleteCertificateFromStore(pCertContextNew);
  // close store! this can generate errors if some related context hasn't closed
  if (hMemoryStore)
    CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_FORCE_FLAG);

  return result;
}

//#endif // Q_OS_WIN
