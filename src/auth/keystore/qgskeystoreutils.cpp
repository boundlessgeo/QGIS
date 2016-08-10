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
 *   Code inspired from Justin Karneges <justin@affinix.com> code get from
 *   https://quickgit.kde.org/?p=qca.git&a=blob&h=b48d8529ccd586c2a14dfa219fae29825c1c7105&hb=eb5eeca609e9960d7afe3462b421bfe0a48b8e21&f=src%2Fqca_systemstore_win.cpp
 *                                                                         *
 ***************************************************************************/

//#ifdef Q_OS_WIN

#ifndef QT_NO_OPENSSL
#include <QSslCertificate>
#include <QSslKey>
#include <QSsl>
#endif
#include <QPair>
#include <QChar>
#include <QDir>
#include <QtGlobal>
#include <QFile>

#include "qgslogger.h"
#include "qgskeystoreutils.h"
#include "qgsauthcertutils.h"

#include <windows.h>
#include <wincrypt.h>

QString get_random_string(const int size)
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

bool have_systemstore(const QString &storeName)
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

QList<QSslCertificate> get_systemstore(const QString &storeName)
{
    QList<QSslCertificate> col;
    HCERTSTORE hSystemStore;

    // open store
    hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
    if(!hSystemStore)
        return col;

    // load certs
    PCCERT_CONTEXT pc = NULL;
    while(1)
    {
        pc = CertFindCertificateInStore(
            hSystemStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            NULL,
            pc);
        if(!pc)
            break;
        int size = pc->cbCertEncoded;
        QByteArray der(size, 0);
        memcpy(der.data(), pc->pbCertEncoded, size);

        QList<QSslCertificate> certs = QSslCertificate::fromData(der, QSsl::Der);
        if( !certs.isEmpty() )
            Q_FOREACH ( const QSslCertificate& cert, certs )
            {
                col.append(cert);
            }
    }

    // close store
    CertCloseStore(hSystemStore, 0);

    return col;
}

QSslCertificate get_systemstore_cert(const QString &certHash, const QString &storeName)
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

bool systemstore_cert_privatekey_available(const QString &certHash, const QString &storeName)
{
    bool isAvailable = false;
    HCERTSTORE hSystemStore;
    CRYPT_HASH_BLOB hashBlob;

    // open store
    hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
    if(!hSystemStore)
    {
        QgsDebugMsg( QString( "Cannot open KeyStore %1" ).arg( storeName ) );
        return isAvailable;
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
        QgsDebugMsg( QString( "Cannot convert hash to binary for hash %1: Wincrypt error %X" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
        return isAvailable;
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

    // load cert related with the hash
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
    free(pbBinary);
    if ( pCertContext )
    {
        // check if cert is RSA
        if (!strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                    szOID_RSA,
                    strlen(szOID_RSA)))
        {
            // check if cert has private key
            DWORD dwKeySpec;
            DWORD dwKeySpecSize = sizeof(dwKeySpec);
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
        }
        else
        {
            QgsDebugMsg( QString( "Cert with hash %1: is not RSA" ).arg( certHash ) );
        }
    }

    // close store
    if(pCertContext)
        CertFreeCertificateContext(pCertContext);
    CertCloseStore(hSystemStore, 0);

    return isAvailable;
}

QPair<QSslCertificate, QSslKey> get_systemstore_cert_with_privatekey(const QString &certHash, const QString &storeName)
{
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
    CRYPT_DATA_BLOB cdb;
    cdb.cbData = 0;
    cdb.pbData = NULL;

    // open store
    hSystemStore = CertOpenSystemStoreA(
                        0,
                        storeName.toStdString().c_str());
    if(!hSystemStore)
    {
        QgsDebugMsg( QString( "Cannot open System Store %1: Wincrypt error %X" ).arg( storeName ).arg( GetLastError(), 0, 16 ) );
        goto terminate;
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
        QgsDebugMsg( QString( "Cannot convert hash to binary for hash %1: Wincrypt error %X" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
        goto terminate;
    }
    pbBinary = (BYTE*) malloc(pcbBinary);

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

    // load cert related with the hash
    // can be available more than one cert with the same hash due to
    // multiple import and different name
    pCertContext = CertFindCertificateInStore(
                            hSystemStore,
                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0,
                            CERT_FIND_HASH,
                            (const void *) &hashBlob,
                            NULL);
    if ( !pCertContext )
    {
        QgsDebugMsg( QString( "No cert found with hash %1: Wincrypt error %X" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
        goto terminate;
    }

    // check if cert is RSA
    if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                szOID_RSA,
                strlen(szOID_RSA)))
    {
        QgsDebugMsg( QString( "Cert with hash %1: is not RSA" ).arg( certHash ) );
        goto terminate;
    }

    // create QSslCertificate from pCertContext
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
    DWORD dwKeySpec;
    DWORD dwKeySpecSize = sizeof(dwKeySpec);

    if (!CertGetCertificateContextProperty(
                pCertContext,
                CERT_KEY_SPEC_PROP_ID,
                &dwKeySpec,
                &dwKeySpecSize))
    {
        QgsDebugMsg( QString( "Cert with hash %1 has not private key: Wincrypt error %X" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
        goto terminate;
    }

    // Retrieve a handle to the certificate's private key's CSP key
    // container
    HCRYPTPROV hProv;
    HCRYPTPROV hProvTemp;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
    BOOL fCallerFreeProvOrNCryptKey;

    if (!CryptAcquireCertificatePrivateKey(
                pCertContext,
                CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
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
    HCRYPTKEY hKey;
    BYTE* pbData = NULL;
    DWORD cbData = 0;

    if (CERT_NCRYPT_KEY_SPEC == dwKeySpec)
    {
        QgsDebugMsg( QString( "Unexpected CERT_NCRYPT_KEY_SPEC KeySpec returned for cert with hash %1").arg( certHash ) );
        goto terminate;
    }

    // entering here means that key can be:
    // AT_KEYEXCHANGE: The key pair is a key exchange pair.
    // AT_SIGNATURE: The key pair is a signature pair.

    // Retrieve a handle to the certificate's private key
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
    bool hasExported = CryptExportKey(
                            hKey,
                            0,
                            PRIVATEKEYBLOB,
                            0,
                            NULL,
                            &cbData);
    if (!hasExported)
    {
        //
        // TODO: notify the user to have permission to export privatekey
        //

        // Mark the certificate's private key as exportable and archivable
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

    /***********************************************************
    * now having the key, start the process to export in a pfx
    * file container
    ************************************************************/

    // Establish a temporary key container
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
    HCRYPTKEY hKeyNew = NULL; // <-- destroy with CryptDestroyKey
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

    // Create a temporary certificate store in memory
    HCERTSTORE hMemoryStore = CertOpenStore(
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
    PCCERT_CONTEXT pCertContextNew = NULL;
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
    if ( !CertSetCertificateContextProperty(
                pCertContext,
                CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID,
                0,
                (void*) hProvTemp ) )
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
    HANDLE hFile = NULL;

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
    // close store
    if ( hFile && (hFile != INVALID_HANDLE_VALUE) )
        CloseHandle(hFile);
    if (pbBinary)
        free(pbBinary);
    if (pbData)
        free(pbData);
    if (hKeyNew)
        if ( !CryptDestroyKey(hKeyNew) )
        {
            QgsDebugMsg( QString( "Cannot destroy temporary key for cert with hash %1: Wincrypt error 0x%2" ).arg( certHash ).arg( GetLastError(), 0, 16 ) );
        }
    if (cdb.pbData)
        free(cdb.pbData);
    if(pCertContext)
        CertFreeCertificateContext(pCertContext);
    if (hSystemStore)
        CertCloseStore(hSystemStore, 0);

    return result;
}


//#endif // Q_OS_WIN
