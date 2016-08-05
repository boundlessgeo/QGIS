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

#include "qgslogger.h"
#include "qgskeystoreutils.h"

#include <windows.h>
#include <wincrypt.h>

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
    QgsDebugMsg( QString("Hash is: -%1-\n").arg( certHash.toLatin1().data() ));
    QgsDebugMsg( QString("Length is: -%1-\n").arg( certHash.toLatin1().size() ));
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
        QgsDebugMsg( QString( "Cannot convert hash to binary" ) );
        return isAvailable;
    }
    QgsDebugMsg( QString("Hex Converted length: %1").arg(pcbBinary) );
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
    QSslKey privateKey = QSslKey();
    QSslCertificate localCertificate = QSslCertificate();
    QPair<QSslCertificate, QSslKey> result;
    result.first = localCertificate;
    result.second = privateKey;
    CRYPT_HASH_BLOB hashBlob;
    QByteArray der;
    QByteArray derKey;
    QList<QSslCertificate> certs;

    HCERTSTORE hSystemStore;
    PCCERT_CONTEXT pCertContext = NULL;

    // open store
    hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
    if(!hSystemStore)
        return result;

    // convert hash in binary hash useful to find certificate
    LPCTSTR pszString = certHash.toLatin1().data();
    QgsDebugMsg( QString("Hash is: -%1-\n").arg( certHash.toLatin1().data() ));
    QgsDebugMsg( QString("Length is: -%1-\n").arg( certHash.toLatin1().size() ));
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
        QgsDebugMsg( QString( "Cannot convert hash to binary" ) );
        return result;
    }
    QgsDebugMsg( QString("Hex Converted length: %1").arg(pcbBinary) );
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
    pCertContext = CertFindCertificateInStore(
                            hSystemStore,
                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0,
                            CERT_FIND_HASH,
                            (const void *) &hashBlob,
                            NULL);
    free(pbBinary);
    if ( !pCertContext )
    {
        QgsDebugMsg( QString( "No cert found with hash %1" ).arg( certHash ) );
        if (pbBinary)
            free(pbBinary);
        goto err;
    }

    // check if cert is RSA
    if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                szOID_RSA,
                strlen(szOID_RSA)))
    {
        QgsDebugMsg( QString( "Cert with hash %1: is not RSA" ).arg( certHash ) );
        goto err;
    }

    // create QSslCertificate from pCertContext
    int size = pCertContext->cbCertEncoded;
    der = QByteArray(size, 0);
    memcpy(der.data(), pCertContext->pbCertEncoded, size);

    certs = QSslCertificate::fromData(der, QSsl::Der);
    if ( (certs.size() == 0) || certs.first().isNull() )
    {
        QgsDebugMsg( QString( "Cannot create QSsl cert from data for cert with hash %1" ).arg( certHash ) );
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
        QgsDebugMsg( QString( "Cert with hash %1 has not private key" ).arg( certHash ) );
        goto err;
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
        QgsDebugMsg( QString( "Cannot retrieve handles for private key for cert with hash %1: Wincrypt error %X" ).arg( certHash ) );
        goto err;
    }

    // export keys
    hProv = hCryptProvOrNCryptKey;
    HCRYPTKEY hKey;
    BYTE* pbData = NULL;
    DWORD cbData = 0;

    if (CERT_NCRYPT_KEY_SPEC == dwKeySpec)
    {
        QgsDebugMsg( QString( "Unexpected CERT_NCRYPT_KEY_SPEC KeySpec returned for cert with hash %1").arg( certHash ) );
        goto err;
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
        QgsDebugMsg( QString( "Cannot retrieve handles for private key for cert with hash %1: Wincrypt error %2" ).arg( certHash ).arg( GetLastError() ) );
        goto err;
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
        QgsDebugMsg( QString( "Cannot export private key for cert with hash %1: Wincrypt error %2" ).arg( certHash ).arg( GetLastError() ) );
        goto err;
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
        QgsDebugMsg( QString( "Cannot export private key for cert with hash %1: Wincrypt error %2" ).arg( certHash ).arg( GetLastError() ) );
        if (pbData)
            free(pbData);
        goto err;
    }

    // get private key
/*
    derKey = QByteArray(cbData, 0);
    memcpy(derKey.data(), pbData, cbData);
    free(pbData);

    privateKey = QSslKey(derKey, QSsl::Rsa, QSsl::Der, QSsl::PrivateKey);
    if (privateKey.isNull())
    {
        QgsDebugMsg( QString( "Cannot create QSslKey from data for cert with hash %1" ).arg( certHash ) );
        goto err;
    }
*/








    // Establish a temporary key container
    CryptAcquireContext(
        &hProvTemp,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET);

    // Import the private key into the temporary key container
    HCRYPTKEY hKeyNew; // <-- destroy with CryptDestroyKey
    CryptImportKey(
        hProvTemp,
        pbData,
        cbData,
        0,
        CRYPT_EXPORTABLE,
        &hKeyNew);

    // Create a temporary certificate store in memory
    HCERTSTORE hMemoryStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0,
        NULL);

    // Add a link to the certificate to our temporary certificate store
    PCCERT_CONTEXT pCertContextNew = NULL;
    CertAddCertificateLinkToStore(
        hMemoryStore,
        pCertContext,
        CERT_STORE_ADD_NEW,
        &pCertContextNew);

    // Set the key container for the linked certificate to be our temporary
    // key container
    CertSetCertificateContextProperty(
        pCertContext,
        CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID,
        0,
        (void*) hProvTemp );

    // Export the temporary certificate store to a PFX data blob in memory
    CRYPT_DATA_BLOB cdb;
    cdb.cbData = 0;
    cdb.pbData = NULL;
    PFXExportCertStoreEx(
        hMemoryStore,
        &cdb,
        NULL,
        NULL,
        EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);

    cdb.pbData = (BYTE*)malloc(cdb.cbData);

    PFXExportCertStoreEx(
        hMemoryStore,
        &cdb,
        NULL,
        NULL,
        EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);


    // get qsslkey from exported der
    derKey = QByteArray(cdb.cbData, 0);
    memcpy(derKey.data(), cdb.pbData, cdb.cbData);
    free(pbData);

    privateKey = QSslKey(derKey, QSsl::Rsa, QSsl::Der, QSsl::PrivateKey);
    if (privateKey.isNull())
    {
        QgsDebugMsg( QString( "Cannot create QSslKey from data for cert with hash %1" ).arg( certHash ) );
        goto err;
    }
















    result.second = privateKey;

    return result;

err:
    // close store
    if(pCertContext)
        CertFreeCertificateContext(pCertContext);
    CertCloseStore(hSystemStore, 0);

    return result;
}


//#endif // Q_OS_WIN
