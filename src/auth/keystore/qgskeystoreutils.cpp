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

//#include "qca_systemstore.h"
#ifndef QT_NO_OPENSSL
#include <QSslCertificate>
#include <QSslKey>
#include <QSsl>
#include <ssl.h>
#include <x509.h>
#include <pem.h>
#endif

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

    // open store
    hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
    if(!hSystemStore)
        return cert;

    // hash blob
    CRYPT_HASH_BLOB blob;
    blob.cbData = certHash.toStdString().size();
    blob.pbData = certHash.toStdString().c_str();

    // load certs
    // can be available more than one cert with the same hash due to
    // multiple import and different name
    PCCERT_CONTEXT pCertContext = nullptr;
    pCertContext = CertFindCertificateInStore(
                            hSystemStore,
                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0,
                            CERT_FIND_HASH,
                            blob,
                            nullptr);
    if ( pCertContext )
    {
        int size = pCertContext->cbCertEncoded;
        QByteArray der(size, 0);
        memcpy(der.data(), pc->pbCertEncoded, size);

        QList<QSslCertificate> certs = QSslCertificate::fromData(der, QSsl::Der);
        if( !certs.isEmpty() )
        {
            Q_FOREACH ( const QSslCertificate& foundCert, certs )
            {
                // return first cert found
                cert = foundCert;
                break;
            }
        }
    }

    // close store
    CertCloseStore(hSystemStore, 0);

    return cert;
}

bool systemstore_cert_privatekey_available(const QString &certHash, const QString &storeName = "ROOT");
{
    bool isAvailable = false;
    HCERTSTORE hSystemStore;

    // open store
    hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
    if(!hSystemStore)
        return isAvailable;

    // hash blob
    CRYPT_HASH_BLOB blob;
    blob.cbData = certHash.toStdString().size();
    blob.pbData = certHash.toStdString().c_str();

    // load cert related with the hash
    // can be available more than one cert with the same hash due to
    // multiple import and different name
    PCCERT_CONTEXT pCertContext = nullptr;
    pCertContext = CertFindCertificateInStore(
                            hSystemStore,
                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0,
                            CERT_FIND_HASH,
                            blob,
                            nullptr);
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
    CertCloseStore(hSystemStore, 0);

    return isAvailable;
}

QPair<QSslCertificate, QSslKey> get_systemstore_cert_with_privatekey(const QString &certHash, const QString &storeName = "ROOT");
{
    QSslKey privateKey;
    QSslCertificate localCertificate;

    HCERTSTORE hSystemStore;
    PCCERT_CONTEXT pCertContext;

    // open store
    hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
    if(!hSystemStore)
        return QPair(localCertificate, privateKey);

    // load cert related with the hash
    // can be available more than one cert with the same hash due to
    // multiple import and different name
    CRYPT_HASH_BLOB blob;
    blob.cbData = certHash.toStdString().size();
    blob.pbData = certHash.toStdString().c_str();

    pCertContext = CertFindCertificateInStore(
                            hSystemStore,
                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0,
                            CERT_FIND_HASH,
                            blob,
                            nullptr);
    if ( pCertContext )
    {
        // check if cert is RSA
        if (!strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                    szOID_RSA,
                    strlen(szOID_RSA)))
        {
            DWORD dwKeySpec;
            DWORD dwKeySpecSize = sizeof(dwKeySpec);
            if (CertGetCertificateContextProperty(
                        pCertContext,
                        CERT_KEY_SPEC_PROP_ID,
                        &dwKeySpec,
                        &dwKeySpecSize))
            {
                // Retrieve a handle to the certificate's private key's CSP key
                // container
                HCRYPTPROV hProv;
                HCRYPTPROV hProvTemp;
            #ifdef WINCE
                HCRYPTPROV hCryptProvOrNCryptKey;
            #else
                HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
                NCRYPT_KEY_HANDLE hNKey;
            #endif
                BOOL fCallerFreeProvOrNCryptKey;
                if (CryptAcquireCertificatePrivateKey(
                            pCertContext,
                        #ifdef WINCE
                            0,
                        #else
                            CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                        #endif
                            NULL,
                            &hCryptProvOrNCryptKey,
                            &dwKeySpec,
                            &fCallerFreeProvOrNCryptKey))
                {
                    // export keys
                    hProv = hCryptProvOrNCryptKey;
                #ifndef WINCE
                    hNKey = hCryptProvOrNCryptKey;
                #endif
                    HCRYPTKEY hKey;
                    BYTE* pbData = NULL;
                    DWORD cbData = 0;
                    if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
                    {
                        // enetering here means that key can be:
                        // AT_KEYEXCHANGE: The key pair is a key exchange pair.
                        // AT_SIGNATURE: The key pair is a signature pair.

                        // Retrieve a handle to the certificate's private key
                        if (CryptGetUserKey(
                                    hProv,
                                    dwKeySpec,
                                    &hKey))
                        {
                            // Export the public/private key
                            // first attend in case key is exportable
                            // and to retieve the lenght, then to retrieve data
                            bool hasExported = CryptExportKey(
                                                    hKey,
                                                    NULL,
                                                    PRIVATEKEYBLOB,
                                                    0,1
                                                    NULL,
                                                    &cbData)
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
                                                  NULL,
                                                  PRIVATEKEYBLOB,
                                                  0,1
                                                  NULL,
                                                  &cbData)
                            }
                            if (hasExported)
                            {
                                pbData = (BYTE*)malloc(cbData);

                                if (CryptExportKey(
                                          hKey,
                                          NULL,
                                          PRIVATEKEYBLOB,
                                          0,
                                          pbData,
                                          &cbData))
                                {
                                #ifndef USE_SSL
                                    QString password("password");
                                    QByteArray dataArray(pbData, cbData);

                                    // get pub key
                                    QList<QSslCertificate> certs = QSslCertificate::fromData(dataArray, QSsl::Der);
                                    if ( certs.size() != 0 )
                                    {
                                        localCertificate = certs.first();
                                    }

                                    // get private key
                                    privateKey = QSslKey(dataArray, QSsl::Rsa, QSsl::Der, QSsl::PrivateKey, password.toAscii());

                                #else
                                    // now I've public/private key in pbData that is a char string with cbData lenght
                                    // try to export in QSsl pubic/private cert using example as in:
                                    // http://stackoverflow.com/questions/13885932/converting-windows-privatekeyblob-to-qts-qsslkey
                                    EVP_PKEY *pkey;
                                    X509 *cert;
                                    STACK_OF(X509) *ca = NULL;
                                    PKCS12 *p12;

                                    // parse PKCS12 cert from memory buffer
                                    BIO* input = BIO_new_mem_buf((void*)pbData, cbData);
                                    p12 = d2i_PKCS12_bio(input, NULL);

                                    PKCS12_parse(p12, password.toStdString().c_str(), &pkey, &cert, &ca);
                                    PKCS12_free(p12);

                                    // generate QSslCertificate from PublicKey cert
                                    if (cert)
                                    {
                                        BIO *boCert = BIO_new( BIO_s_mem() );
                                        PEM_write_bio_X509(boCert, cert);

                                        if (ca && sk_X509_num(ca))
                                        {
                                            for (int i = 0; i < sk_X509_num(ca); i++)
                                            {
                                                PEM_write_bio_X509(boCert, sk_X509_value(ca, i));
                                            }
                                        }
                                        char *certStr;
                                        long len = BIO_get_mem_data(boCert, &certStr);

                                        localCertificate = QSslCertificate( QByteArray::fromRawData(certStr, len) );

                                        BIO_free_all(boCert);
                                    }

                                    // generate QSslKey from PrivateKey pkey
                                    if (pkey)
                                    {
                                        BIO *bo = BIO_new( BIO_s_mem() );
                                        PEM_write_bio_PrivateKey(bo, pkey, NULL, (unsigned char*)(password.toStdString().c_str()), password.length(), NULL, (char*)(password.toStdString().c_str()));

                                        char *p;
                                        long len = BIO_get_mem_data(bo, &p);

                                        privateKey = QSslKey(QByteArray::fromRawData(p, len), QSsl::Rsa);
                                        BIO_free_all(bo);
                                    }
                                #endif //USE_SSL
                                }
                                else
                                {
                                    QgsDebugMsg( QString( "Cannot export private key fo cert with hash %1: Wincrypt error %X" ).arg( certHash ).arg( GetLastError() ) );
                                }
                            }
                            else
                            {
                                QgsDebugMsg( QString( "Cannot export private key fo cert with hash %1: Wincrypt error %X" ).arg( certHash ).arg( GetLastError() ) );
                            }
                        }
                        else
                        {
                            QgsDebugMsg( QString( "Cannot retrieve handles for private key fo cert with hash %1: Wincrypt error %X" ).arg( certHash ).arg( GetLastError() ) );
                        }

                    }
                #ifndef WINCE
                    else
                    {
                        // TODO porting of exportrsa in case of win CE
                        QgsDebugMsg( QString( "Windows CE still not supported to export keystore cert") );
                    }
                #endif
                }
                else
                {
                    QgsDebugMsg( QString( "Cannot retrieve handles for private key fo cert with hash %1: Wincrypt error %X" ).arg( certHash ) );
                }
            }
            else
            {
                QgsDebugMsg( QString( "Cert with hash %1 has not private key" ).arg( certHash ) );
            }
        }
        else
        {
            QgsDebugMsg( QString( "Cert with hash %1: is not RSA" ).arg( certHash ) );
        }
    }
    else
    {
        QgsDebugMsg( QString( "No cert found with hash %1" ).arg( certHash ) );
    }

    // close store
    CertCloseStore(hSystemStore, 0);

    return QPair(localCertificate, privateKey);
}


//#endif // Q_OS_WIN
