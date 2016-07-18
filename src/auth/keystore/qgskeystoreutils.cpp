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
#include <QSsl>
#endif

#include "qgskeystoreutils.h"

#include <windows.h>
#include <wincrypt.h>

bool have_systemstore(const QString &storeName)
{
    bool ok = false;
    HCERTSTORE hSystemStore;
    hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
    if(hSystemStore)
        ok = true;
    CertCloseStore(hSystemStore, 0);
    return ok;
}

QList<QSslCertificate> get_systemstore(const QString &provider, const QString &storeName)
{
    QList<QSslCertificate> col;
    HCERTSTORE hSystemStore;
    hSystemStore = CertOpenSystemStoreA(0, storeName.toStdString().c_str());
    if(!hSystemStore)
        return col;
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
        //Certificate cert = Certificate::fromDER(der, 0, provider);
        if( !certs.isEmpty() )
            Q_FOREACH ( const QSslCertificate& cert, certs )
            {
                col.addCertificate(cert);
            }
    }
    CertCloseStore(hSystemStore, 0);
    return col;
}

//#endif // Q_OS_WIN
