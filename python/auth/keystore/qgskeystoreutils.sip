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
 *                                                                         *
 ***************************************************************************/

%Import QtCore/QtCoremod.sip
%Import QtNetwork/QtNetworkmod.sip

class KeystoreUtils
{
%TypeHeaderCode
#include "qgskeystoreutils.h"
%End

public:
    explicit KeystoreUtils();
    ~KeystoreUtils();

    static bool have_systemstore(const QString &storeName = "ROOT");
    static QList< QSslCertificate > get_systemstore(const QString &storeName = "ROOT");
    static QSslCertificate get_systemstore_cert(const QString &certHash, const QString &storeName = "ROOT");
    static bool systemstore_cert_privatekey_available(const QString &certHash, const QString &storeName = "ROOT");
    static bool systemstore_cert_privatekey_is_exportable(const QString &certHash, const QString &storeName = "ROOT");
    static QPair<QSslCertificate, QSslKey> get_systemstore_cert_with_privatekey(const QString &certHash, const QString &storeName = "ROOT", const bool forceExport = false);
};
