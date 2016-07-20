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
 *   https://quickgit.kde.org/?p=qca.git&a=blob&h=cdf15659b0f8a33cfe13b5d9473471f60ab95fe4&hb=eb5eeca609e9960d7afe3462b421bfe0a48b8e21&f=src%2Fqca_systemstore.h
 *                                                                         *
 ***************************************************************************/

//#ifdef Q_OS_WIN

#ifndef QGSKEYSTOREUTILS_H
#define QGSKEYSTOREUTILS_H

bool have_systemstore(const QString &storeName = "ROOT");
QList<QSslCertificate> get_systemstore(const QString &storeName = "ROOT");
QList<QSslCertificate> get_systemstore_cert(const QString &certHash, const QString &storeName = "ROOT");

#endif // QGSKEYSTOREUTILS_H

//#endif // Q_OS_WIN
