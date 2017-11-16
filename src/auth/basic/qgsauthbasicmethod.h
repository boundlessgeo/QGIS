/***************************************************************************
    qgsauthbasicmethod.h
    ---------------------
    begin                : September 1, 2015
    copyright            : (C) 2015 by Boundless Spatial, Inc. USA
    author               : Larry Shaffer
    email                : lshaffer at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef QGSAUTHBASICMETHOD_H
#define QGSAUTHBASICMETHOD_H

#include <QObject>
#include <QMutex>

#include "qgsauthmethodconfig.h"
#include "qgsauthmethod.h"


class QgsAuthBasicMethod : public QgsAuthMethod
{
    Q_OBJECT

  public:
    explicit QgsAuthBasicMethod( const QString authcfg );

    // QgsAuthMethod interface
    QString key() const override;

    QString description() const override;

    QString displayDescription() const override;

    bool updateNetworkRequest( QNetworkRequest &request,
                               const QString &dataprovider = QString() ) override;

    bool updateDataSourceUriItems( QStringList &connectionItems,
                                   const QString &dataprovider = QString() ) override;


    bool updateNetworkProxy( QNetworkProxy &proxy,
                             const QString &dataprovider = QString() ) override;

    void updateMethodConfig() override;

  private:
    QString escapeUserPass( const QString &val, QChar delim = '\'' ) const;


};

#endif // QGSAUTHBASICMETHOD_H
