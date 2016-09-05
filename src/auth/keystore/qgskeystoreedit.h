/***************************************************************************
    qgskeystoreedit.h
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

//#ifdef Q_OS_WIN

#ifndef QGSKEYSTOREEDIT_H
#define QGSKEYSTOREEDIT_H

#include <QWidget>
#include "qgsauthmethodedit.h"
#include "ui_qgskeystoreedit.h"

#include "qgsauthconfig.h"

class QgsKeyStoreEdit : public QgsAuthMethodEdit, private Ui::QgsKeyStoreEdit
{
  Q_OBJECT

public:
  explicit QgsKeyStoreEdit( QWidget *parent = nullptr );
  virtual ~QgsKeyStoreEdit();

  bool validateConfig() override;

  QgsStringMap configMap() const override;

public slots:
  void loadConfig( const QgsStringMap &configmap ) override;

  void resetConfig() override;

  void clearConfig() override;

private slots:
  void populateIdentityComboBox();

  void on_cmbIdentityCert_currentIndexChanged( int indx );

private:
  QgsStringMap mConfigMap;
  bool mValid;
};

#endif // QGSKEYSTOREEDIT_H

//#endif // Q_OS_WIN
