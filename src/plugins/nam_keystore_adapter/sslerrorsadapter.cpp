/***************************************************************************
  sslerrorsadapter.cpp
  Plugin to modify the sequence of sslErrors nam callback to manage peer cert verification with CAs in win keystore
  -------------------
         begin                : [PluginDate]
         copyright            : [(C) Your Name and Date]
         email                : [Your Email]

 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

//
// QGIS Specific includes
//

#include <qgisinterface.h>
//#include <qgisgui.h>

#include "sslerrorsadapter.h"

//
// Qt4 Related Includes
//

#include <QMetaObject>
#include <QString>
#include <QList>
#include <QTimer>

#include <QSslCertificate>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSslConfiguration>
#include <QSslError>

#include "qgsnetworkaccessmanager.h"
#include "qgslogger.h"
#include "qgskeystoreutils.h"
#include "qgsauthcertutils.h"

static const QString sName = QObject::tr( "NAM sslErrors Adapter" );
static const QString sDescription = QObject::tr( "Plugin to modify the sequence of sslErrors nam callback to manage peer cert verification with CAs in win keystore" );
static const QString sCategory = QObject::tr( "" );
static const QString sPluginVersion = QObject::tr( "Version 0.1" );
static const QgisPlugin::PLUGINTYPE sPluginType = QgisPlugin::UI;
static const QString sPluginIcon = "";

void sslErrorsAdapter::checkPeerCertAgainstKeystoreCAs(
    QNetworkReply *reply,
    const QList<QSslError> &errors)
{
  // set flag to true to avoid to redo this slot
  if (mFired)
    return;
  mFired = true;

  // check if SslError is SelfSignedCertificateInChain
  bool selfSignedFound = false;
  Q_FOREACH ( const QSslError &err, errors )
  {
    if ( err.error() == QSslError::SelfSignedCertificateInChain )
    {
      QgsDebugMsg( QString( "* %1: %2" ).arg(QgsAuthCertUtils::sslErrorEnumString( err.error() ), err.errorString()) );
      selfSignedFound = true;
    }
  }
  if ( selfSignedFound )
  {
    if ( have_systemstore("MY") )
    {
      QList< QSslCertificate > _CAs = get_systemstore("MY");
      if ( !_CAs.isEmpty() )
      {
        QgsDebugMsg( QString( "Adding CAs to a new ssl request from CA KeyStore MY" ) );

        // first avoid signal propagation to QgisApp::namSslError slot it's necessary
        // to disconnect and reconnect
        if (!disconnect( mNam, mMetaSender, mQgisApp, mMetaReceiver) )
        {
          QgsDebugMsg( QString( "Cannot disconnect mQgisApp->namSslErrors from mNam::sslErrors signal" ) );
        }
        if ( !connect(mNam, mMetaSender, mQgisApp, mMetaReceiver) )
        {
          QgsDebugMsg( QString( "Cannot connect mQgisApp->namSslErrors to mNam::sslErrors signal" ) );
        }

        // add new CAs to the reply sslConfig
        QSslConfiguration sslConf = reply->sslConfiguration();
        QList< QSslCertificate > currentCAs = sslConf.caCertificates();

        Q_FOREACH ( const QSslCertificate &ca, _CAs )
        {
          QString hash( QgsAuthCertUtils::shaHexForCert(ca) );
          QString certInfoName( QgsAuthCertUtils::resolvedCertName( ca ) );
          QgsDebugMsg( QString( "Adding CA %1 with hash %2" ).arg(certInfoName, hash) );
        }

        // TODO: would avoid to add duplicated CAs
        currentCAs.append(_CAs);
        sslConf.setCaCertificates(currentCAs);

        // restart request with renewed SslConf
        QNetworkRequest request( reply->request() );
        request.setSslConfiguration(sslConf);
        QgsNetworkAccessManager::instance()->get( request );

        reply->close();
        reply->abort();
      }
      else
      {
        QgsDebugMsg( QString( "No CAs found in CA KeyStore" ) );
      }
    }
  }
}

bool sslErrorsAdapter::modifySslErrorsListeners()
{
  /* This funcion modify the nam::sslError listener sequences adding a previous
   * step to check if peer cert can be verified using a windows Keystore CA
   */

  // disconnect the QGisApp::namSslErrors listener
  // the reason is to add a previous listener to sslErros check if peer cert
  // can be verified from CAs available in keystore

  // disconnect default sslError listenenr to NAM
  if (!disconnect( mNam, mMetaSender, mQgisApp, mMetaReceiver) )
  {
    QgsDebugMsg( QString( "Cannot disconnect mQgisApp->namSslErrors from mNam::sslErrors signal" ) );
    return false;
  }

  // reorder listeners to the mNam::sslErrors signal
  if ( !connect(mNam, mMetaSender, this, mMetaSubstitute) )
  {
    QgsDebugMsg( QString( "Cannot connect QgsKeyStoreMethod::modifySslErrorsListeners to mNam::sslErrors signal" ) );
    return false;
  }

  if ( !connect(mNam, mMetaSender, mQgisApp, mMetaReceiver) )
  {
    QgsDebugMsg( QString( "Cannot connect mQgisApp->namSslErrors to mNam::sslErrors signal" ) );
    return false;
  }

  return true;
}

//////////////////////////////////////////////////////////////////////
//
// THE FOLLOWING METHODS ARE MANDATORY FOR ALL PLUGINS
//
//////////////////////////////////////////////////////////////////////

/**
 * Constructor for the plugin. The plugin is passed a pointer
 * an interface object that provides access to exposed functions in QGIS.
 * @param theQGisInterface - Pointer to the QGIS interface object
 */
sslErrorsAdapter::sslErrorsAdapter( QgisInterface * theQgisInterface ):
    QgisPlugin( sName, sDescription, sCategory, sPluginVersion, sPluginType ),
    mQGisIface( theQgisInterface ),
    mQgisApp(nullptr),
    mNam(nullptr),
    mFired(false)
{
  // get pointers to signals and slot that have to be managed
  mQgisApp = dynamic_cast<QMainWindow*>( mQGisIface->mainWindow() );
  mNam = QgsNetworkAccessManager::instance();

  // disconnect the QGisApp::namSslErrors listener
  // the reason is to add a previous listener to sslErros check if peer cert
  // can be verified from CAs available in keystore
  QString sender("sslErrors(QNetworkReply*,QList<QSslError>)");
  QString receiver("namSslErrors(QNetworkReply*,QList<QSslError>)");
  QString substitute("checkPeerCertAgainstKeystoreCAs(QNetworkReply*,QList<QSslError>)");

  const QMetaObject *mo = mNam->metaObject();
  int senderIndex = mo->indexOfSignal(sender.toStdString().c_str());
  mMetaSender = mo->method(senderIndex);

  const QMetaObject *moa = mQgisApp->metaObject();
  int receiverIndex = moa->indexOfSlot(receiver.toStdString().c_str());
  mMetaReceiver = moa->method(receiverIndex);

  const QMetaObject *mot = this->metaObject();
  int substituteIndex = mot->indexOfSlot(substitute.toStdString().c_str());
  mMetaSubstitute = mot->method(substituteIndex);

  // modify slot sequence
  QObject::connect(mQGisIface, SIGNAL( initializationCompleted() ), this, SLOT( modifySslErrorsListeners() ));
}

sslErrorsAdapter::~sslErrorsAdapter()
{
}

/*
 * Initialize the GUI interface for the plugin - this is only called once when the plugin is
 * added to the plugin registry in the QGIS application.
 */
void sslErrorsAdapter::initGui()
{
}

//method defined in interface
void sslErrorsAdapter::help()
{
  //implement me!
}

// Slot called when the menu item is triggered
// If you created more menu items / toolbar buttons in initiGui, you should
// create a separate handler for each action - this single run() method will
// not be enough
void sslErrorsAdapter::run()
{
  // NOTE!!! it should do nothing... and more it souldn't be ever called
}

// Unload the plugin by cleaning up the GUI
void sslErrorsAdapter::unload()
{
}


//////////////////////////////////////////////////////////////////////////
//
//
//  THE FOLLOWING CODE IS AUTOGENERATED BY THE PLUGIN BUILDER SCRIPT
//    YOU WOULD NORMALLY NOT NEED TO MODIFY THIS, AND YOUR PLUGIN
//      MAY NOT WORK PROPERLY IF YOU MODIFY THIS INCORRECTLY
//
//
//////////////////////////////////////////////////////////////////////////


/**
 * Required extern functions needed  for every plugin
 * These functions can be called prior to creating an instance
 * of the plugin class
 */
// Class factory to return a new instance of the plugin class
QGISEXTERN QgisPlugin * classFactory( QgisInterface * theQgisInterfacePointer )
{
  return new sslErrorsAdapter( theQgisInterfacePointer );
}
// Return the name of the plugin - note that we do not user class members as
// the class may not yet be insantiated when this method is called.
QGISEXTERN QString name()
{
  return sName;
}

// Return the description
QGISEXTERN QString description()
{
  return sDescription;
}

// Return the category
QGISEXTERN QString category()
{
  return sCategory;
}

// Return the type (either UI or MapLayer plugin)
QGISEXTERN int type()
{
  return sPluginType;
}

// Return the version number for the plugin
QGISEXTERN QString version()
{
  return sPluginVersion;
}

QGISEXTERN QString icon()
{
  return sPluginIcon;
}

// Delete ourself
QGISEXTERN void unload( QgisPlugin * thePluginPointer )
{
  delete thePluginPointer;
}
