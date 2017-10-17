/***************************************************************************
     TestQgsAuthCertUtils.cpp
     ----------------------
    Date                 : October 2017
    Copyright            : (C) 2017 by Boundless Spatial, Inc. USA
    Author               : Larry Shaffer
    Email                : lshaffer at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "qgstest.h"
#include <QObject>
#include <QSslKey>
#include <QString>
#include <QStringList>

#include "qgsapplication.h"
#include "qgsauthcrypto.h"
#include "qgsauthcertutils.h"
#include "qgslogger.h"

/**
 * \ingroup UnitTests
 * Unit tests for QgsAuthCertUtils static functions
 */
class TestQgsAuthCertUtils: public QObject
{
    Q_OBJECT

  private slots:
    void initTestCase();
    void cleanupTestCase();
    void init() {}
    void cleanup() {}

    void testPkcsUtils();

  private:
    static QString sPkiData;
};

QString TestQgsAuthCertUtils::sPkiData = QStringLiteral( TEST_DATA_DIR ) + "/auth_system/certs_keys";

void TestQgsAuthCertUtils::initTestCase()
{
  QgsApplication::init();
  QgsApplication::initQgis();
  if ( QgsAuthCrypto::isDisabled() )
    QSKIP( "QCA's qca-ossl plugin is missing, skipping test case", SkipAll );
}

void TestQgsAuthCertUtils::cleanupTestCase()
{
  QgsApplication::exitQgis();
}

void TestQgsAuthCertUtils::testPkcsUtils()
{
#ifdef Q_OS_MAC
  QByteArray pkcs8;
  QByteArray pkcs1 = QgsAuthCertUtils::pkcs8PrivateKey( pkcs8 );
  QVERIFY( pkcs1.isEmpty() );

  pkcs8.clear();
  pkcs1.clear();
  // is actually a PKCS#1 key, not #8
  pkcs8 = QgsAuthCertUtils::fileData( sPkiData + "/gerardus_key.der" , false );
  QVERIFY( !pkcs8.isEmpty() );
  pkcs1 = QgsAuthCertUtils::pkcs8PrivateKey( pkcs8 );
  QVERIFY( pkcs1.isEmpty() );

  pkcs8.clear();
  pkcs1.clear();
  // is PKCS#1 PEM text, not DER
  pkcs8 = QgsAuthCertUtils::fileData( sPkiData + "/gerardus_key.pem" , false );
  QVERIFY( !pkcs8.isEmpty() );
  pkcs1 = QgsAuthCertUtils::pkcs8PrivateKey( pkcs8 );
  QVERIFY( pkcs1.isEmpty() );

  pkcs8.clear();
  pkcs1.clear();
  // is PKCS#8 PEM text, not DER
  pkcs8 = QgsAuthCertUtils::fileData( sPkiData + "/gerardus_key-pkcs8-rsa.pem" , false );
  QVERIFY( !pkcs8.isEmpty() );
  pkcs1 = QgsAuthCertUtils::pkcs8PrivateKey( pkcs8 );
  QVERIFY( pkcs1.isEmpty() );

  pkcs8.clear();
  pkcs1.clear();
  pkcs8 = QgsAuthCertUtils::fileData( sPkiData + "/gerardus_key-pkcs8-rsa.der" , false );
  QVERIFY( !pkcs8.isEmpty() );
  pkcs1 = QgsAuthCertUtils::pkcs8PrivateKey( pkcs8 );
  QVERIFY( !pkcs1.isEmpty() );

  // PKCS#8 DER format should fail, and the reason for QgsAuthCertUtils::pkcs8PrivateKey
  // (as of Qt5.9.0, and where macOS Qt5 SSL backend is not OpenSSL, and
  //  where PKCS#8 is *still* unsupported for macOS)
  QSslKey pkcs8Key( pkcs8, QSsl::Rsa, QSsl::Der, QSsl::PrivateKey );
  QVERIFY( pkcs8Key.isNull() );

  // PKCS#1 DER format should work
  QSslKey pkcs1Key( pkcs1, QSsl::Rsa, QSsl::Der, QSsl::PrivateKey );
  QVERIFY( !pkcs1Key.isNull() );

  QByteArray pkcs1PemRef = QgsAuthCertUtils::fileData( sPkiData + "/gerardus_key.pem" , true );
  QVERIFY( !pkcs1PemRef.isEmpty() );
  QCOMPARE( pkcs1Key.toPem(), pkcs1PemRef );
#endif
}

QGSTEST_MAIN( TestQgsAuthCertUtils )
#include "testqgsauthcertutils.moc"
