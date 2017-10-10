/***************************************************************************
  testqgsauthcrl.h - test the QgsAuthCrl and QgsAuthCrlEntry classes

 ---------------------
 begin                : 11.10.2017
 copyright            : (C) 2017 by Alessandro Pasotti
 email                : apasotti at boundlessgeo dot com
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
#include <QDir>
#include <QFile>
#include <QString>
#include <QStringList>
#include <QTextStream>

#include "qgsapplication.h"
#include "qgsauthmanager.h"
#include "qgsauthconfig.h"
#include "qgssettings.h"
#include "qgsauthcrl.h"

/**
 * \ingroup UnitTests
 * Unit tests for QgsAuthCrl
 */
class TestQgsAuthCrl: public QObject
{
    Q_OBJECT

  public:
    TestQgsAuthCrl();

  private slots:
    void initTestCase();
    void cleanupTestCase();
    void cleanup();

    void testCrl();
    void testToHex();

  private:
    void cleanupTempDir();
    QList<QgsAuthMethodConfig> registerAuthConfigs();

    void reportRow( const QString &msg );
    void reportHeader( const QString &msg );

    QString mPkiData;
    QString mTempDir;
    const char *mPass = nullptr;
    QString mReport;
};


TestQgsAuthCrl::TestQgsAuthCrl()
  : mPkiData( QStringLiteral( TEST_DATA_DIR ) + "/auth_system/certs_keys" )
  , mTempDir( QDir::tempPath() + "/auth" )
  , mPass( "pass" )
{
}

void TestQgsAuthCrl::initTestCase()
{
  cleanupTempDir();

  mReport += QLatin1String( "<h1>QgsAuthManager Tests</h1>\n" );

  // make QGIS_AUTH_DB_DIR_PATH temp dir for qgis-auth.db and master password file
  QDir tmpDir = QDir::temp();
  QVERIFY2( tmpDir.mkpath( mTempDir ), "Couldn't make temp directory" );
  qputenv( "QGIS_AUTH_DB_DIR_PATH", mTempDir.toAscii() );

  // init app and auth manager
  QgsApplication::init();
  QgsApplication::initQgis();
  QVERIFY2( !QgsAuthManager::instance()->isDisabled(),
            "Authentication system is DISABLED" );

  QString mySettings = QgsApplication::showSettings();
  mySettings = mySettings.replace( '\n', QLatin1String( "<br />\n" ) );
  mReport += "<p>" + mySettings + "</p>\n";

  // verify QGIS_AUTH_DB_DIR_PATH (temp auth db path) worked
  QString db1( QFileInfo( QgsAuthManager::instance()->authenticationDatabasePath() ).canonicalFilePath() );
  QString db2( QFileInfo( mTempDir + "/qgis-auth.db" ).canonicalFilePath() );
  QVERIFY2( db1 == db2, "Auth db temp path does not match db path of manager" );

  // verify master pass can be set manually
  // (this also creates a fresh password hash in the new temp database)
  QVERIFY2( QgsAuthManager::instance()->setMasterPassword( mPass, true ),
            "Master password could not be set" );
  QVERIFY2( QgsAuthManager::instance()->masterPasswordIsSet(),
            "Auth master password not set from passed string" );

  // create QGIS_AUTH_PASSWORD_FILE file
  QString passfilepath = mTempDir + "/passfile";
  QFile passfile( passfilepath );
  if ( passfile.open( QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate ) )
  {
    QTextStream fout( &passfile );
    fout << QString( mPass ) << "\r\n";
    passfile.close();
    qputenv( "QGIS_AUTH_PASSWORD_FILE", passfilepath.toAscii() );
  }
  // qDebug( "QGIS_AUTH_PASSWORD_FILE=%s", qgetenv( "QGIS_AUTH_PASSWORD_FILE" ).constData() );

  // re-init app and auth manager
  QgsApplication::quit();
  // QTest::qSleep( 3000 );
  QgsApplication::init();
  QgsApplication::initQgis();
  QVERIFY2( !QgsAuthManager::instance()->isDisabled(),
            "Authentication system is DISABLED" );

  // verify QGIS_AUTH_PASSWORD_FILE worked, when compared against hash in db
  QVERIFY2( QgsAuthManager::instance()->masterPasswordIsSet(),
            "Auth master password not set from QGIS_AUTH_PASSWORD_FILE" );

  // all tests should now have a valid qgis-auth.db and stored/set master password
}

void TestQgsAuthCrl::cleanup()
{
  // Restore password_helper_insecure_fallback value
  QgsSettings settings;
  settings.setValue( QStringLiteral( "password_helper_insecure_fallback" ), false, QgsSettings::Section::Auth );
}

void TestQgsAuthCrl::cleanupTempDir()
{
  QDir tmpDir = QDir( mTempDir );
  if ( tmpDir.exists() )
  {
    Q_FOREACH ( const QString &tf, tmpDir.entryList( QDir::NoDotAndDotDot | QDir::Files ) )
    {
      QVERIFY2( tmpDir.remove( mTempDir + '/' + tf ), qPrintable( "Could not remove " + mTempDir + '/' + tf ) );
    }
    QVERIFY2( tmpDir.rmdir( mTempDir ), qPrintable( "Could not remove directory " + mTempDir ) );
  }
}

void TestQgsAuthCrl::cleanupTestCase()
{
  QgsApplication::exitQgis();
  cleanupTempDir();

  QString myReportFile = QDir::tempPath() + "/qgistest.html";
  QFile myFile( myReportFile );
  if ( myFile.open( QIODevice::WriteOnly | QIODevice::Truncate ) )
  {
    QTextStream myQTextStream( &myFile );
    myQTextStream << mReport;
    myFile.close();
    // QDesktopServices::openUrl( "file:///" + myReportFile );
  }
}


void TestQgsAuthCrl::testCrl()
{
  QgsAuthManager *authm = QgsAuthManager::instance();
  Q_UNUSED( authm );
  QString crlPathPEM = QStringLiteral( TEST_DATA_DIR ) + "/auth_system/crl/crl.pem";
  QString crlPathDER = QStringLiteral( TEST_DATA_DIR ) + "/auth_system/crl/crl.der";
  QgsAuthCrl crlPEM( crlPathPEM );
  QCOMPARE( crlPEM.entries().length(), 1 );
  QgsAuthCrl crlDER( crlPathDER );
  QCOMPARE( crlDER.entries().length(), 1 );
  QCOMPARE( crlDER.serialNumbers()[0], QByteArray::fromHex( "00:d7:f4:4b:8e:53:12:93:f2" ) );
  QString certPathPEM = QStringLiteral( TEST_DATA_DIR ) + "/auth_system/crl/cert.pem";
  QSslCertificate cert = QSslCertificate::fromPath( certPathPEM ).at( 0 ) ;
  const QgsAuthCrlEntry *entry( crlPEM.certificateEntry( cert ) );
  QVERIFY( entry );
  QString rootPathPEM = QStringLiteral( TEST_DATA_DIR ) + "/auth_system/crl/root.pem";
  QSslCertificate rootCert = QSslCertificate::fromPath( rootPathPEM ).at( 0 ) ;
  const QgsAuthCrlEntry *rootEntry( crlPEM.certificateEntry( rootCert ) );
  QVERIFY( ! rootEntry );
}

void TestQgsAuthCrl::testToHex()
{
  QString serialPath = QStringLiteral( TEST_DATA_DIR ) + "/auth_system/crl/serial.txt";
  QFile inputFile( serialPath );
  if ( inputFile.open( QIODevice::ReadOnly ) )
  {
    QTextStream in( &inputFile );
    while ( !in.atEnd() )
    {
      QByteArray line( in.readLine().toAscii() );
      QByteArray serial( QByteArray::fromHex( line ) );
      QgsAuthCrlEntry entry( QgsAuthCrlEntry::Reason::Unspecified, serial, QDateTime::currentDateTime() );
      QCOMPARE( entry.serialNumberAsHexArray(), line );
    }
    inputFile.close();
  }
}

QGSTEST_MAIN( TestQgsAuthCrl )
#include "testqgsauthcrl.moc"
