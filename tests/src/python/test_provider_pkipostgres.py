# -*- coding: utf-8 -*-
"""QGIS Unit tests for the postgres provider.

From build dir: ctest -R PyQgsPostgresPkiProvider -V

.. note:: This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
"""
__author__ = 'Luigi Pirelli'
__date__ = '2016-01-19'
__copyright__ = 'Copyright 2014, Boundless Spatial, Inc.'
# This will get replaced with a git SHA1 when you do a git archive
__revision__ = '$Format:%H$'

import os
import sys
import tempfile
from qgis.core import NULL

from qgis.core import (QgsProviderRegistry,
                       QgsAuthManager
                       )
from utilities import (unitTestDataPath,
                       getQgisTestApp,
                       unittest,
                       TestCase
                       )
from providertestbase import ProviderTestCase

TESTDATA = os.path.join(unitTestDataPath(), 'auth_system')
PKIDATA = os.path.join(TESTDATA, 'certs_keys')
AUTHDBDIR = tempfile.mkdtemp()

os.environ['QGIS_AUTH_DB_DIR_PATH'] = TESTDATA
QGISAPP, CANVAS, IFACE, PARENT = getQgisTestApp()

TEST_DATA_DIR = unitTestDataPath()


class TestPyQgsPostgresPkiProvider(TestCase):

    @classmethod
    def setUpClass(cls):
        """Run before all tests"""
        
        # setup auth configuration
        cls.authm = QgsAuthManager.instance()
        cls.mpass = 'pass'  # master password

        msg = 'Failed to verify master password in auth db'
        assert cls.authm.setMasterPassword(cls.mpass, True), msg
        
        # setup db connection parameters
        # 172.17.0.2 would be the default ip address of a docker postgis instance
        # Fra user has id y45c26z in the test qgis_auth.db
        cls.dbconn = u"host=172.17.0.2 port=5432 user='Fra' authcfg='y45c26z' sslmode='verify-ca'"
        if 'QGIS_PGTEST_DB' in os.environ:
            cls.dbconn = os.environ['QGIS_PGTEST_DB']
        
    @classmethod
    def tearDownClass(cls):
        """Run after all tests"""

    def testConnect(self):
        # set layer toload just to test connection
        self.dbconn += u" dbname='gis' key='coord_dimension' table='public'.'geometry_columns' sql="
        # check if it's possibile to login
        conn = QgsProviderRegistry.instance().provider("postgres", self.dbconn);
        self.assertIsNotNone(conn)
        self.assertTrue(conn.isValid())
        
if __name__ == '__main__':
    unittest.main()
