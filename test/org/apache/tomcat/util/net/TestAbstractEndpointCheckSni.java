/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.net;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TestAbstractEndpointCheckSni {

    private NioEndpoint endpoint;

    @Before
    public void setUp() {
        endpoint = new NioEndpoint();
        endpoint.setSSLEnabled(true);
        endpoint.setStrictSni(true);

        SSLHostConfig defaultConfig = new SSLHostConfig();
        defaultConfig.setHostName(SSLHostConfig.DEFAULT_SSL_HOST_NAME);
        endpoint.addSslHostConfig(defaultConfig);

        SSLHostConfig secureConfig = new SSLHostConfig();
        secureConfig.setHostName("secure.example.com");
        endpoint.addSslHostConfig(secureConfig);
    }

    @Test
    public void testSameHost() {
        Assert.assertTrue(endpoint.checkSni("secure.example.com", "secure.example.com"));
        Assert.assertTrue(endpoint.checkSni("secure.example.com", "SECURE.Example.com"));
    }

    @Test
    public void testDifferentConfig() {
        Assert.assertFalse(endpoint.checkSni("other.example.com", "secure.example.com"));
        Assert.assertFalse(endpoint.checkSni(null, "secure.example.com"));
    }

    @Test
    public void testSameDefaultConfig() {
        Assert.assertTrue(endpoint.checkSni("other.example.com", "another.example.com"));
        Assert.assertTrue(endpoint.checkSni(null, "another.example.com"));
    }

    @Test
    public void testUnicodeLongS() {
        // U+017F LATIN SMALL LETTER LONG S
        Assert.assertFalse(endpoint.checkSni("\u017Fecure.example.com", "secure.example.com"));
    }

    @Test
    public void testUnicodeDotlessI() {
        SSLHostConfig config = new SSLHostConfig();
        config.setHostName("internal.example.com");
        endpoint.addSslHostConfig(config);
        // U+0131 LATIN SMALL LETTER DOTLESS I
        Assert.assertFalse(endpoint.checkSni("\u0131nternal.example.com", "internal.example.com"));
    }

    @Test
    public void testStrictSniDisabled() {
        endpoint.setStrictSni(false);
        Assert.assertTrue(endpoint.checkSni("\u017Fecure.example.com", "secure.example.com"));
    }
}
