/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.valves;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.authenticator.NonLoginAuthenticator;
import org.apache.catalina.startup.TesterServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.descriptor.web.LoginConfig;

/*
 * Tests invalidAuthenticationWhenDeny with a real authenticator and a resource that has no security constraint.
 */
public class TestRequestFilterValveAuthentication extends TomcatBaseTest {

    private static final String USER = "user";
    private static final String PWD = "pwd";

    @Test
    public void testBasicDeniedNoCredentials() throws Exception {
        Map<String,List<String>> resHeaders = new HashMap<>();
        int rc = doTest("BASIC", true, HttpServletResponse.SC_FORBIDDEN, null, resHeaders);
        Assert.assertEquals(HttpServletResponse.SC_UNAUTHORIZED, rc);
        Assert.assertNotNull(getSingleHeader("WWW-Authenticate", resHeaders));
    }

    @Test
    public void testBasicDeniedInvalidScheme() throws Exception {
        int rc = doTest("BASIC", true, HttpServletResponse.SC_FORBIDDEN, "Bearer abc", null);
        Assert.assertEquals(HttpServletResponse.SC_UNAUTHORIZED, rc);
    }

    @Test
    public void testBasicDeniedBadCredentials() throws Exception {
        int rc = doTest("BASIC", true, HttpServletResponse.SC_FORBIDDEN, basic(USER, "wrong"), null);
        Assert.assertEquals(HttpServletResponse.SC_UNAUTHORIZED, rc);
    }

    @Test
    public void testBasicDeniedValidCredentials() throws Exception {
        int rc = doTest("BASIC", true, HttpServletResponse.SC_FORBIDDEN, basic(USER, PWD), null);
        Assert.assertEquals(HttpServletResponse.SC_OK, rc);
    }

    @Test
    public void testBasicAllowed() throws Exception {
        int rc = doTest("BASIC", false, HttpServletResponse.SC_FORBIDDEN, null, null);
        Assert.assertEquals(HttpServletResponse.SC_OK, rc);
    }

    @Test
    public void testNonLoginDenied() throws Exception {
        int rc = doTest("NONE", true, HttpServletResponse.SC_FORBIDDEN, null, null);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, rc);
    }

    @Test
    public void testNonLoginDeniedCustomStatus() throws Exception {
        int rc = doTest("NONE", true, HttpServletResponse.SC_NOT_FOUND, null, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
    }

    @Test
    public void testNoAuthenticatorDenied() throws Exception {
        int rc = doTest(null, true, HttpServletResponse.SC_FORBIDDEN, null, null);
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, rc);
    }


    private int doTest(String authMethod, boolean deny, int denyStatus, String authorization,
            Map<String,List<String>> resHeaders) throws Exception {
        Tomcat tomcat = getTomcatInstance();
        tomcat.addUser(USER, PWD);

        Context ctx = getProgrammaticRootContext();
        ctx.setPreemptiveAuthentication(true);
        Tomcat.addServlet(ctx, "servlet", new TesterServlet());
        ctx.addServletMapping("/", "servlet");

        RemoteCIDRValve valve = new RemoteCIDRValve();
        if (deny) {
            valve.setDeny("0.0.0.0/0, ::/0");
        } else {
            valve.setAllow("0.0.0.0/0, ::/0");
        }
        valve.setDenyStatus(denyStatus);
        valve.setInvalidAuthenticationWhenDeny(true);
        ctx.getPipeline().addValve(valve);

        if (authMethod != null) {
            LoginConfig lc = new LoginConfig();
            lc.setAuthMethod(authMethod);
            ctx.setLoginConfig(lc);
            AuthenticatorBase authenticator;
            if ("BASIC".equals(authMethod)) {
                authenticator = new BasicAuthenticator();
            } else {
                authenticator = new NonLoginAuthenticator();
            }
            ctx.getPipeline().addValve(authenticator);
        }

        tomcat.start();

        Map<String,List<String>> reqHeaders = new HashMap<>();
        if (authorization != null) {
            reqHeaders.put("Authorization", List.of(authorization));
        }
        ByteChunk bc = new ByteChunk();
        return getUrl("http://localhost:" + getPort() + "/", bc, reqHeaders, resHeaders);
    }


    private static String basic(String user, String pwd) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + pwd).getBytes(StandardCharsets.ISO_8859_1));
    }
}
