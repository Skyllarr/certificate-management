/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.certificate.management.x500.util;

import static org.junit.Assert.*;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.wildfly.security.certificate.management.asn1.ASN1;
import org.wildfly.security.certificate.management.asn1.ASN1Encodable;
import org.wildfly.security.certificate.management.asn1.DERDecoder;
import org.wildfly.security.certificate.management.x500.X500;
import org.wildfly.security.certificate.management.x500.X500AttributeTypeAndValue;
import org.wildfly.security.certificate.management.x500.X500PrincipalBuilder;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class X500PrincipalUtilTest {

    @Test
    public void testGetAttributeValues() {
        X500Principal principal;
        principal = new X500Principal("cn=david.lloyd,dc=redhat,dc=com");
        System.out.println(ASN1.formatAsn1(new DERDecoder(principal.getEncoded())));
        System.out.println(principal.getName());
        assertArrayEquals(new String[] { "redhat", "com" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_DC));
        assertArrayEquals(new String[] { "david.lloyd" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_AT_COMMON_NAME));
        principal = new X500Principal("uid=david.lloyd,dc=redhat,dc=com");
        System.out.println(ASN1.formatAsn1(new DERDecoder(principal.getEncoded())));
        System.out.println(principal.getName());
        assertArrayEquals(new String[] { "redhat", "com" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_DC));
        assertArrayEquals(new String[] { "david.lloyd" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_UID));
        principal = new X500Principal("cn=David M. Lloyd+uid=david.lloyd,dc=redhat,dc=com");
        System.out.println(ASN1.formatAsn1(new DERDecoder(principal.getEncoded())));
        System.out.println(principal.getName());
        assertArrayEquals(new String[] { "redhat", "com" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_DC));
        assertArrayEquals(new String[] { "David M. Lloyd" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_AT_COMMON_NAME));
        assertArrayEquals(new String[] { "david.lloyd" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_UID));
        principal = new X500Principal("cn=banana,cn=apple,dc=peanut,dc=butter,dc=com,dc=faux");
        System.out.println(ASN1.formatAsn1(new DERDecoder(principal.getEncoded())));
        System.out.println(principal.getName());
        assertArrayEquals(new String[] { "peanut", "butter", "com", "faux" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_DC));
        assertArrayEquals(new String[] { "banana", "apple" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_AT_COMMON_NAME));
        assertArrayEquals(new String[] { "faux", "com", "butter", "peanut" }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_DC, true));
        principal = new X500Principal("cn=Bob Smith+uid=bsmith,ou=people,dc=redhat,dc=com");
        assertTrue(X500PrincipalUtil.containsAllAttributes(principal, X500.OID_AT_COMMON_NAME, X500.OID_UID, X500.OID_DC));
        assertFalse(X500PrincipalUtil.containsAllAttributes(principal, X500.OID_UID, X500.OID_AT_LOCALITY_NAME, X500.OID_DC));
    }

    @Test
    public void testGetAttributeValuesFromBuiltPrincipal() {
        X500PrincipalBuilder builder = new X500PrincipalBuilder();
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofPrintableString("printableString")));
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofUniversalString("universalString")));
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofUtf8String("utf8String")));
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofBMPString("bmpString")));
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofIA5String("ia5String")));
        X500Principal principal = builder.build();
        System.out.println(ASN1.formatAsn1(new DERDecoder(principal.getEncoded())));
        assertArrayEquals(new String[] {
                "printableString",
                "universalString",
                "utf8String",
                "bmpString",
                "ia5String"
        }, X500PrincipalUtil.getAttributeValues(principal, X500.OID_DC, true));
    }
}
