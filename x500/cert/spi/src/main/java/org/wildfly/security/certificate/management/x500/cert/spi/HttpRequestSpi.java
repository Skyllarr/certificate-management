/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.certificate.management.x500.cert.spi;

import java.net.URI;
import java.util.List;
import java.util.Map;

public interface HttpRequestSpi {

    void setMethod(String method);

    void setURI(URI uri);

    void setHeaders(Map<String, List<String>> headers);

    void setHeader(String key, List<String> value);
    void setBody(String body);

    String getMethod();

    URI getURI();

    Map<String, List<String>> getHeaders();

    List<String> getHeader(String key);

    String getBody();
}
