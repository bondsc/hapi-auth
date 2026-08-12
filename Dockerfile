# ──────────────────────────────────────────────────────────────────────────────
# HAPI FHIR + multi-issuer JWT auth extension
#
# The upstream hapiproject/hapi:latest-tomcat ships an un-exploded ROOT.war
# and has neither `jar` nor `unzip` available, so Spring Boot Loader's
# LOADER_PATH trick does not apply. We build the extension JAR with Maven,
# explode the upstream WAR in a second Maven stage (which has `jar`), inject
# the JAR into WEB-INF/lib, then COPY the exploded webapp back over ROOT.war
# in the final image.
# ──────────────────────────────────────────────────────────────────────────────

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -B -DskipTests package

FROM maven:3.9-eclipse-temurin-17 AS warpack
WORKDIR /work
# Pull the WAR from the official HAPI image and explode it.
# Pinned by DIGEST (not `latest-tomcat`): the auth extension's pom assumes this
# image's exact spring-boot / spring-security 6.3.9 / springdoc 2.6.0 classpath.
# A moving `latest` tag drifts that classpath and breaks springdoc's
# SpringDocSecurityConfiguration at startup. This digest = HAPI latest-tomcat
# validated to bundle spring-security-core 6.3.9 + springdoc 2.6.0.
COPY --from=hapiproject/hapi@sha256:ae5b560683f6259d1fe081aecd38a0aa70f5e9b128d166d938fd26af959ba890 /usr/local/tomcat/webapps/ROOT.war ./ROOT.war
COPY --from=build /src/target/hapi-auth.jar ./hapi-auth.jar
# Extra runtime jars (spring-security oauth2 resource-server etc) that HAPI
# does not ship. Pinned to HAPI's spring-security version via pom.xml.
COPY --from=build /src/target/lib ./extra-lib
RUN mkdir -p ROOT \
    && (cd ROOT && jar xf ../ROOT.war) \
    && rm -f ROOT/WEB-INF/lib/spring-security-*.jar \
    && cp hapi-auth.jar ROOT/WEB-INF/lib/hapi-auth.jar \
    && cp extra-lib/*.jar ROOT/WEB-INF/lib/ \
    && rm -rf ROOT.war hapi-auth.jar extra-lib

FROM hapiproject/hapi@sha256:ae5b560683f6259d1fe081aecd38a0aa70f5e9b128d166d938fd26af959ba890
USER root
# Replace the packaged WAR with the exploded directory carrying our extension.
# Spring Boot auto-configuration discovery (via the JAR's
# META-INF/spring/...AutoConfiguration.imports) wires up the security +
# interceptor beans on startup when hapi.auth.enabled=true.
RUN rm -f /usr/local/tomcat/webapps/ROOT.war
COPY --from=warpack --chown=65532:65532 /work/ROOT /usr/local/tomcat/webapps/ROOT
USER 65532

