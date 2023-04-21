# By default, build on JDK 11
ARG jdk=11
#FROM eclipse-temurin:${jdk}-centos7
FROM eclipse-temurin:11-centos7

LABEL maintainer="rsearls@redhat.com"

COPY ./tools/wrapper/dists/apache-maven-3.6.3-bin/lm9vem38rfmjij3jj0mk5bvnt/apache-maven-3.6.3/conf/settings.xml /root/.m2/

COPY . /wildfly
RUN cd /wildfly && ./build.sh -DskipTests 
CMD ["./integration-tests.sh -f integration/ws/pom.xml -Dtest=WSTrustTestCase"] 
