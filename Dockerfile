FROM openjdk:8
VOLUME /tmp
EXPOSE 38090
ADD gateway-server-0.0.1-SNAPSHOT.jar gateway-server.jar
ENTRYPOINT ["java","-jar","/gateway-server.jar"]