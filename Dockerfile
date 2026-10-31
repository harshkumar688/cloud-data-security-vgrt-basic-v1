FROM maven:3.9.11-eclipse-temurin-25 AS build
WORKDIR /workspace
COPY .mvn .mvn
COPY mvnw pom.xml ./
COPY src src
RUN chmod +x mvnw && ./mvnw -B -DskipTests package

FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build /workspace/target/secure-cloud-0.1.0.jar /app/app.jar
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod 0555 /app/docker-entrypoint.sh
ENV SERVER_ADDRESS=0.0.0.0 \
    PORT=80 \
    VGRT_STORAGE_ROOT=/tmp/vgrt-objects
EXPOSE 80
ENTRYPOINT ["/app/docker-entrypoint.sh"]