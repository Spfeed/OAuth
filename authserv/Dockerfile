FROM openjdk:21-jdk-slim

WORKDIR /app

COPY pom.xml .

COPY . .

RUN ./mvnw clean package -DskipTests

FROM openjdk:21-jdk-slim

WORKDIR /app

COPY --from=0 /app/target/*.jar app.jar

ENTRYPOINT ["java", "-jar", "/app/app.jar"]

EXPOSE 8080