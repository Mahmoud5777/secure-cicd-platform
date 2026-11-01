
# Build stage
FROM eclipse-temurin:21-jdk AS build

WORKDIR /app

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

RUN chmod +x mvnw

COPY src/ src/

RUN ./mvnw clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre

WORKDIR /app

RUN groupadd --system spring && useradd --system --gid spring spring

COPY --from=build /app/target/*.jar app.jar

RUN chown spring:spring app.jar

USER spring

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
