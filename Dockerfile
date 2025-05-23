# Stage 1: Build
FROM openjdk:24-jdk-slim AS build

# Set working directory
WORKDIR /app

# Copy Gradle wrapper and build files
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

# Copy source code
COPY src src

# Make gradlew executable
RUN chmod +x ./gradlew

# Build the application
RUN ./gradlew build --no-daemon

# Stage 2: Runtime
FROM openjdk:24-jdk-slim

# Set working directory
CMD ["sh", "-c", "java -jar $(ls build/libs/*.jar)"]

# Copy the built jar file from the build stage
COPY --from=build /app/build/libs/inventory-core-0.0.1-SNAPSHOT.jar .

# Expose the port your app runs on
# This is the port the application listens on
EXPOSE 8080

# Run the jar file
CMD ["java", "-jar", "inventory-core-0.0.1-SNAPSHOT.jar"]