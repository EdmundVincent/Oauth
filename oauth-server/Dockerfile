# --- 第一阶段：构建 (Builder) ---
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
# 咱们是Windows环境，为了稳妥，这里显式跳过测试
RUN mvn clean package -DskipTests

# --- 第二阶段：运行 (Runner) ---
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]