FROM openjdk:8-jre-slim
RUN apt-get update && apt-get install -y wget unzip && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/dicoogle
# Download the official release
RUN wget -q https://github.com/dicoogle/dicoogle/releases/download/3.3.3/Dicoogle_v3.3.3.zip \
    && unzip Dicoogle_v3.3.3.zip \
    && rm Dicoogle_v3.3.3.zip
RUN mkdir -p Storage
EXPOSE 8080 6666
CMD ["java", "-jar", "dicoogle.jar", "-s"]