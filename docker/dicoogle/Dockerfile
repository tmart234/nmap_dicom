FROM eclipse-temurin:8-jre

# Install unzip and wget
RUN apt-get update && apt-get install -y wget unzip && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/dicoogle

# Download the release
RUN wget -q https://github.com/dicoogle/dicoogle/releases/download/3.3.3/Dicoogle_v3.3.3.zip \
    && unzip Dicoogle_v3.3.3.zip \
    && rm Dicoogle_v3.3.3.zip

RUN mkdir -p Dicoogle_v3.3.3/Storage

EXPOSE 8080 6666

WORKDIR /opt/dicoogle/Dicoogle_v3.3.3

CMD ["java", "-jar", "dicoogle.jar", "-s"]