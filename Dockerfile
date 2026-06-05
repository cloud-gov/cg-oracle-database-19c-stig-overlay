# Dockerfile
FROM cincproject/auditor:latest

# Manage ZScaler certs for GSA envs
COPY .docker/zscaler_cert_pem.txt /tmp/zscaler-root-ca.crt
RUN cp /tmp/zscaler-root-ca.crt /usr/local/share/ca-certificates/zscaler.crt && \
    update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Install Oracle Instant Client 19 and SQL*Plus prerequisites
# jq, vim-tiny, netcat for debuging only
RUN apt-get update && \
    apt-get install -y \
    wget \
    unzip \
    libaio1 \
    libaio-dev \
    jq \
    vim-tiny \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Download and install Oracle Instant Client 19 Basic and SQL*Plus
WORKDIR /tmp

# amd64
# RUN wget https://download.oracle.com/otn_software/linux/instantclient/1923000/instantclient-basic-linux.x64-19.23.0.0.0dbru.zip
# RUN wget https://download.oracle.com/otn_software/linux/instantclient/1923000/instantclient-sqlplus-linux.x64-19.23.0.0.0dbru.zip
# RUN unzip instantclient-basic-linux.x64-19.23.0.0.0dbru.zip -d /opt/oracle && \
#     unzip -o instantclient-sqlplus-linux.x64-19.23.0.0.0dbru.zip -d /opt/oracle && \
#     rm -f instantclient-basic-linux.x64-19.23.0.0.0dbru.zip instantclient-sqlplus-linux.x64-19.23.0.0.0dbru.zip

RUN wget https://download.oracle.com/otn_software/linux/instantclient/1923000/instantclient-basic-linux.arm64-19.23.0.0.0dbru.zip
RUN wget https://download.oracle.com/otn_software/linux/instantclient/1923000/instantclient-sqlplus-linux.arm64-19.23.0.0.0dbru.zip
RUN unzip instantclient-basic-linux.arm64-19.23.0.0.0dbru.zip -d /opt/oracle && \
   unzip -o instantclient-sqlplus-linux.arm64-19.23.0.0.0dbru.zip -d /opt/oracle && \
   rm -f instantclient-basic-linux.arm64-19.23.0.0.0dbru.zip instantclient-sqlplus-linux.arm64-19.23.0.0.0dbru.zip


# Set Oracle environment variables
ENV ORACLE_HOME=/opt/oracle/instantclient_19_23
ENV LD_LIBRARY_PATH=$ORACLE_HOME
ENV PATH=$ORACLE_HOME:$PATH

# Create symlinks for compatibility
RUN sh -c "echo $ORACLE_HOME > /etc/ld.so.conf.d/oracle-instantclient.conf" && \
    ldconfig

WORKDIR /
# ENTRYPOINT [ "/bin/bash" ]

