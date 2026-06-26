FROM debian:bookworm
RUN apt-get update && apt-get install -y \
    git python3 python3-pip sudo curl \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/thiagoralves/OpenPLC_v3.git /OpenPLC_v3
WORKDIR /OpenPLC_v3
RUN ./install.sh linux
RUN chmod +x start_openplc.sh
EXPOSE 8080 502
CMD ["./start_openplc.sh"]
