FROM alpine:latest
RUN apk add --update python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --upgrade pip
RUN pip3 install requests prometheus_client

WORKDIR /opt/xtremio_exporter

COPY xtremio.py xtremio.py
COPY LICENSE LICENSE
COPY README.md README.md
COPY example_config.json example_config.json

CMD ["python3","xtremio.py"]