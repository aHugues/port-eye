FROM python:3.7-alpine

LABEL maintainer="me@aurelienhugues.com"
LABEL description="Simple CLI port scanner using Python"
LABEL version="0.0.2"

WORKDIR /usr/app
COPY setup.py README.md MANIFEST.in ./
COPY port_eye ./port_eye

RUN apk add nmap --no-cache && rm -f /var/cache/apk/*
RUN pip install .
RUN mkdir /files

VOLUME /files

ENTRYPOINT [ "port-eye" ]
CMD []