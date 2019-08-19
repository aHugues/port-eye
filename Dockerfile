FROM python:3.7-alpine

WORKDIR /usr/app
COPY setup.py README.md ./
RUN pip install .