FROM python:3.9-alpine3.13
LABEL maintainer="Safiullah.com"

ENV PYTHONUNBUFFERED 1

COPY ./requirments.txt /tmp/requirments.txt
COPY ./requirments.dev.txt /tmp/requirments.dev.txt
COPY ./app /app
WORKDIR /app
EXPOSE 8000

ARG DEV=false
RUN python -m venv /py && \
    /py/bin/pip install --upgrade pip && \
    apk add --update --no-cache postgresql-client jpeg-dev && \
    apk add --update --no-cache --virtual .tmp-build-deps \
        build-base postgresql-dev musl-dev zlib zlib-dev && \
    /py/bin/pip install -r /tmp/requirments.txt && \
    if [ $DEV = "true" ]; \
        then /py/bin/pip install -r /tmp/requirments.dev.txt; fi && \
    rm -rf /tmp && \
    apk del .tmp-build-deps && \
    adduser \
        --disabled-password \
        --no-create-home \
        django-user

ENV PATH="/py/bin:$PATH"

USER django-user