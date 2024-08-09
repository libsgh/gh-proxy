FROM guysoft/uwsgi-nginx:python3.7
RUN apt-get update \
    && apt-get install -y curl \
    && apt-get install -y ca-certificates
LABEL maintainer="hunshcn <hunsh.cn@gmail.com>"

RUN pip install flask requests diskcache Flask-JWT-Extended

COPY ./app /app
WORKDIR /app

# Make /app/* available to be imported by Python globally to better support several use cases like Alembic migrations.
ENV PYTHONPATH=/app

# Move the base entrypoint to reuse it
RUN mv /entrypoint.sh /uwsgi-nginx-entrypoint.sh
# Copy the entrypoint that will generate Nginx additional configs
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG BAK_VERSION=1.8
ENV BAK_VERSION=${BAK_VERSION}
RUN curl -L "https://github.com/laboratorys/backup-to-github/releases/download/v${BAK_VERSION}/backup2gh-v${BAK_VERSION}-linux-amd64.tar.gz" -o /tmp/backup-to-github.tar.gz \
    && cd /app && tar -xzf /tmp/backup-to-github.tar.gz \
    && rm /tmp/backup-to-github.tar.gz \
    && ls -n
ENTRYPOINT ["/entrypoint.sh"]

# Run the start script provided by the parent image tiangolo/uwsgi-nginx.
# It will check for an /app/prestart.sh script (e.g. for migrations)
# And then will start Supervisor, which in turn will start Nginx and uWSGI

EXPOSE 80

CMD ["/start.sh"]
