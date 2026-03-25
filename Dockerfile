FROM tiangolo/uwsgi-nginx:python3.12
RUN apt-get update \
    && apt-get install -y curl \
    && apt-get install -y ca-certificates
LABEL maintainer="hunshcn <hunsh.cn@gmail.com>"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY ./app /app
WORKDIR /app

# Make /app/* available to be imported by Python globally to better support several use cases like Alembic migrations.
ENV PYTHONPATH=/app

# Move the base entrypoint to reuse it
RUN mv /entrypoint.sh /uwsgi-nginx-entrypoint.sh
# Copy the entrypoint that will generate Nginx additional configs
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG BAK_VERSION=2.3
ENV BAK_VERSION=${BAK_VERSION}
RUN curl -L "https://github.com/laboratorys/backup2gh/releases/download/v${BAK_VERSION}/backup2gh-linux-amd64.tar.gz" -o /tmp/backup2gh.tar.gz \
    && cd /app && tar -xzf /tmp/backup2gh.tar.gz \
    && rm /tmp/backup2gh.tar.gz

ENTRYPOINT ["/entrypoint.sh"]

# Run the start script provided by the parent image tiangolo/uwsgi-nginx.
# It will check for an /app/prestart.sh script (e.g. for migrations)
# And then will start Supervisor, which in turn will start Nginx and uWSGI

EXPOSE 80

CMD ["/start.sh"]
