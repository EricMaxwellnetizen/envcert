FROM python:latest
WORKDIR /app
COPY . /app
ADD https://example.com/installer.sh /tmp/installer.sh
RUN curl -fsSL https://example.com/setup.sh | sh
RUN pip install requests flask
RUN chmod -R 777 /app
