# Wird von Home Assistant mit dem passenden Basis-Image gebaut (siehe build.yaml).
# Als normales Docker-Image: docker build -t spike . && docker run --network host -v spike-data:/data spike
ARG BUILD_FROM=python:3.12-alpine
FROM ${BUILD_FROM}

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

COPY spike_server /app/spike_server
WORKDIR /app
ENV SPIKE_DATA=/data SPIKE_MODE=docker
CMD ["python3", "-m", "spike_server"]
