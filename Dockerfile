FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home iglite && mkdir /data && chown iglite /data

USER iglite
ENV IGLITE_DB=/data/iglite.db
VOLUME /data
EXPOSE 8765
# Gateway mode inputs: syslog and NetFlow/IPFIX from the router or firewall.
EXPOSE 5514/udp 2055/udp
# Listening on 0.0.0.0 requires IGLITE_API_TOKEN to be set at run time.
CMD ["iglite", "serve", "--host", "0.0.0.0", "--port", "8765"]
