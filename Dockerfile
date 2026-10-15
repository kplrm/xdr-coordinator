ARG OSD_VERSION=3.9.0
FROM opensearchproject/opensearch-dashboards:${OSD_VERSION}

# Build context must place the plugin ZIP at xdr-coordinator.zip
COPY xdr-coordinator.zip /tmp/xdr-coordinator.zip
RUN /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install --allow-root file:///tmp/xdr-coordinator.zip
RUN rm -f /tmp/xdr-coordinator.zip || true
