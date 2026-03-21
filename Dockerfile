ARG OSD_VERSION=3.5.0
FROM opensearchproject/opensearch-dashboards:${OSD_VERSION}

# Build context must place the plugin ZIP at xdr-manager-plugin.zip
COPY xdr-manager-plugin.zip /tmp/xdr-manager.zip
RUN /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install --allow-root file:///tmp/xdr-manager.zip
RUN rm -f /tmp/xdr-manager.zip || true
