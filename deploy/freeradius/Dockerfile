# NACo's FreeRADIUS: the stock image with a small, NACo-only configuration,
# running as an unprivileged user. Certificates are mounted at runtime.
FROM freeradius/freeradius-server:3.2.10-alpine

RUN addgroup -S -g 1812 radius \
 && adduser -S -D -H -u 1812 -G radius -s /sbin/nologin radius \
 && rm -rf /opt/etc/raddb/sites-enabled/* /opt/etc/raddb/mods-enabled/* /opt/etc/raddb/certs/* \
 && ln -s ../mods-available/always /opt/etc/raddb/mods-enabled/always \
 && ln -s ../mods-available/attr_filter /opt/etc/raddb/mods-enabled/attr_filter \
 && ln -s ../mods-available/expr /opt/etc/raddb/mods-enabled/expr \
 && install -d -o radius -g radius /opt/var/run/radiusd /opt/var/log/radius

COPY raddb/ /opt/etc/raddb/

# Configuration stays root-owned and read-only for the radius group.
RUN chown -R root:radius /opt/etc/raddb \
 && chmod -R u=rwX,g=rX,o= /opt/etc/raddb

USER radius
EXPOSE 1812/udp 1813/udp
CMD ["radiusd", "-l", "stdout"]
