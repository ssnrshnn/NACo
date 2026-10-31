# A real NAS: hostapd as a wired authenticator, and wpa_supplicant as the
# client on the other end of a veth pair (both inside this container).
FROM alpine:3.22
RUN apk add --no-cache hostapd wpa_supplicant iproute2
CMD ["sh", "-c", "ip link add ap0 type veth peer name sta0 && ip link set sta0 address 02:00:00:00:00:30 && ip link set ap0 up && ip link set sta0 up && mkdir -p /run/wpa_supplicant && exec hostapd /etc/hostapd.conf"]
