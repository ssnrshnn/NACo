# Test supplicant/NAS: radclient (PAP, MAB, accounting) and eapol_test (EAP).
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends freeradius-utils eapoltest ca-certificates \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
