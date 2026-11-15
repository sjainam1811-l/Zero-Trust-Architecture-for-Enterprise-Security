FROM alpine:3.19

# Install security assessment and networking utilities
RUN apk add --no-cache curl nmap bind-tools netcat-openbsd python3 bash

WORKDIR /attacker

COPY attack.sh /attacker/attack.sh
RUN chmod +x /attacker/attack.sh

# Keep container running for interactive university lab testing
CMD ["tail", "-f", "/dev/null"]
