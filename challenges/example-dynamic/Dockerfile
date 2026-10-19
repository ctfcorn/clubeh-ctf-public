FROM python:3.12-alpine
WORKDIR /app
COPY src/ /app/
# Run as an unprivileged user. The entrypoint reads FLAG from the environment
# ONCE, keeps it in memory, and scrubs it from the environment so nothing a
# player runs inside the container can read it back from /proc.
RUN adduser -D -H chall
USER chall
EXPOSE 9000
CMD ["python3", "server.py"]
