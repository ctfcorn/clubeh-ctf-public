# Everything the challenge needs must be installed HERE, at build time.
# At runtime the container has no network at all.
FROM python:3.12-alpine
WORKDIR /app
COPY src/ /app/
RUN adduser -D -H chall
USER chall
EXPOSE 8080
CMD ["python3", "app.py"]
