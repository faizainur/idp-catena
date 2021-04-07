#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY . .
RUN go get -d -v ./...
RUN go build -o app

#final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/app /app
COPY --from=builder /src/templates /templates
ENV MONGODB_URI=""
ENV REDIS_HOST=""
ENV HYDRA_ADMIN_HOST=""
ENV ENABLE_TLS_VERIFICATION=""
ENV PORT_LISTEN=""
ENV OAUTH_LOGIN_CALLBACK=""
ENV OAUTH_CONSENT_CALLBACK=""
ENV RESET_PASSWORD_URI=""
ENTRYPOINT ./app
LABEL Name=idpcatena Version=0.0.1
EXPOSE 4000
