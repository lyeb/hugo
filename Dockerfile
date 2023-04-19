# GitHub:       https://github.com/gohugoio
# Twitter:      https://twitter.com/gohugoio
# Website:      https://gohugo.io/

FROM golang:1.20.3-bullseye AS build

# Optionally set HUGO_BUILD_TAGS to "extended" or "nodeploy" when building like so:
#   docker build --build-arg HUGO_BUILD_TAGS=extended .
ARG HUGO_BUILD_TAGS

ARG CGO=1
ENV CGO_ENABLED=${CGO}
ENV GOOS=linux
ENV GO111MODULE=on

WORKDIR /go/src/github.com/gohugoio/hugo

COPY . /go/src/github.com/gohugoio/hugo/

# gcc/g++ are required to build SASS libraries for extended version
RUN apt -y update && apt -y upgrade && apt -y install gcc g++ git
RUN go install github.com/magefile/mage

RUN mage hugo && mage install

# ---

FROM debian:bullseye-slim

COPY --from=build /go/bin/hugo /usr/bin/hugo

RUN apt -y update && apt -y upgrade && apt -y install ca-certificates git

VOLUME /site
WORKDIR /site

# Expose port for live server
EXPOSE 1313

ENTRYPOINT ["hugo"]
CMD ["--help"]
