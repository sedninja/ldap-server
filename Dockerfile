FROM ubuntu:14.04
MAINTAINER John Fanjoy <jfanjoy@sedninja.com>
ENV NODE_ENV development
# use those super cow powers
RUN \
  apt-get -qq update && \
  apt-get -qqy install nodejs nodejs-dev npm && \
  ln -s /usr/bin/nodejs /usr/bin/node && echo "and now for something completely different"

RUN \
  npm install -g npm@1.4 && npm install -g bunyan && \
  install -dT -m2755 /tmp/build && \
  install -dT -m2755 /opt/ldapserver && \
  echo "All done with the nonsense... on to installing the actual server"
COPY server/package.json /tmp/build/
WORKDIR /tmp/build
RUN npm install && \
    cp -a node_modules /opt/ldapserver
COPY server/server.js /opt/ldapserver/
COPY server/package.json /opt/ldapserver/
COPY server/config.json /opt/ldapserver/
WORKDIR /opt/ldapserver
CMD ["npm","start"]
# it's ldap bitches
EXPOSE 389
