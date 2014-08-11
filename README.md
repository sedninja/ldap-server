ldap-server
===========

nodejs ldap server on top of mongodb

The purpose of this project is to provide a truly lightweight directory server using mongodb as the backend server and nodes awesome event handling. We expect the application will be deployed using docker to make it super easy to install, run, upgrade, maintain, etc. It's intended to be a complete drop in replacement for OpenLDAP so I will be working to add as many features and exops as I can.

I also plan to add a web accessible REST API and client application to simplify the administration of users/groups. The API will provide a mechanism to generate Auth Tokens that can be used by other systems. Users will also have the ability to enable __Dual Factor Authentication__ on their account. DFA will be compatible with Google Authenticator.

---

Where we sit right now
------------

As the API comes together, I will make sure to provide examples and decent documentation. Right now the only thing we actually have working is the LDAP service which is currently only capable of binding users. That said, the first startup generates an admin account which _will_ eventually be able to do everything necessary to populate the db. The admin account password is randomly generated and stored as a `SSHA` hash similarly to conventional OpenLDAP accounts.


Starting the Server
----------

The Docker container built from the __Dockerfile__ does not have a built in mongodb instance. You will want to start up a separate container and link it as _`db`_

```bash
[ user@host ~]# sudo docker run -dt -P --name ldapserver --link mongodb_server:db sedninja/ldap-server:latest
```
