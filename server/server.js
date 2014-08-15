var ldap = require('ldapjs');
var mongoose = require('mongoose');
// var acl = require('mongoose-acl');
var fs = require('fs');
var User = require('./models/user.js');
var Group = require('./models/group.js');

var bunyan = require('bunyan');

var util = require('util');
var config = require('./config.json');

var log = bunyan.createLogger({
  name: "ldap",
  streams: [
    { path: "server.log" },
    { stream: process.stdout, level : "trace" }
  ],
  level: "debug"
});

var dbhost = process.env.DB_PORT_27017_TCP_ADDR || "127.0.0.1",
    dbport = process.env.DB_PORT_27017_TCP_PORT || 27017,
    dbname = new String(process.env.DB_NAME || "/feta/db").replace(/\//g,"");
var dsn = util.format("mongodb://%s:%s/%s",dbhost,dbport,dbname);
mongoose.connect(dsn);

// create the ldap server
var server = ldap.createServer(log);

var pre = [authorize];
var org = config.organization;
if ( process.env.NODE_ENV == undefined ) var port = 8000;
else var port = config.listen || 389;

/**
 * No anonymous searches allowed right now
 **/
function authorize( req, res, next ) {
  if ( !req.connection.ldap.bindDN ) return next(new ldap.InsufficientAccessRightsError());
  return next();
}

server.bind('ou=users,' + config.basedn, function( req, res, next) {
  var binddn = req.dn.toString();
  if ( !req.credentials ) {
    err = new ldap.InvalidCredentialsError();
    log.info(err);
    return next(err);
  }
  var login = req.dn.rdns[0];
  log.info("binding as: " + binddn);
  // accepting logins using uid or cn for now
  User.find( { uid: login.uid || login.cn } , function(err,users) {
    if ( err ) { 
      log.info(err);
      return next(err);
    }
    else if ( !users.length ) {err = new ldap.InvalidCredentialsError(); log.info(err); return next(err);}
    else {
      // investigate further if this ever becomes an issue
      var result = users[0];
      log.debug("Checking credentials now");
      if ( result.verifypw(req.credentials) && result.enabled ) {
        log.trace(result.objectClass('posixaccount'));
        log.info("bind successful.. processing next part of request");
        res.end();
        return next();
      }
    }
    err = new ldap.InvalidCredentialsError();
    log.info(err);
    return next(err);
  });

});

// server user add method
server.add('ou=users,' + config.basedn, pre, function( req, res, next ) {

  var entry = req.entry;
  var u = req.toObject().attributes;
  if ( entry.rdns[0].uid ) {
    // this only applies for users, but for now that's what we're focusing on
    // must have a uid attribute and that uid __MUST__ match the dn uid
    var uid = req.attributes.uid || entry.rdns[0].uid;
    if ( uid === entry.rdns[0].uid ) {
      log.info("adding new account for \"%s\" now",uid);
      var userspec = {}; for ( k in u ) { userspec[k] = u[k][0]; }
      log.debug(userspec);
      User.create(userspec, function(err, user) {
        if ( err ) {
          var death = new ldap.UnwillingToPerformError(err);
          log.fatal(death);
          return next(death);
        }  
        log.info("user account created for \"%s\" sucessfully",user.uid);

        res.end();
        return next();
      });
    }
  } else {
    // more error checking later, for now... ambiguous "constraint violation"
    // will have to do
    err = new ldap.ConstraintViolationError();
    log.info(err);
    return next(err);
  }
});

server.add('ou=groups,' + config.basedn, pre, function( req, res, next ) {
  var entry = req.entry;
  var g = req.toObject().attributes;
  if ( entry.rdns[0].cn ) {
  
  }
});

// support for adding ous or other base objects to the directory
server.add(config.basedn, pre, function( req, res, next ) {
  return next();
});

server.modify( 'ou=users,' + config.basedn, pre, function( req, res, next ) {
  var dn = req.dn.rdns[0],
      uid = dn.uid;
  if ( uid && req.changes.length ) {
    User.find({ uid: dn.uid }, function(err, user) {
      if ( err ) {
        log.error(err);
        return next(err);
      }
      user = user[0];
      var mod, op, field, curop;
      // updating modified will be moved into the pre validate logic soon
      // enough
      var update = {};
      log.trace(req.changes);
      for ( c in req.changes ) {
        mod = req.changes[c].modification, 
              op = req.changes[c].operation,
              field = user[mod.type];
        
        switch(op) {
          case 'add':
            if ( util.isArray(field) ) user.set(mod.type, mod.vals);
            else user.set(mod.type,mod.vals[0]);
            break;
          case 'replace':
            if ( mod.type === 'uid' || !mod.vals || !mod.vals.length || !field ) {
              return next(new ldap.UnwillingToPerformError('unable to change uid without "modifydn operation"'));
            }
            if ( util.isArray(field) ) user.set(mod.type, mod.vals);
            else user.set(mod.type,mod.vals[0]);
            break;
        }
      }
      log.debug("modifying attributes for \"%s\" now",dn.toString());
      user.save(function(err) {
        if ( err ) return next(new ldap.UnwillingToPerformError(err));
        res.end();
        return next();
      });
    });
  } else if ( ! req.changes.length ) return next(new ldap.ProtocolError("changes required"));
  else return next(new ldap.NoSuchObjectError(req.dn.toString()));
});
server.search(config.basedn, pre, function(req, res, next) {
  log.info("performing `ldapsearch` on behalf of dn: " + req.connection.ldap.bindDN);
  
  // very incomplete right now. Only supports the EqualityMatch filter type
  // and completely ignores the field list that may have been supplied by
  // the client
  var filter = req.filter.json,
      attr = filter.attribute,
      val = filter.value,
      attributes = req.json.attributes;

  var search = {};
  search[attr] = val;
  log.trace(search);

  User.find(search,function(err,users) {
    if ( err ) { log.fatal(err) ; return next(err); }
    users.forEach(function(user){
      var ldapUser = user.getLdapEntry();
      var retuser = ldapUser[0];
      attributes.map(function(v,k) {if ( ! /^\+$/.test(v) ) {retuser[v] = user.get(v);}});
      res.send({
        dn: user.DN(config.basedn),
        attributes: retuser
      });
    });
    res.end();
    return next();
  });
});

server.exop("1.3.6.1.4.1.4203.1.11.3", function( req, res, next ) {
  log.debug("who be dat?! ... performing `ldapwhoami`");
  var binddn = req.connection.ldap.bindDN.rdns.toString();
  res.value = "dn: " + binddn;
  log.trace(res.value);
  res.end();
  return next();
});

server.listen(port,function() {
  log.info('Standalone LDAP server started for ' + org + ' organization... listening at: %s', server.url);
  log.info("using directory with base dn: %s" , config.basedn);
  log.debug("using \"" + dbname + "\" mongodb backend database");
  /**
   * Here we check for the existence of a global admin account in our db
   * and make sure the account is part of the admin group unless account
   * enabled === false
   **/
  User.find({ uid: "admin" }, function( err, res) {
    if ( err ) { log.fatal(err); exit(2); }
    if ( res.length < 1 ) {
      log.info("Setting up backend \"admin\" account for the first time");
      var adminpass = User.genpass(14);
      var admin = new User({
        uid: "admin",
        password: adminpass.ssha,
        name: { first: "Big" , last: "Pappa" },
        roles: [ "admin" ],
        groups: [ "everyone" ],
        enabled: true,
        description: "Automatically generated administrator account",
        company: org
      });
      admin.save(function(err) {
        if ( err ) {
          var death = new ldap.UnwillingToPerformError(err);
          log.fatal(death);
          return death;
        } else {
          log.warn("root bindPW is set to \"" + adminpass.plain + "\"");
        }
        log.info("you can add more users with the openldap/ldapadd utility");
        log.info("i.e. ldapadd -H \"ldap://%s:%s\" -WD \"uid=admin,ou=users,%s\" -f newusers.ldif",dbhost,port,config.basedn);
        // User.setAccess(admin,["add","delete","view","edit"]);
        // Group.setAccess(admin,["add","delete","view","edit"]);
      });
    } else {
      log.debug("admin account name: " + res[0].uid);
      log.trace(res[0].objectClass('posixAccount'));
    }
  });
});
