var bunyan = require('bunyan');
var ldap = require('ldapjs');
var mongoose = require('mongoose');
var sprintf = require('sprintf');
var fs = require('fs');
var ssha = require('ssha');
var rand = require('generate-key');
var acl = require('mongoose-acl');
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
var dsn = sprintf("mongodb://%s:%s/%s",dbhost,dbport,dbname);
mongoose.connect(dsn);
/** Model stuff **/
var UserSchema = mongoose.Schema({
  login: String,
  password: String,
  groups: Array,
  roles: Array,
  name: { first: String, last: String },
  enabled: Boolean
});
var GroupSchema = mongoose.Schema({
  name: String,
  members: [
    { id: "ObjectId" , roles: Array }
  ]
});

// setup the acl subjects ( requestors )
UserSchema.plugin(acl.subject, {
  additionalKeys: function() { return this.roles.map(function(role) {return "user-role:" + role;}); }
});
GroupSchema.plugin(acl.subject);

// and the objects ( resources )
UserSchema.plugin(acl.object);
GroupSchema.plugin(acl.object);

// bind our models
var User = mongoose.model("User",UserSchema);
var Group = mongoose.model("Group",GroupSchema);

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

// this is in the nature of the old rootdn rootpw combo
function __admin_bind( req, res, next ) {

  var binddn = req.dn.toString();
  var bindable = new RegExp("(?=())");
}

server.bind(config.basedn, function( req, res, next) {
  var binddn = req.dn.toString();
  // test to make sure the request comes from a bindable object
  var bindable = new RegExp("(?=(ou=(users|services)," + config.basedn + "$))");
  if ( !bindable.test(binddn) ) {
    err = new ldap.InvalidCredentialsError();
    log.info(err);
    return next(err);
  }
  var requser = req.dn.rdns[0];
  var reqcred = req.credentials;
  // now accepting cn and uid logins (to accomodate services)
  var login = requser.uid || requser.cn;
  log.info("binding as: " + binddn);
  User.find( { login: login } , function(err,users) {
    if ( err ) { log.alert(err); return next(err); }
    else {
      log.info("Checking credentials now");
      if ( ssha.verify(reqcred, users[0].password) ) {
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

server.search(config.basedn, pre, function(req, res, next) {
  log.debug("performing `ldapsearch` for dn: " + this.bindDN)
  Object.keys(req.users).forEach(function(k) {
    if ( req.filter.matches(req.users[k].attributes) ) res.send(req.users[k]);
  });
  res.end();
  return next();
});

server.exop("1.3.6.1.4.1.4203.1.11.3", function( req, res, next ) {
  log.debug("who be dat! ... performing exop `ldapwhoami`");
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
  User.find({ login: "admin" }, function( err, res) {
    if ( err ) { log.fatal(err); exit(2); }
    if ( res.length < 1 ) {
      log.info("Setting up backend \"admin\" account for the first time");
      var randompass = rand.generateKey(14);
      var sshapass = ssha.create(randompass);
      var admin = new User({
        login: "admin",
        password: sshapass,
        name: { first: "Big" , last: "Pappa" },
        roles: [ "admin" ],
        groups: [ "everyone" ],
        enabled: true
      });
      admin.save(function(err) {
        if ( err ) {
          var death = new ldap.UnwillingToPerformError(err);
          log.fatal(death);
          return death;
        } else {
          log.warn("root bindPW is set to \"" + randompass + "\"");
        }
        admin.setAccess();
      });
    } else {
      log.info("admin account name: " + res[0].login);
    }
    log.debug("something has to happen here right");
  });
});
