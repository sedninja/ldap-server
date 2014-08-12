var ssha = require('ssha');
var rand = require('generate-key');
var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    ObjectId = Schema.ObjectId,
    sprintf = require('sprintf'),
    objectMerge = require('object-merge');

// this needs a more suitable home
Array.prototype.unique = function() {
  var a = this.concat();
  for(var i=0; i<a.length; ++i) {
    for(var j=i+1; j<a.length; ++j) {
      if(a[i] === a[j])
        a.splice(j--, 1);
    }
  }
  return a;
};

// var acl = require('mongoose-acl');
/**
 * The stored schema is not actually an ldap schema, but we do have
 * the fields we need to store in order to return an ldap account
 * fully qualified under the posixAccount Schema AND/OR the inetOrgPerson
 * Schema
 **/
var userSchema = new Schema({
  uid: String,
  password: String,
  title: String,
  company: String,
  groups: Array,
  roles: Array,
  name: { first: String, last: String },
  enabled: { type: Boolean, default: false },
  created: { type: Date , default: Date.now },
  modified: { type: Date , default: Date.now },
  description: String,
  avatar: String,
  contact: {
    email: String,
    phone: String
  },
  uidNumber: Number,
  gidNumber: Number,
  homeDirectory: String,
  loginShell: { type: String, default: "/bin/false" }
});

/** 
 * This stuff makes our data look more like ldap data and makes it so that we
 * can use tools like ldapadd from the openldap project to manage user accounts
 * even with the REST API we want to maintain backwards compatibility if there
 * will ever be a use case for this server
 **/
userSchema.virtual("cn").get(function() { return this.name.first + " " + this.name.last });
userSchema.virtual("gn").get(function() { return this.name.first });
userSchema.virtual("sn").get(function() { return this.name.first });
userSchema.virtual("gecos").get(function() { return sprintf("%s <%s>", this.cn,this.contact.email)});

userSchema.virtual("gn").set(function(first) { 
  this.set('name.first', first);
});
userSchema.virtual("sn").set(function(sn) { 
  this.set('name.last', sn);
});
userSchema.virtual("cn").set(function(cn) { 
  var str = new String(cn);
  var split = str.split(" "),
    first = split[0],
    last = split[1]; 
  this.set('name.gn', first);
  this.set('name.sn', last);
});

userSchema.methods.genpass = function(length) {
  var randompass = rand.generateKey(length || 14);
  var r = {
    plain: randompass,
    ssha: ssha.create(randompass)
  };
  return r;
};
userSchema.virtual("userPassword").get(function() { return this.password });
userSchema.virtual("userPassword").set(function(password) {
  if ( !password ) {
    // paranoid. even if it means a reset later
    var r = this.genpass();
    log.warn("generated random password \"%s\" since it wasn't defined",r.plain);
    password = r.ssha;
  }
  this.set('password',password);
});
// just in case anyone chooses to use givenname
userSchema.virtual("givenName").set(function(first) { 
  this.set('name.gn', first);
});


/**
 * I am going to try and use virtual fields to serve the preferred schemas to
 * and make our data more flexible for services that may only need or be
 * interested in specific fields (i.e. posixAccount only for systems )
 **/
userSchema.virtual("posix").get(function() { 
  return [{
    uid: this.uid,
    cn: this.cn,
    userPassword: this.password,
    uidNumber: this.uidNumber,
    gidNumber: this.gidNumber,
    gecos: this.gecos,
    homeDirectory: this.homeDirectory,
    loginShell: this.loginShell
  }]; 
});
userSchema.virtual("inetOrgPerson").get(function() {
  return [{
    displayName: this.cn,
    cn: this.cn,
    gn: this.name.first,
    sn: this.name.last,
    title: this.title,
    o: this.company,
    mail: this.contact.email
  }];
});

userSchema.virtual("ldapObjectClasses").get(function(){
  return [{ objectClass: [ "top" , "posixAccount", "inetOrgPerson" ] }];
});
userSchema.methods.getLdapEntry = function() {
  return objectMerge(this.posix,this.inetOrgPerson,this.ldapObjectClasses);
};
userSchema.methods.get
// userSchema.plugin(acl.object);
// userSchema.plugin(acl.subject, {
//   additionalKeys: function() { return this.roles.map(function(role) {return "user-role:" + role;}); }
// });

module.exports = mongoose.model("User",userSchema);
