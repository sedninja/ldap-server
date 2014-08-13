var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    ObjectId = Schema.ObjectId,
    sprintf = require('sprintf'),
    ssha = require('ssha'),
    rand = require('generate-key'),
    objectMerge = require('object-merge');
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
  enabled: { type: Boolean, default: true },
  modified: Date,
  description: String,
  avatar: String,
  contact: {
    email: String,
    phone: String
  },
  uidnumber: Number,
  gidnumber: Number,
  homedirectory: String,
  loginshell: { type: String, default: "/bin/false" }
});

/** 
 * This stuff makes our data look more like ldap data and makes it so that we
 * can use tools like ldapadd from the openldap project to manage user accounts
 * even with the REST API we want to maintain backwards compatibility if there
 * will ever be a use case for this server
 **/
userSchema.virtual("cn").get(function() { return this.name.first + " " + this.name.last });
userSchema.virtual("givenname").get(function() { return this.name.first });
userSchema.virtual("gn").get(function() { return this.name.first });
userSchema.virtual("sn").get(function() { return this.name.last });
userSchema.virtual("gecos").get(function() { return sprintf("%s <%s>", this.cn,this.contact.email)});
userSchema.virtual("userpassword").get(function() { return this.password });
userSchema.virtual("userpassword").set(function(password) { this.set('password',password) });

userSchema.virtual("givenname").set(function(first) { this.set('name.first', first); });
userSchema.virtual("gn").set(function(first) { this.set('name.first', first); });
userSchema.virtual("sn").set(function(sn) { this.set('name.last', sn); });
userSchema.virtual("cn").set(function(cn) { 
  var split = cn.split(" "),
    first = split[0],
    last = split[1]; 
  this.set('name.first', first);
  this.set('name.last', last);
});
userSchema.virtual("mail").set(function(email) { this.set("contact.email", email); });

userSchema.virtual("posixaccount").get(function() { 
  return [{
    uid: this.uid,
    cn: this.cn,
    userPassword: this.password,
    uidNumber: this.uidnumber,
    gidNumber: this.gidnumber,
    gecos: this.gecos,
    homeDirectory: this.homeDirectory,
    loginShell: this.loginShell
  }]; 
});
userSchema.virtual("inetorgperson").get(function() {
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

userSchema.virtual("created").get(function() { return this._id.getTimestamp(); });

userSchema.pre('save' , function(next) {
  this.modified = new Date();
  next();
});

// I plan to change how this is being handled eventually so that you can
// specify the objectclasses you want to use
userSchema.virtual("classlist").get(function(){
  return [{ objectClass: [ "top" , "posixAccount", "inetOrgPerson" ] }];
});

userSchema.statics.genpass = function(length) {
  var randompass = rand.generateKey(length || 14);
  var r = {
    plain: randompass,
    ssha: ssha.create(randompass)
  };
  return r;
};

// create and return a virtual DN dynamically using an input basedn
userSchema.methods.DN = function(basedn) { return sprintf("uid=%s,ou=users,%s",this.uid,basedn); }

userSchema.methods.objectClass = function(oc) { return this.get(oc); };

userSchema.methods.verifypw = function( password ) {
  return ssha.verify(password,this.password);
}

// this is the default expected output of a cmdline ldapsearch query for a user
// with no attributes specified
userSchema.methods.getLdapEntry = function() {
  return objectMerge(this.posixaccount,this.inetorgperson,this.classlist);
};
// userSchema.methods.get
// userSchema.plugin(acl.object);
// userSchema.plugin(acl.subject, {
//   additionalKeys: function() { return this.roles.map(function(role) {return "user-role:" + role;}); }
// });

module.exports = mongoose.model("User",userSchema);
