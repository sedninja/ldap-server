var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    ObjectId = Schema.ObjectId,
    acl = require('mongoose-acl');

var groupSchema = new Schema({
  name: String,
  members: [
    { id: ObjectId , roles: Array }
  ]
});

groupSchema.plugin(acl.subject);
groupSchema.plugin(acl.object);

module.exports = mongoose.model("Group",groupSchema);
