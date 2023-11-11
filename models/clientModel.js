const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const clientSchema = new Schema({
  clientId: { type: String, unique: true, required: true },
  secret: { type: String, required: true },
});

const Client = mongoose.model('Client', clientSchema);

module.exports = Client;
