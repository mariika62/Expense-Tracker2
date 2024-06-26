const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const roleSchema = new Schema(
{
    name: String,
    permissions: [String]
}
);

module.exports = mongoose.model('Role', roleSchema);