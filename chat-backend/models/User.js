const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Hashed
  publicKey: { type: String, required: true }, // Base64-encoded RSA public key
});

module.exports = mongoose.model("User", userSchema);
