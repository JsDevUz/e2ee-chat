const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // Null for broadcast
  encryptedMessage: { type: String, required: true },
  iv: { type: String, required: true },
  encryptedKey: { type: String, required: true }, // Ensure this is present
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Message", messageSchema);
