const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  encryptedMessage: { type: String, required: true },
  iv: { type: String, required: true },
  encryptedKey: { type: String }, // For private messages
  encryptedKeys: [{ userId: String, encryptedKey: String }], // For broadcast messages
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Message", messageSchema);
