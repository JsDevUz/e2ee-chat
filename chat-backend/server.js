require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors"); // Import CORS
const authRoutes = require("./routes/auth");
const Message = require("./models/Message");
const User = require("./models/User");
const jwt = require("jsonwebtoken");

const app = express();
const server = http.createServer(app);

// Configure CORS for Socket.io
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173", // Allow frontend origin (Vite default port)
    methods: ["GET", "POST"], // Allowed methods
    credentials: true, // Allow cookies/auth headers if needed
  },
});

// Configure CORS for Express
app.use(
  cors({
    origin: "http://localhost:5173", // Allow frontend origin
    methods: ["GET", "POST"], // Allowed methods
    credentials: true, // Allow cookies/auth headers if needed
  })
);

app.use(express.json());
app.use("/auth", authRoutes);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Forbidden" });
    req.user = user;
    next();
  });
};

// WebSocket Logic
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("join", (userId) => {
    socket.join(userId);
  });

  socket.on(
    "sendMessage",
    async ({
      senderId,
      recipientId,
      encryptedMessage,
      iv,
      encryptedKey,
      encryptedKeys,
    }) => {
      const messageData = {
        senderId,
        recipientId,
        encryptedMessage,
        iv,
        ...(recipientId ? { encryptedKey } : { encryptedKeys }), // Store appropriate field
      };
      const message = new Message(messageData);
      await message.save();

      if (recipientId) {
        console.log(senderId);

        io.to(recipientId).emit("receiveMessage", message);
      } else {
        io.emit("receiveMessage", message);
      }
    }
  );

  socket.on("disconnect", () => console.log("User disconnected:", socket.id));
});
// Fetch offline messages
app.get("/messages", authenticateToken, async (req, res) => {
  const messages = await Message.find({
    $or: [{ recipientId: req.user.id }, { recipientId: null }],
  });
  res.json(messages);
});

// Fetch all users' public keys
app.get("/users", authenticateToken, async (req, res) => {
  const users = await User.find({}, "username publicKey");
  res.json(users);
});

server.listen(process.env.PORT, () =>
  console.log(`Server running on port ${process.env.PORT}`)
);
