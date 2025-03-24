import { useState, useEffect } from "react";
import axios from "axios";
import io from "socket.io-client";
import {
  encryptMessage,
  decryptMessage,
  generateKeyPair,
} from "./utils/crypto";

const socket = io("http://localhost:8001");

function App() {
  const [user, setUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [users, setUsers] = useState([]);
  const [message, setMessage] = useState("");
  const [recipientId, setRecipientId] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token && user) {
      socket.emit("join", user.userId);
      fetchMessages();
      fetchUsers();
      socket.on("receiveMessage", handleReceiveMessage);
    }
    return () => socket.off("receiveMessage");
  }, [user]);

  const register = async (username, password) => {
    const { publicKey, privateKey } = await generateKeyPair();
    const { data } = await axios.post("http://localhost:8001/auth/register", {
      username,
      password,
      publicKey,
    });
    localStorage.setItem(`privateKey_${data.user._id}`, privateKey); // Store private key locally
    setPrivateKey(privateKey);
    setUser({ userId: data.user._id, username: data.user.username });
    localStorage.setItem("token", data.token);
  };

  const login = async (username, password) => {
    const { data } = await axios.post("http://localhost:8001/auth/login", {
      username,
      password,
    });
    setUser(data);
    localStorage.setItem("token", data.token);
    setPrivateKey(localStorage.getItem(`privateKey_${data.userId}`)); // Load private key
  };

  const fetchMessages = async () => {
    const { data } = await axios.get("http://localhost:8001/messages", {
      headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
    });
    setMessages(data);
  };

  const fetchUsers = async () => {
    const { data } = await axios.get("http://localhost:8001/users", {
      headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
    });
    setUsers(data);
  };
  const sendMessage = async () => {
    if (!users.length) {
      console.error("No users available to send message");
      return;
    }

    const recipient = recipientId
      ? users.find((u) => u._id === recipientId)
      : null;
    const publicKeyToUse = recipient ? recipient.publicKey : users[0].publicKey;

    if (!publicKeyToUse) {
      console.error("No valid public key available for encryption");
      return;
    }

    try {
      const { encryptedMessage, iv, encryptedKey } = await encryptMessage(
        message,
        publicKeyToUse
      );
      console.log("Sending encryptedKey:", encryptedKey); // Log before emit
      if (!encryptedKey) {
        throw new Error("Encrypted key is undefined before sending");
      }

      socket.emit("sendMessage", {
        senderId: user.userId,
        recipientId: recipientId || null,
        encryptedMessage,
        iv,
        encryptedKey,
      });
      setMessage("");
    } catch (error) {
      console.error("Failed to send message:", error.message);
    }
  };
  const handleReceiveMessage = async (msg) => {
    console.log("Received message:", msg, privateKey); // Log full message
    if (msg.recipientId === user.userId || !msg.recipientId) {
      try {
        const decrypted = await decryptMessage(
          msg.encryptedMessage,
          msg.iv,
          msg.encryptedKey,
          privateKey
        );
        setMessages((prev) => [...prev, { ...msg, decrypted }]);
      } catch (error) {
        console.error("Failed to decrypt message:", error, msg, privateKey);
      }
    }
  };
  const RegisterComponent = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    return (
      <div className="flex flex-col gap-4">
        <h2 className="text-xl">Register</h2>
        <input
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="border p-2"
        />
        <input
          placeholder="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="border p-2"
        />
        <button
          onClick={() => register(username, password)}
          className="bg-green-500 text-white p-2"
        >
          Register
        </button>
        <button
          onClick={() => setIsRegistering(false)}
          className="text-blue-500"
        >
          Go to Login
        </button>
      </div>
    );
  };

  const LoginComponent = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    return (
      <div className="flex flex-col gap-4">
        <h2 className="text-xl">Login</h2>
        <input
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="border p-2"
        />
        <input
          placeholder="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="border p-2"
        />
        <button
          onClick={() => login(username, password)}
          className="bg-blue-500 text-white p-2"
        >
          Login
        </button>
        <button
          onClick={() => setIsRegistering(true)}
          className="text-blue-500"
        >
          Go to Register
        </button>
      </div>
    );
  };

  return (
    <div className="max-w-2xl mx-auto p-4">
      {!user ? (
        isRegistering ? (
          <RegisterComponent />
        ) : (
          <LoginComponent />
        )
      ) : (
        <div>
          <h1 className="text-2xl">Welcome, {user.username}</h1>
          <select
            onChange={(e) => setRecipientId(e.target.value)}
            className="border p-2 my-2 w-full"
          >
            <option value="">Broadcast</option>
            {users.map((u) => (
              <option key={u._id} value={u._id}>
                {u.username}
              </option>
            ))}
          </select>
          <div className="h-64 overflow-y-auto border p-2">
            {messages.map((msg) => (
              <p key={msg._id}>
                {msg.senderId === user.userId ? "You" : "Them"}:{" "}
                {msg.decrypted || "Encrypted"}
              </p>
            ))}
          </div>
          <input
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            className="border p-2 w-full my-2"
          />
          <button onClick={sendMessage} className="bg-blue-500 text-white p-2">
            Send
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
