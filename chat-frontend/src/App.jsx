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
      fetchAndDecryptMessages();
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
    const storedPrivateKey = localStorage.getItem(`privateKey_${data.userId}`);

    if (!storedPrivateKey) {
      console.error(
        "No private key found for this user. Cannot decrypt previous messages."
      );
      alert(
        "No private key found. You won’t be able to decrypt previous messages until you provide it."
      );
    } else {
      setPrivateKey(storedPrivateKey);
    }

    localStorage.setItem("token", data.token);
    localStorage.setItem("userId", data.userId);
    setUser({ userId: data.userId, username: data.username });
  };

  const fetchMessages = async () => {
    const { data } = await axios.get("http://localhost:8001/messages", {
      headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
    });
    console.log(data);

    // setMessages(data);
    data.map((msg) => {
      if (msg.recipientId === user.userId || !msg.recipientId) {
        handleReceiveMessage(msg);
      }
    });
  };
  const fetchAndDecryptMessages = async () => {
    try {
      const { data } = await axios.get("http://localhost:8001/messages", {
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
      });
      if (!privateKey) {
        console.warn("No private key available to decrypt messages");
        setMessages(
          data.map((msg) => ({ ...msg, decrypted: "No private key" }))
        );
        return;
      }

      const decryptedMessages = await Promise.all(
        data.map(async (msg) => {
          if (msg.recipientId === user.userId || msg.recipientId === null) {
            try {
              let encryptedKeyInput;
              if (msg.recipientId === null) {
                // Broadcast message
                if (!msg.encryptedKeys || !Array.isArray(msg.encryptedKeys)) {
                  throw new Error(
                    "No encryptedKeys array found for broadcast message"
                  );
                }
                encryptedKeyInput = msg.encryptedKeys;
              } else {
                // Private message
                if (!msg.encryptedKey) {
                  throw new Error("No encryptedKey found for private message");
                }
                encryptedKeyInput = msg.encryptedKey;
              }

              const decrypted = await decryptMessage(
                msg.encryptedMessage,
                msg.iv,
                encryptedKeyInput,
                privateKey,
                user.userId // Pass userId for broadcast decryption
              );
              return { ...msg, decrypted };
            } catch (error) {
              console.error(
                `Failed to decrypt message ${msg._id}:`,
                error.message
              );
              return { ...msg, decrypted: `Failed: ${error.message}` };
            }
          }
          return { ...msg, decrypted: "Not for you" };
        })
      );
      setMessages(decryptedMessages);
    } catch (error) {
      console.error("Failed to fetch messages:", error.message);
      setMessages([]);
    }
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
    const publicKeyToUse = recipient ? recipient.publicKey : null;

    if (!publicKeyToUse && !recipientId) {
      // Broadcast: Use all users' public keys
      const allPublicKeys = users.map((u) => ({
        userId: u._id,
        publicKey: u.publicKey,
      }));
      try {
        const { encryptedMessage, iv, encryptedKeys } = await encryptMessage(
          message,
          null,
          allPublicKeys
        );
        console.log("Sending encryptedKeys:", encryptedKeys);

        socket.emit("sendMessage", {
          senderId: user.userId,
          recipientId: null,
          encryptedMessage,
          iv,
          encryptedKeys,
        });
        setMessage("");
      } catch (error) {
        console.error("Failed to send broadcast message:", error.message);
      }
    } else {
      // Private message
      // const allPublicKeys = users.map((u) => ({
      //   userId: u._id,
      //   publicKey: u.publicKey,
      // }));
      try {
        const { encryptedMessage, iv, encryptedKey } = await encryptMessage(
          message,
          publicKeyToUse
        );
        console.log("Sending encryptedKey:", encryptedKey);

        socket.emit("sendMessage", {
          senderId: user.userId,
          recipientId: recipientId,
          encryptedMessage,
          iv,
          encryptedKey,
        });
        setMessage("");
      } catch (error) {
        console.error("Failed to send private message:", error.message);
      }
    }
  };
  const handleReceiveMessage = async (msg) => {
    console.log("Received message:", msg);
    console.log("Is broadcast?", msg.recipientId === null ? "Yes" : "No");

    if (msg.recipientId === user.userId || msg.recipientId === null) {
      console.log("rrr");

      try {
        console.log("iii");

        let encryptedKey;
        if (msg.recipientId === null) {
          // Broadcast message
          if (!msg.encryptedKeys || !Array.isArray(msg.encryptedKeys)) {
            throw new Error(
              "No encryptedKeys array found for broadcast message"
            );
          }
          encryptedKey = msg.encryptedKeys.find(
            (k) => k.userId === user.userId
          )?.encryptedKey;
          if (!encryptedKey) {
            throw new Error(
              "No encrypted key found for this user in broadcast"
            );
          }
        } else {
          // Private message
          if (!msg.encryptedKey) {
            throw new Error("No encryptedKey found for private message");
          }
          encryptedKey = msg.encryptedKey;
        }
        const decrypted = await decryptMessage(
          msg.encryptedMessage,
          msg.iv,
          encryptedKey, // Handle both formats
          privateKey,
          user.userId
        );
        setMessages((prev) => [...prev, { ...msg, decrypted }]);
      } catch (error) {
        console.error("Failed to decrypt message:", error.message);
        setMessages((prev) => [
          ...prev,
          { ...msg, decrypted: `Failed: ${error.message}` },
        ]);
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
  console.log(messages);

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
