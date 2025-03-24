import CryptoJS from "crypto-js";

export const generateKeyPair = async () => {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const publicKey = await window.crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  );
  const privateKey = await window.crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey
  );

  return {
    publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
    privateKey: btoa(String.fromCharCode(...new Uint8Array(privateKey))),
  };
};

export const encryptMessage = async (
  message,
  recipientPublicKey,
  allPublicKeys = null
) => {
  if (!recipientPublicKey && !allPublicKeys) {
    throw new Error("No public key(s) provided for encryption");
  }

  const aesKey = CryptoJS.lib.WordArray.random(32);
  const iv = CryptoJS.lib.WordArray.random(16);
  const encryptedMessage = CryptoJS.AES.encrypt(message, aesKey, {
    iv,
  }).toString();

  const aesKeyBytes = new Uint8Array(
    aesKey.words.reduce((bytes, word) => {
      bytes.push((word >> 24) & 0xff);
      bytes.push((word >> 16) & 0xff);
      bytes.push((word >> 8) & 0xff);
      bytes.push(word & 0xff);
      return bytes;
    }, [])
  );

  if (allPublicKeys) {
    // Broadcast: Encrypt AES key for each user's public key
    const encryptedKeys = await Promise.all(
      allPublicKeys.map(async ({ userId, publicKey: pubKeyBase64 }) => {
        const decodedKey = atob(pubKeyBase64);
        const publicKey = await window.crypto.subtle.importKey(
          "spki",
          Uint8Array.from(decodedKey, (c) => c.charCodeAt(0)),
          { name: "RSA-OAEP", hash: "SHA-256" },
          false,
          ["encrypt"]
        );
        const encryptedKeyBytes = await window.crypto.subtle.encrypt(
          { name: "RSA-OAEP" },
          publicKey,
          aesKeyBytes
        );
        return {
          userId,
          encryptedKey: btoa(
            String.fromCharCode(...new Uint8Array(encryptedKeyBytes))
          ),
        };
      })
    );
    console.log("Generated encryptedKeys for broadcast:", encryptedKeys);
    return {
      encryptedMessage,
      iv: iv.toString(CryptoJS.enc.Base64),
      encryptedKeys, // Array of { userId, encryptedKey }
    };
  } else {
    // Private message
    const decodedKey = atob(recipientPublicKey);
    const publicKey = await window.crypto.subtle.importKey(
      "spki",
      Uint8Array.from(decodedKey, (c) => c.charCodeAt(0)),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );
    const encryptedKeyBytes = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      aesKeyBytes
    );
    const encryptedKey = btoa(
      String.fromCharCode(...new Uint8Array(encryptedKeyBytes))
    );
    console.log("Generated encryptedKey:", encryptedKey);
    return {
      encryptedMessage,
      iv: iv.toString(CryptoJS.enc.Base64),
      encryptedKey, // Single string
    };
  }
};

export const decryptMessage = async (
  encryptedMessage,
  iv,
  encryptedKeyInput,
  privateKey,
  userId
) => {
  console.log("Decrypting with encryptedKeyInput:", encryptedKeyInput);
  console.log(
    "Private key (first 50 chars):",
    privateKey ? privateKey.slice(0, 50) : "undefined"
  );

  if (!privateKey || typeof privateKey !== "string") {
    throw new Error("Invalid private key");
  }

  // Determine the encryptedKey based on input type
  let encryptedKey;
  if (Array.isArray(encryptedKeyInput)) {
    // Broadcast message: find the encryptedKey for this user
    if (!userId) {
      throw new Error("userId required for broadcast message decryption");
    }
    const keyObj = encryptedKeyInput.find((k) => k.userId === userId);
    if (!keyObj || !keyObj.encryptedKey) {
      throw new Error("No encrypted key found for this user in broadcast");
    }
    encryptedKey = keyObj.encryptedKey;
  } else if (typeof encryptedKeyInput === "string") {
    // Private message: use the single encryptedKey
    encryptedKey = encryptedKeyInput;
  } else {
    throw new Error("Invalid encrypted key format");
  }

  if (!encryptedKey || typeof encryptedKey !== "string") {
    throw new Error("Invalid encrypted key");
  }

  let decodedPrivateKey;
  try {
    decodedPrivateKey = atob(privateKey);
    console.log("Decoded private key length:", decodedPrivateKey.length);
  } catch (e) {
    throw new Error("Failed to decode private key: " + e.message);
  }

  let privKey;
  try {
    privKey = await window.crypto.subtle.importKey(
      "pkcs8",
      Uint8Array.from(decodedPrivateKey, (c) => c.charCodeAt(0)),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  } catch (e) {
    throw new Error("Failed to import private key: " + e.message);
  }

  let decodedEncryptedKey;
  try {
    decodedEncryptedKey = atob(encryptedKey);
    console.log("Decoded encryptedKey length:", decodedEncryptedKey.length);
  } catch (e) {
    throw new Error("Failed to decode encryptedKey: " + e.message);
  }

  let decryptedKey;
  try {
    decryptedKey = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privKey,
      Uint8Array.from(decodedEncryptedKey, (c) => c.charCodeAt(0))
    );
    console.log("Decrypted AES key length:", decryptedKey.byteLength);
  } catch (e) {
    throw new Error("Decryption operation failed: " + e.message);
  }

  const aesKey = CryptoJS.lib.WordArray.create(new Uint32Array(decryptedKey));
  const decrypted = CryptoJS.AES.decrypt(encryptedMessage, aesKey, {
    iv: CryptoJS.enc.Base64.parse(iv),
  });

  const result = decrypted.toString(CryptoJS.enc.Utf8);
  if (!result) {
    throw new Error("AES decryption resulted in empty string");
  }
  return result;
};
