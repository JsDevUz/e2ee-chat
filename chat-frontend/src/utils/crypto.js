import CryptoJS from "crypto-js";

// Generate RSA key pair
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

// Encrypt message with recipient's public key + AES
export const encryptMessage = async (message, recipientPublicKey) => {
  if (!recipientPublicKey || typeof recipientPublicKey !== "string") {
    throw new Error("Invalid recipient public key");
  }

  console.log("Recipient Public Key (raw):", recipientPublicKey);
  console.log("Recipient Public Key Length:", recipientPublicKey.length);

  let decodedKey;
  try {
    decodedKey = atob(recipientPublicKey);
    console.log("Decoded Key Length:", decodedKey.length);
    console.log("Decoded Key (first 10 chars):", decodedKey.slice(0, 10));
  } catch (e) {
    throw new Error("Failed to decode recipient public key: " + e.message);
  }

  try {
    const publicKey = await window.crypto.subtle.importKey(
      "spki",
      Uint8Array.from(decodedKey, (c) => c.charCodeAt(0)),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );

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

    const encryptedKeyBytes = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      aesKeyBytes
    );

    const encryptedKey = btoa(
      String.fromCharCode(...new Uint8Array(encryptedKeyBytes))
    );
    console.log("Generated encryptedKey:", encryptedKey); // Log before sending

    return {
      encryptedMessage,
      iv: iv.toString(CryptoJS.enc.Base64),
      encryptedKey,
    };
  } catch (e) {
    throw new Error(
      "Failed to import or encrypt with public key: " + e.message
    );
  }
};

// Decrypt message with private key
export const decryptMessage = async (
  encryptedMessage,
  iv,
  encryptedKey,
  privateKey
) => {
  console.log("Decrypting with encryptedKey:", encryptedKey); // Log input

  if (!encryptedKey || typeof encryptedKey !== "string") {
    throw new Error("Invalid encrypted key");
  }

  const privKey = await window.crypto.subtle.importKey(
    "pkcs8",
    Uint8Array.from(atob(privateKey), (c) => c.charCodeAt(0)),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );

  let decodedEncryptedKey;
  try {
    decodedEncryptedKey = atob(encryptedKey);
  } catch (e) {
    throw new Error("Failed to decode encryptedKey: " + e.message);
  }

  const decryptedKey = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privKey,
    Uint8Array.from(decodedEncryptedKey, (c) => c.charCodeAt(0))
  );

  const aesKey = CryptoJS.lib.WordArray.create(new Uint32Array(decryptedKey));
  const decrypted = CryptoJS.AES.decrypt(encryptedMessage, aesKey, {
    iv: CryptoJS.enc.Base64.parse(iv),
  });

  return decrypted.toString(CryptoJS.enc.Utf8);
};
