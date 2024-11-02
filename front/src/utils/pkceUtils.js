export const generateCodeVerifier = () => {
  const array = new Uint32Array(28);
  window.crypto.getRandomValues(array);
  return base64UrlEncode(array);
};

const base64UrlEncode = (arrayBuffer) => {
  let binary = "";
  const bytes = new Uint8Array(arrayBuffer);
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

export const generateCodeChallenge = async (codeVerifier) => {
  const hashedBuffer = await window.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier)
  );
  return base64UrlEncode(hashedBuffer);
};
