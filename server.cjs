var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// server.ts
var import_express = __toESM(require("express"), 1);
var import_path = __toESM(require("path"), 1);
var import_dotenv = __toESM(require("dotenv"), 1);
var import_crypto = __toESM(require("crypto"), 1);
var import_http = __toESM(require("http"), 1);
var import_cors = __toESM(require("cors"), 1);
var import_fs = __toESM(require("fs"), 1);
import_dotenv.default.config();
var serverFolderIdCache = {};
var serverPendingFolderPromises = {};
function cleanFolderId(rawId) {
  if (!rawId) return "1Zy5pLVCQ18JIQGLNeRl35Sx2a0ntbKJx";
  let id = rawId.trim();
  if (id.includes("drive.google.com") || id.includes("/folders/")) {
    const match = id.match(/\/folders\/([a-zA-Z0-9_-]+)/);
    if (match && match[1]) {
      id = match[1];
    }
  }
  const queryIndex = id.indexOf("?");
  if (queryIndex !== -1) {
    id = id.substring(0, queryIndex);
  }
  id = id.replace(/[./\s]+$/, "").replace(/^[./\s]+/, "");
  if (!id || id === "." || id.length < 5) {
    return "1Zy5pLVCQ18JIQGLNeRl35Sx2a0ntbKJx";
  }
  return id;
}
var WORKSPACE_ROOT_FOLDER_ID = cleanFolderId(process.env.VITE_GOOGLE_DRIVE_FOLDER_ID || "1Zy5pLVCQ18JIQGLNeRl35Sx2a0ntbKJx");
function cleanPrivateKey(key) {
  if (!key) return "";
  let cleaned = key.trim();
  cleaned = cleaned.replace(/^["']|["']$/g, "");
  if (cleaned.startsWith("{") || cleaned.startsWith('"')) {
    try {
      let rawJson = cleaned;
      if (rawJson.startsWith('"') && rawJson.endsWith('"')) {
        rawJson = JSON.parse(rawJson);
      }
      const parsed = JSON.parse(rawJson);
      if (parsed && typeof parsed === "object") {
        if (parsed.private_key) {
          cleaned = parsed.private_key;
        } else if (parsed.VITE_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY) {
          cleaned = parsed.VITE_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY;
        }
      }
    } catch (err) {
    }
  }
  if (!cleaned.includes("-----BEGIN") && /^[a-zA-Z0-9+/=\s]+$/.test(cleaned) && cleaned.length > 100) {
    try {
      const decoded = Buffer.from(cleaned.replace(/\s/g, ""), "base64").toString("utf8");
      if (decoded.includes("-----BEGIN")) {
        cleaned = decoded;
      } else {
      }
    } catch (err) {
    }
  }
  cleaned = cleaned.replace(/\\n/g, "\n");
  cleaned = cleaned.replace(/\\r/g, "\r");
  const startMatch = cleaned.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  const endMatch = cleaned.match(/-----END [A-Z ]*PRIVATE KEY-----/);
  if (startMatch && endMatch) {
    const startHeader = startMatch[0];
    const endHeader = endMatch[0];
    let body = cleaned.replace(startHeader, "").replace(endHeader, "").replace(/\s+/g, "");
    const lines = [];
    lines.push(startHeader);
    for (let i = 0; i < body.length; i += 64) {
      lines.push(body.substring(i, i + 64));
    }
    lines.push(endHeader);
    cleaned = lines.join("\n");
  } else if (!cleaned.includes("-----BEGIN") && /^[a-zA-Z0-9+/=\s]+$/.test(cleaned) && cleaned.length > 50) {
    let body = cleaned.replace(/\s+/g, "");
    const lines = [];
    lines.push("-----BEGIN PRIVATE KEY-----");
    for (let i = 0; i < body.length; i += 64) {
      lines.push(body.substring(i, i + 64));
    }
    lines.push("-----END PRIVATE KEY-----");
    cleaned = lines.join("\n");
  }
  return cleaned.trim();
}
function signJwtRS256(payload, privateKeyPem, clientEmail) {
  const header = { alg: "RS256", typ: "JWT" };
  const base64UrlEncode = (str) => {
    const buf = Buffer.isBuffer(str) ? str : Buffer.from(str);
    return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const sign = import_crypto.default.createSign("SHA256");
  sign.update(signingInput);
  const formattedKey = cleanPrivateKey(privateKeyPem);
  try {
    const signature = sign.sign(formattedKey);
    return `${signingInput}.${base64UrlEncode(signature)}`;
  } catch (err) {
    if (process.env.NODE_ENV !== "production") {
      console.error("--- PRIVATE KEY SIGNING DIAGNOSTICS ---");
      console.error("Error message:", err.message);
      console.error("Raw key input length:", privateKeyPem ? privateKeyPem.length : 0);
      console.error("Raw key input starts with:", privateKeyPem ? privateKeyPem.substring(0, 40) : "N/A");
      console.error("Raw key input ends with:", privateKeyPem ? privateKeyPem.substring(Math.max(0, privateKeyPem.length - 40)) : "N/A");
      console.error("Formatted key length:", formattedKey ? formattedKey.length : 0);
      console.error("Formatted key starts with:", formattedKey ? formattedKey.substring(0, 45) : "N/A");
      console.error("Formatted key ends with:", formattedKey ? formattedKey.substring(Math.max(0, formattedKey.length - 45)) : "N/A");
      console.error("Does formatted key contain newlines:", formattedKey ? formattedKey.includes("\n") : false);
      console.error("--------------------------------------");
    } else {
      console.error("Erro ao assinar JWT com a chave privada fornecida em produ\xE7\xE3o.");
    }
    throw new Error(`Falha ao assinar JWT com a chave privada fornecida.`);
  }
}
async function getServiceAccountAccessToken() {
  const privateKey = process.env.VITE_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY || "";
  const email = process.env.VITE_GOOGLE_SERVICE_ACCOUNT_EMAIL || "";
  if (!privateKey || !email) {
    throw new Error("As credenciais da Conta de Servi\xE7o Google Drive n\xE3o est\xE3o configuradas nas vari\xE1veis do sistema.");
  }
  const now = Math.floor(Date.now() / 1e3);
  const payload = {
    iss: email,
    scope: "https://www.googleapis.com/auth/drive",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now
  };
  const jwt = signJwtRS256(payload, privateKey, email);
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt
    })
  });
  if (!res.ok) {
    throw new Error(`Google Authentication failed: ${await res.text()}`);
  }
  const data = await res.json();
  return data.access_token;
}
async function findFolder(token, name, parentId) {
  try {
    let query = `mimeType = 'application/vnd.google-apps.folder' and trashed = false`;
    if (parentId) {
      query += ` and '${parentId}' in parents`;
    } else {
      query += ` and 'root' in parents`;
    }
    const url = `https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(query)}&fields=files(id,name)&pageSize=1000&supportsAllDrives=true&includeItemsFromAllDrives=true`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) {
      console.error("Error finding folder on Drive:", await res.text());
      return null;
    }
    const data = await res.json();
    if (data.files && data.files.length > 0) {
      const targetNormalized = name.normalize("NFC").trim().toUpperCase();
      for (const file of data.files) {
        const fileNormalized = file.name.normalize("NFC").trim().toUpperCase();
        if (fileNormalized === targetNormalized) {
          return file.id;
        }
      }
    }
    return null;
  } catch (err) {
    console.error("findFolder exception:", err);
    return null;
  }
}
async function createFolder(token, name, parentId) {
  try {
    const body = {
      name: name.normalize("NFC"),
      mimeType: "application/vnd.google-apps.folder",
      parents: parentId ? [parentId] : void 0
    };
    const res = await fetch("https://www.googleapis.com/drive/v3/files?supportsAllDrives=true", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      throw new Error(`Erro ao criar pasta no Drive: ${await res.text()}`);
    }
    const data = await res.json();
    return data.id;
  } catch (err) {
    console.error("createFolder exception:", err);
    throw err;
  }
}
async function getOrCreateFolder(token, name, parentId) {
  const parentKey = parentId || "root";
  const cleanName = name.normalize("NFC").trim().toUpperCase();
  const cacheKey = `${parentKey}_${cleanName}`;
  if (serverFolderIdCache[cacheKey]) {
    return serverFolderIdCache[cacheKey];
  }
  if (!serverPendingFolderPromises[cacheKey]) {
    serverPendingFolderPromises[cacheKey] = (async () => {
      const existingId = await findFolder(token, name, parentId);
      if (existingId) {
        serverFolderIdCache[cacheKey] = existingId;
        return existingId;
      }
      const createdId = await createFolder(token, name, parentId);
      serverFolderIdCache[cacheKey] = createdId;
      return createdId;
    })();
  }
  try {
    return await serverPendingFolderPromises[cacheKey];
  } finally {
    delete serverPendingFolderPromises[cacheKey];
  }
}
async function uploadFile(token, fileBuffer, name, fileType, parentFolderId) {
  try {
    const boundary = "custom_boundary_drive_upload";
    const delimiter = `\r
--${boundary}\r
`;
    const metadata = {
      name,
      parents: [parentFolderId]
    };
    const metadataPart = `${delimiter}Content-Type: application/json; charset=UTF-8\r
\r
${JSON.stringify(metadata)}\r
`;
    const mediaPartHeader = `${delimiter}Content-Type: ${fileType || "application/octet-stream"}\r
\r
`;
    const mediaPartFooter = `\r
--${boundary}--`;
    const encoder = new TextEncoder();
    const part1 = encoder.encode(metadataPart);
    const part2 = encoder.encode(mediaPartHeader);
    const part3 = encoder.encode(mediaPartFooter);
    const finalBuffer = Buffer.concat([
      part1,
      part2,
      fileBuffer,
      part3
    ]);
    const url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink&supportsAllDrives=true";
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": `multipart/related; boundary=${boundary}`
      },
      body: finalBuffer
    });
    if (!res.ok) {
      throw new Error(`Google Drive upload failed: ${await res.text()}`);
    }
    return await res.json();
  } catch (err) {
    console.error("uploadFile to Drive exception:", err);
    throw err;
  }
}
async function resolveTargetFolder(token, context, fileName) {
  const rootId = WORKSPACE_ROOT_FOLDER_ID;
  const sgestaoId = await getOrCreateFolder(token, "Sistema de Gest\xE3o de Pessoas", rootId);
  if (context.module === "cabinet_composition") {
    const comissionadosId = await getOrCreateFolder(token, "Comissionados", sgestaoId);
    const composicaoId = await getOrCreateFolder(token, "Composi\xE7\xE3o do Gabinete", comissionadosId);
    const yearMonth = (context.yearMonth || (/* @__PURE__ */ new Date()).toISOString().substring(0, 7).replace("-", "_")).trim();
    const yearMonthId = await getOrCreateFolder(token, yearMonth, composicaoId);
    let vereadorName = (context.userName || "Vereador").trim();
    vereadorName = vereadorName.replace(/^(VER\.|VER|VEREADOR\.|VEREADOR)\s+/i, "");
    vereadorName = `Ver. ${vereadorName}`;
    return await getOrCreateFolder(token, vereadorName, yearMonthId);
  }
  const isComissionado = context.module === "frequency_comissionados" || context.module === "hiring_comissionados" || context.category === "comissionado";
  console.log(`[resolveTargetFolder] Uploading "${fileName || "unnamed"}" | module: "${context.module}" | category: "${context.category}" | isComissionado: ${isComissionado}`);
  if (context.module === "frequency" || context.module === "frequency_comissionados") {
    if (isComissionado) {
      const comissionadosId = await getOrCreateFolder(token, "Comissionados", sgestaoId);
      const freqId = await getOrCreateFolder(token, "Frequ\xEAncias", comissionadosId);
      const monthYear = (context.monthYear || (/* @__PURE__ */ new Date()).toISOString().substring(0, 7)).trim();
      const monthYearId = await getOrCreateFolder(token, monthYear, freqId);
      const lotacaoUpper = (context.lotacao || "").trim().toUpperCase();
      if (lotacaoUpper === "GABINETE DA PRESID\xCANCIA") {
        return await getOrCreateFolder(token, "GABINETE DA PRESID\xCANCIA", monthYearId);
      }
      let gestorName = (context.userName || context.lotacao || "N\xE3o Categorizado").trim().toUpperCase();
      gestorName = gestorName.replace(/^(VER\.|VER|VEREADOR\.|VEREADOR)\s+/, "");
      gestorName = `VER. ${gestorName}`;
      return await getOrCreateFolder(token, gestorName, monthYearId);
    } else {
      const estagiariosId = await getOrCreateFolder(token, "Estagi\xE1rios", sgestaoId);
      const freqId = await getOrCreateFolder(token, "Frequ\xEAncias", estagiariosId);
      const monthYear = (context.monthYear || (/* @__PURE__ */ new Date()).toISOString().substring(0, 7)).trim();
      const monthYearId = await getOrCreateFolder(token, monthYear, freqId);
      const lotacao = (context.lotacao || "N\xE3o Categorizado").trim();
      return await getOrCreateFolder(token, lotacao, monthYearId);
    }
  } else {
    if (isComissionado) {
      const comissionadosId = await getOrCreateFolder(token, "Comissionados", sgestaoId);
      const hiringId = await getOrCreateFolder(token, "Contrata\xE7\xF5es", comissionadosId);
      let vereadorName = (context.userName || context.lotacao || "N\xE3o Categorizado").trim();
      const vereadorNameUpper = vereadorName.toUpperCase();
      if (vereadorNameUpper === "GABINETE DA PRESID\xCANCIA" || vereadorNameUpper === "PRESID\xCANCIA") {
        vereadorName = "Gabinete da Presid\xEAncia";
      } else {
        vereadorName = vereadorName.replace(/^(VER\.|VER|VEREADOR\.|VEREADOR)\s+/i, "");
        vereadorName = `Ver. ${vereadorName}`;
      }
      const vereadorId = await getOrCreateFolder(token, vereadorName, hiringId);
      let servidorName = "N\xE3o Categorizado";
      if (context.requestNameAndId) {
        const parts = context.requestNameAndId.split("_");
        if (parts.length > 1) {
          parts.pop();
          servidorName = parts.join(" ");
        } else {
          servidorName = context.requestNameAndId;
        }
      }
      return await getOrCreateFolder(token, servidorName, vereadorId);
    } else {
      const estagiariosId = await getOrCreateFolder(token, "Estagi\xE1rios", sgestaoId);
      const hiringId = await getOrCreateFolder(token, "Contrata\xE7\xF5es", estagiariosId);
      const lotacao = context.lotacao || "N\xE3o Categorizado";
      const lotacaoId = await getOrCreateFolder(token, lotacao, hiringId);
      let folderName = "N\xE3o Categorizado";
      if (context.requestType === "opening") {
        folderName = "Abertura de Vagas";
      } else {
        if (context.requestNameAndId) {
          const parts = context.requestNameAndId.split("_");
          if (parts.length > 1) {
            parts.pop();
            folderName = parts.join(" ");
          } else {
            folderName = context.requestNameAndId;
          }
        }
      }
      return await getOrCreateFolder(token, folderName, lotacaoId);
    }
  }
}
function extractDriveFileId(url) {
  if (!url) return null;
  const match = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
  if (match && match[1]) return match[1];
  const idMatch = url.match(/[?&]id=([a-zA-Z0-9_-]+)/);
  if (idMatch && idMatch[1]) return idMatch[1];
  try {
    const cleanUrl = url.split("?")[0].split("#")[0];
    const segments = cleanUrl.split("/");
    for (const seg of segments) {
      if (seg.length >= 25 && seg.length <= 50 && /^[a-zA-Z0-9_-]+$/.test(seg)) {
        if (seg.toLowerCase() !== "drive" && seg.toLowerCase() !== "docs" && seg.toLowerCase() !== "google") {
          return seg;
        }
      }
    }
  } catch (e) {
  }
  return null;
}
async function updateFileContent(fileIdOrUrl, fileBuffer, fileType) {
  try {
    const fileId = fileIdOrUrl.includes("/") ? extractDriveFileId(fileIdOrUrl) : fileIdOrUrl;
    if (!fileId) {
      console.warn("Could not extract file ID for update:", fileIdOrUrl);
      return false;
    }
    const token = await getServiceAccountAccessToken();
    try {
      const untrashUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?supportsAllDrives=true`;
      await fetch(untrashUrl, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ trashed: false })
      });
    } catch (untrashErr) {
      console.warn("Attempt to untrash file before content update failed, proceeding anyway:", untrashErr);
    }
    const url = `https://www.googleapis.com/upload/drive/v3/files/${fileId}?uploadType=media&supportsAllDrives=true`;
    const res = await fetch(url, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": fileType || "application/pdf"
      },
      body: fileBuffer
    });
    if (!res.ok) {
      console.error("Google Drive patch content failed:", await res.text());
      return false;
    }
    return true;
  } catch (err) {
    console.error("updateFileContent exception:", err);
    return false;
  }
}
async function deleteFile(fileIdOrUrl) {
  try {
    const fileId = fileIdOrUrl.includes("/") ? extractDriveFileId(fileIdOrUrl) : fileIdOrUrl;
    if (!fileId) {
      console.warn("Could not extract file ID for deletion:", fileIdOrUrl);
      return false;
    }
    const token = await getServiceAccountAccessToken();
    try {
      const patchUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?supportsAllDrives=true`;
      const patchRes = await fetch(patchUrl, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ trashed: true })
      });
      if (patchRes.ok) {
        console.log(`Documento do Google Drive (ID: ${fileId}) movido para a lixeira com sucesso.`);
        return true;
      }
      const errText = await patchRes.text();
      if (patchRes.status === 404) {
        console.warn(`Google Drive move to trash: File not found or already deleted (404) for ID ${fileId}. Consolidating deletion as completed.`);
        return true;
      }
      console.warn(`Tentativa de mover para a lixeira falhou, partindo para exclus\xE3o permanente... Erro:`, errText);
    } catch (trashErr) {
      console.warn(`Erro ao mover para a lixeira, partindo para exclus\xE3o permanente:`, trashErr);
    }
    const url = `https://www.googleapis.com/drive/v3/files/${fileId}?supportsAllDrives=true`;
    const res = await fetch(url, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    if (!res.ok) {
      const errText = await res.text();
      if (res.status === 404) {
        console.warn(`Google Drive delete file: File not found or already deleted (404) for ID ${fileId}. Consolidating deletion as completed.`);
        return true;
      }
      console.error("Google Drive permanent delete file failed:", errText);
      return false;
    }
    return true;
  } catch (err) {
    console.error("deleteFile exception:", err);
    return false;
  }
}
async function getUniqueFileName(token, folderId, baseName) {
  const extIndex = baseName.lastIndexOf(".");
  const name = extIndex !== -1 ? baseName.substring(0, extIndex) : baseName;
  const ext = extIndex !== -1 ? baseName.substring(extIndex) : "";
  let uniqueName = baseName;
  let counter = 1;
  try {
    const query = `'${folderId}' in parents and trashed = false`;
    const url = `https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(query)}&fields=files(name)&pageSize=1000&supportsAllDrives=true&includeItemsFromAllDrives=true`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) {
      return baseName;
    }
    const data = await res.json();
    const existingNames = new Set((data.files || []).map((f) => f.name.toLowerCase()));
    while (existingNames.has(uniqueName.toLowerCase())) {
      uniqueName = `${name}_${counter}${ext}`;
      counter++;
    }
    return uniqueName;
  } catch (err) {
    console.error("Error finding unique file name on Drive:", err);
    return baseName;
  }
}
var rateLimitWindowMs = 15 * 60 * 1e3;
var maxRequestsPerWindow = 100;
var ipRequestCounts = {};
function rateLimiter(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  if (!ipRequestCounts[ip] || ipRequestCounts[ip].resetTime < now) {
    ipRequestCounts[ip] = {
      count: 1,
      resetTime: now + rateLimitWindowMs
    };
    return next();
  }
  ipRequestCounts[ip].count += 1;
  if (ipRequestCounts[ip].count > maxRequestsPerWindow) {
    return res.status(429).json({
      error: "Muitas requisi\xE7\xF5es origin\xE1rias deste IP. Por favor, tente novamente mais tarde."
    });
  }
  next();
}
var googlePublicKeys = {};
var nextKeysFetchTime = 0;
async function fetchGooglePublicKeys() {
  const now = Date.now();
  if (now < nextKeysFetchTime && Object.keys(googlePublicKeys).length > 0) {
    return googlePublicKeys;
  }
  try {
    const res = await fetch("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com");
    if (res.ok) {
      googlePublicKeys = await res.json();
      nextKeysFetchTime = now + 3600 * 1e3;
    }
  } catch (err) {
    console.error("Error fetching Google public keys:", err);
  }
  return googlePublicKeys;
}
async function verifyFirebaseToken(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, "base64").toString("utf8"));
    const payload = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8"));
    const now = Math.floor(Date.now() / 1e3);
    if (payload.exp < now) {
      console.warn("Token expired");
      return null;
    }
    const email = payload.email;
    if (!email || !email.endsWith("@cmc.pr.gov.br")) {
      console.warn("Invalid email domain:", email);
      return null;
    }
    const keys = await fetchGooglePublicKeys();
    const cert = keys[header.kid];
    if (!cert) {
      console.warn("Public key certificate not found for kid:", header.kid);
      return null;
    }
    const verify = import_crypto.default.createVerify("RSA-SHA256");
    verify.update(`${headerB64}.${payloadB64}`);
    const base64Signature = signatureB64.replace(/-/g, "+").replace(/_/g, "/");
    const signatureBuf = Buffer.from(base64Signature, "base64");
    const isValid = verify.verify(cert, signatureBuf);
    if (!isValid) {
      console.warn("JWT signature verification failed");
      return null;
    }
    return { email };
  } catch (err) {
    console.error("Error verifying token:", err);
    return null;
  }
}
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send("Acesso n\xE3o autorizado. Token ausente.");
  }
  const token = authHeader.substring(7);
  if (process.env.NODE_ENV !== "production" && token === "local-test-token") {
    req.user = { email: "diego.martins@cmc.pr.gov.br" };
    return next();
  }
  const user = await verifyFirebaseToken(token);
  if (!user) {
    return res.status(401).send("Acesso n\xE3o autorizado. Token inv\xE1lido.");
  }
  req.user = user;
  next();
}
async function startServer() {
  const app = (0, import_express.default)();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3e3;
  const httpServer = import_http.default.createServer(app);
  app.use(import_express.default.json({ limit: "10mb" }));
  app.use((req, res, next) => {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://lh3.googleusercontent.com https://*.googleapis.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com;"
    );
    next();
  });
  app.use("/api/", rateLimiter);
  const allowedOrigins = [
    "https://gestao-pessoas.onrender.com",
    "https://dgep-cmc.github.io",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173"
  ];
  app.use((0, import_cors.default)({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) !== -1) {
        return callback(null, true);
      }
      return callback(new Error("CORS origin not allowed by security policy"), false);
    }
  }));
  app.get("/api/ping", (req, res) => {
    res.json({
      status: "ok",
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      timezone: "America/Sao_Paulo",
      localTime: (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", { timeZone: "America/Sao_Paulo" })
    });
  });
  app.post("/api/drive/upload", authMiddleware, async (req, res) => {
    try {
      const { fileBase64, fileName, fileType, context } = req.body;
      if (!fileBase64 || !fileName || !context) {
        return res.status(400).send("Faltam par\xE2metros obrigat\xF3rios para o upload (fileBase64, fileName ou context).");
      }
      const allowedExtensions = [".pdf", ".png", ".jpg", ".jpeg"];
      const allowedMimeTypes = ["application/pdf", "image/png", "image/jpeg"];
      const fileExt = import_path.default.extname(fileName).toLowerCase();
      if (!allowedExtensions.includes(fileExt) || !allowedMimeTypes.includes(fileType)) {
        return res.status(400).send("Tipo de arquivo n\xE3o permitido. Apenas PDFs e imagens (PNG, JPG, JPEG) s\xE3o aceitos.");
      }
      const fileBuffer = Buffer.from(fileBase64, "base64");
      const token = await getServiceAccountAccessToken();
      const folderId = await resolveTargetFolder(token, context, fileName);
      let resolvedFileName = fileName;
      if (context.requestType === "opening") {
        resolvedFileName = await getUniqueFileName(token, folderId, fileName);
      }
      const result = await uploadFile(token, fileBuffer, resolvedFileName, fileType, folderId);
      return res.json(result);
    } catch (error) {
      console.error("API /api/drive/upload error:", error);
      return res.status(500).send(error.message || "Erro interno ao realizar upload para o Google Drive.");
    }
  });
  app.get("/api/drive/download", authMiddleware, async (req, res) => {
    try {
      const fileId = req.query.fileId;
      if (!fileId) {
        return res.status(400).send("Falta o par\xE2metro fileId.");
      }
      const token = await getServiceAccountAccessToken();
      const url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`;
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      if (!response.ok) {
        const text = await response.text();
        return res.status(response.status).send(`Erro ao baixar arquivo do Drive: ${text}`);
      }
      const contentType = response.headers.get("content-type") || "application/octet-stream";
      res.setHeader("Content-Type", contentType);
      const arrayBuffer = await response.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);
      return res.send(buffer);
    } catch (error) {
      console.error("API /api/drive/download error:", error);
      return res.status(500).send(error.message || "Erro interno ao baixar arquivo do Google Drive.");
    }
  });
  app.get("/api/drive/diagnostics", authMiddleware, (req, res, next) => {
    const isLocal = req.hostname === "localhost" || req.hostname === "127.0.0.1";
    if (process.env.NODE_ENV === "production" && !isLocal) {
      return res.status(403).send("Acesso restrito ao ambiente de desenvolvimento.");
    }
    next();
  }, async (req, res) => {
    try {
      const privateKey = process.env.VITE_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY || "";
      const email = process.env.VITE_GOOGLE_SERVICE_ACCOUNT_EMAIL || "";
      const rootId = WORKSPACE_ROOT_FOLDER_ID;
      const results = {
        credentials: {
          privateKeyPresent: !!privateKey,
          privateKeyLength: privateKey.length,
          serviceAccountEmail: email,
          rootFolderId: rootId
        },
        steps: {}
      };
      if (!privateKey || !email) {
        results.steps.auth = {
          success: false,
          error: "Credenciais de conta de servi\xE7o Google Drive ausentes (VITE_GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY ou EMAIL no arquivo .env)"
        };
        return res.json(results);
      }
      let token = "";
      try {
        token = await getServiceAccountAccessToken();
        results.steps.auth = {
          success: true,
          message: "Autentica\xE7\xE3o realizada com sucesso. Token JWT assinado."
        };
      } catch (authErr) {
        results.steps.auth = {
          success: false,
          error: `Falha na assinatura do JWT ou autentica\xE7\xE3o do token: ${authErr.message}`
        };
        return res.json(results);
      }
      try {
        const metaRes = await fetch(`https://www.googleapis.com/drive/v3/files/${rootId}?fields=id,name,mimeType,capabilities&supportsAllDrives=true`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!metaRes.ok) {
          const errText = await metaRes.text();
          results.steps.rootFolder = {
            success: false,
            error: `Erro ao obter metadados da pasta raiz (ID: ${rootId}) no Google Drive: ${errText}`
          };
          return res.json(results);
        }
        const meta = await metaRes.json();
        results.steps.rootFolder = {
          success: true,
          folderName: meta.name,
          mimeType: meta.mimeType,
          capabilities: meta.capabilities
        };
      } catch (folderErr) {
        results.steps.rootFolder = {
          success: false,
          error: `Falha de rede ou API ao recuperar dados da pasta raiz: ${folderErr.message}`
        };
        return res.json(results);
      }
      try {
        const testName = `TEST_DIAGNOSTICS_${Date.now()}`;
        const createRes = await fetch("https://www.googleapis.com/drive/v3/files?supportsAllDrives=true", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            name: testName,
            mimeType: "application/vnd.google-apps.folder",
            parents: [rootId]
          })
        });
        if (!createRes.ok) {
          const errText = await createRes.text();
          results.steps.writeTest = {
            success: false,
            error: `Erro ao criar nova subpasta teste via API: ${errText}`
          };
        } else {
          const created = await createRes.json();
          results.steps.writeTest = {
            success: true,
            message: `Subpasta de teste criada com sucesso (ID: ${created.id}). Permiss\xF5es de escrita corretas.`
          };
          try {
            await fetch(`https://www.googleapis.com/drive/v3/files/${created.id}?supportsAllDrives=true`, {
              method: "PATCH",
              headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify({ trashed: true })
            });
            await fetch(`https://www.googleapis.com/drive/v3/files/${created.id}?supportsAllDrives=true`, {
              method: "DELETE",
              headers: { Authorization: `Bearer ${token}` }
            });
          } catch (delErr) {
            console.warn("Silent cleanup failed for diagnostics folder ID:", created.id, delErr);
          }
        }
      } catch (writeErr) {
        results.steps.writeTest = {
          success: false,
          error: `Erro durante teste de permiss\xE3o de escrita: ${writeErr.message}`
        };
      }
      return res.json(results);
    } catch (error) {
      console.error("API /api/drive/diagnostics error:", error);
      return res.status(500).send(error.message || "Erro interno ao rodar diagn\xF3sticos.");
    }
  });
  app.post("/api/drive/update", authMiddleware, async (req, res) => {
    try {
      const { fileIdOrUrl, fileBase64, fileType } = req.body;
      if (!fileIdOrUrl || !fileBase64) {
        return res.status(400).send("Faltam par\xE2metros obrigat\xF3rios para a atualiza\xE7\xE3o.");
      }
      const allowedMimeTypes = ["application/pdf", "image/png", "image/jpeg"];
      if (fileType && !allowedMimeTypes.includes(fileType)) {
        return res.status(400).send("Tipo de arquivo n\xE3o permitido.");
      }
      const fileBuffer = Buffer.from(fileBase64, "base64");
      const success = await updateFileContent(fileIdOrUrl, fileBuffer, fileType);
      return res.json({ success });
    } catch (error) {
      console.error("API /api/drive/update error:", error);
      return res.status(500).send(error.message || "Erro interno ao atualizar arquivo no Google Drive.");
    }
  });
  app.post("/api/drive/delete", authMiddleware, async (req, res) => {
    try {
      const { fileIdOrUrl } = req.body;
      if (!fileIdOrUrl) {
        return res.status(400).send("Falta o par\xE2metro fileIdOrUrl.");
      }
      const success = await deleteFile(fileIdOrUrl);
      return res.json({ success });
    } catch (error) {
      console.error("API /api/drive/delete error:", error);
      return res.status(500).send(error.message || "Erro interno ao excluir arquivo no Google Drive.");
    }
  });
  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: { server: httpServer }
      },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = import_fs.default.existsSync(import_path.default.join(process.cwd(), "dist")) ? import_path.default.join(process.cwd(), "dist") : process.cwd();
    app.use(import_express.default.static(distPath));
    app.get("*all", (req, res) => {
      res.sendFile(import_path.default.join(distPath, "index.html"));
    });
  }
  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
  const startSelfPing = () => {
    const RENDER_URL = process.env.RENDER_EXTERNAL_URL || "https://gestao-pessoas.onrender.com";
    if (!RENDER_URL) {
      console.log("[Self-Ping] RENDER_EXTERNAL_URL or fallback is empty. Skipping self-ping setup.");
      return;
    }
    console.log(`[Self-Ping] Inicializado dinamicamente. Alvo: ${RENDER_URL}/api/ping`);
    const triggerNextPing = () => {
      let hour = 12;
      let minute = 0;
      try {
        const options = {
          timeZone: "America/Sao_Paulo",
          hour12: false,
          hour: "2-digit",
          minute: "2-digit"
        };
        const formatter = new Intl.DateTimeFormat("en-US", options);
        const parts = formatter.format(/* @__PURE__ */ new Date()).split(":");
        hour = parseInt(parts[0], 10);
        minute = parseInt(parts[1], 10);
      } catch (e) {
        const d = /* @__PURE__ */ new Date();
        hour = d.getHours();
        minute = d.getMinutes();
      }
      const currentMinutes = hour * 60 + minute;
      const startMinutes = 7 * 60;
      const endMinutes = 21 * 60;
      const isHighFrequency = currentMinutes >= startMinutes && currentMinutes <= endMinutes;
      const delayMinutes = isHighFrequency ? 14 : 30;
      const delayMs = delayMinutes * 60 * 1e3;
      setTimeout(async () => {
        try {
          const modeLabel = isHighFrequency ? "Alta Frequ\xEAncia (07h \xE0s 21h)" : "Baixa Frequ\xEAncia (21h01 \xE0s 06h59)";
          console.log(`[Self-Ping] Enviando ping a ${RENDER_URL}/api/ping para manter ativo... [Modo: ${modeLabel}]`);
          const response = await fetch(`${RENDER_URL}/api/ping`);
          console.log(`[Self-Ping] Ping respondido com sucesso! Status: ${response.status}`);
        } catch (err) {
          console.error(`[Self-Ping] Erro ao enviar ping para manter ativo:`, err.message || err);
        }
        triggerNextPing();
      }, delayMs);
      const nextTarget = new Date(Date.now() + delayMs);
      const nextTimeStr = nextTarget.toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo" });
      console.log(`[Self-Ping] Pr\xF3ximo ping agendado para as ${nextTimeStr} (Em ${delayMinutes} minutos)`);
    };
    triggerNextPing();
  };
  if (process.env.NODE_ENV === "production" || process.env.RENDER_EXTERNAL_URL) {
    startSelfPing();
  }
}
startServer().catch((error) => {
  console.error("Erro fatal ao inicializar o servidor Express:", error);
});
//# sourceMappingURL=server.cjs.map
