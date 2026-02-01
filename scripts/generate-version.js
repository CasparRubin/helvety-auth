/* eslint-disable @typescript-eslint/no-require-imports */
const fs = require("fs");
const path = require("path");

// Get current date and time
const now = new Date();

// Format: Built on dd.MM.yyyy at HH:mm:ss
const dd = String(now.getDate()).padStart(2, "0");
const MM = String(now.getMonth() + 1).padStart(2, "0");
const yyyy = String(now.getFullYear());
const HH = String(now.getHours()).padStart(2, "0");
const mm = String(now.getMinutes()).padStart(2, "0");
const ss = String(now.getSeconds()).padStart(2, "0");

const version = `Built on ${dd}.${MM}.${yyyy} at ${HH}:${mm}:${ss}`;

// Create the version file content
const versionFileContent = `// This file is auto-generated at build time
// Do not edit manually

export const VERSION = "${version}";
`;

// Ensure the lib/config directory exists
const configDir = path.join(process.cwd(), "lib", "config");
if (!fs.existsSync(configDir)) {
  fs.mkdirSync(configDir, { recursive: true });
}

// Write the version file
const versionFilePath = path.join(configDir, "version.ts");
fs.writeFileSync(versionFilePath, versionFileContent, "utf8");

console.log(`Generated version: ${version}`);
