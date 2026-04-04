"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ensureDirForFile = ensureDirForFile;
exports.readJsonFile = readJsonFile;
exports.writeJsonFile = writeJsonFile;
exports.readJsonLines = readJsonLines;
exports.appendJsonLine = appendJsonLine;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
function ensureDirForFile(filePath) {
    const dir = path.dirname(path.resolve(filePath));
    fs.mkdirSync(dir, { recursive: true });
}
function readJsonFile(filePath) {
    const raw = fs.readFileSync(path.resolve(filePath), 'utf8');
    return JSON.parse(raw);
}
function writeJsonFile(filePath, value) {
    ensureDirForFile(filePath);
    fs.writeFileSync(path.resolve(filePath), JSON.stringify(value, null, 2) + '\n', 'utf8');
}
function readJsonLines(filePath) {
    const raw = fs.readFileSync(path.resolve(filePath), 'utf8');
    const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
    return lines.map((line) => JSON.parse(line));
}
function appendJsonLine(filePath, value) {
    ensureDirForFile(filePath);
    fs.appendFileSync(path.resolve(filePath), JSON.stringify(value) + '\n', 'utf8');
}
