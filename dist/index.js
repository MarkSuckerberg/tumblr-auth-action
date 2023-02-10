require('./sourcemap-register.js');/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 4514:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
const core = __importStar(__nccwpck_require__(2810));
const libsodium_wrappers_1 = __importDefault(__nccwpck_require__(8397));
const node_fetch_1 = __importDefault(__nccwpck_require__(5085));
const apiURL = process.env["GITHUB_API_URL"] || "https://api.github.com";
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const secretsToken = core.getInput("secrets-token");
            const tumblrClientID = core.getInput("tumblr-client-id");
            const tumblrClientSecret = core.getInput("tumblr-client-secret");
            const tumblrRefreshToken = core.getInput("tumblr-refresh-token");
            const repository = core.getInput("repository");
            const tokenName = core.getInput("token-name");
            const token = yield handleCIAuth(repository, secretsToken, tumblrRefreshToken, tumblrClientID, tumblrClientSecret, tokenName);
            core.setOutput("tumblr-token", token);
            core.setSecret(token);
            core.exportVariable("TUMBLR_TOKEN", token);
        }
        catch (error) {
            if (error instanceof Error)
                core.setFailed(error.message);
        }
    });
}
//You didn't have to make me do this, tumblr
function handleCIAuth(repo, secretsToken, refreshToken, clientID, clientSecret, tokenName) {
    return __awaiter(this, void 0, void 0, function* () {
        core.debug("Getting new token...");
        const request = yield (0, node_fetch_1.default)("https://api.tumblr.com/v2/oauth2/token", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "TumblrBotKill/0.0.1",
            },
            body: JSON.stringify({
                grant_type: "refresh_token",
                refresh_token: refreshToken,
                client_id: clientID,
                client_secret: clientSecret,
            }),
        });
        if (!request.ok)
            throw new Error(`Failed to get new token: ${request.status} ${request.statusText} ${yield request.text()}`);
        const response = (yield request.json());
        core.debug(`Got new token, fetching github public key at url ${apiURL}/repos/${repo}/actions/secrets/public-key...`);
        //Get the public key from github to encrypt the secret
        const githubPublicKey = yield (0, node_fetch_1.default)(`${apiURL}/repos/${repo}/actions/secrets/public-key`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
                "User-Agent": "X-GitHub-Api-Version: 2022-11-28",
                "Authorization": `Bearer ${secretsToken}`,
            },
        });
        if (!githubPublicKey.ok)
            throw new Error(`Failed to get github public key: ${githubPublicKey.status} ${githubPublicKey.statusText} ${yield githubPublicKey.text()}`);
        const githubPublicKeyResponse = (yield githubPublicKey.json());
        //Encrypt the refresh token using the public key
        const refreshTokenSecret = yield encryptSecret(response.refresh_token, githubPublicKeyResponse.key);
        core.debug("Updating secret...");
        //Update the github secret with the new refresh token for the next run
        const secretUpdate = yield (0, node_fetch_1.default)(`${apiURL}/repos/${repo}/actions/secrets/${tokenName}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
                "User-Agent": "X-GitHub-Api-Version: 2022-11-28",
                "Authorization": `Bearer ${secretsToken}`,
            },
            body: JSON.stringify({
                encrypted_value: refreshTokenSecret,
                key_id: githubPublicKeyResponse.key_id,
            }),
        });
        if (!secretUpdate.ok)
            throw new Error(`Failed to update secret: ${secretUpdate.statusText} ${secretUpdate.status} ${secretUpdate.statusText} ${yield secretUpdate.text()}`);
        return response.access_token;
    });
}
function encryptSecret(secret, key) {
    return __awaiter(this, void 0, void 0, function* () {
        return libsodium_wrappers_1.default.ready.then(() => {
            // Convert Secret & Base64 key to Uint8Array.
            let binkey = libsodium_wrappers_1.default.from_base64(key, libsodium_wrappers_1.default.base64_variants.ORIGINAL);
            let binsec = libsodium_wrappers_1.default.from_string(secret);
            //Encrypt the secret using LibSodium
            let encBytes = libsodium_wrappers_1.default.crypto_box_seal(binsec, binkey);
            // Convert encrypted Uint8Array to Base64
            return libsodium_wrappers_1.default.to_base64(encBytes, libsodium_wrappers_1.default.base64_variants.ORIGINAL);
        });
    });
}
run();
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 5649:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.issue = exports.issueCommand = void 0;
const os = __importStar(__nccwpck_require__(2037));
const utils_1 = __nccwpck_require__(3069);
/**
 * Commands
 *
 * Command Format:
 *   ::name key=value,key=value::message
 *
 * Examples:
 *   ::warning::This is the message
 *   ::set-env name=MY_VAR::some value
 */
function issueCommand(command, properties, message) {
    const cmd = new Command(command, properties, message);
    process.stdout.write(cmd.toString() + os.EOL);
}
exports.issueCommand = issueCommand;
function issue(name, message = '') {
    issueCommand(name, {}, message);
}
exports.issue = issue;
const CMD_STRING = '::';
class Command {
    constructor(command, properties, message) {
        if (!command) {
            command = 'missing.command';
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
    }
    toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
            cmdStr += ' ';
            let first = true;
            for (const key in this.properties) {
                if (this.properties.hasOwnProperty(key)) {
                    const val = this.properties[key];
                    if (val) {
                        if (first) {
                            first = false;
                        }
                        else {
                            cmdStr += ',';
                        }
                        cmdStr += `${key}=${escapeProperty(val)}`;
                    }
                }
            }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
    }
}
function escapeData(s) {
    return utils_1.toCommandValue(s)
        .replace(/%/g, '%25')
        .replace(/\r/g, '%0D')
        .replace(/\n/g, '%0A');
}
function escapeProperty(s) {
    return utils_1.toCommandValue(s)
        .replace(/%/g, '%25')
        .replace(/\r/g, '%0D')
        .replace(/\n/g, '%0A')
        .replace(/:/g, '%3A')
        .replace(/,/g, '%2C');
}
//# sourceMappingURL=command.js.map

/***/ }),

/***/ 2810:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getIDToken = exports.getState = exports.saveState = exports.group = exports.endGroup = exports.startGroup = exports.info = exports.notice = exports.warning = exports.error = exports.debug = exports.isDebug = exports.setFailed = exports.setCommandEcho = exports.setOutput = exports.getBooleanInput = exports.getMultilineInput = exports.getInput = exports.addPath = exports.setSecret = exports.exportVariable = exports.ExitCode = void 0;
const command_1 = __nccwpck_require__(5649);
const file_command_1 = __nccwpck_require__(7054);
const utils_1 = __nccwpck_require__(3069);
const os = __importStar(__nccwpck_require__(2037));
const path = __importStar(__nccwpck_require__(1017));
const oidc_utils_1 = __nccwpck_require__(3050);
/**
 * The code to exit an action
 */
var ExitCode;
(function (ExitCode) {
    /**
     * A code indicating that the action was successful
     */
    ExitCode[ExitCode["Success"] = 0] = "Success";
    /**
     * A code indicating that the action was a failure
     */
    ExitCode[ExitCode["Failure"] = 1] = "Failure";
})(ExitCode = exports.ExitCode || (exports.ExitCode = {}));
//-----------------------------------------------------------------------
// Variables
//-----------------------------------------------------------------------
/**
 * Sets env variable for this action and future actions in the job
 * @param name the name of the variable to set
 * @param val the value of the variable. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function exportVariable(name, val) {
    const convertedVal = utils_1.toCommandValue(val);
    process.env[name] = convertedVal;
    const filePath = process.env['GITHUB_ENV'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('ENV', file_command_1.prepareKeyValueMessage(name, val));
    }
    command_1.issueCommand('set-env', { name }, convertedVal);
}
exports.exportVariable = exportVariable;
/**
 * Registers a secret which will get masked from logs
 * @param secret value of the secret
 */
function setSecret(secret) {
    command_1.issueCommand('add-mask', {}, secret);
}
exports.setSecret = setSecret;
/**
 * Prepends inputPath to the PATH (for this action and future actions)
 * @param inputPath
 */
function addPath(inputPath) {
    const filePath = process.env['GITHUB_PATH'] || '';
    if (filePath) {
        file_command_1.issueFileCommand('PATH', inputPath);
    }
    else {
        command_1.issueCommand('add-path', {}, inputPath);
    }
    process.env['PATH'] = `${inputPath}${path.delimiter}${process.env['PATH']}`;
}
exports.addPath = addPath;
/**
 * Gets the value of an input.
 * Unless trimWhitespace is set to false in InputOptions, the value is also trimmed.
 * Returns an empty string if the value is not defined.
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   string
 */
function getInput(name, options) {
    const val = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || '';
    if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
    }
    if (options && options.trimWhitespace === false) {
        return val;
    }
    return val.trim();
}
exports.getInput = getInput;
/**
 * Gets the values of an multiline input.  Each value is also trimmed.
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   string[]
 *
 */
function getMultilineInput(name, options) {
    const inputs = getInput(name, options)
        .split('\n')
        .filter(x => x !== '');
    if (options && options.trimWhitespace === false) {
        return inputs;
    }
    return inputs.map(input => input.trim());
}
exports.getMultilineInput = getMultilineInput;
/**
 * Gets the input value of the boolean type in the YAML 1.2 "core schema" specification.
 * Support boolean input list: `true | True | TRUE | false | False | FALSE` .
 * The return value is also in boolean type.
 * ref: https://yaml.org/spec/1.2/spec.html#id2804923
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   boolean
 */
function getBooleanInput(name, options) {
    const trueValue = ['true', 'True', 'TRUE'];
    const falseValue = ['false', 'False', 'FALSE'];
    const val = getInput(name, options);
    if (trueValue.includes(val))
        return true;
    if (falseValue.includes(val))
        return false;
    throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}\n` +
        `Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
}
exports.getBooleanInput = getBooleanInput;
/**
 * Sets the value of an output.
 *
 * @param     name     name of the output to set
 * @param     value    value to store. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function setOutput(name, value) {
    const filePath = process.env['GITHUB_OUTPUT'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('OUTPUT', file_command_1.prepareKeyValueMessage(name, value));
    }
    process.stdout.write(os.EOL);
    command_1.issueCommand('set-output', { name }, utils_1.toCommandValue(value));
}
exports.setOutput = setOutput;
/**
 * Enables or disables the echoing of commands into stdout for the rest of the step.
 * Echoing is disabled by default if ACTIONS_STEP_DEBUG is not set.
 *
 */
function setCommandEcho(enabled) {
    command_1.issue('echo', enabled ? 'on' : 'off');
}
exports.setCommandEcho = setCommandEcho;
//-----------------------------------------------------------------------
// Results
//-----------------------------------------------------------------------
/**
 * Sets the action status to failed.
 * When the action exits it will be with an exit code of 1
 * @param message add error issue message
 */
function setFailed(message) {
    process.exitCode = ExitCode.Failure;
    error(message);
}
exports.setFailed = setFailed;
//-----------------------------------------------------------------------
// Logging Commands
//-----------------------------------------------------------------------
/**
 * Gets whether Actions Step Debug is on or not
 */
function isDebug() {
    return process.env['RUNNER_DEBUG'] === '1';
}
exports.isDebug = isDebug;
/**
 * Writes debug message to user log
 * @param message debug message
 */
function debug(message) {
    command_1.issueCommand('debug', {}, message);
}
exports.debug = debug;
/**
 * Adds an error issue
 * @param message error issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function error(message, properties = {}) {
    command_1.issueCommand('error', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.error = error;
/**
 * Adds a warning issue
 * @param message warning issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function warning(message, properties = {}) {
    command_1.issueCommand('warning', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.warning = warning;
/**
 * Adds a notice issue
 * @param message notice issue message. Errors will be converted to string via toString()
 * @param properties optional properties to add to the annotation.
 */
function notice(message, properties = {}) {
    command_1.issueCommand('notice', utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
}
exports.notice = notice;
/**
 * Writes info to log with console.log.
 * @param message info message
 */
function info(message) {
    process.stdout.write(message + os.EOL);
}
exports.info = info;
/**
 * Begin an output group.
 *
 * Output until the next `groupEnd` will be foldable in this group
 *
 * @param name The name of the output group
 */
function startGroup(name) {
    command_1.issue('group', name);
}
exports.startGroup = startGroup;
/**
 * End an output group.
 */
function endGroup() {
    command_1.issue('endgroup');
}
exports.endGroup = endGroup;
/**
 * Wrap an asynchronous function call in a group.
 *
 * Returns the same type as the function itself.
 *
 * @param name The name of the group
 * @param fn The function to wrap in the group
 */
function group(name, fn) {
    return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
            result = yield fn();
        }
        finally {
            endGroup();
        }
        return result;
    });
}
exports.group = group;
//-----------------------------------------------------------------------
// Wrapper action state
//-----------------------------------------------------------------------
/**
 * Saves state for current action, the state can only be retrieved by this action's post job execution.
 *
 * @param     name     name of the state to store
 * @param     value    value to store. Non-string values will be converted to a string via JSON.stringify
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function saveState(name, value) {
    const filePath = process.env['GITHUB_STATE'] || '';
    if (filePath) {
        return file_command_1.issueFileCommand('STATE', file_command_1.prepareKeyValueMessage(name, value));
    }
    command_1.issueCommand('save-state', { name }, utils_1.toCommandValue(value));
}
exports.saveState = saveState;
/**
 * Gets the value of an state set by this action's main execution.
 *
 * @param     name     name of the state to get
 * @returns   string
 */
function getState(name) {
    return process.env[`STATE_${name}`] || '';
}
exports.getState = getState;
function getIDToken(aud) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
    });
}
exports.getIDToken = getIDToken;
/**
 * Summary exports
 */
var summary_1 = __nccwpck_require__(6179);
Object.defineProperty(exports, "summary", ({ enumerable: true, get: function () { return summary_1.summary; } }));
/**
 * @deprecated use core.summary
 */
var summary_2 = __nccwpck_require__(6179);
Object.defineProperty(exports, "markdownSummary", ({ enumerable: true, get: function () { return summary_2.markdownSummary; } }));
/**
 * Path exports
 */
var path_utils_1 = __nccwpck_require__(9191);
Object.defineProperty(exports, "toPosixPath", ({ enumerable: true, get: function () { return path_utils_1.toPosixPath; } }));
Object.defineProperty(exports, "toWin32Path", ({ enumerable: true, get: function () { return path_utils_1.toWin32Path; } }));
Object.defineProperty(exports, "toPlatformPath", ({ enumerable: true, get: function () { return path_utils_1.toPlatformPath; } }));
//# sourceMappingURL=core.js.map

/***/ }),

/***/ 7054:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

// For internal use, subject to change.
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.prepareKeyValueMessage = exports.issueFileCommand = void 0;
// We use any as a valid input type
/* eslint-disable @typescript-eslint/no-explicit-any */
const fs = __importStar(__nccwpck_require__(7147));
const os = __importStar(__nccwpck_require__(2037));
const uuid_1 = __nccwpck_require__(3160);
const utils_1 = __nccwpck_require__(3069);
function issueFileCommand(command, message) {
    const filePath = process.env[`GITHUB_${command}`];
    if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
    }
    if (!fs.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
    }
    fs.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
        encoding: 'utf8'
    });
}
exports.issueFileCommand = issueFileCommand;
function prepareKeyValueMessage(key, value) {
    const delimiter = `ghadelimiter_${uuid_1.v4()}`;
    const convertedValue = utils_1.toCommandValue(value);
    // These should realistically never happen, but just in case someone finds a
    // way to exploit uuid generation let's not allow keys or values that contain
    // the delimiter.
    if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
    }
    if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
    }
    return `${key}<<${delimiter}${os.EOL}${convertedValue}${os.EOL}${delimiter}`;
}
exports.prepareKeyValueMessage = prepareKeyValueMessage;
//# sourceMappingURL=file-command.js.map

/***/ }),

/***/ 3050:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.OidcClient = void 0;
const http_client_1 = __nccwpck_require__(1659);
const auth_1 = __nccwpck_require__(9320);
const core_1 = __nccwpck_require__(2810);
class OidcClient {
    static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
            allowRetries: allowRetry,
            maxRetries: maxRetry
        };
        return new http_client_1.HttpClient('actions/oidc-client', [new auth_1.BearerCredentialHandler(OidcClient.getRequestToken())], requestOptions);
    }
    static getRequestToken() {
        const token = process.env['ACTIONS_ID_TOKEN_REQUEST_TOKEN'];
        if (!token) {
            throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable');
        }
        return token;
    }
    static getIDTokenUrl() {
        const runtimeUrl = process.env['ACTIONS_ID_TOKEN_REQUEST_URL'];
        if (!runtimeUrl) {
            throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable');
        }
        return runtimeUrl;
    }
    static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const httpclient = OidcClient.createHttpClient();
            const res = yield httpclient
                .getJson(id_token_url)
                .catch(error => {
                throw new Error(`Failed to get ID Token. \n 
        Error Code : ${error.statusCode}\n 
        Error Message: ${error.result.message}`);
            });
            const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
            if (!id_token) {
                throw new Error('Response json body do not have ID Token field');
            }
            return id_token;
        });
    }
    static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // New ID Token is requested from action service
                let id_token_url = OidcClient.getIDTokenUrl();
                if (audience) {
                    const encodedAudience = encodeURIComponent(audience);
                    id_token_url = `${id_token_url}&audience=${encodedAudience}`;
                }
                core_1.debug(`ID token url is ${id_token_url}`);
                const id_token = yield OidcClient.getCall(id_token_url);
                core_1.setSecret(id_token);
                return id_token;
            }
            catch (error) {
                throw new Error(`Error message: ${error.message}`);
            }
        });
    }
}
exports.OidcClient = OidcClient;
//# sourceMappingURL=oidc-utils.js.map

/***/ }),

/***/ 9191:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.toPlatformPath = exports.toWin32Path = exports.toPosixPath = void 0;
const path = __importStar(__nccwpck_require__(1017));
/**
 * toPosixPath converts the given path to the posix form. On Windows, \\ will be
 * replaced with /.
 *
 * @param pth. Path to transform.
 * @return string Posix path.
 */
function toPosixPath(pth) {
    return pth.replace(/[\\]/g, '/');
}
exports.toPosixPath = toPosixPath;
/**
 * toWin32Path converts the given path to the win32 form. On Linux, / will be
 * replaced with \\.
 *
 * @param pth. Path to transform.
 * @return string Win32 path.
 */
function toWin32Path(pth) {
    return pth.replace(/[/]/g, '\\');
}
exports.toWin32Path = toWin32Path;
/**
 * toPlatformPath converts the given path to a platform-specific path. It does
 * this by replacing instances of / and \ with the platform-specific path
 * separator.
 *
 * @param pth The path to platformize.
 * @return string The platform-specific path.
 */
function toPlatformPath(pth) {
    return pth.replace(/[/\\]/g, path.sep);
}
exports.toPlatformPath = toPlatformPath;
//# sourceMappingURL=path-utils.js.map

/***/ }),

/***/ 6179:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.summary = exports.markdownSummary = exports.SUMMARY_DOCS_URL = exports.SUMMARY_ENV_VAR = void 0;
const os_1 = __nccwpck_require__(2037);
const fs_1 = __nccwpck_require__(7147);
const { access, appendFile, writeFile } = fs_1.promises;
exports.SUMMARY_ENV_VAR = 'GITHUB_STEP_SUMMARY';
exports.SUMMARY_DOCS_URL = 'https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary';
class Summary {
    constructor() {
        this._buffer = '';
    }
    /**
     * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
     * Also checks r/w permissions.
     *
     * @returns step summary file path
     */
    filePath() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._filePath) {
                return this._filePath;
            }
            const pathFromEnv = process.env[exports.SUMMARY_ENV_VAR];
            if (!pathFromEnv) {
                throw new Error(`Unable to find environment variable for $${exports.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
            }
            try {
                yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
            }
            catch (_a) {
                throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
            }
            this._filePath = pathFromEnv;
            return this._filePath;
        });
    }
    /**
     * Wraps content in an HTML tag, adding any HTML attributes
     *
     * @param {string} tag HTML tag to wrap
     * @param {string | null} content content within the tag
     * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
     *
     * @returns {string} content wrapped in HTML element
     */
    wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs)
            .map(([key, value]) => ` ${key}="${value}"`)
            .join('');
        if (!content) {
            return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
    }
    /**
     * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
     *
     * @param {SummaryWriteOptions} [options] (optional) options for write operation
     *
     * @returns {Promise<Summary>} summary instance
     */
    write(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
            const filePath = yield this.filePath();
            const writeFunc = overwrite ? writeFile : appendFile;
            yield writeFunc(filePath, this._buffer, { encoding: 'utf8' });
            return this.emptyBuffer();
        });
    }
    /**
     * Clears the summary buffer and wipes the summary file
     *
     * @returns {Summary} summary instance
     */
    clear() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.emptyBuffer().write({ overwrite: true });
        });
    }
    /**
     * Returns the current summary buffer as a string
     *
     * @returns {string} string of summary buffer
     */
    stringify() {
        return this._buffer;
    }
    /**
     * If the summary buffer is empty
     *
     * @returns {boolen} true if the buffer is empty
     */
    isEmptyBuffer() {
        return this._buffer.length === 0;
    }
    /**
     * Resets the summary buffer without writing to summary file
     *
     * @returns {Summary} summary instance
     */
    emptyBuffer() {
        this._buffer = '';
        return this;
    }
    /**
     * Adds raw text to the summary buffer
     *
     * @param {string} text content to add
     * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
     *
     * @returns {Summary} summary instance
     */
    addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
    }
    /**
     * Adds the operating system-specific end-of-line marker to the buffer
     *
     * @returns {Summary} summary instance
     */
    addEOL() {
        return this.addRaw(os_1.EOL);
    }
    /**
     * Adds an HTML codeblock to the summary buffer
     *
     * @param {string} code content to render within fenced code block
     * @param {string} lang (optional) language to syntax highlight code
     *
     * @returns {Summary} summary instance
     */
    addCodeBlock(code, lang) {
        const attrs = Object.assign({}, (lang && { lang }));
        const element = this.wrap('pre', this.wrap('code', code), attrs);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML list to the summary buffer
     *
     * @param {string[]} items list of items to render
     * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
     *
     * @returns {Summary} summary instance
     */
    addList(items, ordered = false) {
        const tag = ordered ? 'ol' : 'ul';
        const listItems = items.map(item => this.wrap('li', item)).join('');
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML table to the summary buffer
     *
     * @param {SummaryTableCell[]} rows table rows
     *
     * @returns {Summary} summary instance
     */
    addTable(rows) {
        const tableBody = rows
            .map(row => {
            const cells = row
                .map(cell => {
                if (typeof cell === 'string') {
                    return this.wrap('td', cell);
                }
                const { header, data, colspan, rowspan } = cell;
                const tag = header ? 'th' : 'td';
                const attrs = Object.assign(Object.assign({}, (colspan && { colspan })), (rowspan && { rowspan }));
                return this.wrap(tag, data, attrs);
            })
                .join('');
            return this.wrap('tr', cells);
        })
            .join('');
        const element = this.wrap('table', tableBody);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds a collapsable HTML details element to the summary buffer
     *
     * @param {string} label text for the closed state
     * @param {string} content collapsable content
     *
     * @returns {Summary} summary instance
     */
    addDetails(label, content) {
        const element = this.wrap('details', this.wrap('summary', label) + content);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML image tag to the summary buffer
     *
     * @param {string} src path to the image you to embed
     * @param {string} alt text description of the image
     * @param {SummaryImageOptions} options (optional) addition image attributes
     *
     * @returns {Summary} summary instance
     */
    addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, (width && { width })), (height && { height }));
        const element = this.wrap('img', null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML section heading element
     *
     * @param {string} text heading text
     * @param {number | string} [level=1] (optional) the heading level, default: 1
     *
     * @returns {Summary} summary instance
     */
    addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(tag)
            ? tag
            : 'h1';
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML thematic break (<hr>) to the summary buffer
     *
     * @returns {Summary} summary instance
     */
    addSeparator() {
        const element = this.wrap('hr', null);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML line break (<br>) to the summary buffer
     *
     * @returns {Summary} summary instance
     */
    addBreak() {
        const element = this.wrap('br', null);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML blockquote to the summary buffer
     *
     * @param {string} text quote text
     * @param {string} cite (optional) citation url
     *
     * @returns {Summary} summary instance
     */
    addQuote(text, cite) {
        const attrs = Object.assign({}, (cite && { cite }));
        const element = this.wrap('blockquote', text, attrs);
        return this.addRaw(element).addEOL();
    }
    /**
     * Adds an HTML anchor tag to the summary buffer
     *
     * @param {string} text link text/content
     * @param {string} href hyperlink
     *
     * @returns {Summary} summary instance
     */
    addLink(text, href) {
        const element = this.wrap('a', text, { href });
        return this.addRaw(element).addEOL();
    }
}
const _summary = new Summary();
/**
 * @deprecated use `core.summary`
 */
exports.markdownSummary = _summary;
exports.summary = _summary;
//# sourceMappingURL=summary.js.map

/***/ }),

/***/ 3069:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

// We use any as a valid input type
/* eslint-disable @typescript-eslint/no-explicit-any */
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.toCommandProperties = exports.toCommandValue = void 0;
/**
 * Sanitizes an input into a string so it can be passed into issueCommand safely
 * @param input input to sanitize into a string
 */
function toCommandValue(input) {
    if (input === null || input === undefined) {
        return '';
    }
    else if (typeof input === 'string' || input instanceof String) {
        return input;
    }
    return JSON.stringify(input);
}
exports.toCommandValue = toCommandValue;
/**
 *
 * @param annotationProperties
 * @returns The command properties to send with the actual annotation command
 * See IssueCommandProperties: https://github.com/actions/runner/blob/main/src/Runner.Worker/ActionCommandManager.cs#L646
 */
function toCommandProperties(annotationProperties) {
    if (!Object.keys(annotationProperties).length) {
        return {};
    }
    return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
    };
}
exports.toCommandProperties = toCommandProperties;
//# sourceMappingURL=utils.js.map

/***/ }),

/***/ 9320:
/***/ (function(__unused_webpack_module, exports) {

"use strict";

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PersonalAccessTokenCredentialHandler = exports.BearerCredentialHandler = exports.BasicCredentialHandler = void 0;
class BasicCredentialHandler {
    constructor(username, password) {
        this.username = username;
        this.password = password;
    }
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.BasicCredentialHandler = BasicCredentialHandler;
class BearerCredentialHandler {
    constructor(token) {
        this.token = token;
    }
    // currently implements pre-authorization
    // TODO: support preAuth = false where it hooks on 401
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Bearer ${this.token}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.BearerCredentialHandler = BearerCredentialHandler;
class PersonalAccessTokenCredentialHandler {
    constructor(token) {
        this.token = token;
    }
    // currently implements pre-authorization
    // TODO: support preAuth = false where it hooks on 401
    prepareRequest(options) {
        if (!options.headers) {
            throw Error('The request has no headers');
        }
        options.headers['Authorization'] = `Basic ${Buffer.from(`PAT:${this.token}`).toString('base64')}`;
    }
    // This handler cannot handle 401
    canHandleAuthentication() {
        return false;
    }
    handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('not implemented');
        });
    }
}
exports.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
//# sourceMappingURL=auth.js.map

/***/ }),

/***/ 1659:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

/* eslint-disable @typescript-eslint/no-explicit-any */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HttpClient = exports.isHttps = exports.HttpClientResponse = exports.HttpClientError = exports.getProxyUrl = exports.MediaTypes = exports.Headers = exports.HttpCodes = void 0;
const http = __importStar(__nccwpck_require__(3685));
const https = __importStar(__nccwpck_require__(5687));
const pm = __importStar(__nccwpck_require__(3833));
const tunnel = __importStar(__nccwpck_require__(2264));
var HttpCodes;
(function (HttpCodes) {
    HttpCodes[HttpCodes["OK"] = 200] = "OK";
    HttpCodes[HttpCodes["MultipleChoices"] = 300] = "MultipleChoices";
    HttpCodes[HttpCodes["MovedPermanently"] = 301] = "MovedPermanently";
    HttpCodes[HttpCodes["ResourceMoved"] = 302] = "ResourceMoved";
    HttpCodes[HttpCodes["SeeOther"] = 303] = "SeeOther";
    HttpCodes[HttpCodes["NotModified"] = 304] = "NotModified";
    HttpCodes[HttpCodes["UseProxy"] = 305] = "UseProxy";
    HttpCodes[HttpCodes["SwitchProxy"] = 306] = "SwitchProxy";
    HttpCodes[HttpCodes["TemporaryRedirect"] = 307] = "TemporaryRedirect";
    HttpCodes[HttpCodes["PermanentRedirect"] = 308] = "PermanentRedirect";
    HttpCodes[HttpCodes["BadRequest"] = 400] = "BadRequest";
    HttpCodes[HttpCodes["Unauthorized"] = 401] = "Unauthorized";
    HttpCodes[HttpCodes["PaymentRequired"] = 402] = "PaymentRequired";
    HttpCodes[HttpCodes["Forbidden"] = 403] = "Forbidden";
    HttpCodes[HttpCodes["NotFound"] = 404] = "NotFound";
    HttpCodes[HttpCodes["MethodNotAllowed"] = 405] = "MethodNotAllowed";
    HttpCodes[HttpCodes["NotAcceptable"] = 406] = "NotAcceptable";
    HttpCodes[HttpCodes["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
    HttpCodes[HttpCodes["RequestTimeout"] = 408] = "RequestTimeout";
    HttpCodes[HttpCodes["Conflict"] = 409] = "Conflict";
    HttpCodes[HttpCodes["Gone"] = 410] = "Gone";
    HttpCodes[HttpCodes["TooManyRequests"] = 429] = "TooManyRequests";
    HttpCodes[HttpCodes["InternalServerError"] = 500] = "InternalServerError";
    HttpCodes[HttpCodes["NotImplemented"] = 501] = "NotImplemented";
    HttpCodes[HttpCodes["BadGateway"] = 502] = "BadGateway";
    HttpCodes[HttpCodes["ServiceUnavailable"] = 503] = "ServiceUnavailable";
    HttpCodes[HttpCodes["GatewayTimeout"] = 504] = "GatewayTimeout";
})(HttpCodes = exports.HttpCodes || (exports.HttpCodes = {}));
var Headers;
(function (Headers) {
    Headers["Accept"] = "accept";
    Headers["ContentType"] = "content-type";
})(Headers = exports.Headers || (exports.Headers = {}));
var MediaTypes;
(function (MediaTypes) {
    MediaTypes["ApplicationJson"] = "application/json";
})(MediaTypes = exports.MediaTypes || (exports.MediaTypes = {}));
/**
 * Returns the proxy URL, depending upon the supplied url and proxy environment variables.
 * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
 */
function getProxyUrl(serverUrl) {
    const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
    return proxyUrl ? proxyUrl.href : '';
}
exports.getProxyUrl = getProxyUrl;
const HttpRedirectCodes = [
    HttpCodes.MovedPermanently,
    HttpCodes.ResourceMoved,
    HttpCodes.SeeOther,
    HttpCodes.TemporaryRedirect,
    HttpCodes.PermanentRedirect
];
const HttpResponseRetryCodes = [
    HttpCodes.BadGateway,
    HttpCodes.ServiceUnavailable,
    HttpCodes.GatewayTimeout
];
const RetryableHttpVerbs = ['OPTIONS', 'GET', 'DELETE', 'HEAD'];
const ExponentialBackoffCeiling = 10;
const ExponentialBackoffTimeSlice = 5;
class HttpClientError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.name = 'HttpClientError';
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, HttpClientError.prototype);
    }
}
exports.HttpClientError = HttpClientError;
class HttpClientResponse {
    constructor(message) {
        this.message = message;
    }
    readBody() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
                let output = Buffer.alloc(0);
                this.message.on('data', (chunk) => {
                    output = Buffer.concat([output, chunk]);
                });
                this.message.on('end', () => {
                    resolve(output.toString());
                });
            }));
        });
    }
}
exports.HttpClientResponse = HttpClientResponse;
function isHttps(requestUrl) {
    const parsedUrl = new URL(requestUrl);
    return parsedUrl.protocol === 'https:';
}
exports.isHttps = isHttps;
class HttpClient {
    constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
            if (requestOptions.ignoreSslError != null) {
                this._ignoreSslError = requestOptions.ignoreSslError;
            }
            this._socketTimeout = requestOptions.socketTimeout;
            if (requestOptions.allowRedirects != null) {
                this._allowRedirects = requestOptions.allowRedirects;
            }
            if (requestOptions.allowRedirectDowngrade != null) {
                this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
            }
            if (requestOptions.maxRedirects != null) {
                this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
            }
            if (requestOptions.keepAlive != null) {
                this._keepAlive = requestOptions.keepAlive;
            }
            if (requestOptions.allowRetries != null) {
                this._allowRetries = requestOptions.allowRetries;
            }
            if (requestOptions.maxRetries != null) {
                this._maxRetries = requestOptions.maxRetries;
            }
        }
    }
    options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('OPTIONS', requestUrl, null, additionalHeaders || {});
        });
    }
    get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('GET', requestUrl, null, additionalHeaders || {});
        });
    }
    del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('DELETE', requestUrl, null, additionalHeaders || {});
        });
    }
    post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('POST', requestUrl, data, additionalHeaders || {});
        });
    }
    patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('PATCH', requestUrl, data, additionalHeaders || {});
        });
    }
    put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('PUT', requestUrl, data, additionalHeaders || {});
        });
    }
    head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request('HEAD', requestUrl, null, additionalHeaders || {});
        });
    }
    sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(verb, requestUrl, stream, additionalHeaders);
        });
    }
    /**
     * Gets a typed object from an endpoint
     * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
     */
    getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            const res = yield this.get(requestUrl, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.post(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.put(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
            additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
            const res = yield this.patch(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    /**
     * Makes a raw http request.
     * All other methods such as get, post, patch, and request ultimately call this.
     * Prefer get, del, post and patch
     */
    request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._disposed) {
                throw new Error('Client has already been disposed.');
            }
            const parsedUrl = new URL(requestUrl);
            let info = this._prepareRequest(verb, parsedUrl, headers);
            // Only perform retries on reads since writes may not be idempotent.
            const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb)
                ? this._maxRetries + 1
                : 1;
            let numTries = 0;
            let response;
            do {
                response = yield this.requestRaw(info, data);
                // Check if it's an authentication challenge
                if (response &&
                    response.message &&
                    response.message.statusCode === HttpCodes.Unauthorized) {
                    let authenticationHandler;
                    for (const handler of this.handlers) {
                        if (handler.canHandleAuthentication(response)) {
                            authenticationHandler = handler;
                            break;
                        }
                    }
                    if (authenticationHandler) {
                        return authenticationHandler.handleAuthentication(this, info, data);
                    }
                    else {
                        // We have received an unauthorized response but have no handlers to handle it.
                        // Let the response return to the caller.
                        return response;
                    }
                }
                let redirectsRemaining = this._maxRedirects;
                while (response.message.statusCode &&
                    HttpRedirectCodes.includes(response.message.statusCode) &&
                    this._allowRedirects &&
                    redirectsRemaining > 0) {
                    const redirectUrl = response.message.headers['location'];
                    if (!redirectUrl) {
                        // if there's no location to redirect to, we won't
                        break;
                    }
                    const parsedRedirectUrl = new URL(redirectUrl);
                    if (parsedUrl.protocol === 'https:' &&
                        parsedUrl.protocol !== parsedRedirectUrl.protocol &&
                        !this._allowRedirectDowngrade) {
                        throw new Error('Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.');
                    }
                    // we need to finish reading the response before reassigning response
                    // which will leak the open socket.
                    yield response.readBody();
                    // strip authorization header if redirected to a different hostname
                    if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                        for (const header in headers) {
                            // header names are case insensitive
                            if (header.toLowerCase() === 'authorization') {
                                delete headers[header];
                            }
                        }
                    }
                    // let's make the request with the new redirectUrl
                    info = this._prepareRequest(verb, parsedRedirectUrl, headers);
                    response = yield this.requestRaw(info, data);
                    redirectsRemaining--;
                }
                if (!response.message.statusCode ||
                    !HttpResponseRetryCodes.includes(response.message.statusCode)) {
                    // If not a retry code, return immediately instead of retrying
                    return response;
                }
                numTries += 1;
                if (numTries < maxTries) {
                    yield response.readBody();
                    yield this._performExponentialBackoff(numTries);
                }
            } while (numTries < maxTries);
            return response;
        });
    }
    /**
     * Needs to be called if keepAlive is set to true in request options.
     */
    dispose() {
        if (this._agent) {
            this._agent.destroy();
        }
        this._disposed = true;
    }
    /**
     * Raw request.
     * @param info
     * @param data
     */
    requestRaw(info, data) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                function callbackForResult(err, res) {
                    if (err) {
                        reject(err);
                    }
                    else if (!res) {
                        // If `err` is not passed, then `res` must be passed.
                        reject(new Error('Unknown error'));
                    }
                    else {
                        resolve(res);
                    }
                }
                this.requestRawWithCallback(info, data, callbackForResult);
            });
        });
    }
    /**
     * Raw request with callback.
     * @param info
     * @param data
     * @param onResult
     */
    requestRawWithCallback(info, data, onResult) {
        if (typeof data === 'string') {
            if (!info.options.headers) {
                info.options.headers = {};
            }
            info.options.headers['Content-Length'] = Buffer.byteLength(data, 'utf8');
        }
        let callbackCalled = false;
        function handleResult(err, res) {
            if (!callbackCalled) {
                callbackCalled = true;
                onResult(err, res);
            }
        }
        const req = info.httpModule.request(info.options, (msg) => {
            const res = new HttpClientResponse(msg);
            handleResult(undefined, res);
        });
        let socket;
        req.on('socket', sock => {
            socket = sock;
        });
        // If we ever get disconnected, we want the socket to timeout eventually
        req.setTimeout(this._socketTimeout || 3 * 60000, () => {
            if (socket) {
                socket.end();
            }
            handleResult(new Error(`Request timeout: ${info.options.path}`));
        });
        req.on('error', function (err) {
            // err has statusCode property
            // res should have headers
            handleResult(err);
        });
        if (data && typeof data === 'string') {
            req.write(data, 'utf8');
        }
        if (data && typeof data !== 'string') {
            data.on('close', function () {
                req.end();
            });
            data.pipe(req);
        }
        else {
            req.end();
        }
    }
    /**
     * Gets an http agent. This function is useful when you need an http agent that handles
     * routing through a proxy server - depending upon the url and proxy environment variables.
     * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
     */
    getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
    }
    _prepareRequest(method, requestUrl, headers) {
        const info = {};
        info.parsedUrl = requestUrl;
        const usingSsl = info.parsedUrl.protocol === 'https:';
        info.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info.options = {};
        info.options.host = info.parsedUrl.hostname;
        info.options.port = info.parsedUrl.port
            ? parseInt(info.parsedUrl.port)
            : defaultPort;
        info.options.path =
            (info.parsedUrl.pathname || '') + (info.parsedUrl.search || '');
        info.options.method = method;
        info.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
            info.options.headers['user-agent'] = this.userAgent;
        }
        info.options.agent = this._getAgent(info.parsedUrl);
        // gives handlers an opportunity to participate
        if (this.handlers) {
            for (const handler of this.handlers) {
                handler.prepareRequest(info.options);
            }
        }
        return info;
    }
    _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
            return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
    }
    _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
            clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default;
    }
    _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
            agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
            agent = this._agent;
        }
        // if agent is already assigned use that agent.
        if (agent) {
            return agent;
        }
        const usingSsl = parsedUrl.protocol === 'https:';
        let maxSockets = 100;
        if (this.requestOptions) {
            maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        // This is `useProxy` again, but we need to check `proxyURl` directly for TypeScripts's flow analysis.
        if (proxyUrl && proxyUrl.hostname) {
            const agentOptions = {
                maxSockets,
                keepAlive: this._keepAlive,
                proxy: Object.assign(Object.assign({}, ((proxyUrl.username || proxyUrl.password) && {
                    proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
                })), { host: proxyUrl.hostname, port: proxyUrl.port })
            };
            let tunnelAgent;
            const overHttps = proxyUrl.protocol === 'https:';
            if (usingSsl) {
                tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
            }
            else {
                tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
            }
            agent = tunnelAgent(agentOptions);
            this._proxyAgent = agent;
        }
        // if reusing agent across request and tunneling agent isn't assigned create a new agent
        if (this._keepAlive && !agent) {
            const options = { keepAlive: this._keepAlive, maxSockets };
            agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
            this._agent = agent;
        }
        // if not using private agent and tunnel agent isn't setup then use global agent
        if (!agent) {
            agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
            // we don't want to set NODE_TLS_REJECT_UNAUTHORIZED=0 since that will affect request for entire process
            // http.RequestOptions doesn't expose a way to modify RequestOptions.agent.options
            // we have to cast it to any and change it directly
            agent.options = Object.assign(agent.options || {}, {
                rejectUnauthorized: false
            });
        }
        return agent;
    }
    _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
            retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
            const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
            return new Promise(resolve => setTimeout(() => resolve(), ms));
        });
    }
    _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                const statusCode = res.message.statusCode || 0;
                const response = {
                    statusCode,
                    result: null,
                    headers: {}
                };
                // not found leads to null obj returned
                if (statusCode === HttpCodes.NotFound) {
                    resolve(response);
                }
                // get the result from the body
                function dateTimeDeserializer(key, value) {
                    if (typeof value === 'string') {
                        const a = new Date(value);
                        if (!isNaN(a.valueOf())) {
                            return a;
                        }
                    }
                    return value;
                }
                let obj;
                let contents;
                try {
                    contents = yield res.readBody();
                    if (contents && contents.length > 0) {
                        if (options && options.deserializeDates) {
                            obj = JSON.parse(contents, dateTimeDeserializer);
                        }
                        else {
                            obj = JSON.parse(contents);
                        }
                        response.result = obj;
                    }
                    response.headers = res.message.headers;
                }
                catch (err) {
                    // Invalid resource (contents not json);  leaving result obj null
                }
                // note that 3xx redirects are handled by the http layer.
                if (statusCode > 299) {
                    let msg;
                    // if exception/error in body, attempt to get better error
                    if (obj && obj.message) {
                        msg = obj.message;
                    }
                    else if (contents && contents.length > 0) {
                        // it may be the case that the exception is in the body message as string
                        msg = contents;
                    }
                    else {
                        msg = `Failed request: (${statusCode})`;
                    }
                    const err = new HttpClientError(msg, statusCode);
                    err.result = response.result;
                    reject(err);
                }
                else {
                    resolve(response);
                }
            }));
        });
    }
}
exports.HttpClient = HttpClient;
const lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => ((c[k.toLowerCase()] = obj[k]), c), {});
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 3833:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.checkBypass = exports.getProxyUrl = void 0;
function getProxyUrl(reqUrl) {
    const usingSsl = reqUrl.protocol === 'https:';
    if (checkBypass(reqUrl)) {
        return undefined;
    }
    const proxyVar = (() => {
        if (usingSsl) {
            return process.env['https_proxy'] || process.env['HTTPS_PROXY'];
        }
        else {
            return process.env['http_proxy'] || process.env['HTTP_PROXY'];
        }
    })();
    if (proxyVar) {
        return new URL(proxyVar);
    }
    else {
        return undefined;
    }
}
exports.getProxyUrl = getProxyUrl;
function checkBypass(reqUrl) {
    if (!reqUrl.hostname) {
        return false;
    }
    const noProxy = process.env['no_proxy'] || process.env['NO_PROXY'] || '';
    if (!noProxy) {
        return false;
    }
    // Determine the request port
    let reqPort;
    if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
    }
    else if (reqUrl.protocol === 'http:') {
        reqPort = 80;
    }
    else if (reqUrl.protocol === 'https:') {
        reqPort = 443;
    }
    // Format the request hostname and hostname with port
    const upperReqHosts = [reqUrl.hostname.toUpperCase()];
    if (typeof reqPort === 'number') {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
    }
    // Compare request host against noproxy
    for (const upperNoProxyItem of noProxy
        .split(',')
        .map(x => x.trim().toUpperCase())
        .filter(x => x)) {
        if (upperReqHosts.some(x => x === upperNoProxyItem)) {
            return true;
        }
    }
    return false;
}
exports.checkBypass = checkBypass;
//# sourceMappingURL=proxy.js.map

/***/ }),

/***/ 8397:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

!function(e){function r(e,r){"use strict";var t,a=r.ready.then((function(){function a(){if(0!==t._sodium_init())throw new Error("libsodium was not correctly initialized.");for(var r=["crypto_aead_chacha20poly1305_decrypt","crypto_aead_chacha20poly1305_decrypt_detached","crypto_aead_chacha20poly1305_encrypt","crypto_aead_chacha20poly1305_encrypt_detached","crypto_aead_chacha20poly1305_ietf_decrypt","crypto_aead_chacha20poly1305_ietf_decrypt_detached","crypto_aead_chacha20poly1305_ietf_encrypt","crypto_aead_chacha20poly1305_ietf_encrypt_detached","crypto_aead_chacha20poly1305_ietf_keygen","crypto_aead_chacha20poly1305_keygen","crypto_aead_xchacha20poly1305_ietf_decrypt","crypto_aead_xchacha20poly1305_ietf_decrypt_detached","crypto_aead_xchacha20poly1305_ietf_encrypt","crypto_aead_xchacha20poly1305_ietf_encrypt_detached","crypto_aead_xchacha20poly1305_ietf_keygen","crypto_auth","crypto_auth_hmacsha256","crypto_auth_hmacsha256_final","crypto_auth_hmacsha256_init","crypto_auth_hmacsha256_keygen","crypto_auth_hmacsha256_update","crypto_auth_hmacsha256_verify","crypto_auth_hmacsha512","crypto_auth_hmacsha512_final","crypto_auth_hmacsha512_init","crypto_auth_hmacsha512_keygen","crypto_auth_hmacsha512_update","crypto_auth_hmacsha512_verify","crypto_auth_keygen","crypto_auth_verify","crypto_box_beforenm","crypto_box_curve25519xchacha20poly1305_keypair","crypto_box_curve25519xchacha20poly1305_seal","crypto_box_curve25519xchacha20poly1305_seal_open","crypto_box_detached","crypto_box_easy","crypto_box_easy_afternm","crypto_box_keypair","crypto_box_open_detached","crypto_box_open_easy","crypto_box_open_easy_afternm","crypto_box_seal","crypto_box_seal_open","crypto_box_seed_keypair","crypto_core_ed25519_add","crypto_core_ed25519_from_hash","crypto_core_ed25519_from_uniform","crypto_core_ed25519_is_valid_point","crypto_core_ed25519_random","crypto_core_ed25519_scalar_add","crypto_core_ed25519_scalar_complement","crypto_core_ed25519_scalar_invert","crypto_core_ed25519_scalar_mul","crypto_core_ed25519_scalar_negate","crypto_core_ed25519_scalar_random","crypto_core_ed25519_scalar_reduce","crypto_core_ed25519_scalar_sub","crypto_core_ed25519_sub","crypto_core_hchacha20","crypto_core_hsalsa20","crypto_core_ristretto255_add","crypto_core_ristretto255_from_hash","crypto_core_ristretto255_is_valid_point","crypto_core_ristretto255_random","crypto_core_ristretto255_scalar_add","crypto_core_ristretto255_scalar_complement","crypto_core_ristretto255_scalar_invert","crypto_core_ristretto255_scalar_mul","crypto_core_ristretto255_scalar_negate","crypto_core_ristretto255_scalar_random","crypto_core_ristretto255_scalar_reduce","crypto_core_ristretto255_scalar_sub","crypto_core_ristretto255_sub","crypto_generichash","crypto_generichash_blake2b_salt_personal","crypto_generichash_final","crypto_generichash_init","crypto_generichash_keygen","crypto_generichash_update","crypto_hash","crypto_hash_sha256","crypto_hash_sha256_final","crypto_hash_sha256_init","crypto_hash_sha256_update","crypto_hash_sha512","crypto_hash_sha512_final","crypto_hash_sha512_init","crypto_hash_sha512_update","crypto_kdf_derive_from_key","crypto_kdf_keygen","crypto_kx_client_session_keys","crypto_kx_keypair","crypto_kx_seed_keypair","crypto_kx_server_session_keys","crypto_onetimeauth","crypto_onetimeauth_final","crypto_onetimeauth_init","crypto_onetimeauth_keygen","crypto_onetimeauth_update","crypto_onetimeauth_verify","crypto_pwhash","crypto_pwhash_scryptsalsa208sha256","crypto_pwhash_scryptsalsa208sha256_ll","crypto_pwhash_scryptsalsa208sha256_str","crypto_pwhash_scryptsalsa208sha256_str_verify","crypto_pwhash_str","crypto_pwhash_str_needs_rehash","crypto_pwhash_str_verify","crypto_scalarmult","crypto_scalarmult_base","crypto_scalarmult_ed25519","crypto_scalarmult_ed25519_base","crypto_scalarmult_ed25519_base_noclamp","crypto_scalarmult_ed25519_noclamp","crypto_scalarmult_ristretto255","crypto_scalarmult_ristretto255_base","crypto_secretbox_detached","crypto_secretbox_easy","crypto_secretbox_keygen","crypto_secretbox_open_detached","crypto_secretbox_open_easy","crypto_secretstream_xchacha20poly1305_init_pull","crypto_secretstream_xchacha20poly1305_init_push","crypto_secretstream_xchacha20poly1305_keygen","crypto_secretstream_xchacha20poly1305_pull","crypto_secretstream_xchacha20poly1305_push","crypto_secretstream_xchacha20poly1305_rekey","crypto_shorthash","crypto_shorthash_keygen","crypto_shorthash_siphashx24","crypto_sign","crypto_sign_detached","crypto_sign_ed25519_pk_to_curve25519","crypto_sign_ed25519_sk_to_curve25519","crypto_sign_ed25519_sk_to_pk","crypto_sign_ed25519_sk_to_seed","crypto_sign_final_create","crypto_sign_final_verify","crypto_sign_init","crypto_sign_keypair","crypto_sign_open","crypto_sign_seed_keypair","crypto_sign_update","crypto_sign_verify_detached","crypto_stream_chacha20","crypto_stream_chacha20_ietf_xor","crypto_stream_chacha20_ietf_xor_ic","crypto_stream_chacha20_keygen","crypto_stream_chacha20_xor","crypto_stream_chacha20_xor_ic","crypto_stream_keygen","crypto_stream_xchacha20_keygen","crypto_stream_xchacha20_xor","crypto_stream_xchacha20_xor_ic","randombytes_buf","randombytes_buf_deterministic","randombytes_close","randombytes_random","randombytes_set_implementation","randombytes_stir","randombytes_uniform","sodium_version_string"],a=[E,x,k,S,T,w,Y,B,A,K,M,I,N,L,U,O,C,R,P,G,X,D,F,V,H,q,j,z,W,J,Q,Z,$,ee,re,te,ae,_e,se,ne,ce,oe,he,pe,ye,ie,le,ue,de,ve,ge,be,fe,me,Ee,xe,ke,Se,Te,we,Ye,Be,Ae,Ke,Me,Ie,Ne,Le,Ue,Oe,Ce,Re,Pe,Ge,Xe,De,Fe,Ve,He,qe,je,ze,We,Je,Qe,Ze,$e,er,rr,tr,ar,_r,sr,nr,cr,or,hr,pr,yr,ir,lr,ur,dr,vr,gr,br,fr,mr,Er,xr,kr,Sr,Tr,wr,Yr,Br,Ar,Kr,Mr,Ir,Nr,Lr,Ur,Or,Cr,Rr,Pr,Gr,Xr,Dr,Fr,Vr,Hr,qr,jr,zr,Wr,Jr,Qr,Zr,$r,et,rt,tt,at,_t,st,nt,ct,ot,ht,pt,yt,it,lt,ut,dt,vt,gt,bt,ft,mt],_=0;_<a.length;_++)"function"==typeof t["_"+r[_]]&&(e[r[_]]=a[_]);var s=["SODIUM_LIBRARY_VERSION_MAJOR","SODIUM_LIBRARY_VERSION_MINOR","crypto_aead_chacha20poly1305_ABYTES","crypto_aead_chacha20poly1305_IETF_ABYTES","crypto_aead_chacha20poly1305_IETF_KEYBYTES","crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX","crypto_aead_chacha20poly1305_IETF_NPUBBYTES","crypto_aead_chacha20poly1305_IETF_NSECBYTES","crypto_aead_chacha20poly1305_KEYBYTES","crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX","crypto_aead_chacha20poly1305_NPUBBYTES","crypto_aead_chacha20poly1305_NSECBYTES","crypto_aead_chacha20poly1305_ietf_ABYTES","crypto_aead_chacha20poly1305_ietf_KEYBYTES","crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX","crypto_aead_chacha20poly1305_ietf_NPUBBYTES","crypto_aead_chacha20poly1305_ietf_NSECBYTES","crypto_aead_xchacha20poly1305_IETF_ABYTES","crypto_aead_xchacha20poly1305_IETF_KEYBYTES","crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX","crypto_aead_xchacha20poly1305_IETF_NPUBBYTES","crypto_aead_xchacha20poly1305_IETF_NSECBYTES","crypto_aead_xchacha20poly1305_ietf_ABYTES","crypto_aead_xchacha20poly1305_ietf_KEYBYTES","crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX","crypto_aead_xchacha20poly1305_ietf_NPUBBYTES","crypto_aead_xchacha20poly1305_ietf_NSECBYTES","crypto_auth_BYTES","crypto_auth_KEYBYTES","crypto_auth_hmacsha256_BYTES","crypto_auth_hmacsha256_KEYBYTES","crypto_auth_hmacsha512256_BYTES","crypto_auth_hmacsha512256_KEYBYTES","crypto_auth_hmacsha512_BYTES","crypto_auth_hmacsha512_KEYBYTES","crypto_box_BEFORENMBYTES","crypto_box_MACBYTES","crypto_box_MESSAGEBYTES_MAX","crypto_box_NONCEBYTES","crypto_box_PUBLICKEYBYTES","crypto_box_SEALBYTES","crypto_box_SECRETKEYBYTES","crypto_box_SEEDBYTES","crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES","crypto_box_curve25519xchacha20poly1305_MACBYTES","crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX","crypto_box_curve25519xchacha20poly1305_NONCEBYTES","crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES","crypto_box_curve25519xchacha20poly1305_SEALBYTES","crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES","crypto_box_curve25519xchacha20poly1305_SEEDBYTES","crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES","crypto_box_curve25519xsalsa20poly1305_MACBYTES","crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX","crypto_box_curve25519xsalsa20poly1305_NONCEBYTES","crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES","crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES","crypto_box_curve25519xsalsa20poly1305_SEEDBYTES","crypto_core_ed25519_BYTES","crypto_core_ed25519_HASHBYTES","crypto_core_ed25519_NONREDUCEDSCALARBYTES","crypto_core_ed25519_SCALARBYTES","crypto_core_ed25519_UNIFORMBYTES","crypto_core_hchacha20_CONSTBYTES","crypto_core_hchacha20_INPUTBYTES","crypto_core_hchacha20_KEYBYTES","crypto_core_hchacha20_OUTPUTBYTES","crypto_core_hsalsa20_CONSTBYTES","crypto_core_hsalsa20_INPUTBYTES","crypto_core_hsalsa20_KEYBYTES","crypto_core_hsalsa20_OUTPUTBYTES","crypto_core_ristretto255_BYTES","crypto_core_ristretto255_HASHBYTES","crypto_core_ristretto255_NONREDUCEDSCALARBYTES","crypto_core_ristretto255_SCALARBYTES","crypto_core_salsa2012_CONSTBYTES","crypto_core_salsa2012_INPUTBYTES","crypto_core_salsa2012_KEYBYTES","crypto_core_salsa2012_OUTPUTBYTES","crypto_core_salsa20_CONSTBYTES","crypto_core_salsa20_INPUTBYTES","crypto_core_salsa20_KEYBYTES","crypto_core_salsa20_OUTPUTBYTES","crypto_generichash_BYTES","crypto_generichash_BYTES_MAX","crypto_generichash_BYTES_MIN","crypto_generichash_KEYBYTES","crypto_generichash_KEYBYTES_MAX","crypto_generichash_KEYBYTES_MIN","crypto_generichash_blake2b_BYTES","crypto_generichash_blake2b_BYTES_MAX","crypto_generichash_blake2b_BYTES_MIN","crypto_generichash_blake2b_KEYBYTES","crypto_generichash_blake2b_KEYBYTES_MAX","crypto_generichash_blake2b_KEYBYTES_MIN","crypto_generichash_blake2b_PERSONALBYTES","crypto_generichash_blake2b_SALTBYTES","crypto_hash_BYTES","crypto_hash_sha256_BYTES","crypto_hash_sha512_BYTES","crypto_kdf_BYTES_MAX","crypto_kdf_BYTES_MIN","crypto_kdf_CONTEXTBYTES","crypto_kdf_KEYBYTES","crypto_kdf_blake2b_BYTES_MAX","crypto_kdf_blake2b_BYTES_MIN","crypto_kdf_blake2b_CONTEXTBYTES","crypto_kdf_blake2b_KEYBYTES","crypto_kx_PUBLICKEYBYTES","crypto_kx_SECRETKEYBYTES","crypto_kx_SEEDBYTES","crypto_kx_SESSIONKEYBYTES","crypto_onetimeauth_BYTES","crypto_onetimeauth_KEYBYTES","crypto_onetimeauth_poly1305_BYTES","crypto_onetimeauth_poly1305_KEYBYTES","crypto_pwhash_ALG_ARGON2I13","crypto_pwhash_ALG_ARGON2ID13","crypto_pwhash_ALG_DEFAULT","crypto_pwhash_BYTES_MAX","crypto_pwhash_BYTES_MIN","crypto_pwhash_MEMLIMIT_INTERACTIVE","crypto_pwhash_MEMLIMIT_MAX","crypto_pwhash_MEMLIMIT_MIN","crypto_pwhash_MEMLIMIT_MODERATE","crypto_pwhash_MEMLIMIT_SENSITIVE","crypto_pwhash_OPSLIMIT_INTERACTIVE","crypto_pwhash_OPSLIMIT_MAX","crypto_pwhash_OPSLIMIT_MIN","crypto_pwhash_OPSLIMIT_MODERATE","crypto_pwhash_OPSLIMIT_SENSITIVE","crypto_pwhash_PASSWD_MAX","crypto_pwhash_PASSWD_MIN","crypto_pwhash_SALTBYTES","crypto_pwhash_STRBYTES","crypto_pwhash_argon2i_BYTES_MAX","crypto_pwhash_argon2i_BYTES_MIN","crypto_pwhash_argon2i_SALTBYTES","crypto_pwhash_argon2i_STRBYTES","crypto_pwhash_argon2id_BYTES_MAX","crypto_pwhash_argon2id_BYTES_MIN","crypto_pwhash_argon2id_SALTBYTES","crypto_pwhash_argon2id_STRBYTES","crypto_pwhash_scryptsalsa208sha256_BYTES_MAX","crypto_pwhash_scryptsalsa208sha256_BYTES_MIN","crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE","crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX","crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN","crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE","crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE","crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX","crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN","crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE","crypto_pwhash_scryptsalsa208sha256_SALTBYTES","crypto_pwhash_scryptsalsa208sha256_STRBYTES","crypto_scalarmult_BYTES","crypto_scalarmult_SCALARBYTES","crypto_scalarmult_curve25519_BYTES","crypto_scalarmult_curve25519_SCALARBYTES","crypto_scalarmult_ed25519_BYTES","crypto_scalarmult_ed25519_SCALARBYTES","crypto_scalarmult_ristretto255_BYTES","crypto_scalarmult_ristretto255_SCALARBYTES","crypto_secretbox_KEYBYTES","crypto_secretbox_MACBYTES","crypto_secretbox_MESSAGEBYTES_MAX","crypto_secretbox_NONCEBYTES","crypto_secretbox_xchacha20poly1305_KEYBYTES","crypto_secretbox_xchacha20poly1305_MACBYTES","crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX","crypto_secretbox_xchacha20poly1305_NONCEBYTES","crypto_secretbox_xsalsa20poly1305_KEYBYTES","crypto_secretbox_xsalsa20poly1305_MACBYTES","crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX","crypto_secretbox_xsalsa20poly1305_NONCEBYTES","crypto_secretstream_xchacha20poly1305_ABYTES","crypto_secretstream_xchacha20poly1305_HEADERBYTES","crypto_secretstream_xchacha20poly1305_KEYBYTES","crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX","crypto_secretstream_xchacha20poly1305_TAG_FINAL","crypto_secretstream_xchacha20poly1305_TAG_MESSAGE","crypto_secretstream_xchacha20poly1305_TAG_PUSH","crypto_secretstream_xchacha20poly1305_TAG_REKEY","crypto_shorthash_BYTES","crypto_shorthash_KEYBYTES","crypto_shorthash_siphash24_BYTES","crypto_shorthash_siphash24_KEYBYTES","crypto_shorthash_siphashx24_BYTES","crypto_shorthash_siphashx24_KEYBYTES","crypto_sign_BYTES","crypto_sign_MESSAGEBYTES_MAX","crypto_sign_PUBLICKEYBYTES","crypto_sign_SECRETKEYBYTES","crypto_sign_SEEDBYTES","crypto_sign_ed25519_BYTES","crypto_sign_ed25519_MESSAGEBYTES_MAX","crypto_sign_ed25519_PUBLICKEYBYTES","crypto_sign_ed25519_SECRETKEYBYTES","crypto_sign_ed25519_SEEDBYTES","crypto_stream_KEYBYTES","crypto_stream_MESSAGEBYTES_MAX","crypto_stream_NONCEBYTES","crypto_stream_chacha20_IETF_KEYBYTES","crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX","crypto_stream_chacha20_IETF_NONCEBYTES","crypto_stream_chacha20_KEYBYTES","crypto_stream_chacha20_MESSAGEBYTES_MAX","crypto_stream_chacha20_NONCEBYTES","crypto_stream_chacha20_ietf_KEYBYTES","crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX","crypto_stream_chacha20_ietf_NONCEBYTES","crypto_stream_salsa2012_KEYBYTES","crypto_stream_salsa2012_MESSAGEBYTES_MAX","crypto_stream_salsa2012_NONCEBYTES","crypto_stream_salsa208_KEYBYTES","crypto_stream_salsa208_MESSAGEBYTES_MAX","crypto_stream_salsa208_NONCEBYTES","crypto_stream_salsa20_KEYBYTES","crypto_stream_salsa20_MESSAGEBYTES_MAX","crypto_stream_salsa20_NONCEBYTES","crypto_stream_xchacha20_KEYBYTES","crypto_stream_xchacha20_MESSAGEBYTES_MAX","crypto_stream_xchacha20_NONCEBYTES","crypto_stream_xsalsa20_KEYBYTES","crypto_stream_xsalsa20_MESSAGEBYTES_MAX","crypto_stream_xsalsa20_NONCEBYTES","crypto_verify_16_BYTES","crypto_verify_32_BYTES","crypto_verify_64_BYTES"];for(_=0;_<s.length;_++)"function"==typeof(c=t["_"+s[_].toLowerCase()])&&(e[s[_]]=c());var n=["SODIUM_VERSION_STRING","crypto_pwhash_STRPREFIX","crypto_pwhash_scryptsalsa208sha256_STRPREFIX"];for(_=0;_<n.length;_++){var c;"function"==typeof(c=t["_"+n[_].toLowerCase()])&&(e[n[_]]=t.UTF8ToString(c()))}}t=r;try{a();var _=new Uint8Array([98,97,108,108,115]),s=e.randombytes_buf(e.crypto_secretbox_NONCEBYTES),n=e.randombytes_buf(e.crypto_secretbox_KEYBYTES),c=e.crypto_secretbox_easy(_,s,n),o=e.crypto_secretbox_open_easy(c,s,n);if(e.memcmp(_,o))return}catch(e){if(null==t.useBackupModule)throw new Error("Both wasm and asm failed to load"+e)}t.useBackupModule(),a()}));function _(e){if("function"==typeof TextEncoder)return(new TextEncoder).encode(e);e=unescape(encodeURIComponent(e));for(var r=new Uint8Array(e.length),t=0,a=e.length;t<a;t++)r[t]=e.charCodeAt(t);return r}function s(e){if("function"==typeof TextDecoder)return new TextDecoder("utf-8",{fatal:!0}).decode(e);var r=8192,t=Math.ceil(e.length/r);if(t<=1)try{return decodeURIComponent(escape(String.fromCharCode.apply(null,e)))}catch(e){throw new TypeError("The encoded data was not valid.")}for(var a="",_=0,n=0;n<t;n++){var c=Array.prototype.slice.call(e,n*r+_,(n+1)*r+_);if(0!=c.length){var o,h=c.length,p=0;do{var y=c[--h];y>=240?(p=4,o=!0):y>=224?(p=3,o=!0):y>=192?(p=2,o=!0):y<128&&(p=1,o=!0)}while(!o);for(var i=p-(c.length-h),l=0;l<i;l++)_--,c.pop();a+=s(c)}}return a}function n(e){e=m(null,e,"input");for(var r,t,a,_="",s=0;s<e.length;s++)a=87+(t=15&e[s])+(t-10>>8&-39)<<8|87+(r=e[s]>>>4)+(r-10>>8&-39),_+=String.fromCharCode(255&a)+String.fromCharCode(a>>>8);return _}var c={ORIGINAL:1,ORIGINAL_NO_PADDING:3,URLSAFE:5,URLSAFE_NO_PADDING:7};function o(e){if(null==e)return c.URLSAFE_NO_PADDING;if(e!==c.ORIGINAL&&e!==c.ORIGINAL_NO_PADDING&&e!==c.URLSAFE&&e!=c.URLSAFE_NO_PADDING)throw new Error("unsupported base64 variant");return e}function h(e,r){r=o(r),e=m(_,e,"input");var a,_=[],n=0|Math.floor(e.length/3),c=e.length-3*n,h=4*n+(0!==c?0==(2&r)?4:2+(c>>>1):0),p=new l(h+1),y=u(e);return _.push(y),_.push(p.address),0===t._sodium_bin2base64(p.address,p.length,y,e.length,r)&&g(_,"conversion failed"),p.length=h,a=s(p.to_Uint8Array()),v(_),a}function p(e,r){var t=r||"uint8array";if(!y(t))throw new Error(t+" output format is not available");if(e instanceof l){if("uint8array"===t)return e.to_Uint8Array();if("text"===t)return s(e.to_Uint8Array());if("hex"===t)return n(e.to_Uint8Array());if("base64"===t)return h(e.to_Uint8Array(),c.URLSAFE_NO_PADDING);throw new Error('What is output format "'+t+'"?')}if("object"==typeof e){for(var a=Object.keys(e),_={},o=0;o<a.length;o++)_[a[o]]=p(e[a[o]],t);return _}if("string"==typeof e)return e;throw new TypeError("Cannot format output")}function y(e){for(var r=["uint8array","text","hex","base64"],t=0;t<r.length;t++)if(r[t]===e)return!0;return!1}function i(e){if(e){if("string"!=typeof e)throw new TypeError("When defined, the output format must be a string");if(!y(e))throw new Error(e+" is not a supported output format")}}function l(e){this.length=e,this.address=d(e)}function u(e){var r=d(e.length);return t.HEAPU8.set(e,r),r}function d(e){var r=t._malloc(e);if(0===r)throw{message:"_malloc() failed",length:e};return r}function v(e){if(e)for(var r=0;r<e.length;r++)a=e[r],t._free(a);var a}function g(e,r){throw v(e),new Error(r)}function b(e,r){throw v(e),new TypeError(r)}function f(e,r,t){null==r&&b(e,t+" cannot be null or undefined")}function m(e,r,t){return f(e,r,t),r instanceof Uint8Array?r:"string"==typeof r?_(r):void b(e,"unsupported input type for "+t)}function E(e,r,a,_,s,n){var c=[];i(n);var o=null;null!=e&&(o=u(e=m(c,e,"secret_nonce")),e.length,c.push(o)),r=m(c,r,"ciphertext");var h,y=t._crypto_aead_chacha20poly1305_abytes(),d=r.length;d<y&&b(c,"ciphertext is too short"),h=u(r),c.push(h);var f=null,E=0;null!=a&&(f=u(a=m(c,a,"additional_data")),E=a.length,c.push(f)),_=m(c,_,"public_nonce");var x,k=0|t._crypto_aead_chacha20poly1305_npubbytes();_.length!==k&&b(c,"invalid public_nonce length"),x=u(_),c.push(x),s=m(c,s,"key");var S,T=0|t._crypto_aead_chacha20poly1305_keybytes();s.length!==T&&b(c,"invalid key length"),S=u(s),c.push(S);var w=new l(d-t._crypto_aead_chacha20poly1305_abytes()|0),Y=w.address;if(c.push(Y),0===t._crypto_aead_chacha20poly1305_decrypt(Y,null,o,h,d,0,f,E,0,x,S)){var B=p(w,n);return v(c),B}g(c,"ciphertext cannot be decrypted using that key")}function x(e,r,a,_,s,n,c){var o=[];i(c);var h=null;null!=e&&(h=u(e=m(o,e,"secret_nonce")),e.length,o.push(h));var y=u(r=m(o,r,"ciphertext")),d=r.length;o.push(y),a=m(o,a,"mac");var f,E=0|t._crypto_box_macbytes();a.length!==E&&b(o,"invalid mac length"),f=u(a),o.push(f);var x=null,k=0;null!=_&&(x=u(_=m(o,_,"additional_data")),k=_.length,o.push(x)),s=m(o,s,"public_nonce");var S,T=0|t._crypto_aead_chacha20poly1305_npubbytes();s.length!==T&&b(o,"invalid public_nonce length"),S=u(s),o.push(S),n=m(o,n,"key");var w,Y=0|t._crypto_aead_chacha20poly1305_keybytes();n.length!==Y&&b(o,"invalid key length"),w=u(n),o.push(w);var B=new l(0|d),A=B.address;if(o.push(A),0===t._crypto_aead_chacha20poly1305_decrypt_detached(A,h,y,d,0,f,x,k,0,S,w)){var K=p(B,c);return v(o),K}g(o,"ciphertext cannot be decrypted using that key")}function k(e,r,a,_,s,n){var c=[];i(n);var o=u(e=m(c,e,"message")),h=e.length;c.push(o);var y=null,d=0;null!=r&&(y=u(r=m(c,r,"additional_data")),d=r.length,c.push(y));var f=null;null!=a&&(f=u(a=m(c,a,"secret_nonce")),a.length,c.push(f)),_=m(c,_,"public_nonce");var E,x=0|t._crypto_aead_chacha20poly1305_npubbytes();_.length!==x&&b(c,"invalid public_nonce length"),E=u(_),c.push(E),s=m(c,s,"key");var k,S=0|t._crypto_aead_chacha20poly1305_keybytes();s.length!==S&&b(c,"invalid key length"),k=u(s),c.push(k);var T=new l(h+t._crypto_aead_chacha20poly1305_abytes()|0),w=T.address;if(c.push(w),0===t._crypto_aead_chacha20poly1305_encrypt(w,null,o,h,0,y,d,0,f,E,k)){var Y=p(T,n);return v(c),Y}g(c,"invalid usage")}function S(e,r,a,_,s,n){var c=[];i(n);var o=u(e=m(c,e,"message")),h=e.length;c.push(o);var y=null,d=0;null!=r&&(y=u(r=m(c,r,"additional_data")),d=r.length,c.push(y));var f=null;null!=a&&(f=u(a=m(c,a,"secret_nonce")),a.length,c.push(f)),_=m(c,_,"public_nonce");var E,x=0|t._crypto_aead_chacha20poly1305_npubbytes();_.length!==x&&b(c,"invalid public_nonce length"),E=u(_),c.push(E),s=m(c,s,"key");var k,S=0|t._crypto_aead_chacha20poly1305_keybytes();s.length!==S&&b(c,"invalid key length"),k=u(s),c.push(k);var T=new l(0|h),w=T.address;c.push(w);var Y=new l(0|t._crypto_aead_chacha20poly1305_abytes()),B=Y.address;if(c.push(B),0===t._crypto_aead_chacha20poly1305_encrypt_detached(w,B,null,o,h,0,y,d,0,f,E,k)){var A=p({ciphertext:T,mac:Y},n);return v(c),A}g(c,"invalid usage")}function T(e,r,a,_,s,n){var c=[];i(n);var o=null;null!=e&&(o=u(e=m(c,e,"secret_nonce")),e.length,c.push(o)),r=m(c,r,"ciphertext");var h,y=t._crypto_aead_chacha20poly1305_ietf_abytes(),d=r.length;d<y&&b(c,"ciphertext is too short"),h=u(r),c.push(h);var f=null,E=0;null!=a&&(f=u(a=m(c,a,"additional_data")),E=a.length,c.push(f)),_=m(c,_,"public_nonce");var x,k=0|t._crypto_aead_chacha20poly1305_ietf_npubbytes();_.length!==k&&b(c,"invalid public_nonce length"),x=u(_),c.push(x),s=m(c,s,"key");var S,T=0|t._crypto_aead_chacha20poly1305_ietf_keybytes();s.length!==T&&b(c,"invalid key length"),S=u(s),c.push(S);var w=new l(d-t._crypto_aead_chacha20poly1305_ietf_abytes()|0),Y=w.address;if(c.push(Y),0===t._crypto_aead_chacha20poly1305_ietf_decrypt(Y,null,o,h,d,0,f,E,0,x,S)){var B=p(w,n);return v(c),B}g(c,"ciphertext cannot be decrypted using that key")}function w(e,r,a,_,s,n,c){var o=[];i(c);var h=null;null!=e&&(h=u(e=m(o,e,"secret_nonce")),e.length,o.push(h));var y=u(r=m(o,r,"ciphertext")),d=r.length;o.push(y),a=m(o,a,"mac");var f,E=0|t._crypto_box_macbytes();a.length!==E&&b(o,"invalid mac length"),f=u(a),o.push(f);var x=null,k=0;null!=_&&(x=u(_=m(o,_,"additional_data")),k=_.length,o.push(x)),s=m(o,s,"public_nonce");var S,T=0|t._crypto_aead_chacha20poly1305_ietf_npubbytes();s.length!==T&&b(o,"invalid public_nonce length"),S=u(s),o.push(S),n=m(o,n,"key");var w,Y=0|t._crypto_aead_chacha20poly1305_ietf_keybytes();n.length!==Y&&b(o,"invalid key length"),w=u(n),o.push(w);var B=new l(0|d),A=B.address;if(o.push(A),0===t._crypto_aead_chacha20poly1305_ietf_decrypt_detached(A,h,y,d,0,f,x,k,0,S,w)){var K=p(B,c);return v(o),K}g(o,"ciphertext cannot be decrypted using that key")}function Y(e,r,a,_,s,n){var c=[];i(n);var o=u(e=m(c,e,"message")),h=e.length;c.push(o);var y=null,d=0;null!=r&&(y=u(r=m(c,r,"additional_data")),d=r.length,c.push(y));var f=null;null!=a&&(f=u(a=m(c,a,"secret_nonce")),a.length,c.push(f)),_=m(c,_,"public_nonce");var E,x=0|t._crypto_aead_chacha20poly1305_ietf_npubbytes();_.length!==x&&b(c,"invalid public_nonce length"),E=u(_),c.push(E),s=m(c,s,"key");var k,S=0|t._crypto_aead_chacha20poly1305_ietf_keybytes();s.length!==S&&b(c,"invalid key length"),k=u(s),c.push(k);var T=new l(h+t._crypto_aead_chacha20poly1305_ietf_abytes()|0),w=T.address;if(c.push(w),0===t._crypto_aead_chacha20poly1305_ietf_encrypt(w,null,o,h,0,y,d,0,f,E,k)){var Y=p(T,n);return v(c),Y}g(c,"invalid usage")}function B(e,r,a,_,s,n){var c=[];i(n);var o=u(e=m(c,e,"message")),h=e.length;c.push(o);var y=null,d=0;null!=r&&(y=u(r=m(c,r,"additional_data")),d=r.length,c.push(y));var f=null;null!=a&&(f=u(a=m(c,a,"secret_nonce")),a.length,c.push(f)),_=m(c,_,"public_nonce");var E,x=0|t._crypto_aead_chacha20poly1305_ietf_npubbytes();_.length!==x&&b(c,"invalid public_nonce length"),E=u(_),c.push(E),s=m(c,s,"key");var k,S=0|t._crypto_aead_chacha20poly1305_ietf_keybytes();s.length!==S&&b(c,"invalid key length"),k=u(s),c.push(k);var T=new l(0|h),w=T.address;c.push(w);var Y=new l(0|t._crypto_aead_chacha20poly1305_ietf_abytes()),B=Y.address;if(c.push(B),0===t._crypto_aead_chacha20poly1305_ietf_encrypt_detached(w,B,null,o,h,0,y,d,0,f,E,k)){var A=p({ciphertext:T,mac:Y},n);return v(c),A}g(c,"invalid usage")}function A(e){var r=[];i(e);var a=new l(0|t._crypto_aead_chacha20poly1305_ietf_keybytes()),_=a.address;r.push(_),t._crypto_aead_chacha20poly1305_ietf_keygen(_);var s=p(a,e);return v(r),s}function K(e){var r=[];i(e);var a=new l(0|t._crypto_aead_chacha20poly1305_keybytes()),_=a.address;r.push(_),t._crypto_aead_chacha20poly1305_keygen(_);var s=p(a,e);return v(r),s}function M(e,r,a,_,s,n){var c=[];i(n);var o=null;null!=e&&(o=u(e=m(c,e,"secret_nonce")),e.length,c.push(o)),r=m(c,r,"ciphertext");var h,y=t._crypto_aead_xchacha20poly1305_ietf_abytes(),d=r.length;d<y&&b(c,"ciphertext is too short"),h=u(r),c.push(h);var f=null,E=0;null!=a&&(f=u(a=m(c,a,"additional_data")),E=a.length,c.push(f)),_=m(c,_,"public_nonce");var x,k=0|t._crypto_aead_xchacha20poly1305_ietf_npubbytes();_.length!==k&&b(c,"invalid public_nonce length"),x=u(_),c.push(x),s=m(c,s,"key");var S,T=0|t._crypto_aead_xchacha20poly1305_ietf_keybytes();s.length!==T&&b(c,"invalid key length"),S=u(s),c.push(S);var w=new l(d-t._crypto_aead_xchacha20poly1305_ietf_abytes()|0),Y=w.address;if(c.push(Y),0===t._crypto_aead_xchacha20poly1305_ietf_decrypt(Y,null,o,h,d,0,f,E,0,x,S)){var B=p(w,n);return v(c),B}g(c,"ciphertext cannot be decrypted using that key")}function I(e,r,a,_,s,n,c){var o=[];i(c);var h=null;null!=e&&(h=u(e=m(o,e,"secret_nonce")),e.length,o.push(h));var y=u(r=m(o,r,"ciphertext")),d=r.length;o.push(y),a=m(o,a,"mac");var f,E=0|t._crypto_box_macbytes();a.length!==E&&b(o,"invalid mac length"),f=u(a),o.push(f);var x=null,k=0;null!=_&&(x=u(_=m(o,_,"additional_data")),k=_.length,o.push(x)),s=m(o,s,"public_nonce");var S,T=0|t._crypto_aead_xchacha20poly1305_ietf_npubbytes();s.length!==T&&b(o,"invalid public_nonce length"),S=u(s),o.push(S),n=m(o,n,"key");var w,Y=0|t._crypto_aead_xchacha20poly1305_ietf_keybytes();n.length!==Y&&b(o,"invalid key length"),w=u(n),o.push(w);var B=new l(0|d),A=B.address;if(o.push(A),0===t._crypto_aead_xchacha20poly1305_ietf_decrypt_detached(A,h,y,d,0,f,x,k,0,S,w)){var K=p(B,c);return v(o),K}g(o,"ciphertext cannot be decrypted using that key")}function N(e,r,a,_,s,n){var c=[];i(n);var o=u(e=m(c,e,"message")),h=e.length;c.push(o);var y=null,d=0;null!=r&&(y=u(r=m(c,r,"additional_data")),d=r.length,c.push(y));var f=null;null!=a&&(f=u(a=m(c,a,"secret_nonce")),a.length,c.push(f)),_=m(c,_,"public_nonce");var E,x=0|t._crypto_aead_xchacha20poly1305_ietf_npubbytes();_.length!==x&&b(c,"invalid public_nonce length"),E=u(_),c.push(E),s=m(c,s,"key");var k,S=0|t._crypto_aead_xchacha20poly1305_ietf_keybytes();s.length!==S&&b(c,"invalid key length"),k=u(s),c.push(k);var T=new l(h+t._crypto_aead_xchacha20poly1305_ietf_abytes()|0),w=T.address;if(c.push(w),0===t._crypto_aead_xchacha20poly1305_ietf_encrypt(w,null,o,h,0,y,d,0,f,E,k)){var Y=p(T,n);return v(c),Y}g(c,"invalid usage")}function L(e,r,a,_,s,n){var c=[];i(n);var o=u(e=m(c,e,"message")),h=e.length;c.push(o);var y=null,d=0;null!=r&&(y=u(r=m(c,r,"additional_data")),d=r.length,c.push(y));var f=null;null!=a&&(f=u(a=m(c,a,"secret_nonce")),a.length,c.push(f)),_=m(c,_,"public_nonce");var E,x=0|t._crypto_aead_xchacha20poly1305_ietf_npubbytes();_.length!==x&&b(c,"invalid public_nonce length"),E=u(_),c.push(E),s=m(c,s,"key");var k,S=0|t._crypto_aead_xchacha20poly1305_ietf_keybytes();s.length!==S&&b(c,"invalid key length"),k=u(s),c.push(k);var T=new l(0|h),w=T.address;c.push(w);var Y=new l(0|t._crypto_aead_xchacha20poly1305_ietf_abytes()),B=Y.address;if(c.push(B),0===t._crypto_aead_xchacha20poly1305_ietf_encrypt_detached(w,B,null,o,h,0,y,d,0,f,E,k)){var A=p({ciphertext:T,mac:Y},n);return v(c),A}g(c,"invalid usage")}function U(e){var r=[];i(e);var a=new l(0|t._crypto_aead_xchacha20poly1305_ietf_keybytes()),_=a.address;r.push(_),t._crypto_aead_xchacha20poly1305_ietf_keygen(_);var s=p(a,e);return v(r),s}function O(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"key");var c,o=0|t._crypto_auth_keybytes();r.length!==o&&b(_,"invalid key length"),c=u(r),_.push(c);var h=new l(0|t._crypto_auth_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_auth(y,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function C(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"key");var c,o=0|t._crypto_auth_hmacsha256_keybytes();r.length!==o&&b(_,"invalid key length"),c=u(r),_.push(c);var h=new l(0|t._crypto_auth_hmacsha256_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_auth_hmacsha256(y,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function R(e,r){var a=[];i(r),f(a,e,"state_address");var _=new l(0|t._crypto_auth_hmacsha256_bytes()),s=_.address;if(a.push(s),0==(0|t._crypto_auth_hmacsha256_final(e,s))){var n=(t._free(e),p(_,r));return v(a),n}g(a,"invalid usage")}function P(e,r){var a=[];i(r);var _=null,s=0;null!=e&&(_=u(e=m(a,e,"key")),s=e.length,a.push(_));var n=new l(208).address;if(0==(0|t._crypto_auth_hmacsha256_init(n,_,s))){var c=n;return v(a),c}g(a,"invalid usage")}function G(e){var r=[];i(e);var a=new l(0|t._crypto_auth_hmacsha256_keybytes()),_=a.address;r.push(_),t._crypto_auth_hmacsha256_keygen(_);var s=p(a,e);return v(r),s}function X(e,r,a){var _=[];i(a),f(_,e,"state_address");var s=u(r=m(_,r,"message_chunk")),n=r.length;_.push(s),0!=(0|t._crypto_auth_hmacsha256_update(e,s,n))&&g(_,"invalid usage"),v(_)}function D(e,r,a){var _=[];e=m(_,e,"tag");var s,n=0|t._crypto_auth_hmacsha256_bytes();e.length!==n&&b(_,"invalid tag length"),s=u(e),_.push(s);var c=u(r=m(_,r,"message")),o=r.length;_.push(c),a=m(_,a,"key");var h,p=0|t._crypto_auth_hmacsha256_keybytes();a.length!==p&&b(_,"invalid key length"),h=u(a),_.push(h);var y=0==(0|t._crypto_auth_hmacsha256_verify(s,c,o,0,h));return v(_),y}function F(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"key");var c,o=0|t._crypto_auth_hmacsha512_keybytes();r.length!==o&&b(_,"invalid key length"),c=u(r),_.push(c);var h=new l(0|t._crypto_auth_hmacsha512_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_auth_hmacsha512(y,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function V(e,r){var a=[];i(r),f(a,e,"state_address");var _=new l(0|t._crypto_auth_hmacsha512_bytes()),s=_.address;if(a.push(s),0==(0|t._crypto_auth_hmacsha512_final(e,s))){var n=(t._free(e),p(_,r));return v(a),n}g(a,"invalid usage")}function H(e,r){var a=[];i(r);var _=null,s=0;null!=e&&(_=u(e=m(a,e,"key")),s=e.length,a.push(_));var n=new l(416).address;if(0==(0|t._crypto_auth_hmacsha512_init(n,_,s))){var c=n;return v(a),c}g(a,"invalid usage")}function q(e){var r=[];i(e);var a=new l(0|t._crypto_auth_hmacsha512_keybytes()),_=a.address;r.push(_),t._crypto_auth_hmacsha512_keygen(_);var s=p(a,e);return v(r),s}function j(e,r,a){var _=[];i(a),f(_,e,"state_address");var s=u(r=m(_,r,"message_chunk")),n=r.length;_.push(s),0!=(0|t._crypto_auth_hmacsha512_update(e,s,n))&&g(_,"invalid usage"),v(_)}function z(e,r,a){var _=[];e=m(_,e,"tag");var s,n=0|t._crypto_auth_hmacsha512_bytes();e.length!==n&&b(_,"invalid tag length"),s=u(e),_.push(s);var c=u(r=m(_,r,"message")),o=r.length;_.push(c),a=m(_,a,"key");var h,p=0|t._crypto_auth_hmacsha512_keybytes();a.length!==p&&b(_,"invalid key length"),h=u(a),_.push(h);var y=0==(0|t._crypto_auth_hmacsha512_verify(s,c,o,0,h));return v(_),y}function W(e){var r=[];i(e);var a=new l(0|t._crypto_auth_keybytes()),_=a.address;r.push(_),t._crypto_auth_keygen(_);var s=p(a,e);return v(r),s}function J(e,r,a){var _=[];e=m(_,e,"tag");var s,n=0|t._crypto_auth_bytes();e.length!==n&&b(_,"invalid tag length"),s=u(e),_.push(s);var c=u(r=m(_,r,"message")),o=r.length;_.push(c),a=m(_,a,"key");var h,p=0|t._crypto_auth_keybytes();a.length!==p&&b(_,"invalid key length"),h=u(a),_.push(h);var y=0==(0|t._crypto_auth_verify(s,c,o,0,h));return v(_),y}function Q(e,r,a){var _=[];i(a),e=m(_,e,"publicKey");var s,n=0|t._crypto_box_publickeybytes();e.length!==n&&b(_,"invalid publicKey length"),s=u(e),_.push(s),r=m(_,r,"privateKey");var c,o=0|t._crypto_box_secretkeybytes();r.length!==o&&b(_,"invalid privateKey length"),c=u(r),_.push(c);var h=new l(0|t._crypto_box_beforenmbytes()),y=h.address;if(_.push(y),0==(0|t._crypto_box_beforenm(y,s,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function Z(e){var r=[];i(e);var a=new l(0|t._crypto_box_curve25519xchacha20poly1305_publickeybytes()),_=a.address;r.push(_);var s=new l(0|t._crypto_box_curve25519xchacha20poly1305_secretkeybytes()),n=s.address;r.push(n),t._crypto_box_curve25519xchacha20poly1305_keypair(_,n);var c=p({publicKey:a,privateKey:s,keyType:"curve25519"},e);return v(r),c}function $(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"publicKey");var c,o=0|t._crypto_box_curve25519xchacha20poly1305_publickeybytes();r.length!==o&&b(_,"invalid publicKey length"),c=u(r),_.push(c);var h=new l(n+t._crypto_box_curve25519xchacha20poly1305_sealbytes()|0),y=h.address;_.push(y),t._crypto_box_curve25519xchacha20poly1305_seal(y,s,n,0,c);var d=p(h,a);return v(_),d}function ee(e,r,a,_){var s=[];i(_),e=m(s,e,"ciphertext");var n,c=t._crypto_box_curve25519xchacha20poly1305_sealbytes(),o=e.length;o<c&&b(s,"ciphertext is too short"),n=u(e),s.push(n),r=m(s,r,"publicKey");var h,y=0|t._crypto_box_curve25519xchacha20poly1305_publickeybytes();r.length!==y&&b(s,"invalid publicKey length"),h=u(r),s.push(h),a=m(s,a,"secretKey");var d,g=0|t._crypto_box_curve25519xchacha20poly1305_secretkeybytes();a.length!==g&&b(s,"invalid secretKey length"),d=u(a),s.push(d);var f=new l(o-t._crypto_box_curve25519xchacha20poly1305_sealbytes()|0),E=f.address;s.push(E),t._crypto_box_curve25519xchacha20poly1305_seal_open(E,n,o,0,h,d);var x=p(f,_);return v(s),x}function re(e,r,a,_,s){var n=[];i(s);var c=u(e=m(n,e,"message")),o=e.length;n.push(c),r=m(n,r,"nonce");var h,y=0|t._crypto_box_noncebytes();r.length!==y&&b(n,"invalid nonce length"),h=u(r),n.push(h),a=m(n,a,"publicKey");var d,f=0|t._crypto_box_publickeybytes();a.length!==f&&b(n,"invalid publicKey length"),d=u(a),n.push(d),_=m(n,_,"privateKey");var E,x=0|t._crypto_box_secretkeybytes();_.length!==x&&b(n,"invalid privateKey length"),E=u(_),n.push(E);var k=new l(0|o),S=k.address;n.push(S);var T=new l(0|t._crypto_box_macbytes()),w=T.address;if(n.push(w),0==(0|t._crypto_box_detached(S,w,c,o,0,h,d,E))){var Y=p({ciphertext:k,mac:T},s);return v(n),Y}g(n,"invalid usage")}function te(e,r,a,_,s){var n=[];i(s);var c=u(e=m(n,e,"message")),o=e.length;n.push(c),r=m(n,r,"nonce");var h,y=0|t._crypto_box_noncebytes();r.length!==y&&b(n,"invalid nonce length"),h=u(r),n.push(h),a=m(n,a,"publicKey");var d,f=0|t._crypto_box_publickeybytes();a.length!==f&&b(n,"invalid publicKey length"),d=u(a),n.push(d),_=m(n,_,"privateKey");var E,x=0|t._crypto_box_secretkeybytes();_.length!==x&&b(n,"invalid privateKey length"),E=u(_),n.push(E);var k=new l(o+t._crypto_box_macbytes()|0),S=k.address;if(n.push(S),0==(0|t._crypto_box_easy(S,c,o,0,h,d,E))){var T=p(k,s);return v(n),T}g(n,"invalid usage")}function ae(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"message")),c=e.length;s.push(n),r=m(s,r,"nonce");var o,h=0|t._crypto_box_noncebytes();r.length!==h&&b(s,"invalid nonce length"),o=u(r),s.push(o),a=m(s,a,"sharedKey");var y,d=0|t._crypto_box_beforenmbytes();a.length!==d&&b(s,"invalid sharedKey length"),y=u(a),s.push(y);var f=new l(c+t._crypto_box_macbytes()|0),E=f.address;if(s.push(E),0==(0|t._crypto_box_easy_afternm(E,n,c,0,o,y))){var x=p(f,_);return v(s),x}g(s,"invalid usage")}function _e(e){var r=[];i(e);var a=new l(0|t._crypto_box_publickeybytes()),_=a.address;r.push(_);var s=new l(0|t._crypto_box_secretkeybytes()),n=s.address;if(r.push(n),0==(0|t._crypto_box_keypair(_,n))){var c={publicKey:p(a,e),privateKey:p(s,e),keyType:"x25519"};return v(r),c}g(r,"internal error")}function se(e,r,a,_,s,n){var c=[];i(n);var o=u(e=m(c,e,"ciphertext")),h=e.length;c.push(o),r=m(c,r,"mac");var y,d=0|t._crypto_box_macbytes();r.length!==d&&b(c,"invalid mac length"),y=u(r),c.push(y),a=m(c,a,"nonce");var f,E=0|t._crypto_box_noncebytes();a.length!==E&&b(c,"invalid nonce length"),f=u(a),c.push(f),_=m(c,_,"publicKey");var x,k=0|t._crypto_box_publickeybytes();_.length!==k&&b(c,"invalid publicKey length"),x=u(_),c.push(x),s=m(c,s,"privateKey");var S,T=0|t._crypto_box_secretkeybytes();s.length!==T&&b(c,"invalid privateKey length"),S=u(s),c.push(S);var w=new l(0|h),Y=w.address;if(c.push(Y),0==(0|t._crypto_box_open_detached(Y,o,y,h,0,f,x,S))){var B=p(w,n);return v(c),B}g(c,"incorrect key pair for the given ciphertext")}function ne(e,r,a,_,s){var n=[];i(s),e=m(n,e,"ciphertext");var c,o=t._crypto_box_macbytes(),h=e.length;h<o&&b(n,"ciphertext is too short"),c=u(e),n.push(c),r=m(n,r,"nonce");var y,d=0|t._crypto_box_noncebytes();r.length!==d&&b(n,"invalid nonce length"),y=u(r),n.push(y),a=m(n,a,"publicKey");var f,E=0|t._crypto_box_publickeybytes();a.length!==E&&b(n,"invalid publicKey length"),f=u(a),n.push(f),_=m(n,_,"privateKey");var x,k=0|t._crypto_box_secretkeybytes();_.length!==k&&b(n,"invalid privateKey length"),x=u(_),n.push(x);var S=new l(h-t._crypto_box_macbytes()|0),T=S.address;if(n.push(T),0==(0|t._crypto_box_open_easy(T,c,h,0,y,f,x))){var w=p(S,s);return v(n),w}g(n,"incorrect key pair for the given ciphertext")}function ce(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"ciphertext")),c=e.length;s.push(n),r=m(s,r,"nonce");var o,h=0|t._crypto_box_noncebytes();r.length!==h&&b(s,"invalid nonce length"),o=u(r),s.push(o),a=m(s,a,"sharedKey");var y,d=0|t._crypto_box_beforenmbytes();a.length!==d&&b(s,"invalid sharedKey length"),y=u(a),s.push(y);var f=new l(c-t._crypto_box_macbytes()|0),E=f.address;if(s.push(E),0==(0|t._crypto_box_open_easy_afternm(E,n,c,0,o,y))){var x=p(f,_);return v(s),x}g(s,"incorrect secret key for the given ciphertext")}function oe(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"publicKey");var c,o=0|t._crypto_box_publickeybytes();r.length!==o&&b(_,"invalid publicKey length"),c=u(r),_.push(c);var h=new l(n+t._crypto_box_sealbytes()|0),y=h.address;if(_.push(y),0==(0|t._crypto_box_seal(y,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function he(e,r,a,_){var s=[];i(_),e=m(s,e,"ciphertext");var n,c=t._crypto_box_sealbytes(),o=e.length;o<c&&b(s,"ciphertext is too short"),n=u(e),s.push(n),r=m(s,r,"publicKey");var h,y=0|t._crypto_box_publickeybytes();r.length!==y&&b(s,"invalid publicKey length"),h=u(r),s.push(h),a=m(s,a,"privateKey");var d,f=0|t._crypto_box_secretkeybytes();a.length!==f&&b(s,"invalid privateKey length"),d=u(a),s.push(d);var E=new l(o-t._crypto_box_sealbytes()|0),x=E.address;if(s.push(x),0==(0|t._crypto_box_seal_open(x,n,o,0,h,d))){var k=p(E,_);return v(s),k}g(s,"incorrect key pair for the given ciphertext")}function pe(e,r){var a=[];i(r),e=m(a,e,"seed");var _,s=0|t._crypto_box_seedbytes();e.length!==s&&b(a,"invalid seed length"),_=u(e),a.push(_);var n=new l(0|t._crypto_box_publickeybytes()),c=n.address;a.push(c);var o=new l(0|t._crypto_box_secretkeybytes()),h=o.address;if(a.push(h),0==(0|t._crypto_box_seed_keypair(c,h,_))){var y={publicKey:p(n,r),privateKey:p(o,r),keyType:"x25519"};return v(a),y}g(a,"invalid usage")}function ye(e,r,a){var _=[];i(a),e=m(_,e,"p");var s,n=0|t._crypto_core_ed25519_bytes();e.length!==n&&b(_,"invalid p length"),s=u(e),_.push(s),r=m(_,r,"q");var c,o=0|t._crypto_core_ed25519_bytes();r.length!==o&&b(_,"invalid q length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ed25519_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_core_ed25519_add(y,s,c))){var d=p(h,a);return v(_),d}g(_,"input is an invalid element")}function ie(e,r){var a=[];i(r);var _=u(e=m(a,e,"r"));e.length,a.push(_);var s=new l(0|t._crypto_core_ed25519_bytes()),n=s.address;if(a.push(n),0==(0|t._crypto_core_ed25519_from_hash(n,_))){var c=p(s,r);return v(a),c}g(a,"invalid usage")}function le(e,r){var a=[];i(r);var _=u(e=m(a,e,"r"));e.length,a.push(_);var s=new l(0|t._crypto_core_ed25519_bytes()),n=s.address;if(a.push(n),0==(0|t._crypto_core_ed25519_from_uniform(n,_))){var c=p(s,r);return v(a),c}g(a,"invalid usage")}function ue(e,r){var a=[];i(r),e=m(a,e,"repr");var _,s=0|t._crypto_core_ed25519_bytes();e.length!==s&&b(a,"invalid repr length"),_=u(e),a.push(_);var n=1==(0|t._crypto_core_ed25519_is_valid_point(_));return v(a),n}function de(e){var r=[];i(e);var a=new l(0|t._crypto_core_ed25519_bytes()),_=a.address;r.push(_),t._crypto_core_ed25519_random(_);var s=p(a,e);return v(r),s}function ve(e,r,a){var _=[];i(a),e=m(_,e,"x");var s,n=0|t._crypto_core_ed25519_scalarbytes();e.length!==n&&b(_,"invalid x length"),s=u(e),_.push(s),r=m(_,r,"y");var c,o=0|t._crypto_core_ed25519_scalarbytes();r.length!==o&&b(_,"invalid y length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ed25519_scalarbytes()),y=h.address;_.push(y),t._crypto_core_ed25519_scalar_add(y,s,c);var d=p(h,a);return v(_),d}function ge(e,r){var a=[];i(r),e=m(a,e,"s");var _,s=0|t._crypto_core_ed25519_scalarbytes();e.length!==s&&b(a,"invalid s length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ed25519_scalarbytes()),c=n.address;a.push(c),t._crypto_core_ed25519_scalar_complement(c,_);var o=p(n,r);return v(a),o}function be(e,r){var a=[];i(r),e=m(a,e,"s");var _,s=0|t._crypto_core_ed25519_scalarbytes();e.length!==s&&b(a,"invalid s length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ed25519_scalarbytes()),c=n.address;if(a.push(c),0==(0|t._crypto_core_ed25519_scalar_invert(c,_))){var o=p(n,r);return v(a),o}g(a,"invalid reciprocate")}function fe(e,r,a){var _=[];i(a),e=m(_,e,"x");var s,n=0|t._crypto_core_ed25519_scalarbytes();e.length!==n&&b(_,"invalid x length"),s=u(e),_.push(s),r=m(_,r,"y");var c,o=0|t._crypto_core_ed25519_scalarbytes();r.length!==o&&b(_,"invalid y length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ed25519_scalarbytes()),y=h.address;_.push(y),t._crypto_core_ed25519_scalar_mul(y,s,c);var d=p(h,a);return v(_),d}function me(e,r){var a=[];i(r),e=m(a,e,"s");var _,s=0|t._crypto_core_ed25519_scalarbytes();e.length!==s&&b(a,"invalid s length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ed25519_scalarbytes()),c=n.address;a.push(c),t._crypto_core_ed25519_scalar_negate(c,_);var o=p(n,r);return v(a),o}function Ee(e){var r=[];i(e);var a=new l(0|t._crypto_core_ed25519_scalarbytes()),_=a.address;r.push(_),t._crypto_core_ed25519_scalar_random(_);var s=p(a,e);return v(r),s}function xe(e,r){var a=[];i(r),e=m(a,e,"sample");var _,s=0|t._crypto_core_ed25519_nonreducedscalarbytes();e.length!==s&&b(a,"invalid sample length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ed25519_scalarbytes()),c=n.address;a.push(c),t._crypto_core_ed25519_scalar_reduce(c,_);var o=p(n,r);return v(a),o}function ke(e,r,a){var _=[];i(a),e=m(_,e,"x");var s,n=0|t._crypto_core_ed25519_scalarbytes();e.length!==n&&b(_,"invalid x length"),s=u(e),_.push(s),r=m(_,r,"y");var c,o=0|t._crypto_core_ed25519_scalarbytes();r.length!==o&&b(_,"invalid y length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ed25519_scalarbytes()),y=h.address;_.push(y),t._crypto_core_ed25519_scalar_sub(y,s,c);var d=p(h,a);return v(_),d}function Se(e,r,a){var _=[];i(a),e=m(_,e,"p");var s,n=0|t._crypto_core_ed25519_bytes();e.length!==n&&b(_,"invalid p length"),s=u(e),_.push(s),r=m(_,r,"q");var c,o=0|t._crypto_core_ed25519_bytes();r.length!==o&&b(_,"invalid q length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ed25519_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_core_ed25519_sub(y,s,c))){var d=p(h,a);return v(_),d}g(_,"input is an invalid element")}function Te(e,r,a,_){var s=[];i(_),e=m(s,e,"input");var n,c=0|t._crypto_core_hchacha20_inputbytes();e.length!==c&&b(s,"invalid input length"),n=u(e),s.push(n),r=m(s,r,"privateKey");var o,h=0|t._crypto_core_hchacha20_keybytes();r.length!==h&&b(s,"invalid privateKey length"),o=u(r),s.push(o);var y=null;null!=a&&(y=u(a=m(s,a,"constant")),a.length,s.push(y));var d=new l(0|t._crypto_core_hchacha20_outputbytes()),f=d.address;if(s.push(f),0==(0|t._crypto_core_hchacha20(f,n,o,y))){var E=p(d,_);return v(s),E}g(s,"invalid usage")}function we(e,r,a,_){var s=[];i(_),e=m(s,e,"input");var n,c=0|t._crypto_core_hsalsa20_inputbytes();e.length!==c&&b(s,"invalid input length"),n=u(e),s.push(n),r=m(s,r,"privateKey");var o,h=0|t._crypto_core_hsalsa20_keybytes();r.length!==h&&b(s,"invalid privateKey length"),o=u(r),s.push(o);var y=null;null!=a&&(y=u(a=m(s,a,"constant")),a.length,s.push(y));var d=new l(0|t._crypto_core_hsalsa20_outputbytes()),f=d.address;if(s.push(f),0==(0|t._crypto_core_hsalsa20(f,n,o,y))){var E=p(d,_);return v(s),E}g(s,"invalid usage")}function Ye(e,r,a){var _=[];i(a),e=m(_,e,"p");var s,n=0|t._crypto_core_ristretto255_bytes();e.length!==n&&b(_,"invalid p length"),s=u(e),_.push(s),r=m(_,r,"q");var c,o=0|t._crypto_core_ristretto255_bytes();r.length!==o&&b(_,"invalid q length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ristretto255_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_core_ristretto255_add(y,s,c))){var d=p(h,a);return v(_),d}g(_,"input is an invalid element")}function Be(e,r){var a=[];i(r);var _=u(e=m(a,e,"r"));e.length,a.push(_);var s=new l(0|t._crypto_core_ristretto255_bytes()),n=s.address;if(a.push(n),0==(0|t._crypto_core_ristretto255_from_hash(n,_))){var c=p(s,r);return v(a),c}g(a,"invalid usage")}function Ae(e,r){var a=[];i(r),e=m(a,e,"repr");var _,s=0|t._crypto_core_ristretto255_bytes();e.length!==s&&b(a,"invalid repr length"),_=u(e),a.push(_);var n=1==(0|t._crypto_core_ristretto255_is_valid_point(_));return v(a),n}function Ke(e){var r=[];i(e);var a=new l(0|t._crypto_core_ristretto255_bytes()),_=a.address;r.push(_),t._crypto_core_ristretto255_random(_);var s=p(a,e);return v(r),s}function Me(e,r,a){var _=[];i(a),e=m(_,e,"x");var s,n=0|t._crypto_core_ristretto255_scalarbytes();e.length!==n&&b(_,"invalid x length"),s=u(e),_.push(s),r=m(_,r,"y");var c,o=0|t._crypto_core_ristretto255_scalarbytes();r.length!==o&&b(_,"invalid y length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ristretto255_scalarbytes()),y=h.address;_.push(y),t._crypto_core_ristretto255_scalar_add(y,s,c);var d=p(h,a);return v(_),d}function Ie(e,r){var a=[];i(r),e=m(a,e,"s");var _,s=0|t._crypto_core_ristretto255_scalarbytes();e.length!==s&&b(a,"invalid s length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ristretto255_scalarbytes()),c=n.address;a.push(c),t._crypto_core_ristretto255_scalar_complement(c,_);var o=p(n,r);return v(a),o}function Ne(e,r){var a=[];i(r),e=m(a,e,"s");var _,s=0|t._crypto_core_ristretto255_scalarbytes();e.length!==s&&b(a,"invalid s length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ristretto255_scalarbytes()),c=n.address;if(a.push(c),0==(0|t._crypto_core_ristretto255_scalar_invert(c,_))){var o=p(n,r);return v(a),o}g(a,"invalid reciprocate")}function Le(e,r,a){var _=[];i(a),e=m(_,e,"x");var s,n=0|t._crypto_core_ristretto255_scalarbytes();e.length!==n&&b(_,"invalid x length"),s=u(e),_.push(s),r=m(_,r,"y");var c,o=0|t._crypto_core_ristretto255_scalarbytes();r.length!==o&&b(_,"invalid y length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ristretto255_scalarbytes()),y=h.address;_.push(y),t._crypto_core_ristretto255_scalar_mul(y,s,c);var d=p(h,a);return v(_),d}function Ue(e,r){var a=[];i(r),e=m(a,e,"s");var _,s=0|t._crypto_core_ristretto255_scalarbytes();e.length!==s&&b(a,"invalid s length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ristretto255_scalarbytes()),c=n.address;a.push(c),t._crypto_core_ristretto255_scalar_negate(c,_);var o=p(n,r);return v(a),o}function Oe(e){var r=[];i(e);var a=new l(0|t._crypto_core_ristretto255_scalarbytes()),_=a.address;r.push(_),t._crypto_core_ristretto255_scalar_random(_);var s=p(a,e);return v(r),s}function Ce(e,r){var a=[];i(r),e=m(a,e,"sample");var _,s=0|t._crypto_core_ristretto255_nonreducedscalarbytes();e.length!==s&&b(a,"invalid sample length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ristretto255_scalarbytes()),c=n.address;a.push(c),t._crypto_core_ristretto255_scalar_reduce(c,_);var o=p(n,r);return v(a),o}function Re(e,r,a){var _=[];i(a),e=m(_,e,"x");var s,n=0|t._crypto_core_ristretto255_scalarbytes();e.length!==n&&b(_,"invalid x length"),s=u(e),_.push(s),r=m(_,r,"y");var c,o=0|t._crypto_core_ristretto255_scalarbytes();r.length!==o&&b(_,"invalid y length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ristretto255_scalarbytes()),y=h.address;_.push(y),t._crypto_core_ristretto255_scalar_sub(y,s,c);var d=p(h,a);return v(_),d}function Pe(e,r,a){var _=[];i(a),e=m(_,e,"p");var s,n=0|t._crypto_core_ristretto255_bytes();e.length!==n&&b(_,"invalid p length"),s=u(e),_.push(s),r=m(_,r,"q");var c,o=0|t._crypto_core_ristretto255_bytes();r.length!==o&&b(_,"invalid q length"),c=u(r),_.push(c);var h=new l(0|t._crypto_core_ristretto255_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_core_ristretto255_sub(y,s,c))){var d=p(h,a);return v(_),d}g(_,"input is an invalid element")}function Ge(e,r,a,_){var s=[];i(_),f(s,e,"hash_length"),("number"!=typeof e||(0|e)!==e||e<0)&&b(s,"hash_length must be an unsigned integer");var n=u(r=m(s,r,"message")),c=r.length;s.push(n);var o=null,h=0;null!=a&&(o=u(a=m(s,a,"key")),h=a.length,s.push(o));var y=new l(e|=0),d=y.address;if(s.push(d),0==(0|t._crypto_generichash(d,e,n,c,0,o,h))){var E=p(y,_);return v(s),E}g(s,"invalid usage")}function Xe(e,r,a,_,s){var n=[];i(s),f(n,e,"subkey_len"),("number"!=typeof e||(0|e)!==e||e<0)&&b(n,"subkey_len must be an unsigned integer");var c=null,o=0;null!=r&&(c=u(r=m(n,r,"key")),o=r.length,n.push(c)),a=m(n,a,"id");var h,y=0|t._crypto_generichash_blake2b_saltbytes();a.length!==y&&b(n,"invalid id length"),h=u(a),n.push(h),_=m(n,_,"ctx");var d,E=0|t._crypto_generichash_blake2b_personalbytes();_.length!==E&&b(n,"invalid ctx length"),d=u(_),n.push(d);var x=new l(0|e),k=x.address;if(n.push(k),0==(0|t._crypto_generichash_blake2b_salt_personal(k,e,null,0,0,c,o,h,d))){var S=p(x,s);return v(n),S}g(n,"invalid usage")}function De(e,r,a){var _=[];i(a),f(_,e,"state_address"),f(_,r,"hash_length"),("number"!=typeof r||(0|r)!==r||r<0)&&b(_,"hash_length must be an unsigned integer");var s=new l(r|=0),n=s.address;if(_.push(n),0==(0|t._crypto_generichash_final(e,n,r))){var c=(t._free(e),p(s,a));return v(_),c}g(_,"invalid usage")}function Fe(e,r,a){var _=[];i(a);var s=null,n=0;null!=e&&(s=u(e=m(_,e,"key")),n=e.length,_.push(s)),f(_,r,"hash_length"),("number"!=typeof r||(0|r)!==r||r<0)&&b(_,"hash_length must be an unsigned integer");var c=new l(357).address;if(0==(0|t._crypto_generichash_init(c,s,n,r))){var o=c;return v(_),o}g(_,"invalid usage")}function Ve(e){var r=[];i(e);var a=new l(0|t._crypto_generichash_keybytes()),_=a.address;r.push(_),t._crypto_generichash_keygen(_);var s=p(a,e);return v(r),s}function He(e,r,a){var _=[];i(a),f(_,e,"state_address");var s=u(r=m(_,r,"message_chunk")),n=r.length;_.push(s),0!=(0|t._crypto_generichash_update(e,s,n))&&g(_,"invalid usage"),v(_)}function qe(e,r){var a=[];i(r);var _=u(e=m(a,e,"message")),s=e.length;a.push(_);var n=new l(0|t._crypto_hash_bytes()),c=n.address;if(a.push(c),0==(0|t._crypto_hash(c,_,s,0))){var o=p(n,r);return v(a),o}g(a,"invalid usage")}function je(e,r){var a=[];i(r);var _=u(e=m(a,e,"message")),s=e.length;a.push(_);var n=new l(0|t._crypto_hash_sha256_bytes()),c=n.address;if(a.push(c),0==(0|t._crypto_hash_sha256(c,_,s,0))){var o=p(n,r);return v(a),o}g(a,"invalid usage")}function ze(e,r){var a=[];i(r),f(a,e,"state_address");var _=new l(0|t._crypto_hash_sha256_bytes()),s=_.address;if(a.push(s),0==(0|t._crypto_hash_sha256_final(e,s))){var n=(t._free(e),p(_,r));return v(a),n}g(a,"invalid usage")}function We(e){var r=[];i(e);var a=new l(104).address;if(0==(0|t._crypto_hash_sha256_init(a))){var _=a;return v(r),_}g(r,"invalid usage")}function Je(e,r,a){var _=[];i(a),f(_,e,"state_address");var s=u(r=m(_,r,"message_chunk")),n=r.length;_.push(s),0!=(0|t._crypto_hash_sha256_update(e,s,n))&&g(_,"invalid usage"),v(_)}function Qe(e,r){var a=[];i(r);var _=u(e=m(a,e,"message")),s=e.length;a.push(_);var n=new l(0|t._crypto_hash_sha512_bytes()),c=n.address;if(a.push(c),0==(0|t._crypto_hash_sha512(c,_,s,0))){var o=p(n,r);return v(a),o}g(a,"invalid usage")}function Ze(e,r){var a=[];i(r),f(a,e,"state_address");var _=new l(0|t._crypto_hash_sha512_bytes()),s=_.address;if(a.push(s),0==(0|t._crypto_hash_sha512_final(e,s))){var n=(t._free(e),p(_,r));return v(a),n}g(a,"invalid usage")}function $e(e){var r=[];i(e);var a=new l(208).address;if(0==(0|t._crypto_hash_sha512_init(a))){var _=a;return v(r),_}g(r,"invalid usage")}function er(e,r,a){var _=[];i(a),f(_,e,"state_address");var s=u(r=m(_,r,"message_chunk")),n=r.length;_.push(s),0!=(0|t._crypto_hash_sha512_update(e,s,n))&&g(_,"invalid usage"),v(_)}function rr(e,r,a,s,n){var c=[];i(n),f(c,e,"subkey_len"),("number"!=typeof e||(0|e)!==e||e<0)&&b(c,"subkey_len must be an unsigned integer"),f(c,r,"subkey_id"),("number"!=typeof r||(0|r)!==r||r<0)&&b(c,"subkey_id must be an unsigned integer"),"string"!=typeof a&&b(c,"ctx must be a string"),a=_(a+"\0"),null!=h&&a.length-1!==h&&b(c,"invalid ctx length");var o=u(a),h=a.length-1;c.push(o),s=m(c,s,"key");var y,d=0|t._crypto_kdf_keybytes();s.length!==d&&b(c,"invalid key length"),y=u(s),c.push(y);var g=new l(0|e),E=g.address;c.push(E),t._crypto_kdf_derive_from_key(E,e,r,r>>>24>>>8,o,y);var x=p(g,n);return v(c),x}function tr(e){var r=[];i(e);var a=new l(0|t._crypto_kdf_keybytes()),_=a.address;r.push(_),t._crypto_kdf_keygen(_);var s=p(a,e);return v(r),s}function ar(e,r,a,_){var s=[];i(_),e=m(s,e,"clientPublicKey");var n,c=0|t._crypto_kx_publickeybytes();e.length!==c&&b(s,"invalid clientPublicKey length"),n=u(e),s.push(n),r=m(s,r,"clientSecretKey");var o,h=0|t._crypto_kx_secretkeybytes();r.length!==h&&b(s,"invalid clientSecretKey length"),o=u(r),s.push(o),a=m(s,a,"serverPublicKey");var y,d=0|t._crypto_kx_publickeybytes();a.length!==d&&b(s,"invalid serverPublicKey length"),y=u(a),s.push(y);var f=new l(0|t._crypto_kx_sessionkeybytes()),E=f.address;s.push(E);var x=new l(0|t._crypto_kx_sessionkeybytes()),k=x.address;if(s.push(k),0==(0|t._crypto_kx_client_session_keys(E,k,n,o,y))){var S=p({sharedRx:f,sharedTx:x},_);return v(s),S}g(s,"invalid usage")}function _r(e){var r=[];i(e);var a=new l(0|t._crypto_kx_publickeybytes()),_=a.address;r.push(_);var s=new l(0|t._crypto_kx_secretkeybytes()),n=s.address;if(r.push(n),0==(0|t._crypto_kx_keypair(_,n))){var c={publicKey:p(a,e),privateKey:p(s,e),keyType:"x25519"};return v(r),c}g(r,"internal error")}function sr(e,r){var a=[];i(r),e=m(a,e,"seed");var _,s=0|t._crypto_kx_seedbytes();e.length!==s&&b(a,"invalid seed length"),_=u(e),a.push(_);var n=new l(0|t._crypto_kx_publickeybytes()),c=n.address;a.push(c);var o=new l(0|t._crypto_kx_secretkeybytes()),h=o.address;if(a.push(h),0==(0|t._crypto_kx_seed_keypair(c,h,_))){var y={publicKey:p(n,r),privateKey:p(o,r),keyType:"x25519"};return v(a),y}g(a,"internal error")}function nr(e,r,a,_){var s=[];i(_),e=m(s,e,"serverPublicKey");var n,c=0|t._crypto_kx_publickeybytes();e.length!==c&&b(s,"invalid serverPublicKey length"),n=u(e),s.push(n),r=m(s,r,"serverSecretKey");var o,h=0|t._crypto_kx_secretkeybytes();r.length!==h&&b(s,"invalid serverSecretKey length"),o=u(r),s.push(o),a=m(s,a,"clientPublicKey");var y,d=0|t._crypto_kx_publickeybytes();a.length!==d&&b(s,"invalid clientPublicKey length"),y=u(a),s.push(y);var f=new l(0|t._crypto_kx_sessionkeybytes()),E=f.address;s.push(E);var x=new l(0|t._crypto_kx_sessionkeybytes()),k=x.address;if(s.push(k),0==(0|t._crypto_kx_server_session_keys(E,k,n,o,y))){var S=p({sharedRx:f,sharedTx:x},_);return v(s),S}g(s,"invalid usage")}function cr(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"key");var c,o=0|t._crypto_onetimeauth_keybytes();r.length!==o&&b(_,"invalid key length"),c=u(r),_.push(c);var h=new l(0|t._crypto_onetimeauth_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_onetimeauth(y,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function or(e,r){var a=[];i(r),f(a,e,"state_address");var _=new l(0|t._crypto_onetimeauth_bytes()),s=_.address;if(a.push(s),0==(0|t._crypto_onetimeauth_final(e,s))){var n=(t._free(e),p(_,r));return v(a),n}g(a,"invalid usage")}function hr(e,r){var a=[];i(r);var _=null;null!=e&&(_=u(e=m(a,e,"key")),e.length,a.push(_));var s=new l(144).address;if(0==(0|t._crypto_onetimeauth_init(s,_))){var n=s;return v(a),n}g(a,"invalid usage")}function pr(e){var r=[];i(e);var a=new l(0|t._crypto_onetimeauth_keybytes()),_=a.address;r.push(_),t._crypto_onetimeauth_keygen(_);var s=p(a,e);return v(r),s}function yr(e,r,a){var _=[];i(a),f(_,e,"state_address");var s=u(r=m(_,r,"message_chunk")),n=r.length;_.push(s),0!=(0|t._crypto_onetimeauth_update(e,s,n))&&g(_,"invalid usage"),v(_)}function ir(e,r,a){var _=[];e=m(_,e,"hash");var s,n=0|t._crypto_onetimeauth_bytes();e.length!==n&&b(_,"invalid hash length"),s=u(e),_.push(s);var c=u(r=m(_,r,"message")),o=r.length;_.push(c),a=m(_,a,"key");var h,p=0|t._crypto_onetimeauth_keybytes();a.length!==p&&b(_,"invalid key length"),h=u(a),_.push(h);var y=0==(0|t._crypto_onetimeauth_verify(s,c,o,0,h));return v(_),y}function lr(e,r,a,_,s,n,c){var o=[];i(c),f(o,e,"keyLength"),("number"!=typeof e||(0|e)!==e||e<0)&&b(o,"keyLength must be an unsigned integer");var h=u(r=m(o,r,"password")),y=r.length;o.push(h),a=m(o,a,"salt");var d,E=0|t._crypto_pwhash_saltbytes();a.length!==E&&b(o,"invalid salt length"),d=u(a),o.push(d),f(o,_,"opsLimit"),("number"!=typeof _||(0|_)!==_||_<0)&&b(o,"opsLimit must be an unsigned integer"),f(o,s,"memLimit"),("number"!=typeof s||(0|s)!==s||s<0)&&b(o,"memLimit must be an unsigned integer"),f(o,n,"algorithm"),("number"!=typeof n||(0|n)!==n||n<0)&&b(o,"algorithm must be an unsigned integer");var x=new l(0|e),k=x.address;if(o.push(k),0==(0|t._crypto_pwhash(k,e,0,h,y,0,d,_,0,s,n))){var S=p(x,c);return v(o),S}g(o,"invalid usage")}function ur(e,r,a,_,s,n){var c=[];i(n),f(c,e,"keyLength"),("number"!=typeof e||(0|e)!==e||e<0)&&b(c,"keyLength must be an unsigned integer");var o=u(r=m(c,r,"password")),h=r.length;c.push(o),a=m(c,a,"salt");var y,d=0|t._crypto_pwhash_scryptsalsa208sha256_saltbytes();a.length!==d&&b(c,"invalid salt length"),y=u(a),c.push(y),f(c,_,"opsLimit"),("number"!=typeof _||(0|_)!==_||_<0)&&b(c,"opsLimit must be an unsigned integer"),f(c,s,"memLimit"),("number"!=typeof s||(0|s)!==s||s<0)&&b(c,"memLimit must be an unsigned integer");var E=new l(0|e),x=E.address;if(c.push(x),0==(0|t._crypto_pwhash_scryptsalsa208sha256(x,e,0,o,h,0,y,_,0,s))){var k=p(E,n);return v(c),k}g(c,"invalid usage")}function dr(e,r,a,_,s,n,c){var o=[];i(c);var h=u(e=m(o,e,"password")),y=e.length;o.push(h);var d=u(r=m(o,r,"salt")),E=r.length;o.push(d),f(o,a,"opsLimit"),("number"!=typeof a||(0|a)!==a||a<0)&&b(o,"opsLimit must be an unsigned integer"),f(o,_,"r"),("number"!=typeof _||(0|_)!==_||_<0)&&b(o,"r must be an unsigned integer"),f(o,s,"p"),("number"!=typeof s||(0|s)!==s||s<0)&&b(o,"p must be an unsigned integer"),f(o,n,"keyLength"),("number"!=typeof n||(0|n)!==n||n<0)&&b(o,"keyLength must be an unsigned integer");var x=new l(0|n),k=x.address;if(o.push(k),0==(0|t._crypto_pwhash_scryptsalsa208sha256_ll(h,y,d,E,a,0,_,s,k,n))){var S=p(x,c);return v(o),S}g(o,"invalid usage")}function vr(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"password")),c=e.length;s.push(n),f(s,r,"opsLimit"),("number"!=typeof r||(0|r)!==r||r<0)&&b(s,"opsLimit must be an unsigned integer"),f(s,a,"memLimit"),("number"!=typeof a||(0|a)!==a||a<0)&&b(s,"memLimit must be an unsigned integer");var o=new l(0|t._crypto_pwhash_scryptsalsa208sha256_strbytes()).address;if(s.push(o),0==(0|t._crypto_pwhash_scryptsalsa208sha256_str(o,n,c,0,r,0,a))){var h=t.UTF8ToString(o);return v(s),h}g(s,"invalid usage")}function gr(e,r,a){var s=[];i(a),"string"!=typeof e&&b(s,"hashed_password must be a string"),e=_(e+"\0"),null!=c&&e.length-1!==c&&b(s,"invalid hashed_password length");var n=u(e),c=e.length-1;s.push(n);var o=u(r=m(s,r,"password")),h=r.length;s.push(o);var p=0==(0|t._crypto_pwhash_scryptsalsa208sha256_str_verify(n,o,h,0));return v(s),p}function br(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"password")),c=e.length;s.push(n),f(s,r,"opsLimit"),("number"!=typeof r||(0|r)!==r||r<0)&&b(s,"opsLimit must be an unsigned integer"),f(s,a,"memLimit"),("number"!=typeof a||(0|a)!==a||a<0)&&b(s,"memLimit must be an unsigned integer");var o=new l(0|t._crypto_pwhash_strbytes()).address;if(s.push(o),0==(0|t._crypto_pwhash_str(o,n,c,0,r,0,a))){var h=t.UTF8ToString(o);return v(s),h}g(s,"invalid usage")}function fr(e,r,a,s){var n=[];i(s),"string"!=typeof e&&b(n,"hashed_password must be a string"),e=_(e+"\0"),null!=o&&e.length-1!==o&&b(n,"invalid hashed_password length");var c=u(e),o=e.length-1;n.push(c),f(n,r,"opsLimit"),("number"!=typeof r||(0|r)!==r||r<0)&&b(n,"opsLimit must be an unsigned integer"),f(n,a,"memLimit"),("number"!=typeof a||(0|a)!==a||a<0)&&b(n,"memLimit must be an unsigned integer");var h=0!=(0|t._crypto_pwhash_str_needs_rehash(c,r,0,a));return v(n),h}function mr(e,r,a){var s=[];i(a),"string"!=typeof e&&b(s,"hashed_password must be a string"),e=_(e+"\0"),null!=c&&e.length-1!==c&&b(s,"invalid hashed_password length");var n=u(e),c=e.length-1;s.push(n);var o=u(r=m(s,r,"password")),h=r.length;s.push(o);var p=0==(0|t._crypto_pwhash_str_verify(n,o,h,0));return v(s),p}function Er(e,r,a){var _=[];i(a),e=m(_,e,"privateKey");var s,n=0|t._crypto_scalarmult_scalarbytes();e.length!==n&&b(_,"invalid privateKey length"),s=u(e),_.push(s),r=m(_,r,"publicKey");var c,o=0|t._crypto_scalarmult_bytes();r.length!==o&&b(_,"invalid publicKey length"),c=u(r),_.push(c);var h=new l(0|t._crypto_scalarmult_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_scalarmult(y,s,c))){var d=p(h,a);return v(_),d}g(_,"weak public key")}function xr(e,r){var a=[];i(r),e=m(a,e,"privateKey");var _,s=0|t._crypto_scalarmult_scalarbytes();e.length!==s&&b(a,"invalid privateKey length"),_=u(e),a.push(_);var n=new l(0|t._crypto_scalarmult_bytes()),c=n.address;if(a.push(c),0==(0|t._crypto_scalarmult_base(c,_))){var o=p(n,r);return v(a),o}g(a,"unknown error")}function kr(e,r,a){var _=[];i(a),e=m(_,e,"n");var s,n=0|t._crypto_scalarmult_ed25519_scalarbytes();e.length!==n&&b(_,"invalid n length"),s=u(e),_.push(s),r=m(_,r,"p");var c,o=0|t._crypto_scalarmult_ed25519_bytes();r.length!==o&&b(_,"invalid p length"),c=u(r),_.push(c);var h=new l(0|t._crypto_scalarmult_ed25519_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_scalarmult_ed25519(y,s,c))){var d=p(h,a);return v(_),d}g(_,"invalid point or scalar is 0")}function Sr(e,r){var a=[];i(r),e=m(a,e,"scalar");var _,s=0|t._crypto_scalarmult_ed25519_scalarbytes();e.length!==s&&b(a,"invalid scalar length"),_=u(e),a.push(_);var n=new l(0|t._crypto_scalarmult_ed25519_bytes()),c=n.address;if(a.push(c),0==(0|t._crypto_scalarmult_ed25519_base(c,_))){var o=p(n,r);return v(a),o}g(a,"scalar is 0")}function Tr(e,r){var a=[];i(r),e=m(a,e,"scalar");var _,s=0|t._crypto_scalarmult_ed25519_scalarbytes();e.length!==s&&b(a,"invalid scalar length"),_=u(e),a.push(_);var n=new l(0|t._crypto_scalarmult_ed25519_bytes()),c=n.address;if(a.push(c),0==(0|t._crypto_scalarmult_ed25519_base_noclamp(c,_))){var o=p(n,r);return v(a),o}g(a,"scalar is 0")}function wr(e,r,a){var _=[];i(a),e=m(_,e,"n");var s,n=0|t._crypto_scalarmult_ed25519_scalarbytes();e.length!==n&&b(_,"invalid n length"),s=u(e),_.push(s),r=m(_,r,"p");var c,o=0|t._crypto_scalarmult_ed25519_bytes();r.length!==o&&b(_,"invalid p length"),c=u(r),_.push(c);var h=new l(0|t._crypto_scalarmult_ed25519_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_scalarmult_ed25519_noclamp(y,s,c))){var d=p(h,a);return v(_),d}g(_,"invalid point or scalar is 0")}function Yr(e,r,a){var _=[];i(a),e=m(_,e,"scalar");var s,n=0|t._crypto_scalarmult_ristretto255_scalarbytes();e.length!==n&&b(_,"invalid scalar length"),s=u(e),_.push(s),r=m(_,r,"element");var c,o=0|t._crypto_scalarmult_ristretto255_bytes();r.length!==o&&b(_,"invalid element length"),c=u(r),_.push(c);var h=new l(0|t._crypto_scalarmult_ristretto255_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_scalarmult_ristretto255(y,s,c))){var d=p(h,a);return v(_),d}g(_,"result is identity element")}function Br(e,r){var a=[];i(r),e=m(a,e,"scalar");var _,s=0|t._crypto_core_ristretto255_scalarbytes();e.length!==s&&b(a,"invalid scalar length"),_=u(e),a.push(_);var n=new l(0|t._crypto_core_ristretto255_bytes()),c=n.address;if(a.push(c),0==(0|t._crypto_scalarmult_ristretto255_base(c,_))){var o=p(n,r);return v(a),o}g(a,"scalar is 0")}function Ar(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"message")),c=e.length;s.push(n),r=m(s,r,"nonce");var o,h=0|t._crypto_secretbox_noncebytes();r.length!==h&&b(s,"invalid nonce length"),o=u(r),s.push(o),a=m(s,a,"key");var y,d=0|t._crypto_secretbox_keybytes();a.length!==d&&b(s,"invalid key length"),y=u(a),s.push(y);var f=new l(0|c),E=f.address;s.push(E);var x=new l(0|t._crypto_secretbox_macbytes()),k=x.address;if(s.push(k),0==(0|t._crypto_secretbox_detached(E,k,n,c,0,o,y))){var S=p({mac:x,cipher:f},_);return v(s),S}g(s,"invalid usage")}function Kr(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"message")),c=e.length;s.push(n),r=m(s,r,"nonce");var o,h=0|t._crypto_secretbox_noncebytes();r.length!==h&&b(s,"invalid nonce length"),o=u(r),s.push(o),a=m(s,a,"key");var y,d=0|t._crypto_secretbox_keybytes();a.length!==d&&b(s,"invalid key length"),y=u(a),s.push(y);var f=new l(c+t._crypto_secretbox_macbytes()|0),E=f.address;if(s.push(E),0==(0|t._crypto_secretbox_easy(E,n,c,0,o,y))){var x=p(f,_);return v(s),x}g(s,"invalid usage")}function Mr(e){var r=[];i(e);var a=new l(0|t._crypto_secretbox_keybytes()),_=a.address;r.push(_),t._crypto_secretbox_keygen(_);var s=p(a,e);return v(r),s}function Ir(e,r,a,_,s){var n=[];i(s);var c=u(e=m(n,e,"ciphertext")),o=e.length;n.push(c),r=m(n,r,"mac");var h,y=0|t._crypto_secretbox_macbytes();r.length!==y&&b(n,"invalid mac length"),h=u(r),n.push(h),a=m(n,a,"nonce");var d,f=0|t._crypto_secretbox_noncebytes();a.length!==f&&b(n,"invalid nonce length"),d=u(a),n.push(d),_=m(n,_,"key");var E,x=0|t._crypto_secretbox_keybytes();_.length!==x&&b(n,"invalid key length"),E=u(_),n.push(E);var k=new l(0|o),S=k.address;if(n.push(S),0==(0|t._crypto_secretbox_open_detached(S,c,h,o,0,d,E))){var T=p(k,s);return v(n),T}g(n,"wrong secret key for the given ciphertext")}function Nr(e,r,a,_){var s=[];i(_),e=m(s,e,"ciphertext");var n,c=t._crypto_secretbox_macbytes(),o=e.length;o<c&&b(s,"ciphertext is too short"),n=u(e),s.push(n),r=m(s,r,"nonce");var h,y=0|t._crypto_secretbox_noncebytes();r.length!==y&&b(s,"invalid nonce length"),h=u(r),s.push(h),a=m(s,a,"key");var d,f=0|t._crypto_secretbox_keybytes();a.length!==f&&b(s,"invalid key length"),d=u(a),s.push(d);var E=new l(o-t._crypto_secretbox_macbytes()|0),x=E.address;if(s.push(x),0==(0|t._crypto_secretbox_open_easy(x,n,o,0,h,d))){var k=p(E,_);return v(s),k}g(s,"wrong secret key for the given ciphertext")}function Lr(e,r,a){var _=[];i(a),e=m(_,e,"header");var s,n=0|t._crypto_secretstream_xchacha20poly1305_headerbytes();e.length!==n&&b(_,"invalid header length"),s=u(e),_.push(s),r=m(_,r,"key");var c,o=0|t._crypto_secretstream_xchacha20poly1305_keybytes();r.length!==o&&b(_,"invalid key length"),c=u(r),_.push(c);var h=new l(52).address;if(0==(0|t._crypto_secretstream_xchacha20poly1305_init_pull(h,s,c))){var p=h;return v(_),p}g(_,"invalid usage")}function Ur(e,r){var a=[];i(r),e=m(a,e,"key");var _,s=0|t._crypto_secretstream_xchacha20poly1305_keybytes();e.length!==s&&b(a,"invalid key length"),_=u(e),a.push(_);var n=new l(52).address,c=new l(0|t._crypto_secretstream_xchacha20poly1305_headerbytes()),o=c.address;if(a.push(o),0==(0|t._crypto_secretstream_xchacha20poly1305_init_push(n,o,_))){var h={state:n,header:p(c,r)};return v(a),h}g(a,"invalid usage")}function Or(e){var r=[];i(e);var a=new l(0|t._crypto_secretstream_xchacha20poly1305_keybytes()),_=a.address;r.push(_),t._crypto_secretstream_xchacha20poly1305_keygen(_);var s=p(a,e);return v(r),s}function Cr(e,r,a,_){var s=[];i(_),f(s,e,"state_address"),r=m(s,r,"cipher");var n,c=t._crypto_secretstream_xchacha20poly1305_abytes(),o=r.length;o<c&&b(s,"cipher is too short"),n=u(r),s.push(n);var h=null,y=0;null!=a&&(h=u(a=m(s,a,"ad")),y=a.length,s.push(h));var g=new l(o-t._crypto_secretstream_xchacha20poly1305_abytes()|0),E=g.address;s.push(E);var x,k=(x=d(1),s.push(x),(k=0===t._crypto_secretstream_xchacha20poly1305_pull(e,E,0,x,n,o,0,h,y)&&{tag:t.HEAPU8[x],message:g})&&{message:p(k.message,_),tag:k.tag});return v(s),k}function Rr(e,r,a,_,s){var n=[];i(s),f(n,e,"state_address");var c=u(r=m(n,r,"message_chunk")),o=r.length;n.push(c);var h=null,y=0;null!=a&&(h=u(a=m(n,a,"ad")),y=a.length,n.push(h)),f(n,_,"tag"),("number"!=typeof _||(0|_)!==_||_<0)&&b(n,"tag must be an unsigned integer");var d=new l(o+t._crypto_secretstream_xchacha20poly1305_abytes()|0),E=d.address;if(n.push(E),0==(0|t._crypto_secretstream_xchacha20poly1305_push(e,E,0,c,o,0,h,y,0,_))){var x=p(d,s);return v(n),x}g(n,"invalid usage")}function Pr(e,r){var a=[];return i(r),f(a,e,"state_address"),t._crypto_secretstream_xchacha20poly1305_rekey(e),v(a),!0}function Gr(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"key");var c,o=0|t._crypto_shorthash_keybytes();r.length!==o&&b(_,"invalid key length"),c=u(r),_.push(c);var h=new l(0|t._crypto_shorthash_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_shorthash(y,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function Xr(e){var r=[];i(e);var a=new l(0|t._crypto_shorthash_keybytes()),_=a.address;r.push(_),t._crypto_shorthash_keygen(_);var s=p(a,e);return v(r),s}function Dr(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"key");var c,o=0|t._crypto_shorthash_siphashx24_keybytes();r.length!==o&&b(_,"invalid key length"),c=u(r),_.push(c);var h=new l(0|t._crypto_shorthash_siphashx24_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_shorthash_siphashx24(y,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function Fr(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"privateKey");var c,o=0|t._crypto_sign_secretkeybytes();r.length!==o&&b(_,"invalid privateKey length"),c=u(r),_.push(c);var h=new l(e.length+t._crypto_sign_bytes()|0),y=h.address;if(_.push(y),0==(0|t._crypto_sign(y,null,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function Vr(e,r,a){var _=[];i(a);var s=u(e=m(_,e,"message")),n=e.length;_.push(s),r=m(_,r,"privateKey");var c,o=0|t._crypto_sign_secretkeybytes();r.length!==o&&b(_,"invalid privateKey length"),c=u(r),_.push(c);var h=new l(0|t._crypto_sign_bytes()),y=h.address;if(_.push(y),0==(0|t._crypto_sign_detached(y,null,s,n,0,c))){var d=p(h,a);return v(_),d}g(_,"invalid usage")}function Hr(e,r){var a=[];i(r),e=m(a,e,"edPk");var _,s=0|t._crypto_sign_publickeybytes();e.length!==s&&b(a,"invalid edPk length"),_=u(e),a.push(_);var n=new l(0|t._crypto_scalarmult_scalarbytes()),c=n.address;if(a.push(c),0==(0|t._crypto_sign_ed25519_pk_to_curve25519(c,_))){var o=p(n,r);return v(a),o}g(a,"invalid key")}function qr(e,r){var a=[];i(r),e=m(a,e,"edSk");var _,s=0|t._crypto_sign_secretkeybytes();e.length!==s&&b(a,"invalid edSk length"),_=u(e),a.push(_);var n=new l(0|t._crypto_scalarmult_scalarbytes()),c=n.address;if(a.push(c),0==(0|t._crypto_sign_ed25519_sk_to_curve25519(c,_))){var o=p(n,r);return v(a),o}g(a,"invalid key")}function jr(e,r){var a=[];i(r),e=m(a,e,"privateKey");var _,s=0|t._crypto_sign_secretkeybytes();e.length!==s&&b(a,"invalid privateKey length"),_=u(e),a.push(_);var n=new l(0|t._crypto_sign_publickeybytes()),c=n.address;if(a.push(c),0==(0|t._crypto_sign_ed25519_sk_to_pk(c,_))){var o=p(n,r);return v(a),o}g(a,"invalid key")}function zr(e,r){var a=[];i(r),e=m(a,e,"privateKey");var _,s=0|t._crypto_sign_secretkeybytes();e.length!==s&&b(a,"invalid privateKey length"),_=u(e),a.push(_);var n=new l(0|t._crypto_sign_seedbytes()),c=n.address;if(a.push(c),0==(0|t._crypto_sign_ed25519_sk_to_seed(c,_))){var o=p(n,r);return v(a),o}g(a,"invalid key")}function Wr(e,r,a){var _=[];i(a),f(_,e,"state_address"),r=m(_,r,"privateKey");var s,n=0|t._crypto_sign_secretkeybytes();r.length!==n&&b(_,"invalid privateKey length"),s=u(r),_.push(s);var c=new l(0|t._crypto_sign_bytes()),o=c.address;if(_.push(o),0==(0|t._crypto_sign_final_create(e,o,null,s))){var h=(t._free(e),p(c,a));return v(_),h}g(_,"invalid usage")}function Jr(e,r,a,_){var s=[];i(_),f(s,e,"state_address"),r=m(s,r,"signature");var n,c=0|t._crypto_sign_bytes();r.length!==c&&b(s,"invalid signature length"),n=u(r),s.push(n),a=m(s,a,"publicKey");var o,h=0|t._crypto_sign_publickeybytes();a.length!==h&&b(s,"invalid publicKey length"),o=u(a),s.push(o);var p=0==(0|t._crypto_sign_final_verify(e,n,o));return v(s),p}function Qr(e){var r=[];i(e);var a=new l(208).address;if(0==(0|t._crypto_sign_init(a))){var _=a;return v(r),_}g(r,"internal error")}function Zr(e){var r=[];i(e);var a=new l(0|t._crypto_sign_publickeybytes()),_=a.address;r.push(_);var s=new l(0|t._crypto_sign_secretkeybytes()),n=s.address;if(r.push(n),0==(0|t._crypto_sign_keypair(_,n))){var c={publicKey:p(a,e),privateKey:p(s,e),keyType:"ed25519"};return v(r),c}g(r,"internal error")}function $r(e,r,a){var _=[];i(a),e=m(_,e,"signedMessage");var s,n=t._crypto_sign_bytes(),c=e.length;c<n&&b(_,"signedMessage is too short"),s=u(e),_.push(s),r=m(_,r,"publicKey");var o,h=0|t._crypto_sign_publickeybytes();r.length!==h&&b(_,"invalid publicKey length"),o=u(r),_.push(o);var y=new l(c-t._crypto_sign_bytes()|0),d=y.address;if(_.push(d),0==(0|t._crypto_sign_open(d,null,s,c,0,o))){var f=p(y,a);return v(_),f}g(_,"incorrect signature for the given public key")}function et(e,r){var a=[];i(r),e=m(a,e,"seed");var _,s=0|t._crypto_sign_seedbytes();e.length!==s&&b(a,"invalid seed length"),_=u(e),a.push(_);var n=new l(0|t._crypto_sign_publickeybytes()),c=n.address;a.push(c);var o=new l(0|t._crypto_sign_secretkeybytes()),h=o.address;if(a.push(h),0==(0|t._crypto_sign_seed_keypair(c,h,_))){var y={publicKey:p(n,r),privateKey:p(o,r),keyType:"ed25519"};return v(a),y}g(a,"invalid usage")}function rt(e,r,a){var _=[];i(a),f(_,e,"state_address");var s=u(r=m(_,r,"message_chunk")),n=r.length;_.push(s),0!=(0|t._crypto_sign_update(e,s,n,0))&&g(_,"invalid usage"),v(_)}function tt(e,r,a){var _=[];e=m(_,e,"signature");var s,n=0|t._crypto_sign_bytes();e.length!==n&&b(_,"invalid signature length"),s=u(e),_.push(s);var c=u(r=m(_,r,"message")),o=r.length;_.push(c),a=m(_,a,"publicKey");var h,p=0|t._crypto_sign_publickeybytes();a.length!==p&&b(_,"invalid publicKey length"),h=u(a),_.push(h);var y=0==(0|t._crypto_sign_verify_detached(s,c,o,0,h));return v(_),y}function at(e,r,a,_){var s=[];i(_),f(s,e,"outLength"),("number"!=typeof e||(0|e)!==e||e<0)&&b(s,"outLength must be an unsigned integer"),r=m(s,r,"key");var n,c=0|t._crypto_stream_chacha20_keybytes();r.length!==c&&b(s,"invalid key length"),n=u(r),s.push(n),a=m(s,a,"nonce");var o,h=0|t._crypto_stream_chacha20_noncebytes();a.length!==h&&b(s,"invalid nonce length"),o=u(a),s.push(o);var y=new l(0|e),d=y.address;s.push(d),t._crypto_stream_chacha20(d,e,0,o,n);var g=p(y,_);return v(s),g}function _t(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"input_message")),c=e.length;s.push(n),r=m(s,r,"nonce");var o,h=0|t._crypto_stream_chacha20_ietf_noncebytes();r.length!==h&&b(s,"invalid nonce length"),o=u(r),s.push(o),a=m(s,a,"key");var y,d=0|t._crypto_stream_chacha20_ietf_keybytes();a.length!==d&&b(s,"invalid key length"),y=u(a),s.push(y);var f=new l(0|c),E=f.address;if(s.push(E),0===t._crypto_stream_chacha20_ietf_xor(E,n,c,0,o,y)){var x=p(f,_);return v(s),x}g(s,"invalid usage")}function st(e,r,a,_,s){var n=[];i(s);var c=u(e=m(n,e,"input_message")),o=e.length;n.push(c),r=m(n,r,"nonce");var h,y=0|t._crypto_stream_chacha20_ietf_noncebytes();r.length!==y&&b(n,"invalid nonce length"),h=u(r),n.push(h),f(n,a,"nonce_increment"),("number"!=typeof a||(0|a)!==a||a<0)&&b(n,"nonce_increment must be an unsigned integer"),_=m(n,_,"key");var d,E=0|t._crypto_stream_chacha20_ietf_keybytes();_.length!==E&&b(n,"invalid key length"),d=u(_),n.push(d);var x=new l(0|o),k=x.address;if(n.push(k),0===t._crypto_stream_chacha20_ietf_xor_ic(k,c,o,0,h,a,d)){var S=p(x,s);return v(n),S}g(n,"invalid usage")}function nt(e){var r=[];i(e);var a=new l(0|t._crypto_stream_chacha20_keybytes()),_=a.address;r.push(_),t._crypto_stream_chacha20_keygen(_);var s=p(a,e);return v(r),s}function ct(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"input_message")),c=e.length;s.push(n),r=m(s,r,"nonce");var o,h=0|t._crypto_stream_chacha20_noncebytes();r.length!==h&&b(s,"invalid nonce length"),o=u(r),s.push(o),a=m(s,a,"key");var y,d=0|t._crypto_stream_chacha20_keybytes();a.length!==d&&b(s,"invalid key length"),y=u(a),s.push(y);var f=new l(0|c),E=f.address;if(s.push(E),0===t._crypto_stream_chacha20_xor(E,n,c,0,o,y)){var x=p(f,_);return v(s),x}g(s,"invalid usage")}function ot(e,r,a,_,s){var n=[];i(s);var c=u(e=m(n,e,"input_message")),o=e.length;n.push(c),r=m(n,r,"nonce");var h,y=0|t._crypto_stream_chacha20_noncebytes();r.length!==y&&b(n,"invalid nonce length"),h=u(r),n.push(h),f(n,a,"nonce_increment"),("number"!=typeof a||(0|a)!==a||a<0)&&b(n,"nonce_increment must be an unsigned integer"),_=m(n,_,"key");var d,E=0|t._crypto_stream_chacha20_keybytes();_.length!==E&&b(n,"invalid key length"),d=u(_),n.push(d);var x=new l(0|o),k=x.address;if(n.push(k),0===t._crypto_stream_chacha20_xor_ic(k,c,o,0,h,a,0,d)){var S=p(x,s);return v(n),S}g(n,"invalid usage")}function ht(e){var r=[];i(e);var a=new l(0|t._crypto_stream_keybytes()),_=a.address;r.push(_),t._crypto_stream_keygen(_);var s=p(a,e);return v(r),s}function pt(e){var r=[];i(e);var a=new l(0|t._crypto_stream_xchacha20_keybytes()),_=a.address;r.push(_),t._crypto_stream_xchacha20_keygen(_);var s=p(a,e);return v(r),s}function yt(e,r,a,_){var s=[];i(_);var n=u(e=m(s,e,"input_message")),c=e.length;s.push(n),r=m(s,r,"nonce");var o,h=0|t._crypto_stream_xchacha20_noncebytes();r.length!==h&&b(s,"invalid nonce length"),o=u(r),s.push(o),a=m(s,a,"key");var y,d=0|t._crypto_stream_xchacha20_keybytes();a.length!==d&&b(s,"invalid key length"),y=u(a),s.push(y);var f=new l(0|c),E=f.address;if(s.push(E),0===t._crypto_stream_xchacha20_xor(E,n,c,0,o,y)){var x=p(f,_);return v(s),x}g(s,"invalid usage")}function it(e,r,a,_,s){var n=[];i(s);var c=u(e=m(n,e,"input_message")),o=e.length;n.push(c),r=m(n,r,"nonce");var h,y=0|t._crypto_stream_xchacha20_noncebytes();r.length!==y&&b(n,"invalid nonce length"),h=u(r),n.push(h),f(n,a,"nonce_increment"),("number"!=typeof a||(0|a)!==a||a<0)&&b(n,"nonce_increment must be an unsigned integer"),_=m(n,_,"key");var d,E=0|t._crypto_stream_xchacha20_keybytes();_.length!==E&&b(n,"invalid key length"),d=u(_),n.push(d);var x=new l(0|o),k=x.address;if(n.push(k),0===t._crypto_stream_xchacha20_xor_ic(k,c,o,0,h,a,0,d)){var S=p(x,s);return v(n),S}g(n,"invalid usage")}function lt(e,r){var a=[];i(r),f(a,e,"length"),("number"!=typeof e||(0|e)!==e||e<0)&&b(a,"length must be an unsigned integer");var _=new l(0|e),s=_.address;a.push(s),t._randombytes_buf(s,e);var n=p(_,r);return v(a),n}function ut(e,r,a){var _=[];i(a),f(_,e,"length"),("number"!=typeof e||(0|e)!==e||e<0)&&b(_,"length must be an unsigned integer"),r=m(_,r,"seed");var s,n=0|t._randombytes_seedbytes();r.length!==n&&b(_,"invalid seed length"),s=u(r),_.push(s);var c=new l(0|e),o=c.address;_.push(o),t._randombytes_buf_deterministic(o,e,s);var h=p(c,a);return v(_),h}function dt(e){i(e),t._randombytes_close()}function vt(e){i(e);var r=t._randombytes_random()>>>0;return v([]),r}function gt(e,r){var a=[];i(r);for(var _=t._malloc(24),s=0;s<6;s++)t.setValue(_+4*s,t.Runtime.addFunction(e[["implementation_name","random","stir","uniform","buf","close"][s]]),"i32");0!=(0|t._randombytes_set_implementation(_))&&g(a,"unsupported implementation"),v(a)}function bt(e){i(e),t._randombytes_stir()}function ft(e,r){var a=[];i(r),f(a,e,"upper_bound"),("number"!=typeof e||(0|e)!==e||e<0)&&b(a,"upper_bound must be an unsigned integer");var _=t._randombytes_uniform(e)>>>0;return v(a),_}function mt(){var e=t._sodium_version_string(),r=t.UTF8ToString(e);return v([]),r}return l.prototype.to_Uint8Array=function(){var e=new Uint8Array(this.length);return e.set(t.HEAPU8.subarray(this.address,this.address+this.length)),e},e.add=function(e,r){if(!(e instanceof Uint8Array&&r instanceof Uint8Array))throw new TypeError("Only Uint8Array instances can added");var t=e.length,a=0,_=0;if(r.length!=e.length)throw new TypeError("Arguments must have the same length");for(_=0;_<t;_++)a>>=8,a+=e[_]+r[_],e[_]=255&a},e.base64_variants=c,e.compare=function(e,r){if(!(e instanceof Uint8Array&&r instanceof Uint8Array))throw new TypeError("Only Uint8Array instances can be compared");if(e.length!==r.length)throw new TypeError("Only instances of identical length can be compared");for(var t=0,a=1,_=e.length;_-- >0;)t|=r[_]-e[_]>>8&a,a&=(r[_]^e[_])-1>>8;return t+t+a-1},e.from_base64=function(e,r){r=o(r);var a,_=[],s=new l(3*(e=m(_,e,"input")).length/4),n=u(e),c=d(4),h=d(4);return _.push(n),_.push(s.address),_.push(s.result_bin_len_p),_.push(s.b64_end_p),0!==t._sodium_base642bin(s.address,s.length,n,e.length,0,c,h,r)&&g(_,"invalid input"),t.getValue(h,"i32")-n!==e.length&&g(_,"incomplete input"),s.length=t.getValue(c,"i32"),a=s.to_Uint8Array(),v(_),a},e.from_hex=function(e){var r,a=[],_=new l((e=m(a,e,"input")).length/2),s=u(e),n=d(4);return a.push(s),a.push(_.address),a.push(_.hex_end_p),0!==t._sodium_hex2bin(_.address,_.length,s,e.length,0,0,n)&&g(a,"invalid input"),t.getValue(n,"i32")-s!==e.length&&g(a,"incomplete input"),r=_.to_Uint8Array(),v(a),r},e.from_string=_,e.increment=function(e){if(!(e instanceof Uint8Array))throw new TypeError("Only Uint8Array instances can be incremented");for(var r=256,t=0,a=e.length;t<a;t++)r>>=8,r+=e[t],e[t]=255&r},e.is_zero=function(e){if(!(e instanceof Uint8Array))throw new TypeError("Only Uint8Array instances can be checked");for(var r=0,t=0,a=e.length;t<a;t++)r|=e[t];return 0===r},e.libsodium=r,e.memcmp=function(e,r){if(!(e instanceof Uint8Array&&r instanceof Uint8Array))throw new TypeError("Only Uint8Array instances can be compared");if(e.length!==r.length)throw new TypeError("Only instances of identical length can be compared");for(var t=0,a=0,_=e.length;a<_;a++)t|=e[a]^r[a];return 0===t},e.memzero=function(e){if(!(e instanceof Uint8Array))throw new TypeError("Only Uint8Array instances can be wiped");for(var r=0,t=e.length;r<t;r++)e[r]=0},e.output_formats=function(){return["uint8array","text","hex","base64"]},e.pad=function(e,r){if(!(e instanceof Uint8Array))throw new TypeError("buffer must be a Uint8Array");if((r|=0)<=0)throw new Error("block size must be > 0");var a,_=[],s=d(4),n=1,c=0,o=0|e.length,h=new l(o+r);_.push(s),_.push(h.address);for(var p=h.address,y=h.address+o+r;p<y;p++)t.HEAPU8[p]=e[c],c+=n=1&~((65535&((o-=n)>>>48|o>>>32|o>>>16|o))-1>>16);return 0!==t._sodium_pad(s,h.address,e.length,r,h.length)&&g(_,"internal error"),h.length=t.getValue(s,"i32"),a=h.to_Uint8Array(),v(_),a},e.unpad=function(e,r){if(!(e instanceof Uint8Array))throw new TypeError("buffer must be a Uint8Array");if((r|=0)<=0)throw new Error("block size must be > 0");var a=[],_=u(e),s=d(4);return a.push(_),a.push(s),0!==t._sodium_unpad(s,_,e.length,r)&&g(a,"unsupported/invalid padding"),e=(e=new Uint8Array(e)).subarray(0,t.getValue(s,"i32")),v(a),e},e.ready=a,e.symbols=function(){return Object.keys(e).sort()},e.to_base64=h,e.to_hex=n,e.to_string=s,e}var t="object"==typeof e.sodium&&"function"==typeof e.sodium.onload?e.sodium.onload:null;"function"==typeof define&&define.amd?define(["exports","libsodium"],r): true&&"string"!=typeof exports.nodeName?r(exports,__nccwpck_require__(8314)):e.sodium=r(e.commonJsStrict={},e.libsodium),t&&e.sodium.ready.then((function(){t(e.sodium)}))}(this);


/***/ }),

/***/ 8314:
/***/ (function(module, exports, __nccwpck_require__) {

!function(A){function I(A){"use strict";var I;void 0===(I=A)&&(I={});var g=I;"object"!=typeof g.sodium&&("object"==typeof global?g=global:"object"==typeof window&&(g=window)),"object"==typeof g.sodium&&"number"==typeof g.sodium.totalMemory&&(I.TOTAL_MEMORY=g.sodium.totalMemory);var B=I;return I.ready=new Promise((function(A,I){(a=B).onAbort=I,a.print=function(A){},a.printErr=function(A){},a.onRuntimeInitialized=function(){try{a._crypto_secretbox_keybytes(),A()}catch(A){I(A)}},a.useBackupModule=function(){return new Promise((function(A,I){(a={}).onAbort=I,a.onRuntimeInitialized=function(){Object.keys(B).forEach((function(A){"getRandomValue"!==A&&delete B[A]})),Object.keys(a).forEach((function(A){B[A]=a[A]})),A()};var g,C,Q,E,i,n,a=void 0!==a?a:{},r=Object.assign({},a),o=[],t="object"==typeof window,e="function"==typeof importScripts,f="object"==typeof process&&"object"==typeof process.versions&&"string"==typeof process.versions.node,c="";f?(c=e?(__nccwpck_require__(1017).dirname)(c)+"/":__dirname+"/",n=()=>{i||(E=__nccwpck_require__(7147),i=__nccwpck_require__(1017))},g=function(A,I){var g=AA(A);return g?I?g:g.toString():(n(),A=i.normalize(A),E.readFileSync(A,I?void 0:"utf8"))},Q=A=>{var I=g(A,!0);return I.buffer||(I=new Uint8Array(I)),I},C=(A,I,g)=>{var B=AA(A);B&&I(B),n(),A=i.normalize(A),E.readFile(A,(function(A,B){A?g(A):I(B.buffer)}))},process.argv.length>1&&process.argv[1].replace(/\\/g,"/"),o=process.argv.slice(2), true&&(module.exports=a),a.inspect=function(){return"[Emscripten Module object]"}):(t||e)&&(e?c=self.location.href:"undefined"!=typeof document&&document.currentScript&&(c=document.currentScript.src),c=0!==c.indexOf("blob:")?c.substr(0,c.replace(/[?#].*/,"").lastIndexOf("/")+1):"",g=A=>{try{var I=new XMLHttpRequest;return I.open("GET",A,!1),I.send(null),I.responseText}catch(I){var g=AA(A);if(g)return function(A){for(var I=[],g=0;g<A.length;g++){var B=A[g];B>255&&(B&=255),I.push(String.fromCharCode(B))}return I.join("")}(g);throw I}},e&&(Q=A=>{try{var I=new XMLHttpRequest;return I.open("GET",A,!1),I.responseType="arraybuffer",I.send(null),new Uint8Array(I.response)}catch(I){var g=AA(A);if(g)return g;throw I}}),C=(A,I,g)=>{var B=new XMLHttpRequest;B.open("GET",A,!0),B.responseType="arraybuffer",B.onload=()=>{if(200==B.status||0==B.status&&B.response)I(B.response);else{var C=AA(A);C?I(C.buffer):g()}},B.onerror=g,B.send(null)}),a.print;var y,s=a.printErr||void 0;Object.assign(a,r),r=null,a.arguments&&(o=a.arguments),a.thisProgram&&a.thisProgram,a.quit&&a.quit,a.wasmBinary&&(y=a.wasmBinary),a.noExitRuntime;var w,D={Memory:function(A){this.buffer=new ArrayBuffer(65536*A.initial)},Module:function(A){},Instance:function(A,I){this.exports=function(A){for(var I,g=new Uint8Array(123),B=25;B>=0;--B)g[48+B]=52+B,g[65+B]=B,g[97+B]=26+B;function C(A,I,B){for(var C,Q,E=0,i=I,n=B.length,a=I+(3*n>>2)-("="==B[n-2])-("="==B[n-1]);E<n;E+=4)C=g[B.charCodeAt(E+1)],Q=g[B.charCodeAt(E+2)],A[i++]=g[B.charCodeAt(E)]<<2|C>>4,i<a&&(A[i++]=C<<4|Q>>2),i<a&&(A[i++]=Q<<6|g[B.charCodeAt(E+3)])}return g[43]=62,g[47]=63,function(A){var g=A.a,B=g.buffer;g.grow=function(A){A|=0;var C=0|Mg(),o=C+A|0;if(C<o&&o<65536){var t=new ArrayBuffer(r(o,65536));new Int8Array(t).set(Q),Q=new Int8Array(t),E=new Int16Array(t),i=new Int32Array(t),n=new Uint8Array(t),new Uint16Array(t),a=new Uint32Array(t),new Float32Array(t),new Float64Array(t),B=t,g.buffer=B,I=n}return C};var Q=new Int8Array(B),E=new Int16Array(B),i=new Int32Array(B),n=new Uint8Array(B),a=(new Uint16Array(B),new Uint32Array(B)),r=(new Float32Array(B),new Float64Array(B),Math.imul),o=(Math.fround,Math.abs,Math.clz32),t=(Math.min,Math.max,Math.floor,Math.ceil,Math.trunc,Math.sqrt,A.abort),e=A.b,f=A.c,c=A.d,y=A.e,s=5279280,w=0,D=0,h=0;function p(A,I){var g,B,C,E,a,r=0,o=0,t=0,e=0,f=0,c=0,y=0,w=0,D=0,p=0,u=0,F=0,l=0,_=0,k=0,H=0,G=0,U=0,S=0,b=0,m=0,v=0,M=0,P=0,Y=0,N=0,R=0,d=0,J=0,x=0,L=0,K=0,X=0,T=0,V=0,q=0,z=0,j=0,W=0,O=0,Z=0,$=0,AA=0,IA=0,gA=0,BA=0,CA=0,QA=0,EA=0,iA=0,nA=0,aA=0,rA=0,oA=0,tA=0,eA=0,fA=0,cA=0,yA=0,sA=0,wA=0;for(s=q=s-256|0;j=(K=X<<3)+(q+128|0)|0,IA=n[4+(K=I+K|0)|0]|n[K+5|0]<<8|n[K+6|0]<<16|n[K+7|0]<<24,i[j>>2]=n[0|K]|n[K+1|0]<<8|n[K+2|0]<<16|n[K+3|0]<<24,i[j+4>>2]=IA,16!=(0|(X=X+1|0)););for(g=eI(q,A,64),K=i[(I=g)>>2],X=i[I+4>>2],o=K,K=(IA=i[I+32>>2])+(q=i[I+128>>2])|0,I=(O=i[I+36>>2])+i[I+132>>2]|0,I=K>>>0<q>>>0?I+1|0:I,q=K,I=I+X|0,q=I=(K=o+K|0)>>>0<q>>>0?I+1|0:I,L=pA((X=K)^(n[0|(K=A- -64|0)]|n[K+1|0]<<8|n[K+2|0]<<16|n[K+3|0]<<24)^-1377402159,I^(n[K+4|0]|n[K+5|0]<<8|n[K+6|0]<<16|n[K+7|0]<<24)^1359893119,32),K=I=h,I=I+1779033703|0,o=IA^(j=L-205731576|0),IA=I=j>>>0<4089235720?I+1|0:I,H=pA(o,O^I,24),O=I=h,T=K,o=L,I=I+q|0,I=(I=(L=H+X|0)>>>0<X>>>0?I+1|0:I)+(t=B=i[g+140>>2])|0,r=pA(o^(b=X=(K=i[g+136>>2])+L|0),(p=b>>>0<L>>>0?I+1|0:I)^T,16),I=IA+(f=h)|0,o=pA((Y=X=j+r|0)^H,(q=Y>>>0<j>>>0?I+1|0:I)^O,63),w=h,j=i[g+12>>2],X=(H=i[g+144>>2])+(IA=i[g+40>>2])|0,I=(gA=i[g+148>>2])+(O=i[g+44>>2])|0,T=X,I=(I=X>>>0<IA>>>0?I+1|0:I)+j|0,I=(X=X+i[g+8>>2]|0)>>>0<T>>>0?I+1|0:I,L=pA(X^(n[A+72|0]|n[A+73|0]<<8|n[A+74|0]<<16|n[A+75|0]<<24)^725511199,(n[A+76|0]|n[A+77|0]<<8|n[A+78|0]<<16|n[A+79|0]<<24)^I^-1694144372,32),T=pA(u=IA^(j=L-2067093701|0),O^(t=(IA=h)-((L>>>0<2067093701)+1150833018|0)|0),24),G=i[g+156>>2],u=T,I=I+(O=h)|0,I=(I=(T=X+T|0)>>>0<X>>>0?I+1|0:I)+G|0,z=pA((S=X=T+i[g+152>>2]|0)^L,(_=S>>>0<T>>>0?I+1|0:I)^IA,16),I=t+(v=h)|0,fA=X=j+z|0,L=pA(u^X,(j=X>>>0<j>>>0?I+1|0:I)^O,63),t=h,IA=i[g+20>>2],X=(U=i[g+160>>2])+(T=i[g+48>>2])|0,I=(QA=i[g+164>>2])+(G=i[g+52>>2])|0,O=X,I=(I=X>>>0<T>>>0?I+1|0:I)+IA|0,nA=X=X+i[g+16>>2]|0,X=X>>>0<O>>>0?I+1|0:I,k=pA(nA^(n[A+80|0]|n[A+81|0]<<8|n[A+82|0]<<16|n[A+83|0]<<24)^-79577749,X^(n[A+84|0]|n[A+85|0]<<8|n[A+86|0]<<16|n[A+87|0]<<24)^528734635,32),IA=I=h,I=I+1013904242|0,u=T^(O=k-23791573|0),T=I=O>>>0<4271175723?I+1|0:I,I=pA(u,G^I,24),c=IA,C=i[g+172>>2],e=I,u=k,k=I,nA=I+nA|0,I=(G=h)+X|0,I=(I=k>>>0>nA>>>0?I+1|0:I)+(F=C)|0,J=pA(u^(F=X=(IA=i[g+168>>2])+(k=nA)|0),(M=k>>>0>F>>>0?I+1|0:I)^c,16),I=T+(l=h)|0,G=pA(e^(P=X=O+J|0),(T=P>>>0<O>>>0?I+1|0:I)^G,63),c=h,k=i[g+28>>2],O=(X=i[g+176>>2])+(nA=i[g+56>>2])|0,I=(E=i[g+180>>2])+(m=i[g+60>>2])|0,I=(I=O>>>0<nA>>>0?I+1|0:I)+k|0,I=(y=O)>>>0>(N=O=y+i[g+24>>2]|0)>>>0?I+1|0:I,e=pA(N^(n[A+88|0]|n[A+89|0]<<8|n[A+90|0]<<16|n[A+91|0]<<24)^327033209,I^(n[A+92|0]|n[A+93|0]<<8|n[A+94|0]<<16|n[A+95|0]<<24)^1541459225,32),k=pA(u=nA^(D=(k=e)+1595750129|0),m^(nA=(O=h)-((k>>>0<2699217167)+1521486533|0)|0),24),y=nA,u=O,nA=i[g+188>>2],d=k,I=(m=h)+I|0,I=(I=(N=k+N|0)>>>0<k>>>0?I+1|0:I)+nA|0,V=k=(O=i[g+184>>2])+N|0,e=pA(k^e,(R=u)^(u=k>>>0<N>>>0?I+1|0:I),16),I=(I=y)+(y=h)|0,N=k=e+D|0,D=m,m=I=k>>>0<e>>>0?I+1|0:I,R=pA(d^k,D^I,63),k=h,d=L,I=t+p|0,I=(I=(b=b+L|0)>>>0<L>>>0?I+1|0:I)+(D=W=i[g+196>>2])|0,D=P,b=pA((P=L=(CA=i[g+192>>2])+(p=b)|0)^e,(L=p>>>0>P>>>0?I+1|0:I)^y,32),I=(I=T)+(T=h)|0,e=t,t=I=(p=D+(y=b)|0)>>>0<y>>>0?I+1|0:I,I=pA(d^p,e^I,24),aA=i[g+204>>2],x=I,d=y,e=P,P=I,e=e+I|0,I=(y=h)+L|0,I=(I=e>>>0<P>>>0?I+1|0:I)+(D=aA)|0,Z=L=(b=i[g+200>>2])+e|0,oA=pA(d^L,(P=e>>>0>L>>>0?I+1|0:I)^T,16),I=t+(e=h)|0,x=pA(x^(D=T=p+oA|0),(t=y)^(y=p>>>0>D>>>0?I+1|0:I),63),p=h,d=G,I=c+_|0,I=(I=(T=G+S|0)>>>0<G>>>0?I+1|0:I)+(t=iA=i[g+212>>2])|0,S=pA((t=r)^(r=T=(L=i[g+208>>2])+(G=T)|0),(G=G>>>0>r>>>0?I+1|0:I)^f,32),I=m+(t=h)|0,T=pA(d^(m=T=N+S|0),(I=N>>>0>m>>>0?I+1|0:I)^c,24),f=I,_=t,AA=i[g+220>>2],$=T,d=m,I=(c=h)+G|0,I=(I=(m=r+T|0)>>>0<T>>>0?I+1|0:I)+(N=AA)|0,_=pA((m=T=(t=i[g+216>>2])+(G=m)|0)^S,(N=G>>>0>m>>>0?I+1|0:I)^_,16),I=(r=h)+f|0,rA=T=d+_|0,d=pA($^T,(G=_>>>0>T>>>0?I+1|0:I)^c,63),c=h,$=R,I=k+M|0,I=(f=F+R|0)>>>0<F>>>0?I+1|0:I,F=f,I=I+(S=a=i[g+228>>2])|0,R=pA((M=f=(T=i[g+224>>2])+f|0)^z,(f=f>>>0<F>>>0?I+1|0:I)^v,32),I=(v=h)+q|0,Y=F=R+Y|0,q=pA($^F,(I=F>>>0<R>>>0?I+1|0:I)^k,24),F=I,z=i[g+236>>2],$=q,I=(k=h)+f|0,I=(I=(M=M+q|0)>>>0<q>>>0?I+1|0:I)+(S=z)|0,eA=pA((M=q=(BA=i[g+232>>2])+(f=M)|0)^R,(S=v)^(v=f>>>0>M>>>0?I+1|0:I),16),I=(I=F)+(F=h)|0,k=pA($^(R=q=(f=eA)+Y|0),(Y=f>>>0>R>>>0?I+1|0:I)^k,63),f=h,$=o,I=w+u|0,I=(I=(S=o+V|0)>>>0<o>>>0?I+1|0:I)+(cA=i[g+244>>2])|0,I=(o=(q=i[g+240>>2])+(u=S)|0)>>>0<u>>>0?I+1|0:I,u=l,l=I,S=pA(o^J,u^I,32),I=(I=j)+(j=h)|0,J=u=S+fA|0,V=pA($^u,(I=u>>>0<S>>>0?I+1|0:I)^w,24),w=I,u=j,fA=i[g+252>>2],tA=V,EA=J,J=S,I=l+($=h)|0,I=(I=(S=o+V|0)>>>0<o>>>0?I+1|0:I)+fA|0,I=(o=(j=i[g+248>>2])+(l=S)|0)>>>0<l>>>0?I+1|0:I,l=o,S=u,u=I,V=pA(J^o,S^I,16),I=(S=h)+w|0,J=pA(tA^(EA=o=EA+(J=V)|0),(o=o>>>0<J>>>0?I+1|0:I)^$,63),$=I=h,w=I,tA=_,I=P+cA|0,P=_=q+Z|0,I=(I=_>>>0<q>>>0?I+1|0:I)+w|0,Z=pA(tA^(w=_=_+J|0),(_=w>>>0<P>>>0?I+1|0:I)^r,32),I=Y+(P=h)|0,R=I=(r=R+Z|0)>>>0<R>>>0?I+1|0:I,J=pA(J^r,$^I,24),$=I=h,Y=I,yA=J,I=_+iA|0,_=J=w+L|0,I=(I=J>>>0<w>>>0?I+1|0:I)+Y|0,J=Z,Z=w=yA+_|0,tA=pA(J^w,(Y=P)^(P=w>>>0<_>>>0?I+1|0:I),16),I=R+(Y=h)|0,R=I=(w=r+tA|0)>>>0<r>>>0?I+1|0:I,J=pA(yA^(r=w),I^$,63),_=h,I=p+QA|0,I=(I=(w=U+x|0)>>>0<U>>>0?I+1|0:I)+N|0,U=I=(w=w+m|0)>>>0<m>>>0?I+1|0:I,N=pA(w^eA,I^F,32),I=(I=o)+(o=h)|0,I=(F=(m=N)+EA|0)>>>0<m>>>0?I+1|0:I,m=p,p=I,x=pA(F^x,m^I,24),QA=I=h,m=I,$=N,I=U+W|0,I=(I=(N=w+CA|0)>>>0<w>>>0?I+1|0:I)+m|0,I=(w=(U=N)+x|0)>>>0<U>>>0?I+1|0:I,U=w,m=I,eA=pA($^w,I^o,16),I=p+(N=h)|0,$=o=F+eA|0,x=pA(o^x,(w=o>>>0<F>>>0?I+1|0:I)^QA,63),o=h,I=c+aA|0,I=(I=(p=b+d|0)>>>0<b>>>0?I+1|0:I)+v|0,S=pA((b=p=p+M|0)^V,(p=p>>>0<M>>>0?I+1|0:I)^S,32),I=y+(v=h)|0,y=c,c=I=(F=D+S|0)>>>0<D>>>0?I+1|0:I,y=pA(F^d,y^I,24),D=I=h,d=y,I=p+fA|0,I=(I=(y=b+j|0)>>>0<j>>>0?I+1|0:I)+D|0,aA=p=d+y|0,EA=pA(p^S,(b=v)^(v=p>>>0<y>>>0?I+1|0:I),16),I=c+(M=h)|0,b=p=F+EA|0,S=pA(d^p,(c=p>>>0<F>>>0?I+1|0:I)^D,63),p=h,D=k,I=f+z|0,I=(I=(F=k+BA|0)>>>0<k>>>0?I+1|0:I)+u|0,I=(k=F+l|0)>>>0<l>>>0?I+1|0:I,l=k,k=I,y=pA(l^oA,I^e,32),I=(I=G)+(G=h)|0,u=F=y+rA|0,e=pA(D^F,(I=y>>>0>F>>>0?I+1|0:I)^f,24),D=f=h,F=I,I=k+E|0,I=(I=(l=l+X|0)>>>0<X>>>0?I+1|0:I)+f|0,I=(k=l+e|0)>>>0<l>>>0?I+1|0:I,f=u,l=k,u=k^y,y=I,G=f+(k=u=pA(u,I^G,16))|0,I=(f=h)+F|0,V=G,d=pA(G^e,(k=G>>>0<k>>>0?I+1|0:I)^D,63),G=h,D=b,e=u,I=P+B|0,u=F=K+Z|0,I=(I=F>>>0<K>>>0?I+1|0:I)+o|0,I=(F=F+x|0)>>>0<u>>>0?I+1|0:I,u=f,f=I,b=pA(e^F,u^I,32),I=(I=c)+(c=h)|0,P=u=D+b|0,e=pA(u^x,(I=u>>>0<b>>>0?I+1|0:I)^o,24),D=o=h,u=I,x=b,I=f+a|0,I=(I=(b=F+T|0)>>>0<F>>>0?I+1|0:I)+o|0,I=(f=(F=b)+e|0)>>>0<F>>>0?I+1|0:I,F=f,b=I,oA=pA(x^f,I^c,16),I=(I=u)+(u=h)|0,P=o=(c=oA)+P|0,QA=pA(f=o^e,(e=o>>>0<c>>>0?I+1|0:I)^D,63),c=h,I=p+m|0,I=(o=U+S|0)>>>0<U>>>0?I+1|0:I,U=o,I=I+(f=rA=i[g+132>>2])|0,f=I=(o=(D=i[g+128>>2])+o|0)>>>0<U>>>0?I+1|0:I,m=pA(o^tA,I^Y,32),I=(I=k)+(k=h)|0,Y=U=m+V|0,S=pA(U^S,(I=U>>>0<m>>>0?I+1|0:I)^p,24),x=p=h,U=I,V=m,I=f+gA|0,I=(I=(m=o+H|0)>>>0<o>>>0?I+1|0:I)+p|0,m=o=(f=m)+S|0,o=pA(V^o,(p=k)^(k=o>>>0<f>>>0?I+1|0:I),16),I=(I=U)+(U=h)|0,Y=p=o+Y|0,V=pA(f=p^S,(S=o>>>0>p>>>0?I+1|0:I)^x,63),p=h,Z=d,I=v+AA|0,v=f=t+aA|0,I=(I=f>>>0<t>>>0?I+1|0:I)+G|0,d=pA((x=f=f+d|0)^eA,(f=f>>>0<v>>>0?I+1|0:I)^N,32),I=R+(v=h)|0,I=r>>>0>(N=r+d|0)>>>0?I+1|0:I,R=pA(Z^(r=N),I^G,24),aA=G=h,N=I,tA=R,Z=r,I=f+nA|0,I=(I=(r=x+O|0)>>>0<O>>>0?I+1|0:I)+G|0,I=r>>>0>(f=r+R|0)>>>0?I+1|0:I,r=f,G=v,v=I,eA=pA(f^d,G^I,16),I=(G=h)+N|0,N=f=Z+(R=eA)|0,aA=pA(tA^f,(I=f>>>0<R>>>0?I+1|0:I)^aA,63),f=h,R=I,x=o,I=_+C|0,I=(I=(o=J+IA|0)>>>0<IA>>>0?I+1|0:I)+y|0,I=(o=o+l|0)>>>0<l>>>0?I+1|0:I,l=o,y=M,M=I,d=pA(o^EA,y^I,32),I=(o=h)+w|0,Z=pA((y=d+$|0)^J,(I=y>>>0<d>>>0?I+1|0:I)^_,24),w=I,_=o,J=i[g+156>>2],tA=y,I=M+($=h)|0,I=(I=(y=l+Z|0)>>>0<l>>>0?I+1|0:I)+J|0,l=I=y>>>0>(M=(o=i[g+152>>2])+y|0)>>>0?I+1|0:I,EA=pA(M^d,I^_,16),I=(I=w)+(w=h)|0,d=I=(y=EA)>>>0>(_=tA+y|0)>>>0?I+1|0:I,Z=pA((y=_)^Z,I^$,63),$=I=h,_=I,tA=N,I=b+AA|0,I=(I=(N=t+F|0)>>>0<F>>>0?I+1|0:I)+_|0,_=F=N+Z|0,x=pA(F^x,(b=U)^(U=F>>>0<N>>>0?I+1|0:I),32),I=(F=h)+R|0,b=I=(b=x)>>>0>(N=tA+b|0)>>>0?I+1|0:I,Z=pA(Z^N,$^I,24),$=I=h,R=I,tA=x,I=U+W|0,I=(I=(x=_+CA|0)>>>0<_>>>0?I+1|0:I)+R|0,I=(_=(U=x)+Z|0)>>>0<U>>>0?I+1|0:I,U=_,R=F,F=I,CA=pA(tA^_,R^I,16),I=b+(R=h)|0,I=(_=N+CA|0)>>>0<N>>>0?I+1|0:I,N=_,b=I,x=pA(_^Z,I^$,63),_=h,Z=QA,I=c+a|0,I=(I=(W=T+QA|0)>>>0<T>>>0?I+1|0:I)+k|0,k=G,G=I=m>>>0>(W=m+W|0)>>>0?I+1|0:I,QA=pA(W^eA,k^I,32),I=d+(k=h)|0,I=y>>>0>(m=y+QA|0)>>>0?I+1|0:I,y=c,c=I,d=pA(Z^m,y^I,24),Z=I=h,y=I,$=d,I=G+rA|0,I=(I=(d=D+W|0)>>>0<D>>>0?I+1|0:I)+y|0,W=G=$+(D=d)|0,QA=pA(G^QA,(y=G>>>0<D>>>0?I+1|0:I)^k,16),I=c+(D=h)|0,rA=G=m+QA|0,d=pA($^G,(k=G>>>0<m>>>0?I+1|0:I)^Z,63),G=h,Z=V,I=p+C|0,I=(I=(c=IA+V|0)>>>0<IA>>>0?I+1|0:I)+v|0,I=(c=c+r|0)>>>0<r>>>0?I+1|0:I,r=c,m=w,w=I,V=pA(c^EA,m^I,32),I=e+(c=h)|0,e=p,p=I=(v=P+V|0)>>>0<P>>>0?I+1|0:I,P=pA(Z^v,e^I,24),e=I=h,$=P,I=w+gA|0,I=(I=(P=r+H|0)>>>0<H>>>0?I+1|0:I)+e|0,r=V,V=w=$+P|0,Z=pA(r^w,(m=w>>>0<P>>>0?I+1|0:I)^c,16),I=p+(P=h)|0,eA=w=v+Z|0,e=pA($^w,(p=w>>>0<v>>>0?I+1|0:I)^e,63),w=h,I=f+fA|0,I=(I=(c=j+aA|0)>>>0<j>>>0?I+1|0:I)+l|0,v=I=(c=c+M|0)>>>0<M>>>0?I+1|0:I,r=pA(c^oA,I^u,32),I=S+(M=h)|0,u=f,f=I=(l=Y+r|0)>>>0<Y>>>0?I+1|0:I,Y=pA(l^aA,u^I,24),S=I=h,u=I,$=r,I=v+z|0,I=(I=(r=c+BA|0)>>>0<c>>>0?I+1|0:I)+u|0,u=c=r+Y|0,r=pA($^c,(v=M)^(M=c>>>0<r>>>0?I+1|0:I),16),I=f+(v=h)|0,aA=c=l+r|0,Y=pA(c^Y,(f=c>>>0<l>>>0?I+1|0:I)^S,63),c=h,I=F+iA|0,I=(I=(l=U+L|0)>>>0<U>>>0?I+1|0:I)+G|0,l=U=(F=l)+d|0,r=pA(U^r,(S=v)^(v=F>>>0>U>>>0?I+1|0:I),32),I=(I=p)+(p=h)|0,F=G,G=I=r>>>0>(U=r+eA|0)>>>0?I+1|0:I,S=pA(U^d,F^I,24),d=I=h,F=I,I=v+cA|0,I=(I=(l=l+q|0)>>>0<q>>>0?I+1|0:I)+F|0,oA=v=l+S|0,eA=pA(v^r,(F=v>>>0<l>>>0?I+1|0:I)^p,16),I=G+(l=h)|0,$=p=U+eA|0,S=pA(p^S,(G=p>>>0<U>>>0?I+1|0:I)^d,63),p=h,d=e,I=y+J|0,I=(I=(v=o+W|0)>>>0<o>>>0?I+1|0:I)+w|0,e=pA((y=v=(U=v)+e|0)^CA,(v=y>>>0<U>>>0?I+1|0:I)^R,32),I=(I=f)+(f=h)|0,R=pA(d^(r=U=e+aA|0),(I=e>>>0>r>>>0?I+1|0:I)^w,24),d=w=h,U=I,W=R,I=v+E|0,I=(I=(y=y+X|0)>>>0<X>>>0?I+1|0:I)+w|0,I=y>>>0>(v=y+R|0)>>>0?I+1|0:I,w=r,r=(y=v)^e,e=I,r=pA(r,I^f,16),I=(R=h)+U|0,f=pA(W^(EA=w=w+r|0),(w=w>>>0<r>>>0?I+1|0:I)^d,63),v=h,W=Y,I=m+nA|0,m=U=O+V|0,I=(I=U>>>0<O>>>0?I+1|0:I)+c|0,d=pA((Y=U=U+Y|0)^QA,(U=U>>>0<m>>>0?I+1|0:I)^D,32),I=b+(m=h)|0,b=D=N+d|0,D=pA(W^D,(I=D>>>0<N>>>0?I+1|0:I)^c,24),W=c=h,N=I,V=b,I=U+B|0,I=(I=(b=Y+K|0)>>>0<K>>>0?I+1|0:I)+c|0,I=(U=b+D|0)>>>0<b>>>0?I+1|0:I,b=U,c=m,m=I,tA=pA(U^d,c^I,16),I=(I=N)+(N=h)|0,d=pA((c=V+(U=tA)|0)^D,(I=c>>>0<U>>>0?I+1|0:I)^W,63),U=h,D=c,Y=I,I=_+M|0,M=c=u+x|0,I=(I=c>>>0<u>>>0?I+1|0:I)+(W=i[g+204>>2])|0,M=I=(c=(CA=i[g+200>>2])+c|0)>>>0<M>>>0?I+1|0:I,P=pA(c^Z,I^P,32),I=(I=k)+(k=h)|0,x=pA((u=P+rA|0)^x,(I=u>>>0<P>>>0?I+1|0:I)^_,24),_=I,QA=i[g+164>>2],rA=u,I=M+(aA=h)|0,I=(I=(u=c+x|0)>>>0<c>>>0?I+1|0:I)+QA|0,M=c=(V=i[g+160>>2])+u|0,u=I=c>>>0<u>>>0?I+1|0:I,Z=pA(c^P,I^k,16),I=(P=h)+_|0,x=pA((rA=c=rA+(k=Z)|0)^x,(c=c>>>0<k>>>0?I+1|0:I)^aA,63),aA=I=h,k=I,I=F+nA|0,I=(I=(_=O+oA|0)>>>0<O>>>0?I+1|0:I)+k|0,R=pA((k=_=(F=_)+x|0)^r,(_=F>>>0>k>>>0?I+1|0:I)^R,32),I=(F=h)+Y|0,Y=D=(r=R)+D|0,x=pA(x^D,aA^(I=r>>>0>D>>>0?I+1|0:I),24),aA=D=h,r=I,yA=x,oA=R,I=_+W|0,I=(I=(R=k+CA|0)>>>0<k>>>0?I+1|0:I)+D|0,R=k=(_=R)+x|0,x=pA(oA^k,(D=F)^(F=_>>>0>k>>>0?I+1|0:I),16),I=(D=h)+r|0,aA=pA(yA^(oA=k=(_=x)+Y|0),(k=_>>>0>k>>>0?I+1|0:I)^aA,63),_=h,I=p+J|0,I=(I=(r=o+S|0)>>>0<o>>>0?I+1|0:I)+e|0,r=pA((e=o=r+y|0)^tA,(o=o>>>0<y>>>0?I+1|0:I)^N,32),I=(I=c)+(c=h)|0,N=p,p=I=(y=r+rA|0)>>>0<r>>>0?I+1|0:I,Y=pA(y^S,N^I,24),S=I=h,N=I,I=o+B|0,I=(I=(e=e+K|0)>>>0<K>>>0?I+1|0:I)+N|0,J=o=e+Y|0,rA=pA(o^r,(N=o>>>0<e>>>0?I+1|0:I)^c,16),I=p+(e=h)|0,tA=o=y+rA|0,r=pA(o^Y,(c=o>>>0<y>>>0?I+1|0:I)^S,63),o=h,Y=f,I=v+z|0,I=(I=(p=f+BA|0)>>>0<f>>>0?I+1|0:I)+m|0,f=I=(p=p+b|0)>>>0<b>>>0?I+1|0:I,y=pA(p^Z,I^P,32),I=(I=G)+(G=h)|0,b=m=y+$|0,P=pA(Y^m,(I=y>>>0>m>>>0?I+1|0:I)^v,24),m=I,S=b,Y=y,I=f+a|0,f=y=p+T|0,I=(I=y>>>0<p>>>0?I+1|0:I)+(v=h)|0,Z=pA(Y^(y=p=y+P|0),(b=y>>>0<f>>>0?I+1|0:I)^G,16),I=(I=m)+(m=h)|0,f=P,P=G=S+(p=Z)|0,Y=pA(f^G,(p=p>>>0>G>>>0?I+1|0:I)^v,63),G=h,I=U+AA|0,I=(I=(f=t+d|0)>>>0<t>>>0?I+1|0:I)+u|0,l=pA((u=f=f+M|0)^eA,(f=f>>>0<M>>>0?I+1|0:I)^l,32),I=(I=w)+(w=h)|0,M=U,U=I=(v=l+EA|0)>>>0<l>>>0?I+1|0:I,S=pA(v^d,M^I,24),d=I=h,M=I,z=l,I=f+cA|0,I=(I=(l=u+q|0)>>>0<q>>>0?I+1|0:I)+M|0,M=f=l+S|0,u=pA(z^f,(l=f>>>0<l>>>0?I+1|0:I)^w,16),I=U+(f=h)|0,I=(w=v+u|0)>>>0<v>>>0?I+1|0:I,v=w,U=I,S=pA(w^S,I^d,63),w=h,z=P,d=u,I=F+gA|0,I=(I=(u=H+R|0)>>>0<H>>>0?I+1|0:I)+o|0,I=(F=u+r|0)>>>0<u>>>0?I+1|0:I,u=F,P=f,f=I,P=pA(d^F,P^I,32),I=(I=p)+(p=h)|0,R=pA((R=r)^(r=F=z+P|0),(I=r>>>0<P>>>0?I+1|0:I)^o,24),d=o=h,F=I,I=f+E|0,I=(I=(u=u+X|0)>>>0<X>>>0?I+1|0:I)+o|0,I=(f=u+R|0)>>>0<u>>>0?I+1|0:I,u=f,o=f^P,P=I,eA=pA(o,I^p,16),I=(I=F)+(F=h)|0,r=o=(p=eA)+r|0,d=pA(f=o^R,(R=o>>>0<p>>>0?I+1|0:I)^d,63),f=h,z=Y,I=N+C|0,p=o=J+IA|0,I=(I=o>>>0<IA>>>0?I+1|0:I)+G|0,D=pA((Y=o=o+Y|0)^x,(o=o>>>0<p>>>0?I+1|0:I)^D,32),I=U+(p=h)|0,N=pA(z^(U=N=v+D|0),(I=v>>>0>U>>>0?I+1|0:I)^G,24),x=G=h,v=I,J=N,z=U,I=o+iA|0,I=(I=(U=Y+L|0)>>>0<L>>>0?I+1|0:I)+G|0,N=o=U+N|0,G=pA(G=o^D,(D=o>>>0<U>>>0?I+1|0:I)^p,16),I=(U=h)+v|0,$=o=z+G|0,z=pA(J^o,(p=o>>>0<G>>>0?I+1|0:I)^x,63),v=h,Y=S,I=b+QA|0,I=(o=y+V|0)>>>0<y>>>0?I+1|0:I,y=o,I=I+w|0,I=(o=o+S|0)>>>0<y>>>0?I+1|0:I,y=o,b=I,S=pA(o^rA,I^e,32),I=(o=h)+k|0,x=e=S+oA|0,Y=pA(Y^e,(I=e>>>0<S>>>0?I+1|0:I)^w,24),k=I,e=o,BA=i[g+132>>2],J=Y,I=b+(w=h)|0,I=(I=(Y=y+Y|0)>>>0<y>>>0?I+1|0:I)+BA|0,b=I=(y=(o=i[g+128>>2])+(b=Y)|0)>>>0<b>>>0?I+1|0:I,oA=pA(y^S,I^e,16),I=(e=h)+k|0,J=pA(J^(Y=(S=oA)+x|0),(I=S>>>0>Y>>>0?I+1|0:I)^w,63),k=h,S=I,x=G,I=_+fA|0,I=(I=(G=j+aA|0)>>>0<j>>>0?I+1|0:I)+l|0,m=pA((w=G=G+M|0)^Z,(M=w>>>0<M>>>0?I+1|0:I)^m,32),I=(G=h)+c|0,Z=pA((l=m+tA|0)^aA,(I=l>>>0<m>>>0?I+1|0:I)^_,24),c=I,_=G,aA=i[g+196>>2],tA=Z,EA=l,I=M+(rA=h)|0,I=(I=(l=w+Z|0)>>>0<w>>>0?I+1|0:I)+aA|0,M=w=(G=i[g+192>>2])+l|0,l=I=w>>>0<l>>>0?I+1|0:I,Z=pA(w^m,I^_,16),I=(I=c)+(c=h)|0,m=pA(tA^(EA=w=EA+(_=Z)|0),(w=w>>>0<_>>>0?I+1|0:I)^rA,63),rA=I=h,_=I,tA=Y,I=P+W|0,I=(I=(Y=u+CA|0)>>>0<u>>>0?I+1|0:I)+_|0,I=(u=(P=Y)+m|0)>>>0<P>>>0?I+1|0:I,P=u,_=I,Y=pA(u^x,I^U,32),I=(U=h)+S|0,S=u=tA+Y|0,x=pA(m^u,rA^(I=u>>>0<Y>>>0?I+1|0:I),24),W=m=h,u=I,I=_+BA|0,I=(I=(P=o+P|0)>>>0<o>>>0?I+1|0:I)+m|0,CA=_=P+x|0,rA=pA(_^Y,(m=_>>>0<P>>>0?I+1|0:I)^U,16),I=(I=u)+(u=h)|0,P=_=(U=rA)+S|0,W=pA(_^x,(Y=_>>>0<U>>>0?I+1|0:I)^W,63),U=h,I=f+C|0,I=(I=(_=d+IA|0)>>>0<IA>>>0?I+1|0:I)+D|0,N=I=(_=_+N|0)>>>0<N>>>0?I+1|0:I,S=pA(_^oA,I^e,32),I=(I=w)+(w=h)|0,I=(e=(D=S)+EA|0)>>>0<D>>>0?I+1|0:I,D=f,f=I,x=pA(e^d,D^I,24),d=I=h,D=I,EA=S,I=N+nA|0,I=(I=(S=_+O|0)>>>0<_>>>0?I+1|0:I)+D|0,N=_=S+x|0,D=I=_>>>0<S>>>0?I+1|0:I,oA=pA(EA^_,I^w,16),I=f+(S=h)|0,EA=w=e+oA|0,x=pA(w^x,(f=w>>>0<e>>>0?I+1|0:I)^d,63),w=h,I=v+gA|0,I=(I=(_=H+z|0)>>>0<H>>>0?I+1|0:I)+b|0,e=c,c=I=y>>>0>(_=y+_|0)>>>0?I+1|0:I,d=pA(_^Z,e^I,32),I=R+(y=h)|0,I=r>>>0>(b=r+d|0)>>>0?I+1|0:I,r=v,v=I,r=pA(b^z,r^I,24),R=I=h,e=I,Z=r,I=c+QA|0,I=(I=(r=_+V|0)>>>0<_>>>0?I+1|0:I)+e|0,_=d,d=c=Z+r|0,z=pA(_^c,(e=y)^(y=c>>>0<r>>>0?I+1|0:I),16),I=v+(e=h)|0,b=pA(Z^(r=c=b+z|0),(_=r>>>0<b>>>0?I+1|0:I)^R,63),c=h,I=k+iA|0,I=(I=(v=L+J|0)>>>0<L>>>0?I+1|0:I)+l|0,I=(v=v+M|0)>>>0<M>>>0?I+1|0:I,M=v,v=I,l=pA(M^eA,I^F,32),I=(I=p)+(p=h)|0,R=F=l+$|0,J=pA(F^J,(I=F>>>0<l>>>0?I+1|0:I)^k,24),QA=k=h,F=I,I=v+fA|0,I=(I=(M=M+j|0)>>>0<j>>>0?I+1|0:I)+k|0,M=I=(v=M+J|0)>>>0<M>>>0?I+1|0:I,k=(p=l=pA(v^l,I^p,16))+R|0,I=(I=F)+(F=h)|0,R=J,J=k,R=pA(R^k,(p=p>>>0>k>>>0?I+1|0:I)^QA,63),k=h,Z=r,V=l,I=m+cA|0,m=l=q+CA|0,I=(I=l>>>0<q>>>0?I+1|0:I)+w|0,I=(l=l+x|0)>>>0<m>>>0?I+1|0:I,m=l,r=F,F=I,r=pA(V^l,r^I,32),I=(I=_)+(_=h)|0,V=x,x=l=Z+r|0,CA=pA(V^l,(I=r>>>0>l>>>0?I+1|0:I)^w,24),QA=w=h,l=I,I=F+B|0,I=(I=(m=m+K|0)>>>0<K>>>0?I+1|0:I)+w|0,V=F=m+CA|0,Z=pA(F^r,(w=_)^(_=F>>>0<m>>>0?I+1|0:I),16),I=(F=h)+l|0,l=w=(m=Z)+x|0,CA=pA(w^CA,(m=w>>>0<m>>>0?I+1|0:I)^QA,63),w=h,x=b,I=D+AA|0,I=(I=(b=t+N|0)>>>0<N>>>0?I+1|0:I)+c|0,r=pA((D=N=x+b|0)^rA,(r=u)^(u=b>>>0>D>>>0?I+1|0:I),32),I=(I=p)+(p=h)|0,b=c,c=I=r>>>0>(N=r+J|0)>>>0?I+1|0:I,x=pA(x^N,b^I,24),J=I=h,b=I,I=u+a|0,I=(I=(D=D+T|0)>>>0<T>>>0?I+1|0:I)+b|0,b=I=(u=D+x|0)>>>0<D>>>0?I+1|0:I,p=pA(u^r,I^p,16),I=c+(D=h)|0,I=(r=N+p|0)>>>0<N>>>0?I+1|0:I,N=r,r=I,J=pA(N^x,I^J,63),c=h,$=R,I=y+E|0,I=(I=(R=d+X|0)>>>0<X>>>0?I+1|0:I)+k|0,d=pA((x=y=$+R|0)^oA,(y=y>>>0<R>>>0?I+1|0:I)^S,32),I=Y+(R=h)|0,Y=k,k=I=(S=P+d|0)>>>0<P>>>0?I+1|0:I,S=pA($^(P=S),Y^I,24),QA=I=h,Y=I,$=S,I=y+aA|0,I=(I=(S=G+x|0)>>>0<G>>>0?I+1|0:I)+Y|0,Y=R,R=I=(y=$+S|0)>>>0<S>>>0?I+1|0:I,oA=pA(y^d,Y^I,16),I=k+(Y=h)|0,I=(S=P+oA|0)>>>0<P>>>0?I+1|0:I,QA=pA($^(P=S),I^QA,63),k=h,S=I,I=U+M|0,I=(I=(d=v+W|0)>>>0<v>>>0?I+1|0:I)+(rA=i[g+156>>2])|0,M=I=(v=(x=i[g+152>>2])+(M=d)|0)>>>0<M>>>0?I+1|0:I,d=pA(v^z,I^e,32),I=(I=f)+(f=h)|0,z=pA((e=d+EA|0)^W,(I=e>>>0<d>>>0?I+1|0:I)^U,24),U=I,eA=i[g+236>>2],EA=e,$=d,I=M+(W=h)|0,I=(I=(d=v+z|0)>>>0<v>>>0?I+1|0:I)+eA|0,I=(v=(e=i[g+232>>2])+(M=d)|0)>>>0<M>>>0?I+1|0:I,M=f,f=I,$=pA($^v,M^I,16),I=(I=U)+(U=h)|0,d=I=(M=EA+(d=$)|0)>>>0<d>>>0?I+1|0:I,W=pA(M^z,I^W,63),z=I=h,EA=P,P=p,I=_+gA|0,I=(I=(p=H+V|0)>>>0<H>>>0?I+1|0:I)+z|0,D=pA(P^(gA=H=p+W|0),(H=p>>>0>H>>>0?I+1|0:I)^D,32),I=(p=h)+S|0,S=_=EA+D|0,z=pA(W^_,z^(I=_>>>0<D>>>0?I+1|0:I),24),W=_=h,P=I,V=D,I=H+a|0,I=(I=(D=T+gA|0)>>>0<T>>>0?I+1|0:I)+_|0,V=pA(V^(_=H=D+z|0),(D=_>>>0<D>>>0?I+1|0:I)^p,16),I=(I=P)+(P=h)|0,S=H=(p=V)+S|0,gA=pA(gA=H^z,(z=p>>>0>H>>>0?I+1|0:I)^W,63),p=h,I=w+E|0,I=(I=(H=X+CA|0)>>>0<X>>>0?I+1|0:I)+b|0,Y=pA((W=H=H+u|0)^oA,(H=H>>>0<u>>>0?I+1|0:I)^Y,32),I=d+(u=h)|0,I=(b=M+Y|0)>>>0<M>>>0?I+1|0:I,M=b,d=w,w=I,d=pA(b^CA,d^I,24),CA=I=h,b=I,EA=Y,I=H+iA|0,I=(I=(Y=L+W|0)>>>0<L>>>0?I+1|0:I)+b|0,W=H=Y+d|0,oA=pA(EA^H,(b=u)^(u=H>>>0<Y>>>0?I+1|0:I),16),I=w+(b=h)|0,I=(H=M+oA|0)>>>0<M>>>0?I+1|0:I,M=H,Y=I,d=pA(H^d,I^CA,63),w=h,I=c+BA|0,I=(I=(H=o+J|0)>>>0<o>>>0?I+1|0:I)+R|0,I=y>>>0>(H=y+H|0)>>>0?I+1|0:I,y=H,H=I,R=pA(y^$,I^U,32),I=m+(o=h)|0,I=l>>>0>(U=l+R|0)>>>0?I+1|0:I,l=c,c=I,m=pA(U^J,l^I,24),BA=I=h,l=I,J=m,I=H+AA|0,I=(I=(m=t+y|0)>>>0<t>>>0?I+1|0:I)+l|0,y=R,R=H=J+(t=m)|0,AA=pA(y^H,(l=t>>>0>H>>>0?I+1|0:I)^o,16),I=c+(m=h)|0,CA=H=U+AA|0,y=pA(J^H,(o=H>>>0<U>>>0?I+1|0:I)^BA,63),H=h,I=k+aA|0,I=(I=(t=G+QA|0)>>>0<G>>>0?I+1|0:I)+f|0,I=(t=t+v|0)>>>0<v>>>0?I+1|0:I,v=t,t=I,U=pA(v^Z,I^F,32),I=r+(G=h)|0,f=k,k=I=(c=N+U|0)>>>0<N>>>0?I+1|0:I,F=pA(c^QA,f^I,24),N=I=h,f=I,r=F,I=t+rA|0,I=(I=(v=v+x|0)>>>0<x>>>0?I+1|0:I)+f|0,f=t=v+F|0,F=pA(t^U,(v=t>>>0<v>>>0?I+1|0:I)^G,16),I=k+(U=h)|0,BA=t=c+F|0,r=pA(r^t,(G=t>>>0<c>>>0?I+1|0:I)^N,63),t=h,I=w+D|0,I=(c=_+d|0)>>>0<_>>>0?I+1|0:I,_=c,I=I+(k=i[g+164>>2])|0,U=pA((k=F)^(F=c=c+i[g+160>>2]|0),(c=c>>>0<_>>>0?I+1|0:I)^U,32),I=(I=o)+(o=h)|0,N=w,w=I=(_=U)>>>0>(k=_+CA|0)>>>0?I+1|0:I,N=pA(k^d,N^I,24),D=I=h,_=I,d=U,I=c+eA|0,I=(I=(U=F+e|0)>>>0<e>>>0?I+1|0:I)+_|0,J=pA(d^(CA=c=U+N|0),(c=c>>>0<U>>>0?I+1|0:I)^o,16),I=w+(_=h)|0,I=(o=k+J|0)>>>0<k>>>0?I+1|0:I,k=o,U=I,x=pA(o^N,I^D,63),o=h,D=y,I=u+nA|0,F=w=O+W|0,I=(I=w>>>0<O>>>0?I+1|0:I)+H|0,N=pA((u=w=w+y|0)^V,(w=w>>>0<F>>>0?I+1|0:I)^P,32),I=(I=G)+(G=h)|0,e=H,H=I=(y=N)>>>0>(F=y+BA|0)>>>0?I+1|0:I,P=pA(D^F,e^I,24),e=I=h,y=I,I=w+C|0,I=(I=(u=u+IA|0)>>>0<IA>>>0?I+1|0:I)+y|0,w=pA((y=w=u+P|0)^N,(u=y>>>0<u>>>0?I+1|0:I)^G,16),I=H+(N=h)|0,I=F>>>0>(G=F+w|0)>>>0?I+1|0:I,G=(F=G)^P,P=I,d=pA(G,I^e,63),H=h,V=r,I=l+fA|0,I=(I=(G=R+j|0)>>>0<j>>>0?I+1|0:I)+t|0,r=pA((D=G=(l=G)+r|0)^oA,(G=D>>>0<l>>>0?I+1|0:I)^b,32),I=z+(l=h)|0,e=t,t=I=(b=S+r|0)>>>0<S>>>0?I+1|0:I,R=pA(V^b,e^I,24),S=I=h,e=I,I=G+cA|0,I=(I=(D=D+q|0)>>>0<q>>>0?I+1|0:I)+e|0,z=pA((e=G=D+R|0)^r,(G=l)^(l=e>>>0<D>>>0?I+1|0:I),16),I=t+(D=h)|0,S=pA((t=G=b+z|0)^R,(I=t>>>0<b>>>0?I+1|0:I)^S,63),G=h,b=I,I=p+B|0,I=(I=(r=K+gA|0)>>>0<K>>>0?I+1|0:I)+v|0,f=I=(r=r+f|0)>>>0<f>>>0?I+1|0:I,R=pA(r^AA,I^m,32),I=Y+(v=h)|0,I=(m=M+R|0)>>>0<M>>>0?I+1|0:I,M=m,Y=p,p=I,I=pA(m^gA,Y^I,24),gA=i[g+204>>2],V=I,m=I,r=I+r|0,I=(Y=h)+f|0,I=(I=r>>>0<m>>>0?I+1|0:I)+gA|0,I=(f=r+i[g+200>>2]|0)>>>0<r>>>0?I+1|0:I,r=v,v=I,gA=pA(f^R,r^I,16),I=p+(m=h)|0,p=r=M+gA|0,R=pA(V^r,(M=r>>>0<M>>>0?I+1|0:I)^Y,63),r=I=h,Z=t,V=w,I=c+a|0,w=t=T+CA|0,I=(I=t>>>0<T>>>0?I+1|0:I)+r|0,AA=pA(V^(Y=t=t+R|0),(t=t>>>0<w>>>0?I+1|0:I)^N,32),I=(w=h)+b|0,N=I=(c=Z+(N=AA)|0)>>>0<N>>>0?I+1|0:I,r=pA(R^c,r^I,24),BA=I=h,b=I,V=r,I=t+C|0,I=(I=(r=Y+IA|0)>>>0<IA>>>0?I+1|0:I)+b|0,b=t=V+r|0,AA=pA(t^AA,(r=t>>>0<r>>>0?I+1|0:I)^w,16),I=N+(R=h)|0,N=t=c+AA|0,w=pA(V^t,(Y=t>>>0<c>>>0?I+1|0:I)^BA,63),c=h,V=x,I=o+B|0,I=(I=(t=K+x|0)>>>0<K>>>0?I+1|0:I)+u|0,D=pA((x=t=t+y|0)^z,(t=t>>>0<y>>>0?I+1|0:I)^D,32),I=M+(y=h)|0,I=p>>>0>(u=p+D|0)>>>0?I+1|0:I,p=u,u=o,o=I,u=pA(V^p,u^I,24),z=I=h,M=I,V=u,I=t+fA|0,I=(I=(u=x+j|0)>>>0<j>>>0?I+1|0:I)+M|0,BA=t=V+u|0,W=pA(t^D,(M=t>>>0<u>>>0?I+1|0:I)^y,16),I=o+(y=h)|0,I=(t=p+W|0)>>>0<p>>>0?I+1|0:I,p=t,u=I,D=pA(V^t,I^z,63),o=h,I=H+cA|0,I=(I=(t=d+q|0)>>>0<q>>>0?I+1|0:I)+l|0,I=(t=t+e|0)>>>0<e>>>0?I+1|0:I,e=t,t=I,x=pA(e^gA,I^m,32),I=U+(l=h)|0,U=H,H=I=k>>>0>(m=k+x|0)>>>0?I+1|0:I,I=pA((k=m)^d,U^I,24),d=i[g+236>>2],V=I,m=I,e=I+e|0,I=(U=h)+t|0,I=(I=e>>>0<m>>>0?I+1|0:I)+d|0,I=(t=e+i[g+232>>2]|0)>>>0<e>>>0?I+1|0:I,m=t,e=l,l=I,z=pA(t^x,e^I,16),I=H+(e=h)|0,x=pA(V^(d=t=k+z|0),(t=t>>>0<k>>>0?I+1|0:I)^U,63),H=h,V=S,I=G+v|0,I=(I=(k=f+S|0)>>>0<f>>>0?I+1|0:I)+(U=i[g+164>>2])|0,S=pA((U=k=(f=k)+i[g+160>>2]|0)^J,(k=f>>>0>k>>>0?I+1|0:I)^_,32),I=P+(f=h)|0,I=F>>>0>(_=F+S|0)>>>0?I+1|0:I,F=G,G=I,F=pA(V^_,F^I,24),P=I=h,v=I,I=k+iA|0,I=(I=(U=U+L|0)>>>0<L>>>0?I+1|0:I)+v|0,U=pA((gA=k=U+F|0)^S,(k=k>>>0<U>>>0?I+1|0:I)^f,16),I=G+(f=h)|0,I=(v=_+U|0)>>>0<_>>>0?I+1|0:I,_=v,v=I,S=pA(_^F,I^P,63),G=h,P=U,I=o+r|0,I=(U=D+b|0)>>>0<b>>>0?I+1|0:I,b=U,I=I+(F=i[g+132>>2])|0,I=(U=U+i[g+128>>2]|0)>>>0<b>>>0?I+1|0:I,b=U,r=f,f=I,P=pA(P^U,r^I,32),I=(I=t)+(t=h)|0,r=o,o=I=(F=P)>>>0>(U=F+d|0)>>>0?I+1|0:I,D=pA(U^D,r^I,24),r=I=h,I=f+nA|0,I=(I=(b=b+O|0)>>>0<O>>>0?I+1|0:I)+r|0,J=pA((CA=f=b+D|0)^P,(f=f>>>0<b>>>0?I+1|0:I)^t,16),I=o+(F=h)|0,I=(t=U+J|0)>>>0<U>>>0?I+1|0:I,U=t,b=I,d=pA(t^D,I^r,63),t=h,I=M+E|0,M=o=X+BA|0,I=(I=o>>>0<X>>>0?I+1|0:I)+H|0,r=pA((D=o=o+x|0)^AA,(o=o>>>0<M>>>0?I+1|0:I)^R,32),I=v+(M=h)|0,I=_>>>0>(P=_+r|0)>>>0?I+1|0:I,_=P,P=H,H=I,I=pA(_^x,P^I,24),R=i[g+156>>2],x=I,P=I,D=I+D|0,I=(v=h)+o|0,I=(I=D>>>0<P>>>0?I+1|0:I)+R|0,I=(o=D+i[g+152>>2]|0)>>>0<D>>>0?I+1|0:I,P=o,D=M,M=I,AA=pA(o^r,D^I,16),I=H+(D=h)|0,I=(o=_+AA|0)>>>0<_>>>0?I+1|0:I,_=o,r=v,v=I,x=pA(x^o,r^I,63),o=h,I=G+l|0,l=H=m+S|0,I=(I=H>>>0<m>>>0?I+1|0:I)+(r=i[g+204>>2])|0,l=I=(H=H+i[g+200>>2]|0)>>>0<l>>>0?I+1|0:I,R=pA(H^W,I^y,32),I=Y+(m=h)|0,r=G,G=I=(y=N+R|0)>>>0<N>>>0?I+1|0:I,r=pA(y^S,r^I,24),N=I=h,S=r,I=I+l|0,I=(I=(r=r+H|0)>>>0<H>>>0?I+1|0:I)+(Y=i[g+148>>2])|0,I=(H=r+i[g+144>>2]|0)>>>0<r>>>0?I+1|0:I,l=H,r=m,m=I,BA=pA(H^R,r^I,16),I=G+(r=h)|0,G=N,N=I=y>>>0>(H=y+BA|0)>>>0?I+1|0:I,Y=pA(S^(y=H),G^I,63),G=h,S=w,I=c+k|0,I=(I=(H=w+gA|0)>>>0<w>>>0?I+1|0:I)+(R=i[g+196>>2])|0,R=H=(w=H)+i[g+192>>2]|0,e=pA(H^z,(w=w>>>0>H>>>0?I+1|0:I)^e,32),I=u+(k=h)|0,u=H=p+e|0,H=pA(S^H,(I=p>>>0>H>>>0?I+1|0:I)^c,24),p=I,z=i[g+220>>2],$=H,Z=u,V=e,I=(c=h)+w|0,I=(I=(e=H+R|0)>>>0<H>>>0?I+1|0:I)+(S=z)|0,gA=pA(V^(e=H=(u=i[g+216>>2])+(w=e)|0),(H=k)^(k=w>>>0>e>>>0?I+1|0:I),16),I=(I=p)+(p=h)|0,R=I=(w=gA)>>>0>(H=Z+w|0)>>>0?I+1|0:I,I=pA($^H,I^c,63),W=i[g+236>>2],V=I,c=I,S=I+CA|0,I=(w=h)+f|0,I=(I=c>>>0>S>>>0?I+1|0:I)+W|0,AA=pA((S=c=(f=S)+i[g+232>>2]|0)^AA,(c=c>>>0<f>>>0?I+1|0:I)^D,32),I=N+(f=h)|0,N=w,w=I=y>>>0>(D=y+AA|0)>>>0?I+1|0:I,D=I=pA(V^(y=D),N^I,24),S=I+S|0,I=(N=h)+c|0,I=z+(D>>>0>S>>>0?I+1|0:I)|0,z=c=u+S|0,AA=pA(c^AA,(S=f)^(f=c>>>0<u>>>0?I+1|0:I),16),I=w+(u=h)|0,w=N,N=I=(c=y+AA|0)>>>0<y>>>0?I+1|0:I,w=pA(D^(y=c),w^I,63),c=h,I=t+nA|0,I=(I=(D=d+O|0)>>>0<O>>>0?I+1|0:I)+M|0,S=D=D+P|0,r=pA(D^BA,(M=D>>>0<P>>>0?I+1|0:I)^r,32),I=R+(P=h)|0,I=H>>>0>(D=H+r|0)>>>0?I+1|0:I,H=D,R=t,t=I,R=pA(D^d,R^I,24),d=I=h,D=I,V=r,I=M+cA|0,I=(I=(r=S+q|0)>>>0<q>>>0?I+1|0:I)+D|0,W=pA(V^(BA=M=r+R|0),(M=r>>>0>M>>>0?I+1|0:I)^P,16),I=t+(P=h)|0,r=I=H>>>0>(D=H+W|0)>>>0?I+1|0:I,R=pA(D^R,I^d,63),H=h,I=o+a|0,I=(I=(t=x+T|0)>>>0<T>>>0?I+1|0:I)+m|0,S=pA((m=t=t+l|0)^gA,(t=t>>>0<l>>>0?I+1|0:I)^p,32),I=b+(p=h)|0,I=(l=U+S|0)>>>0<U>>>0?I+1|0:I,U=l,l=o,o=I,b=pA(U^x,l^I,24),x=I=h,l=I,I=t+B|0,I=(I=(m=m+K|0)>>>0<K>>>0?I+1|0:I)+l|0,l=t=m+b|0,d=pA(t^S,(d=p)^(p=t>>>0<m>>>0?I+1|0:I),16),I=o+(m=h)|0,I=(t=U+d|0)>>>0<U>>>0?I+1|0:I,U=t,o=t^b,b=I,S=pA(o,I^x,63),t=h,V=Y,I=G+k|0,k=o=e+Y|0,I=(I=o>>>0<e>>>0?I+1|0:I)+(x=i[g+156>>2])|0,k=I=(o=o+i[g+152>>2]|0)>>>0<k>>>0?I+1|0:I,Y=pA(o^J,I^F,32),I=v+(F=h)|0,I=(e=_+Y|0)>>>0<_>>>0?I+1|0:I,_=e,v=G,G=I,e=pA(V^e,v^I,24),v=I=h,J=e,I=I+k|0,I=(I=(e=o+e|0)>>>0<o>>>0?I+1|0:I)+(x=i[g+204>>2])|0,gA=o=e+i[g+200>>2]|0,e=pA(o^Y,(k=o>>>0<e>>>0?I+1|0:I)^F,16),I=G+(F=h)|0,G=o=_+e|0,Y=pA(J^o,(_=o>>>0<_>>>0?I+1|0:I)^v,63),o=h,x=R,I=f+C|0,I=(I=(v=z+IA|0)>>>0<IA>>>0?I+1|0:I)+H|0,v=I=(f=v+R|0)>>>0<v>>>0?I+1|0:I,R=pA(f^e,I^F,32),I=b+(F=h)|0,I=(e=U+R|0)>>>0<U>>>0?I+1|0:I,U=e,b=H,H=I,e=pA(x^e,b^I,24),b=I=h,J=e,I=I+v|0,I=(I=(e=f+e|0)>>>0<f>>>0?I+1|0:I)+(x=i[g+132>>2])|0,CA=pA((z=f=e+i[g+128>>2]|0)^R,(f=f>>>0<e>>>0?I+1|0:I)^F,16),I=H+(v=h)|0,I=(F=U+CA|0)>>>0<U>>>0?I+1|0:I,U=F,F=I,x=pA(J^U,I^b,63),H=h,I=M+fA|0,I=(I=(b=j+BA|0)>>>0<j>>>0?I+1|0:I)+t|0,R=pA((e=M=b+S|0)^AA,(M=b>>>0>e>>>0?I+1|0:I)^u,32),I=_+(u=h)|0,I=G>>>0>(b=G+R|0)>>>0?I+1|0:I,G=b,b=t,t=I,I=pA(G^S,b^I,24),S=i[g+164>>2],J=I,b=I,e=I+e|0,I=(_=h)+M|0,I=(I=e>>>0<b>>>0?I+1|0:I)+S|0,I=e>>>0>(M=e+i[g+160>>2]|0)>>>0?I+1|0:I,e=u,u=I,b=pA(M^R,e^I,16),I=t+(e=h)|0,t=_,_=I=G>>>0>(R=G+b|0)>>>0?I+1|0:I,t=pA(J^R,t^I,63),G=h,J=Y,I=o+p|0,I=(I=(Y=l+Y|0)>>>0<l>>>0?I+1|0:I)+(S=i[g+196>>2])|0,S=pA((Y=p=(l=Y)+i[g+192>>2]|0)^W,(p=p>>>0<l>>>0?I+1|0:I)^P,32),I=N+(l=h)|0,N=o,o=I=y>>>0>(P=y+S|0)>>>0?I+1|0:I,P=pA(J^(y=P),N^I,24),AA=I=h,N=I,J=P,I=p+E|0,I=(I=(P=Y+X|0)>>>0<X>>>0?I+1|0:I)+N|0,W=pA((BA=p=J+P|0)^S,(p=p>>>0<P>>>0?I+1|0:I)^l,16),I=o+(l=h)|0,I=y>>>0>(N=y+W|0)>>>0?I+1|0:I,Y=pA(J^(y=N),I^AA,63),o=h,N=I,J=w,I=c+k|0,I=(I=(P=w+gA|0)>>>0<w>>>0?I+1|0:I)+(S=i[g+148>>2])|0,d=pA((S=w=(k=P)+i[g+144>>2]|0)^d,(w=w>>>0<k>>>0?I+1|0:I)^m,32),I=r+(k=h)|0,r=c,c=I=D>>>0>(m=D+d|0)>>>0?I+1|0:I,D=pA(J^m,r^I,24),r=I=h,J=D,I=w+iA|0,I=(I=(D=S+L|0)>>>0<L>>>0?I+1|0:I)+r|0,P=w=J+D|0,d=pA(w^d,(S=k)^(k=w>>>0<D>>>0?I+1|0:I),16),I=c+(D=h)|0,r=pA(J^(c=w=m+d|0),(m=c>>>0<m>>>0?I+1|0:I)^r,63),S=I=h,w=I,J=y,I=f+E|0,I=(I=(y=X+z|0)>>>0<X>>>0?I+1|0:I)+w|0,z=f=y+r|0,e=pA(f^b,(w=f>>>0<y>>>0?I+1|0:I)^e,32),I=(f=h)+N|0,N=I=(y=J+e|0)>>>0<e>>>0?I+1|0:I,r=pA(r^y,S^I,24),S=I=h,b=I,J=e,I=w+fA|0,I=(I=(e=j+z|0)>>>0<j>>>0?I+1|0:I)+b|0,z=w=e+r|0,gA=pA(J^w,(b=f)^(f=w>>>0<e>>>0?I+1|0:I),16),I=N+(b=h)|0,N=I=(w=y+gA|0)>>>0<y>>>0?I+1|0:I,S=pA((y=w)^r,I^S,63),w=h,I=H+cA|0,I=(I=(e=x+q|0)>>>0<q>>>0?I+1|0:I)+u|0,M=I=(e=e+M|0)>>>0<M>>>0?I+1|0:I,r=pA(e^W,I^l,32),I=m+(l=h)|0,I=c>>>0>(u=c+r|0)>>>0?I+1|0:I,c=u,u=H,H=I,I=pA(c^x,u^I,24),x=i[g+204>>2],J=I,u=I,e=I+e|0,I=(m=h)+M|0,I=(I=u>>>0>e>>>0?I+1|0:I)+x|0,W=pA((AA=M=e+i[g+200>>2]|0)^r,(M=e>>>0>M>>>0?I+1|0:I)^l,16),I=H+(l=h)|0,r=m,m=I=c>>>0>(u=c+W|0)>>>0?I+1|0:I,r=pA(J^u,r^I,63),H=h,x=t,I=p+G|0,I=(I=(c=t+BA|0)>>>0<t>>>0?I+1|0:I)+(e=i[g+220>>2])|0,D=pA((e=t=c+i[g+216>>2]|0)^d,(t=t>>>0<c>>>0?I+1|0:I)^D,32),I=F+(c=h)|0,I=(p=U+D|0)>>>0<U>>>0?I+1|0:I,U=G,G=I,I=pA(x^p,U^I,24),x=i[g+156>>2],d=I,F=I,e=I+e|0,I=(U=h)+t|0,I=(I=F>>>0>e>>>0?I+1|0:I)+x|0,BA=t=e+i[g+152>>2]|0,J=pA(t^D,(F=t>>>0<e>>>0?I+1|0:I)^c,16),I=G+(e=h)|0,I=(t=p+J|0)>>>0<p>>>0?I+1|0:I,p=t,c=U,U=I,G=pA(d^t,c^I,63),c=h,d=Y,I=o+k|0,k=t=P+Y|0,I=(I=t>>>0<P>>>0?I+1|0:I)+(D=i[g+132>>2])|0,k=I=(t=t+i[g+128>>2]|0)>>>0<k>>>0?I+1|0:I,Y=pA(t^CA,I^v,32),I=_+(v=h)|0,D=pA(d^(_=P=R+Y|0),(P=o)^(o=_>>>0<R>>>0?I+1|0:I),24),P=I=h,d=D,I=I+k|0,k=D=t+D|0,I=(I=D>>>0<t>>>0?I+1|0:I)+(R=i[g+196>>2])|0,D=t=D+i[g+192>>2]|0,R=pA(t^Y,(R=v)^(v=t>>>0<k>>>0?I+1|0:I),16),I=o+(k=h)|0,I=(t=_+R|0)>>>0<_>>>0?I+1|0:I,_=t,o=P,P=I,x=pA(d^t,o^I,63),t=h,Y=r,I=f+a|0,f=o=T+z|0,I=(I=o>>>0<T>>>0?I+1|0:I)+H|0,I=(o=o+r|0)>>>0<f>>>0?I+1|0:I,f=k,k=I,R=pA(o^R,f^I,32),I=U+(f=h)|0,U=r=p+R|0,r=pA(Y^r,(I=p>>>0>r>>>0?I+1|0:I)^H,24),p=I,z=i[g+148>>2],V=r,d=U,I=k+(H=h)|0,I=(I=(r=o+r|0)>>>0<o>>>0?I+1|0:I)+(Y=z)|0,CA=o=(U=i[g+144>>2])+r|0,QA=pA(o^R,(k=f)^(f=o>>>0<r>>>0?I+1|0:I),16),I=(r=h)+p|0,R=o=d+(k=QA)|0,o=pA(V^o,(Y=o>>>0<k>>>0?I+1|0:I)^H,63),k=h,d=G,I=c+M|0,I=(H=G+AA|0)>>>0<G>>>0?I+1|0:I,G=H,I=I+(p=i[g+236>>2])|0,b=pA((M=H=H+i[g+232>>2]|0)^gA,(H=H>>>0<G>>>0?I+1|0:I)^b,32),I=P+(G=h)|0,I=(p=_+b|0)>>>0<_>>>0?I+1|0:I,_=c,c=I,P=pA(d^p,_^I,24),d=I=h,_=I,I=H+nA|0,I=(I=(M=M+O|0)>>>0<O>>>0?I+1|0:I)+_|0,gA=H=M+P|0,H=pA(H^b,(_=H>>>0<M>>>0?I+1|0:I)^G,16),I=c+(M=h)|0,b=G=p+H|0,d=pA(c=G^P,(P=p>>>0>G>>>0?I+1|0:I)^d,63),G=h,V=x,I=F+B|0,p=c=K+BA|0,I=(I=c>>>0<K>>>0?I+1|0:I)+t|0,p=I=(c=c+x|0)>>>0<p>>>0?I+1|0:I,x=pA(c^W,I^l,32),I=N+(F=h)|0,I=y>>>0>(l=y+x|0)>>>0?I+1|0:I,N=pA(V^(y=l),I^t,24),l=I,AA=i[g+164>>2],$=N,Z=y,I=p+(t=h)|0,I=(I=(N=c+N|0)>>>0<c>>>0?I+1|0:I)+AA|0,N=c=(y=i[g+160>>2])+(p=N)|0,BA=pA(c^x,(V=F)^(F=c>>>0<p>>>0?I+1|0:I),16),I=(I=l)+(l=h)|0,I=(c=Z+(p=BA)|0)>>>0<p>>>0?I+1|0:I,p=c,x=t,t=I,x=pA($^c,x^I,63),c=h,V=S,I=w+iA|0,I=(I=(S=S+L|0)>>>0<L>>>0?I+1|0:I)+v|0,v=I=D>>>0>(S=D+S|0)>>>0?I+1|0:I,W=pA(S^J,I^e,32),I=m+(e=h)|0,m=D=u+W|0,D=pA(V^D,(J=w)^(w=u>>>0>D>>>0?I+1|0:I),24),J=I=h,u=I,V=D,I=v+C|0,I=(I=(D=S+IA|0)>>>0<IA>>>0?I+1|0:I)+u|0,u=I=(v=V+D|0)>>>0<D>>>0?I+1|0:I,W=pA(v^W,I^e,16),I=w+(e=h)|0,I=(D=m+W|0)>>>0<m>>>0?I+1|0:I,m=D,D=I,S=pA(V^m,I^J,63),J=I=h,w=I,V=H,I=f+iA|0,I=(I=(H=L+CA|0)>>>0<L>>>0?I+1|0:I)+w|0,M=pA(V^(f=L=H+S|0),(H=H>>>0>f>>>0?I+1|0:I)^M,32),I=t+(w=h)|0,iA=L=p+M|0,p=I=p>>>0>L>>>0?I+1|0:I,J=L=pA(S^L,J^I,24),I=(t=h)+H|0,I=(I=(f=f+L|0)>>>0<L>>>0?I+1|0:I)+z|0,z=pA((S=L=f+U|0)^M,(f=U>>>0>S>>>0?I+1|0:I)^w,16),I=(U=h)+p|0,iA=L=(H=z)+iA|0,w=pA(J^L,(H=H>>>0>L>>>0?I+1|0:I)^t,63),p=h,J=o,I=_+k|0,I=(I=(L=o+gA|0)>>>0<o>>>0?I+1|0:I)+(t=i[g+196>>2])|0,l=pA((M=L=(o=L)+i[g+192>>2]|0)^BA,(L=o>>>0>M>>>0?I+1|0:I)^l,32),I=D+(t=h)|0,_=k,k=I=(o=m+l|0)>>>0<m>>>0?I+1|0:I,D=I=pA(J^o,_^I,24),m=l,l=M,M=I,l=l+I|0,I=(_=h)+L|0,I=AA+(l>>>0<M>>>0?I+1|0:I)|0,gA=L=y+l|0,AA=pA(m^L,(M=y>>>0>L>>>0?I+1|0:I)^t,16),I=k+(l=h)|0,D=pA(D^(k=L=o+AA|0),(t=_)^(_=o>>>0>k>>>0?I+1|0:I),63),L=h,I=G+nA|0,I=(I=(t=d+O|0)>>>0<O>>>0?I+1|0:I)+F|0,N=pA((y=t=t+N|0)^W,(t=t>>>0<N>>>0?I+1|0:I)^e,32),I=Y+(o=h)|0,e=G,G=I=(F=R+N|0)>>>0<R>>>0?I+1|0:I,e=pA(F^d,e^I,24),R=I=h,m=I,I=t+E|0,I=(I=(y=y+X|0)>>>0<X>>>0?I+1|0:I)+m|0,m=t=y+e|0,d=pA(t^N,(y=t>>>0<y>>>0?I+1|0:I)^o,16),I=G+(N=h)|0,o=pA((o=e)^(e=t=F+d|0),(t=t>>>0<F>>>0?I+1|0:I)^R,63),G=h,I=c+B|0,I=(I=(F=K+x|0)>>>0<K>>>0?I+1|0:I)+u|0,R=F=F+v|0,r=pA(F^QA,(v=F>>>0<v>>>0?I+1|0:I)^r,32),I=P+(F=h)|0,I=(u=b+r|0)>>>0<b>>>0?I+1|0:I,b=c,c=I,P=pA(u^x,b^I,24),Y=I=h,b=I,x=P,I=v+C|0,I=(I=(P=R+IA|0)>>>0<IA>>>0?I+1|0:I)+b|0,P=pA((R=v=x+P|0)^r,(v=v>>>0<P>>>0?I+1|0:I)^F,16),I=c+(F=h)|0,I=u>>>0>(b=u+P|0)>>>0?I+1|0:I,u=b,b=I,r=pA(x^u,I^Y,63),c=h,J=D,x=e,Y=P,I=f+fA|0,I=(I=(P=S+j|0)>>>0<j>>>0?I+1|0:I)+L|0,D=pA(Y^(e=f=P+D|0),(f=e>>>0<P>>>0?I+1|0:I)^F,32),I=(I=t)+(t=h)|0,P=L,L=I=(F=x+D|0)>>>0<D>>>0?I+1|0:I,I=pA(J^F,P^I,24),Y=i[g+220>>2],J=I,x=D,P=e,e=I,D=P+I|0,I=(P=h)+f|0,I=(I=e>>>0>D>>>0?I+1|0:I)+Y|0,x=pA(x^(S=f=(e=D)+i[g+216>>2]|0),(f=f>>>0<e>>>0?I+1|0:I)^t,16),I=L+(e=h)|0,I=(t=F+x|0)>>>0<F>>>0?I+1|0:I,F=t,D=P,P=I,L=pA(J^t,D^I,63),t=h,J=o,I=G+M|0,M=D=o+gA|0,I=(I=D>>>0<o>>>0?I+1|0:I)+(Y=i[g+204>>2])|0,Y=pA((D=o=D+i[g+200>>2]|0)^z,(o=o>>>0<M>>>0?I+1|0:I)^U,32),I=b+(U=h)|0,I=u>>>0>(M=u+Y|0)>>>0?I+1|0:I,u=G,G=I,b=pA(J^M,u^I,24),z=I=h,u=I,J=b,I=o+cA|0,I=(I=(b=D+q|0)>>>0<q>>>0?I+1|0:I)+u|0,gA=o=J+b|0,BA=pA(o^Y,(u=U)^(U=o>>>0<b>>>0?I+1|0:I),16),I=G+(u=h)|0,I=(o=M+BA|0)>>>0<M>>>0?I+1|0:I,M=o,b=I,o=pA(J^o,I^z,63),G=h,J=r,I=c+y|0,y=r=r+m|0,I=(I=r>>>0<m>>>0?I+1|0:I)+(Y=z=i[g+156>>2])|0,Y=pA((r=m=(D=i[g+152>>2])+r|0)^AA,(m=l)^(l=y>>>0>r>>>0?I+1|0:I),32),I=(I=H)+(H=h)|0,I=(y=Y)>>>0>(m=y+iA|0)>>>0?I+1|0:I,y=c,c=I,iA=pA(J^m,y^I,24),AA=I=h,y=I,J=iA,I=l+a|0,I=(I=(r=r+T|0)>>>0<T>>>0?I+1|0:I)+y|0,W=pA((iA=l=r+iA|0)^Y,(l=r>>>0>l>>>0?I+1|0:I)^H,16),I=c+(y=h)|0,Y=pA(J^(c=H=m+W|0),(m=c>>>0<m>>>0?I+1|0:I)^AA,63),H=h,J=w,I=p+v|0,v=r=w+R|0,I=(I=r>>>0<w>>>0?I+1|0:I)+(AA=i[g+236>>2])|0,R=pA((r=w=r+i[g+232>>2]|0)^d,(v=r>>>0<v>>>0?I+1|0:I)^N,32),I=_+(N=h)|0,_=w=k+R|0,w=pA(J^w,(I=w>>>0<k>>>0?I+1|0:I)^p,24),p=I,d=i[g+132>>2],V=w,J=_,I=(k=h)+v|0,I=(I=(r=w+r|0)>>>0<w>>>0?I+1|0:I)+d|0,I=(w=(_=i[g+128>>2])+r|0)>>>0<r>>>0?I+1|0:I,v=w,r=N,N=I,AA=pA(w^R,r^I,16),I=(I=p)+(p=h)|0,I=(w=J+(r=AA)|0)>>>0<r>>>0?I+1|0:I,r=w,w=k,k=I,J=I=pA(V^r,w^I,63),R=I,S=I+S|0,I=(w=h)+f|0,I=d+(S>>>0<R>>>0?I+1|0:I)|0,S=pA((R=f=_+S|0)^BA,(f=f>>>0<_>>>0?I+1|0:I)^u,32),I=m+(_=h)|0,I=c>>>0>(u=c+S|0)>>>0?I+1|0:I,c=u,u=w,w=I,u=pA(J^c,u^I,24),d=I=h,m=I,J=u,I=f+B|0,I=(I=(u=R+K|0)>>>0<K>>>0?I+1|0:I)+m|0,BA=pA((R=f=J+u|0)^S,(f=f>>>0<u>>>0?I+1|0:I)^_,16),I=w+(_=h)|0,u=I=c>>>0>(m=c+BA|0)>>>0?I+1|0:I,S=pA(J^m,I^d,63),w=h,J=L,I=t+U|0,I=(I=(c=L+gA|0)>>>0<L>>>0?I+1|0:I)+(d=i[g+148>>2])|0,y=pA((d=L=c+i[g+144>>2]|0)^W,(L=c>>>0>L>>>0?I+1|0:I)^y,32),I=k+(c=h)|0,V=I=pA(J^(k=U=r+y|0),(U=t)^(t=r>>>0>k>>>0?I+1|0:I),24),J=y,y=I,r=I+d|0,I=(U=h)+L|0,I=z+(r>>>0<y>>>0?I+1|0:I)|0,d=pA(J^(r=L=r+D|0),(y=D>>>0>r>>>0?I+1|0:I)^c,16),I=t+(D=h)|0,t=U,U=I=k>>>0>(L=k+d|0)>>>0?I+1|0:I,t=pA(V^(k=L),t^I,63),c=h,J=o,I=G+l|0,I=(I=(L=o+iA|0)>>>0<o>>>0?I+1|0:I)+(z=i[g+164>>2])|0,z=pA((l=L=(o=L)+i[g+160>>2]|0)^AA,(L=o>>>0>l>>>0?I+1|0:I)^p,32),I=P+(o=h)|0,I=(p=F+z|0)>>>0<F>>>0?I+1|0:I,F=G,G=I,P=pA(J^p,F^I,24),iA=I=h,F=I,I=L+C|0,I=(I=(l=l+IA|0)>>>0<IA>>>0?I+1|0:I)+F|0,J=z,z=L=l+P|0,gA=pA(J^L,(F=l>>>0>L>>>0?I+1|0:I)^o,16),I=G+(l=h)|0,I=p>>>0>(L=p+gA|0)>>>0?I+1|0:I,o=(p=L)^P,P=I,o=pA(o,I^iA,63),G=h,J=Y,I=H+E|0,I=(I=(L=Y+X|0)>>>0<X>>>0?I+1|0:I)+N|0,e=pA((Y=L=v+L|0)^x,(L=v>>>0>L>>>0?I+1|0:I)^e,32),I=b+(v=h)|0,I=M>>>0>(N=M+e|0)>>>0?I+1|0:I,M=N,N=H,H=I,b=pA(J^M,N^I,24),x=I=h,N=I,J=b,I=L+nA|0,I=(I=(b=Y+O|0)>>>0<O>>>0?I+1|0:I)+N|0,e=pA((N=L=J+b|0)^e,(Y=v)^(v=b>>>0>N>>>0?I+1|0:I),16),I=H+(b=h)|0,iA=L=M+e|0,Y=pA(J^L,(H=M>>>0>L>>>0?I+1|0:I)^x,63),L=h,J=t,I=c+f|0,f=M=t+R|0,I=(I=M>>>0<t>>>0?I+1|0:I)+(x=i[g+196>>2])|0,b=pA((M=e)^(e=t=f+i[g+192>>2]|0),(t=t>>>0<f>>>0?I+1|0:I)^b,32),I=P+(f=h)|0,P=c,c=I=p>>>0>(M=p+b|0)>>>0?I+1|0:I,I=pA(J^(p=M),P^I,24),R=i[g+204>>2],V=I,J=b,b=I,P=I+e|0,I=(M=h)+t|0,I=(I=b>>>0>P>>>0?I+1|0:I)+R|0,x=t=(b=P)+i[g+200>>2]|0,AA=pA(J^t,(e=f)^(f=t>>>0<b>>>0?I+1|0:I),16),I=c+(b=h)|0,I=(t=p+AA|0)>>>0<p>>>0?I+1|0:I,p=t,c=M,M=I,t=pA(V^t,c^I,63),c=h,J=o,I=y+G|0,y=e=o+r|0,I=(I=e>>>0<o>>>0?I+1|0:I)+(R=W=i[g+212>>2])|0,r=pA((e=o=(P=i[g+208>>2])+e|0)^BA,(o=o>>>0<y>>>0?I+1|0:I)^_,32),I=(I=H)+(H=h)|0,y=G,G=I=r>>>0>(_=r+iA|0)>>>0?I+1|0:I,I=pA(J^_,y^I,24),R=i[g+220>>2],V=I,J=r,r=e,e=I,r=r+I|0,I=(y=h)+o|0,I=(I=r>>>0<e>>>0?I+1|0:I)+R|0,iA=o=r+i[g+216>>2]|0,r=pA(J^o,(e=o>>>0<r>>>0?I+1|0:I)^H,16),I=G+(R=h)|0,o=y,y=I=(H=_+r|0)>>>0<_>>>0?I+1|0:I,H=pA(V^(_=H),o^I,63),o=h,J=Y,I=F+a|0,I=(I=(G=T+z|0)>>>0<T>>>0?I+1|0:I)+L|0,F=I=(F=G)>>>0>(G=F+Y|0)>>>0?I+1|0:I,d=pA(G^d,I^D,32),I=u+(D=h)|0,u=L,L=I=m>>>0>(Y=m+d|0)>>>0?I+1|0:I,Y=pA(J^(m=Y),u^I,24),u=I=h,J=Y,I=I+F|0,F=Y=G+Y|0,I=(I=Y>>>0<G>>>0?I+1|0:I)+(z=i[g+236>>2])|0,Y=d,d=G=F+i[g+232>>2]|0,z=pA(Y^G,(F=F>>>0>G>>>0?I+1|0:I)^D,16),I=L+(D=h)|0,m=I=(G=m+z|0)>>>0<m>>>0?I+1|0:I,Y=pA(J^G,I^u,63),L=h,J=S,I=w+cA|0,I=(I=(u=S+q|0)>>>0<q>>>0?I+1|0:I)+v|0,I=(u=u+N|0)>>>0<N>>>0?I+1|0:I,N=u,v=I,S=pA(u^gA,I^l,32),I=U+(l=h)|0,I=(u=k+S|0)>>>0<k>>>0?I+1|0:I,k=u,u=w,w=I,u=pA(J^k,u^I,24),gA=I=h,U=I,J=u,I=v+fA|0,I=(I=(u=N+j|0)>>>0<j>>>0?I+1|0:I)+U|0,U=I=u>>>0>(v=J+u|0)>>>0?I+1|0:I,S=pA(v^S,I^l,16),I=w+(l=h)|0,I=(u=k+S|0)>>>0<k>>>0?I+1|0:I,k=u,u=I,N=pA(J^k,I^gA,63),gA=I=h,w=I,J=r,I=f+cA|0,f=r=x+q|0,I=(I=r>>>0<q>>>0?I+1|0:I)+w|0,R=pA(J^(r=q=r+N|0),(q=f>>>0>r>>>0?I+1|0:I)^R,32),I=m+(w=h)|0,I=(f=G+R|0)>>>0<G>>>0?I+1|0:I,G=f,f=I,x=I=pA(N^G,gA^I,24),N=I,r=I+r|0,I=(m=h)+q|0,I=W+(r>>>0<N>>>0?I+1|0:I)|0,R=pA((r=q=r+P|0)^R,(N=P>>>0>r>>>0?I+1|0:I)^w,16),I=f+(P=h)|0,G=pA(x^(f=q=G+R|0),(w=m)^(m=G>>>0>f>>>0?I+1|0:I),63),w=h,J=t,I=c+e|0,I=(I=(q=t+iA|0)>>>0<t>>>0?I+1|0:I)+(x=i[g+164>>2])|0,D=pA((x=q=(t=q)+i[g+160>>2]|0)^z,(q=t>>>0>x>>>0?I+1|0:I)^D,32),I=u+(t=h)|0,I=(e=k+D|0)>>>0<k>>>0?I+1|0:I,k=e,u=c,c=I,I=pA(J^e,u^I,24),z=i[g+196>>2],V=I,J=D,e=I,D=I+x|0,I=(u=h)+q|0,I=(I=e>>>0>D>>>0?I+1|0:I)+z|0,x=pA(J^(D=q=(e=D)+i[g+192>>2]|0),(x=t)^(t=e>>>0>D>>>0?I+1|0:I),16),I=c+(z=h)|0,u=pA(V^(c=q=k+x|0),(k=k>>>0>c>>>0?I+1|0:I)^u,63),q=h,J=H,I=o+F|0,F=e=H+d|0,I=(I=e>>>0<H>>>0?I+1|0:I)+(cA=i[g+204>>2])|0,S=pA((e=H=e+i[g+200>>2]|0)^S,(H=F>>>0>e>>>0?I+1|0:I)^l,32),I=M+(F=h)|0,I=p>>>0>(l=p+S|0)>>>0?I+1|0:I,p=l,l=o,o=I,l=pA(J^p,l^I,24),d=I=h,M=I,J=l,I=H+fA|0,I=(I=(l=e+j|0)>>>0<j>>>0?I+1|0:I)+M|0,S=pA((e=j=J+(H=l)|0)^S,(l=F)^(F=H>>>0>e>>>0?I+1|0:I),16),I=o+(M=h)|0,j=pA(J^(o=j=p+S|0),(p=p>>>0>o>>>0?I+1|0:I)^d,63),H=h,J=Y,I=U+L|0,I=(I=(l=v+Y|0)>>>0<v>>>0?I+1|0:I)+(d=i[g+236>>2])|0,b=pA((Y=v=l+i[g+232>>2]|0)^AA,(v=v>>>0<l>>>0?I+1|0:I)^b,32),I=y+(U=h)|0,I=_>>>0>(l=_+b|0)>>>0?I+1|0:I,_=l,l=L,L=I,y=pA(J^_,l^I,24),l=I=h,d=y,I=v+E|0,I=(I=(y=Y+X|0)>>>0<X>>>0?I+1|0:I)+l|0,I=y>>>0>(X=d+y|0)>>>0?I+1|0:I,y=U,U=I,b=pA((v=X)^b,y^I,16),I=L+(Y=h)|0,y=l,l=I=_>>>0>(X=_+b|0)>>>0?I+1|0:I,X=pA(d^(_=X),y^I,63),L=h,I=N+B|0,I=(I=(y=r+K|0)>>>0<K>>>0?I+1|0:I)+q|0,I=y>>>0>(K=y+u|0)>>>0?I+1|0:I,N=K,y=T+K|0,K=I,I=a+I|0,T=(r=y)>>>0<T>>>0?I+1|0:I,y=u,u=pA(b^N,Y^K,32),I=p+(N=h)|0,q=(o=b=pA(y^(p=K=o+u|0),(K=o>>>0>p>>>0?I+1|0:I)^q,24))+r|0,I=(r=h)+T|0,I=o>>>0>q>>>0?I+1|0:I,o=q,i[g>>2]=o,i[g+4>>2]=I,q=I,I=pA(o^u,I^N,16),y=T=h,i[g+120>>2]=I,i[g+124>>2]=y,T=I,p=I+p|0,I=y+K|0,i[g+80>>2]=p,I=p>>>0<T>>>0?I+1|0:I,i[g+84>>2]=I,sA=g,wA=pA(b^p,I^r,63),i[sA+40>>2]=wA,i[g+44>>2]=h,r=j,I=t+H|0,I=(K=D+j|0)>>>0<j>>>0?I+1|0:I,j=K,I=I+(T=i[g+132>>2])|0,j=I=(K=K+i[g+128>>2]|0)>>>0<j>>>0?I+1|0:I,t=pA(K^R,I^P,32),I=l+(p=h)|0,I=_>>>0>(T=_+t|0)>>>0?I+1|0:I,_=T,T=I,l=pA(r^_,I^H,24),I=j+(y=h)|0,I=(H=l+K|0)>>>0<K>>>0?I+1|0:I,K=(j=i[g+144>>2])+H|0,I=i[g+148>>2]+I|0,I=K>>>0<j>>>0?I+1|0:I,i[g+8>>2]=K,i[g+12>>2]=I,I=pA(t^K,I^p,16),H=K=h,i[g+96>>2]=I,i[g+100>>2]=H,K=I,j=I+_|0,I=H+T|0,I=K>>>0>j>>>0?I+1|0:I,K=j,i[g+88>>2]=K,i[g+92>>2]=I,sA=g,wA=pA(l^K,I^y,63),i[sA+48>>2]=wA,i[g+52>>2]=h,r=O,I=F+L|0,O=K=e+X|0,I=(I=K>>>0<X>>>0?I+1|0:I)+(j=i[g+220>>2])|0,T=K=K+i[g+216>>2]|0,j=r+K|0,K=I=K>>>0<O>>>0?I+1|0:I,I=I+nA|0,j=(H=j)>>>0<T>>>0?I+1|0:I,r=H,T=pA(x^T,K^z,32),I=m+(H=h)|0,L=pA((t=K=f+T|0)^X,(K=f>>>0>t>>>0?I+1|0:I)^L,24),I=(p=h)+j|0,I=L>>>0>(X=r+L|0)>>>0?I+1|0:I,i[g+16>>2]=X,i[g+20>>2]=I,I=pA(X^T,I^H,16),O=X=h,i[g+104>>2]=I,i[g+108>>2]=X,X=I,j=I+t|0,I=K+O|0,K=j,i[g+64>>2]=K,I=X>>>0>K>>>0?I+1|0:I,i[g+68>>2]=I,sA=g,wA=pA(L^K,I^p,63),i[sA+56>>2]=wA,i[g+60>>2]=h,I=w+C|0,I=(I=(K=G+IA|0)>>>0<G>>>0?I+1|0:I)+U|0,X=I=v>>>0>(K=v+K|0)>>>0?I+1|0:I,T=pA(K^S,I^M,32),I=k+(L=h)|0,IA=I=c>>>0>(j=c+T|0)>>>0?I+1|0:I,H=pA(j^G,I^w,24),I=X+(t=h)|0,I=K>>>0>(O=K+H|0)>>>0?I+1|0:I,K=(X=i[g+152>>2])+O|0,I=i[g+156>>2]+I|0,I=K>>>0<X>>>0?I+1|0:I,i[g+24>>2]=K,i[g+28>>2]=I,I=pA(K^T,I^L,16),i[g+112>>2]=I,X=h,i[g+116>>2]=X,K=I+j|0,I=X+IA|0,I=K>>>0<j>>>0?I+1|0:I,i[g+72>>2]=K,i[g+76>>2]=I,sA=g,wA=pA(H^K,I^t,63),i[sA+32>>2]=wA,i[g+36>>2]=h,I=i[g+68>>2]^(n[A+4|0]|n[A+5|0]<<8|n[A+6|0]<<16|n[A+7|0]<<24)^q,K=i[g+64>>2]^(n[0|A]|n[A+1|0]<<8|n[A+2|0]<<16|n[A+3|0]<<24)^o,Q[0|A]=K,Q[A+1|0]=K>>>8,Q[A+2|0]=K>>>16,Q[A+3|0]=K>>>24,Q[A+4|0]=I,Q[A+5|0]=I>>>8,Q[A+6|0]=I>>>16,Q[A+7|0]=I>>>24,X=1;I=(K=X<<3)+A|0,q=i[(K=g+K|0)>>2]^(n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24),IA=i[(j=K- -64|0)>>2],K=i[j+4>>2]^i[K+4>>2]^(n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24),q^=IA,Q[0|I]=q,Q[I+1|0]=q>>>8,Q[I+2|0]=q>>>16,Q[I+3|0]=q>>>24,Q[I+4|0]=K,Q[I+5|0]=K>>>8,Q[I+6|0]=K>>>16,Q[I+7|0]=K>>>24,8!=(0|(X=X+1|0)););s=g+256|0}function u(A,I,g,B,C,E,a){var r,o,t,e,f,c,y,w,D,p,u,F,_,k,H,G,U,S,b,m,v,M,P,Y,N,R,d,J,x,L,K,X,T,V,q,j,W,O,Z,$,AA,IA=0,gA=0,CA=0,QA=0,EA=0,iA=0,nA=0,aA=0,rA=0,oA=0,tA=0,eA=0,fA=0,cA=0,yA=0,sA=0,wA=0,DA=0,hA=0,pA=0,uA=0,FA=0,lA=0,_A=0,kA=0,HA=0,GA=0,UA=0,SA=0,bA=0,mA=0,vA=0,PA=0,YA=0,NA=0,RA=0,dA=0,JA=0,xA=0,LA=0,KA=0,XA=0,TA=0,VA=0,zA=0,jA=0,WA=0,OA=0,ZA=0,$A=0,AI=0,gI=0,BI=0;return s=R=s-560|0,WI(rA=R+352|0,a),_I(d=R+288|0,E,32,0),z(rA,R+320|0,32,0),z(rA,g,B,C),MA(rA,r=R+224|0),IA=n[E+32|0]|n[E+33|0]<<8|n[E+34|0]<<16|n[E+35|0]<<24,QA=n[E+36|0]|n[E+37|0]<<8|n[E+38|0]<<16|n[E+39|0]<<24,nA=n[E+40|0]|n[E+41|0]<<8|n[E+42|0]<<16|n[E+43|0]<<24,gA=n[E+44|0]|n[E+45|0]<<8|n[E+46|0]<<16|n[E+47|0]<<24,EA=n[E+48|0]|n[E+49|0]<<8|n[E+50|0]<<16|n[E+51|0]<<24,iA=n[E+52|0]|n[E+53|0]<<8|n[E+54|0]<<16|n[E+55|0]<<24,oA=n[E+60|0]|n[E+61|0]<<8|n[E+62|0]<<16|n[E+63|0]<<24,E=n[E+56|0]|n[E+57|0]<<8|n[E+58|0]<<16|n[E+59|0]<<24,Q[A+56|0]=E,Q[A+57|0]=E>>>8,Q[A+58|0]=E>>>16,Q[A+59|0]=E>>>24,Q[A+60|0]=oA,Q[A+61|0]=oA>>>8,Q[A+62|0]=oA>>>16,Q[A+63|0]=oA>>>24,E=EA,Q[A+48|0]=E,Q[A+49|0]=E>>>8,Q[A+50|0]=E>>>16,Q[A+51|0]=E>>>24,E=iA,Q[A+52|0]=E,Q[A+53|0]=E>>>8,Q[A+54|0]=E>>>16,Q[A+55|0]=E>>>24,E=nA,Q[A+40|0]=E,Q[A+41|0]=E>>>8,Q[A+42|0]=E>>>16,Q[A+43|0]=E>>>24,E=gA,Q[A+44|0]=E,Q[A+45|0]=E>>>8,Q[A+46|0]=E>>>16,Q[A+47|0]=E>>>24,Q[0|(E=A+32|0)]=IA,Q[E+1|0]=IA>>>8,Q[E+2|0]=IA>>>16,Q[E+3|0]=IA>>>24,IA=QA,Q[E+4|0]=IA,Q[E+5|0]=IA>>>8,Q[E+6|0]=IA>>>16,Q[E+7|0]=IA>>>24,l(r),BA(R,r),II(A,R),WI(rA,a),z(rA,A,64,0),z(rA,g,B,C),MA(rA,A=R+160|0),l(A),Q[0|d]=248&n[0|d],Q[d+31|0]=63&n[d+31|0]|64,TA=uI(A),nA=n[A+2|0]|n[A+3|0]<<8|n[A+4|0]<<16|n[A+5|0]<<24,SA=uI(A+5|0),EA=h,gA=n[A+7|0]|n[A+8|0]<<8|n[A+9|0]<<16|n[A+10|0]<<24,rA=n[A+10|0]|n[A+11|0]<<8|n[A+12|0]<<16|n[A+13|0]<<24,LA=uI(A+13|0),oA=h,aA=n[A+15|0]|n[A+16|0]<<8|n[A+17|0]<<16|n[A+18|0]<<24,bA=uI(A+18|0),cA=h,NA=uI(A+21|0),B=n[A+23|0]|n[A+24|0]<<8|n[A+25|0]<<16|n[A+26|0]<<24,iA=uI(A+26|0),g=h,C=n[A+28|0]|n[A+29|0]<<8|n[A+30|0]<<16|n[A+31|0]<<24,KA=uI(d),uA=n[(A=d)+2|0]|n[A+3|0]<<8|n[A+4|0]<<16|n[A+5|0]<<24,RA=uI(A+5|0),kA=h,fA=n[A+7|0]|n[A+8|0]<<8|n[A+9|0]<<16|n[A+10|0]<<24,tA=n[A+10|0]|n[A+11|0]<<8|n[A+12|0]<<16|n[A+13|0]<<24,jA=uI(A+13|0),FA=h,sA=n[A+15|0]|n[A+16|0]<<8|n[A+17|0]<<16|n[A+18|0]<<24,VA=uI(A+18|0),hA=h,dA=uI(A+21|0),a=n[A+23|0]|n[A+24|0]<<8|n[A+25|0]<<16|n[A+26|0]<<24,eA=uI(A+26|0),IA=h,QA=n[A+28|0]|n[A+29|0]<<8|n[A+30|0]<<16|n[A+31|0]<<24,W=uI(r),O=n[(A=r)+2|0]|n[A+3|0]<<8|n[A+4|0]<<16|n[A+5|0]<<24,Z=uI(A+5|0),$=h,AA=n[A+7|0]|n[A+8|0]<<8|n[A+9|0]<<16|n[A+10|0]<<24,PA=n[A+10|0]|n[A+11|0]<<8|n[A+12|0]<<16|n[A+13|0]<<24,$A=uI(A+13|0),HA=h,DA=n[A+15|0]|n[A+16|0]<<8|n[A+17|0]<<16|n[A+18|0]<<24,AI=uI(A+18|0),yA=h,JA=uI(A+21|0),A=qA(o=QA>>>7|0,0,t=2097151&((3&(A=g))<<30|(g=iA)>>>2),0),g=h,QA=A,C=qA(e=2097151&((3&(A=IA))<<30|(IA=eA)>>>2),0,f=C>>>7|0,0),g=h+g|0,QA=A=QA+C|0,IA=A>>>0<C>>>0?g+1|0:g,A=qA(t,CA,e,CA),C=h,g=(a=qA(c=a>>>5&2097151,0,f,0))+A|0,A=h+C|0,A=g>>>0<a>>>0?A+1|0:A,C=qA(o,0,y=B>>>5&2097151,0),B=h+A|0,B=(g=C+g|0)>>>0<C>>>0?B+1|0:B,C=g,mA=B,wA=A=B-((g>>>0<4293918720)-1|0)|0,a=(2097151&A)<<11|(iA=g- -1048576|0)>>>21,A=(A>>21)+IA|0,A=(B=a+QA|0)>>>0<a>>>0?A+1|0:A,a=B,GA=A,vA=IA=A-((B>>>0<4293918720)-1|0)|0,g=IA>>21,UA=(A=qA(o,0,f,0))-(lA=-2097152&(pA=A- -1048576|0))|0,A=((eA=h)-((A>>>0<lA>>>0)+(B=eA-((A>>>0<4293918720)-1|0)|0)|0)|0)+g|0,T=IA=UA+((2097151&IA)<<11|(QA=a- -1048576|0)>>>21)|0,eA=A=IA>>>0<UA>>>0?A+1|0:A,g=qA(IA,A,-683901,-1),IA=h,J=(2097151&B)<<11|pA>>>21,pA=A=B>>21,A=(B=qA(J,A,136657,0))+g|0,g=h+IA|0,UA=A,lA=A>>>0<B>>>0?g+1|0:g,A=qA(w=2097151&((1&(A=FA))<<31|jA>>>1),0,t,CA),g=h,IA=qA(D=tA>>>4&2097151,0,f,0),B=h+g|0,B=(A=IA+A|0)>>>0<IA>>>0?B+1|0:B,IA=qA(p=sA>>>6&2097151,0,y,0),g=h+B|0,g=(A=IA+A|0)>>>0<IA>>>0?g+1|0:g,FA=A,IA=qA(u=2097151&dA,B=0,F=2097151&((7&(A=cA))<<29|bA>>>3),0),A=h+g|0,g=A=(B=FA+IA|0)>>>0<IA>>>0?A+1|0:A,A=(IA=qA(_=2097151&((7&(A=hA))<<29|VA>>>3),0,k=2097151&NA,0))+B|0,B=h+g|0,B=A>>>0<IA>>>0?B+1|0:B,IA=qA(c,0,H=aA>>>6&2097151,0),g=h+B|0,g=(A=IA+A|0)>>>0<IA>>>0?g+1|0:g,B=A,IA=qA(e,CA,G=2097151&((1&(A=oA))<<31|LA>>>1),0),A=h+g|0,A=(B=B+IA|0)>>>0<IA>>>0?A+1|0:A,g=(IA=qA(o,0,U=rA>>>4&2097151,0))+B|0,B=h+A|0,cA=g,rA=g>>>0<IA>>>0?B+1|0:B,A=qA(t,CA,D,0),g=h,B=qA(S=fA>>>7&2097151,0,f,0),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=(IA=qA(y,0,w,CA))+A|0,A=h+g|0,A=B>>>0<IA>>>0?A+1|0:A,g=(IA=qA(p,0,k,CA))+B|0,B=h+A|0,B=g>>>0<IA>>>0?B+1|0:B,A=(IA=qA(u,CA,H,0))+g|0,g=h+B|0,g=A>>>0<IA>>>0?g+1|0:g,B=(IA=qA(F,CA,_,CA))+A|0,A=h+g|0,A=B>>>0<IA>>>0?A+1|0:A,IA=qA(c,0,G,CA),g=h+A|0,g=(B=IA+B|0)>>>0<IA>>>0?g+1|0:g,IA=qA(e,CA,U,0),A=h+g|0,A=(B=IA+B|0)>>>0<IA>>>0?A+1|0:A,g=(IA=qA(o,0,b=gA>>>7&2097151,0))+B|0,B=h+A|0,B=g>>>0<IA>>>0?B+1|0:B,IA=g,oA=B,A=B-((g>>>0<4293918720)-1|0)|0,B=g- -1048576|0,aA=A,g=cA,cA=(2097151&A)<<11|B>>>21,A=(A>>21)+rA|0,A=(gA=(g=gA=g+cA|0)>>>0<cA>>>0?A+1|0:A)+lA|0,A=g>>>0>(rA=g+UA|0)>>>0?A+1|0:A,gA=gA-((g>>>0<4293918720)-1|0)|0,tA=rA-(g=-2097152&(fA=g- -1048576|0))|0,rA=A-((g>>>0>rA>>>0)+gA|0)|0,cA=GA-(((A=-2097152&QA)>>>0>a>>>0)+vA|0)|0,x=a-A|0,a=qA(J,pA,-997805,-1),g=h+oA|0,g=(A=a+IA|0)>>>0<a>>>0?g+1|0:g,a=(IA=qA(T,eA,136657,0))+A|0,A=h+g|0,A=a>>>0<IA>>>0?A+1|0:A,g=a,a=qA(x,cA,-683901,-1),A=h+A|0,QA=(g=g+a|0)-(B&=-2097152)|0,oA=(A=g>>>0<a>>>0?A+1|0:A)-((g>>>0<B>>>0)+aA|0)|0,A=qA(t,CA,S,0),B=h,g=A,a=qA(m=2097151&((3&(A=kA))<<30|RA>>>2),0,f,0),A=h+B|0,A=(g=g+a|0)>>>0<a>>>0?A+1|0:A,a=qA(y,0,D,0),B=h+A|0,B=(g=a+g|0)>>>0<a>>>0?B+1|0:B,A=(a=qA(w,CA,k,CA))+g|0,g=h+B|0,g=A>>>0<a>>>0?g+1|0:g,B=(a=qA(p,0,F,CA))+A|0,A=h+g|0,A=B>>>0<a>>>0?A+1|0:A,a=qA(u,CA,G,CA),g=h+A|0,g=(B=a+B|0)>>>0<a>>>0?g+1|0:g,a=qA(_,CA,H,0),A=h+g|0,A=(B=a+B|0)>>>0<a>>>0?A+1|0:A,g=(a=qA(c,0,U,0))+B|0,B=h+A|0,B=g>>>0<a>>>0?B+1|0:B,A=(a=qA(e,CA,b,0))+g|0,g=h+B|0,g=A>>>0<a>>>0?g+1|0:g,B=A,a=qA(o,0,v=2097151&((3&(A=EA))<<30|SA>>>2),0),A=h+g|0,EA=B=B+a|0,IA=B>>>0<a>>>0?A+1|0:A,A=qA(t,CA,m,0),g=h,B=qA(M=uA>>>5&2097151,0,f,0),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=qA(y,0,S,0),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=(a=qA(D,0,k,CA))+A|0,A=h+g|0,A=B>>>0<a>>>0?A+1|0:A,g=B,B=qA(w,CA,F,CA),A=h+A|0,A=(g=g+B|0)>>>0<B>>>0?A+1|0:A,a=qA(p,0,H,0),B=h+A|0,B=(g=a+g|0)>>>0<a>>>0?B+1|0:B,A=(a=qA(u,CA,U,0))+g|0,g=h+B|0,g=A>>>0<a>>>0?g+1|0:g,B=qA(_,CA,G,CA),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=(a=qA(c,0,b,0))+A|0,A=h+g|0,A=B>>>0<a>>>0?A+1|0:A,g=B,B=qA(e,CA,v,0),A=h+A|0,A=(g=g+B|0)>>>0<B>>>0?A+1|0:A,a=qA(o,0,P=nA>>>5&2097151,0),B=h+A|0,B=(g=a+g|0)>>>0<a>>>0?B+1|0:B,a=g,SA=B,LA=g=B-((g>>>0<4293918720)-1|0)|0,A=(A=g>>21)+IA|0,IA=g=(B=(2097151&g)<<11|(hA=a- -1048576|0)>>>21)+EA|0,bA=A=g>>>0<B>>>0?A+1|0:A,NA=g=A-((g>>>0<4293918720)-1|0)|0,A=g>>21,g=(B=QA)+(QA=(2097151&g)<<11|(GA=IA- -1048576|0)>>>21)|0,B=A+oA|0,B=g>>>0<QA>>>0?B+1|0:B,QA=g,RA=B,jA=g=B-((g>>>0<4293918720)-1|0)|0,A=(A=g>>21)+rA|0,nA=g=(B=(2097151&g)<<11|(vA=QA- -1048576|0)>>>21)+tA|0,lA=A=g>>>0<B>>>0?A+1|0:A,VA=g=A-((g>>>0<4293918720)-1|0)|0,uA=(2097151&g)<<11|(aA=nA- -1048576|0)>>>21,rA=g>>21,A=qA(t,CA,p,0),g=h,EA=qA(f,0,w,CA),B=h+g|0,B=(A=EA+A|0)>>>0<EA>>>0?B+1|0:B,EA=qA(u,CA,k,CA),g=h+B|0,g=(A=EA+A|0)>>>0<EA>>>0?g+1|0:g,B=(EA=qA(y,0,_,CA))+A|0,A=h+g|0,A=B>>>0<EA>>>0?A+1|0:A,EA=qA(c,0,F,CA),g=h+A|0,g=(B=EA+B|0)>>>0<EA>>>0?g+1|0:g,EA=qA(e,CA,H,0),A=h+g|0,A=(B=EA+B|0)>>>0<EA>>>0?A+1|0:A,g=(EA=qA(o,0,G,CA))+B|0,B=h+A|0,B=g>>>0<EA>>>0?B+1|0:B,A=g,oA=qA(J,pA,-683901,-1),g=h+B|0,g=(EA=A+oA|0)>>>0<oA>>>0?g+1|0:g,oA=EA,EA=B-((A>>>0<4293918720)-1|0)|0,B=oA-(A=-2097152&(kA=A- -1048576|0))|0,oA=g-((A>>>0>oA>>>0)+EA|0)|0,g=(A=B)+(B=(2097151&gA)<<11|fA>>>21)|0,A=(gA>>21)+oA|0,A=g>>>0<B>>>0?A+1|0:A,B=uA,fA=g-(uA=-2097152&(oA=g- -1048576|0))|0,g=(A-((gA=A-((g>>>0<4293918720)-1|0)|0)+(g>>>0<uA>>>0)|0)|0)+rA|0,V=B=B+fA|0,uA=g=B>>>0<fA>>>0?g+1|0:g,rA=qA(B,g,-683901,-1),fA=h,A=qA(y,0,u,CA),B=h,g=(tA=qA(f,0,p,0))+A|0,A=h+B|0,A=g>>>0<tA>>>0?A+1|0:A,B=(tA=qA(t,CA,_,CA))+g|0,g=h+A|0,g=B>>>0<tA>>>0?g+1|0:g,tA=qA(c,0,k,CA),A=h+g|0,A=(B=tA+B|0)>>>0<tA>>>0?A+1|0:A,g=(tA=qA(e,CA,F,CA))+B|0,B=h+A|0,B=g>>>0<tA>>>0?B+1|0:B,A=(tA=qA(o,0,H,0))+g|0,g=h+B|0,g=A>>>0<tA>>>0?g+1|0:g,B=A,A=(A=EA>>21)+g|0,FA=B=(A=(g=B=B+(EA=(2097151&EA)<<11|kA>>>21)|0)>>>0<EA>>>0?A+1|0:A)-((g>>>0<4293918720)-1|0)|0,kA=g-(EA=-2097152&(UA=g- -1048576|0))|0,B=A-((g>>>0<EA>>>0)+B|0)|0,g=(g=(A=gA)>>21)+B|0,q=A=(gA=(2097151&A)<<11|(gA=oA)>>>21)+kA|0,kA=g=A>>>0<gA>>>0?g+1|0:g,B=qA(A,g,136657,0),A=h+fA|0,gI=g=B+rA|0,dA=g>>>0<B>>>0?A+1|0:A,A=qA(k,CA,M,0),B=h,g=(gA=qA(Y=2097151&KA,0,y,0))+A|0,A=h+B|0,A=g>>>0<gA>>>0?A+1|0:A,gA=qA(F,CA,m,0),B=h+A|0,B=(g=gA+g|0)>>>0<gA>>>0?B+1|0:B,A=(gA=qA(H,0,S,0))+g|0,g=h+B|0,g=A>>>0<gA>>>0?g+1|0:g,B=(gA=qA(D,0,G,CA))+A|0,A=h+g|0,A=B>>>0<gA>>>0?A+1|0:A,gA=qA(w,CA,U,0),g=h+A|0,g=(B=gA+B|0)>>>0<gA>>>0?g+1|0:g,gA=qA(p,0,b,0),A=h+g|0,A=(B=gA+B|0)>>>0<gA>>>0?A+1|0:A,g=(gA=qA(u,CA,P,0))+B|0,B=h+A|0,B=g>>>0<gA>>>0?B+1|0:B,A=(gA=qA(_,CA,v,0))+g|0,g=h+B|0,g=A>>>0<gA>>>0?g+1|0:g,B=(gA=qA(c,0,N=2097151&TA,0))+A|0,A=h+g|0,A=B>>>0<gA>>>0?A+1|0:A,rA=B=(gA=(n[r+23|0]|n[r+24|0]<<8|n[r+25|0]<<16|n[r+26|0]<<24)>>>5&2097151)+B|0,EA=B>>>0<gA>>>0?A+1|0:A,A=qA(F,CA,M,0),g=h,gA=qA(k,CA,Y,0),B=h+g|0,B=(A=gA+A|0)>>>0<gA>>>0?B+1|0:B,gA=qA(H,0,m,0),g=h+B|0,g=(A=gA+A|0)>>>0<gA>>>0?g+1|0:g,B=(gA=qA(G,CA,S,0))+A|0,A=h+g|0,A=B>>>0<gA>>>0?A+1|0:A,g=B,B=qA(D,0,U,0),A=h+A|0,A=(g=g+B|0)>>>0<B>>>0?A+1|0:A,B=(gA=qA(w,CA,b,0))+g|0,g=h+A|0,g=B>>>0<gA>>>0?g+1|0:g,A=(gA=qA(p,0,v,0))+B|0,B=h+g|0,B=A>>>0<gA>>>0?B+1|0:B,gA=qA(N,0,u,CA),g=h+B|0,g=(A=gA+A|0)>>>0<gA>>>0?g+1|0:g,B=(gA=qA(_,CA,P,0))+A|0,A=h+g|0,A=B>>>0<gA>>>0?A+1|0:A,gA=g=(g=B)+(B=2097151&JA)|0,sA=A=g>>>0<B>>>0?A+1|0:A,TA=A=A-((g>>>0<4293918720)-1|0)|0,oA=g- -1048576|0,g=(B=A>>>21|0)+EA|0,EA=A=(tA=rA)+(rA=(2097151&A)<<11|oA>>>21)|0,KA=A>>>0<rA>>>0?g+1|0:g,fA=C-(A=-2097152&iA)|0,WA=mA-((A>>>0>C>>>0)+wA|0)|0,A=qA(t,CA,c,0),B=h,g=(C=qA(f,0,u,CA))+A|0,A=h+B|0,A=g>>>0<C>>>0?A+1|0:A,C=qA(e,CA,y,0),B=h+A|0,B=(g=C+g|0)>>>0<C>>>0?B+1|0:B,A=(C=qA(o,0,k,CA))+g|0,g=h+B|0,tA=A,iA=A>>>0<C>>>0?g+1|0:g,A=qA(f,0,_,CA),g=h,B=qA(t,CA,u,CA),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=(C=qA(c,0,y,0))+A|0,A=h+g|0,A=B>>>0<C>>>0?A+1|0:A,g=B,B=qA(e,CA,k,CA),A=h+A|0,A=(g=g+B|0)>>>0<B>>>0?A+1|0:A,C=qA(o,0,F,CA),B=h+A|0,B=(g=C+g|0)>>>0<C>>>0?B+1|0:B,C=g,mA=B,wA=g=B-((g>>>0<4293918720)-1|0)|0,A=tA,tA=(2097151&g)<<11|(rA=C- -1048576|0)>>>21,g=(g>>21)+iA|0,iA=B=A+tA|0,JA=g=B>>>0<tA>>>0?g+1|0:g,tA=B- -1048576|0,B=(A=(g=g-((B>>>0<4293918720)-1|0)|0)>>21)+WA|0,L=fA=(ZA=(2097151&g)<<11|tA>>>21)+fA|0,fA=B=fA>>>0<ZA>>>0?B+1|0:B,A=qA(L,B,470296,0),B=h,tA=JA-((YA=g)+((g=-2097152&tA)>>>0>iA>>>0)|0)|0,K=iA-g|0,iA=qA(x,cA,666643,0),g=h+B|0,g=(A=iA+A|0)>>>0<iA>>>0?g+1|0:g,B=(iA=qA(K,tA,654183,0))+A|0,A=h+g|0,A=B>>>0<iA>>>0?A+1|0:A,iA=B,B=A,rA=mA-(((A=-2097152&rA)>>>0>C>>>0)+wA|0)|0,C=g=C-A|0,FA=(2097151&(g=FA))<<11|UA>>>21,g=(A=g>>21)+rA|0,j=C=C+FA|0,FA=g=C>>>0<FA>>>0?g+1|0:g,rA=KA-(((A=EA)>>>0<4293918720)-1|0)|0,XA=A- -1048576|0,C=qA(C,g,-997805,-1),g=h+B|0,g=(A=C+iA|0)>>>0<C>>>0?g+1|0:g,C=A,B=EA+A|0,A=g+KA|0,A=B>>>0<C>>>0?A+1|0:A,UA=(g=B)-(B=-2097152&XA)|0,WA=A-((g>>>0<B>>>0)+rA|0)|0,A=qA(K,tA,470296,0),g=h,B=qA(L,fA,666643,0),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=(C=qA(j,FA,654183,0))+A|0,A=h+g|0,g=B+gA|0,B=sA+(B>>>0<C>>>0?A+1|0:A)|0,B=g>>>0<gA>>>0?B+1|0:B,oA=(A=g)-(g=-2097152&oA)|0,sA=B-((A>>>0<g>>>0)+TA|0)|0,A=qA(H,0,M,0),B=h,g=(C=qA(F,CA,Y,0))+A|0,A=h+B|0,A=g>>>0<C>>>0?A+1|0:A,B=qA(G,CA,m,0),A=h+A|0,A=(g=B+g|0)>>>0<B>>>0?A+1|0:A,C=qA(U,0,S,0),B=h+A|0,B=(g=C+g|0)>>>0<C>>>0?B+1|0:B,A=(C=qA(D,0,b,0))+g|0,g=h+B|0,g=A>>>0<C>>>0?g+1|0:g,B=qA(w,CA,v,0),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=(C=qA(p,0,P,0))+A|0,A=h+g|0,A=B>>>0<C>>>0?A+1|0:A,g=B,B=qA(N,0,_,CA),A=h+A|0,A=(g=g+B|0)>>>0<B>>>0?A+1|0:A,B=g,g=A,iA=A=(C=2097151&((7&(A=yA))<<29|AI>>>3))+B|0,C=A>>>0<C>>>0?g+1|0:g,A=qA(G,CA,M,0),g=h,B=qA(H,0,Y,0),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=(gA=qA(U,0,m,0))+A|0,A=h+g|0,A=B>>>0<gA>>>0?A+1|0:A,gA=qA(S,0,b,0),g=h+A|0,g=(B=gA+B|0)>>>0<gA>>>0?g+1|0:g,gA=qA(D,0,v,0),A=h+g|0,A=(B=gA+B|0)>>>0<gA>>>0?A+1|0:A,g=(gA=qA(w,CA,P,0))+B|0,B=h+A|0,B=g>>>0<gA>>>0?B+1|0:B,A=(gA=qA(N,0,p,0))+g|0,g=h+B|0,B=A,A=A>>>0<gA>>>0?g+1|0:g,gA=g=(g=B)+(B=DA>>>6&2097151)|0,yA=A=g>>>0<B>>>0?A+1|0:A,mA=A=A-((g>>>0<4293918720)-1|0)|0,EA=g- -1048576|0,g=(B=A>>>21|0)+C|0,C=A=(wA=iA)+(iA=(2097151&A)<<11|EA>>>21)|0,wA=g=A>>>0<iA>>>0?g+1|0:g,TA=A=g-((A>>>0<4293918720)-1|0)|0,g=oA,oA=(2097151&A)<<11|(iA=C- -1048576|0)>>>21,A=(A>>>21|0)+sA|0,sA=g=g+oA|0,KA=A=g>>>0<oA>>>0?A+1|0:A,JA=A=A-((g>>>0<4293918720)-1|0)|0,DA=g- -1048576|0,g=(B=A>>21)+WA|0,g=(A=(oA=(2097151&A)<<11|DA>>>21)+UA|0)>>>0<oA>>>0?g+1|0:g,B=A,oA=A+gI|0,A=g+dA|0,A=B>>>0>oA>>>0?A+1|0:A,dA=oA,oA=g-((B>>>0<4293918720)-1|0)|0,OA=dA-(g=-2097152&(zA=B- -1048576|0))|0,xA=A-((g>>>0>dA>>>0)+oA|0)|0,g=qA(q,kA,-997805,-1),B=h+KA|0,YA=A=g+sA|0,dA=A>>>0<g>>>0?B+1|0:B,A=qA(j,FA,470296,0),B=h,g=(sA=qA(K,tA,666643,0))+A|0,A=h+B|0,A=(A=g>>>0<sA>>>0?A+1|0:A)+wA|0,sA=(g=g+C|0)-(B=-2097152&iA)|0,wA=(A=g>>>0<C>>>0?A+1|0:A)-((g>>>0<B>>>0)+TA|0)|0,B=qA(j,FA,666643,0),g=h+yA|0,yA=A=B+gA|0,iA=A>>>0<B>>>0?g+1|0:g,A=qA(U,0,M,0),B=h,g=(C=qA(G,CA,Y,0))+A|0,A=h+B|0,A=g>>>0<C>>>0?A+1|0:A,B=qA(b,0,m,0),A=h+A|0,A=(g=B+g|0)>>>0<B>>>0?A+1|0:A,C=qA(S,0,v,0),B=h+A|0,B=(g=C+g|0)>>>0<C>>>0?B+1|0:B,A=(C=qA(D,0,P,0))+g|0,g=h+B|0,g=A>>>0<C>>>0?g+1|0:g,B=qA(N,0,w,CA),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,B=A,C=2097151&((1&(A=HA))<<31|$A>>>1),A=g,HA=B=B+C|0,gA=B>>>0<C>>>0?A+1|0:A,A=qA(b,0,M,0),B=h,g=(C=qA(U,0,Y,0))+A|0,A=h+B|0,A=g>>>0<C>>>0?A+1|0:A,B=(C=qA(m,0,v,0))+g|0,g=h+A|0,g=B>>>0<C>>>0?g+1|0:g,A=(C=qA(S,0,P,0))+B|0,B=h+g|0,B=A>>>0<C>>>0?B+1|0:B,C=qA(N,0,D,0),g=h+B|0,B=A=C+A|0,A=A>>>0<C>>>0?g+1|0:g,C=g=(g=B)+(B=PA>>>4&2097151)|0,TA=A=g>>>0<B>>>0?A+1|0:A,KA=A=A-((g>>>0<4293918720)-1|0)|0,PA=g- -1048576|0,g=(B=A>>>21|0)+gA|0,gA=A=(UA=HA)+(HA=(2097151&A)<<11|PA>>>21)|0,UA=g=A>>>0<HA>>>0?g+1|0:g,$A=A=g-((A>>>0<4293918720)-1|0)|0,g=yA,yA=(2097151&A)<<11|(HA=gA- -1048576|0)>>>21,A=(A>>>21|0)+iA|0,AI=A=(A=(g=g+yA|0)>>>0<yA>>>0?A+1|0:A)-(((B=-2097152&EA)>>>0>g>>>0)+mA|0)|0,gI=A=A-(((EA=g-B|0)>>>0<4293918720)-1|0)|0,B=(g=A>>21)+wA|0,mA=A=(iA=(2097151&A)<<11|(yA=EA- -1048576|0)>>>21)+sA|0,WA=B=A>>>0<iA>>>0?B+1|0:B,ZA=A=B-((A>>>0<4293918720)-1|0)|0,sA=lA-(((g=-2097152&aA)>>>0>nA>>>0)+VA|0)|0,X=nA-g|0,nA=(2097151&A)<<11|(wA=mA- -1048576|0)>>>21,A=(A>>21)+dA|0,A=(B=nA+YA|0)>>>0<nA>>>0?A+1|0:A,g=(iA=qA(V,uA,136657,0))+(B-(nA=-2097152&DA)|0)|0,B=h+(A-((B>>>0<nA>>>0)+JA|0)|0)|0,B=g>>>0<iA>>>0?B+1|0:B,nA=qA(X,sA,-683901,-1),A=h+B|0,A=(g=nA+g|0)>>>0<nA>>>0?A+1|0:A,nA=g,VA=A,dA=A=A-((g>>>0<4293918720)-1|0)|0,B=(g=A>>21)+xA|0,B=(A=(iA=(2097151&A)<<11|(DA=nA- -1048576|0)>>>21)+OA|0)>>>0<iA>>>0?B+1|0:B,iA=A,JA=B,OA=A=B-((A>>>0<4293918720)-1|0)|0,BI=(2097151&A)<<11|(lA=iA- -1048576|0)>>>21,xA=A>>21,A=qA(y,0,M,0),B=h,g=(aA=qA(t,CA,Y,0))+A|0,A=h+B|0,A=g>>>0<aA>>>0?A+1|0:A,B=(aA=qA(k,CA,m,0))+g|0,g=h+A|0,g=B>>>0<aA>>>0?g+1|0:g,A=(aA=qA(F,CA,S,0))+B|0,B=h+g|0,B=A>>>0<aA>>>0?B+1|0:B,g=(aA=qA(D,0,H,0))+A|0,A=h+B|0,A=g>>>0<aA>>>0?A+1|0:A,B=(aA=qA(w,CA,G,CA))+g|0,g=h+A|0,g=B>>>0<aA>>>0?g+1|0:g,aA=qA(p,0,U,0),A=h+g|0,A=(B=aA+B|0)>>>0<aA>>>0?A+1|0:A,aA=qA(u,CA,v,0),g=h+A|0,g=(B=aA+B|0)>>>0<aA>>>0?g+1|0:g,A=(aA=qA(_,CA,b,0))+B|0,B=h+g|0,B=A>>>0<aA>>>0?B+1|0:B,g=(aA=qA(c,0,P,0))+A|0,A=h+B|0,A=g>>>0<aA>>>0?A+1|0:A,B=(aA=qA(N,0,e,CA))+g|0,g=h+A|0,g=B>>>0<aA>>>0?g+1|0:g,YA=B,B=uI(r+26|0),aA=2097151&((3&(A=h))<<30|B>>>2),A=g,A=(B=YA+aA|0)>>>0<aA>>>0?A+1|0:A,aA=B,YA=A,A=qA(x,cA,470296,0),g=h,B=qA(T,eA,666643,0),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,_A=qA(L,fA,654183,0),B=h+g|0,B=(A=_A+A|0)>>>0<_A>>>0?B+1|0:B,_A=qA(K,tA,-997805,-1),g=h+B|0,g=(A=_A+A|0)>>>0<_A>>>0?g+1|0:g,B=(_A=qA(j,FA,136657,0))+A|0,A=h+g|0,A=(A=B>>>0<_A>>>0?A+1|0:A)+YA|0,A=(g=B+aA|0)>>>0<B>>>0?A+1|0:A,B=g,aA=YA-(((g=aA)>>>0<4293918720)-1|0)|0,YA=g- -1048576|0,g=A+(g=rA>>>21|0)|0,g=(B=(rA=(2097151&rA)<<11|XA>>>21)+B|0)>>>0<rA>>>0?g+1|0:g,B=(A=B)-(XA=-2097152&YA)|0,_A=qA(q,kA,-683901,-1),A=(g=g-((A>>>0<XA>>>0)+aA|0)|0)+h|0,A=(rA=B+_A|0)>>>0<_A>>>0?A+1|0:A,_A=rA,rA=g-((B>>>0<4293918720)-1|0)|0,XA=B- -1048576|0,g=A+(g=oA>>21)|0,g=(B=(oA=(2097151&oA)<<11|zA>>>21)+_A|0)>>>0<oA>>>0?g+1|0:g,B=(A=B)-(zA=-2097152&XA)|0,A=(_A=xA)+(xA=g-((A>>>0<zA>>>0)+rA|0)|0)|0,A=B>>>0>(oA=B+BI|0)>>>0?A+1|0:A,g=oA,oA=xA-((B>>>0<4293918720)-1|0)|0,zA=g-(B=-2097152&(xA=B- -1048576|0))|0,BI=A-((g>>>0<B>>>0)+oA|0)|0,_A=iA-(A=-2097152&lA)|0,JA=JA-((A>>>0>iA>>>0)+OA|0)|0,OA=nA-(A=-2097152&DA)|0,VA=VA-((A>>>0>nA>>>0)+dA|0)|0,B=qA(q,kA,654183,0),A=h+WA|0,A=(g=B+mA|0)>>>0<B>>>0?A+1|0:A,B=(iA=qA(V,uA,-997805,-1))+(g-(nA=-2097152&wA)|0)|0,g=h+(A-((g>>>0<nA>>>0)+ZA|0)|0)|0,g=B>>>0<iA>>>0?g+1|0:g,nA=qA(X,sA,136657,0),A=h+g|0,lA=B=nA+B|0,DA=B>>>0<nA>>>0?A+1|0:A,iA=QA-(A=-2097152&vA)|0,RA=RA-((A>>>0>QA>>>0)+jA|0)|0,A=qA(T,eA,-997805,-1),g=h,QA=qA(J,pA,654183,0),B=h+g|0,B=(A=QA+A|0)>>>0<QA>>>0?B+1|0:B,QA=qA(x,cA,136657,0),g=h+B|0,g=(A=QA+A|0)>>>0<QA>>>0?g+1|0:g,B=(QA=qA(L,fA,-683901,-1))+A|0,A=h+g|0,g=(A=B>>>0<QA>>>0?A+1|0:A)+bA|0,g=(B=B+IA|0)>>>0<IA>>>0?g+1|0:g,QA=(A=B)-(B=-2097152&GA)|0,bA=g-((A>>>0<B>>>0)+NA|0)|0,A=qA(T,eA,654183,0),g=h,IA=qA(J,pA,470296,0),B=h+g|0,B=(A=IA+A|0)>>>0<IA>>>0?B+1|0:B,g=(IA=qA(x,cA,-997805,-1))+A|0,A=h+B|0,B=g+a|0,g=SA+(g>>>0<IA>>>0?A+1|0:A)|0,g=B>>>0<a>>>0?g+1|0:g,A=B,B=qA(L,fA,136657,0),g=h+g|0,g=(A=A+B|0)>>>0<B>>>0?g+1|0:g,B=(a=qA(K,tA,-683901,-1))+A|0,A=h+g|0,A=B>>>0<a>>>0?A+1|0:A,IA=(g=B)-(B=-2097152&hA)|0,hA=A-((g>>>0<B>>>0)+LA|0)|0,A=qA(t,CA,M,0),B=h,g=(a=qA(f,0,Y,0))+A|0,A=h+B|0,A=g>>>0<a>>>0?A+1|0:A,B=(a=qA(y,0,m,0))+g|0,g=h+A|0,g=B>>>0<a>>>0?g+1|0:g,a=qA(k,CA,S,0),A=h+g|0,A=(B=a+B|0)>>>0<a>>>0?A+1|0:A,a=qA(D,0,F,CA),g=h+A|0,g=(B=a+B|0)>>>0<a>>>0?g+1|0:g,A=(a=qA(w,CA,H,0))+B|0,B=h+g|0,B=A>>>0<a>>>0?B+1|0:B,g=(a=qA(p,0,G,CA))+A|0,A=h+B|0,A=g>>>0<a>>>0?A+1|0:A,B=(a=qA(u,CA,b,0))+g|0,g=h+A|0,g=B>>>0<a>>>0?g+1|0:g,a=qA(_,CA,U,0),A=h+g|0,A=(B=a+B|0)>>>0<a>>>0?A+1|0:A,a=qA(c,0,v,0),g=h+A|0,g=(B=a+B|0)>>>0<a>>>0?g+1|0:g,A=(a=qA(N,0,o,0))+B|0,B=h+g|0,B=A>>>0<a>>>0?B+1|0:B,g=(a=qA(e,CA,P,0))+A|0,A=h+B|0,A=g>>>0<a>>>0?A+1|0:A,A=(aA>>>21|0)+(g=(B=(a=(n[r+28|0]|n[r+29|0]<<8|n[r+30|0]<<16|n[r+31|0]<<24)>>>7|0)+g|0)>>>0<a>>>0?A+1|0:A)|0,A=(B=(a=(2097151&aA)<<11|YA>>>21)+B|0)>>>0<a>>>0?A+1|0:A,a=B,GA=A,vA=A=A-((B>>>0<4293918720)-1|0)|0,g=IA,IA=(2097151&A)<<11|(nA=B- -1048576|0)>>>21,A=(A>>21)+hA|0,A=(B=g+IA|0)>>>0<IA>>>0?A+1|0:A,IA=B,mA=A,wA=A=A-((B>>>0<4293918720)-1|0)|0,g=QA,QA=(2097151&A)<<11|(CA=B- -1048576|0)>>>21,A=(A>>21)+bA|0,aA=A=(B=g+QA|0)>>>0<QA>>>0?A+1|0:A,hA=A=A-((B>>>0<4293918720)-1|0)|0,SA=(2097151&A)<<11|(QA=B- -1048576|0)>>>21,A=(A>>21)+RA|0,bA=iA=SA+iA|0,iA=A=iA>>>0<SA>>>0?A+1|0:A,A=(g=lA)+(lA=qA(bA,A,-683901,-1))|0,g=h+DA|0,SA=A,DA=A>>>0<lA>>>0?g+1|0:g,aA=aA-(((A=-2097152&QA)>>>0>B>>>0)+hA|0)|0,NA=B-A|0,g=qA(q,kA,470296,0)+EA|0,A=AI+h|0,A=g>>>0<EA>>>0?A+1|0:A,B=(EA=qA(V,uA,654183,0))+(g-(QA=-2097152&yA)|0)|0,g=h+(A-((g>>>0<QA>>>0)+gI|0)|0)|0,g=B>>>0<EA>>>0?g+1|0:g,A=B,B=qA(X,sA,-997805,-1),g=h+g|0,g=(A=A+B|0)>>>0<B>>>0?g+1|0:g,B=(QA=qA(bA,iA,136657,0))+A|0,A=h+g|0,A=B>>>0<QA>>>0?A+1|0:A,g=(QA=qA(NA,aA,-683901,-1))+B|0,B=h+A|0,yA=B=g>>>0<QA>>>0?B+1|0:B,lA=B=B-((g>>>0<4293918720)-1|0)|0,A=(A=B>>21)+DA|0,A=(B=(QA=(2097151&B)<<11|(EA=g- -1048576|0)>>>21)+SA|0)>>>0<QA>>>0?A+1|0:A,QA=B,DA=A,SA=B=A-((B>>>0<4293918720)-1|0)|0,RA=(2097151&B)<<11|(hA=QA- -1048576|0)>>>21,B=(B>>21)+VA|0,B=RA>>>0>(LA=RA+OA|0)>>>0?B+1|0:B,RA=LA,LA=B,jA=QA-(A=-2097152&hA)|0,SA=DA-((A>>>0>QA>>>0)+SA|0)|0,DA=g-(A=-2097152&EA)|0,yA=yA-((A>>>0>g>>>0)+lA|0)|0,A=(B=qA(q,kA,666643,0))+(gA-(g=-2097152&HA)|0)|0,g=h+(UA-((g>>>0>gA>>>0)+$A|0)|0)|0,g=A>>>0<B>>>0?g+1|0:g,QA=qA(V,uA,470296,0),B=h+g|0,B=(A=QA+A|0)>>>0<QA>>>0?B+1|0:B,g=(QA=qA(X,sA,654183,0))+A|0,A=h+B|0,hA=g,QA=g>>>0<QA>>>0?A+1|0:A,gA=IA-(A=-2097152&CA)|0,IA=mA-((A>>>0>IA>>>0)+wA|0)|0,A=qA(T,eA,470296,0),B=h,g=(EA=qA(J,pA,666643,0))+A|0,A=h+B|0,A=g>>>0<EA>>>0?A+1|0:A,EA=qA(x,cA,654183,0),B=h+A|0,B=(g=EA+g|0)>>>0<EA>>>0?B+1|0:B,EA=qA(L,fA,-997805,-1),A=h+B|0,A=(g=EA+g|0)>>>0<EA>>>0?A+1|0:A,B=(EA=qA(K,tA,136657,0))+g|0,g=h+A|0,g=B>>>0<EA>>>0?g+1|0:g,A=B,B=qA(j,FA,-683901,-1),g=h+g|0,g=(A=A+B|0)>>>0<B>>>0?g+1|0:g,B=A+a|0,A=g+GA|0,A=B>>>0<a>>>0?A+1|0:A,a=(g=B)-(B=-2097152&nA)|0,B=A-((g>>>0<B>>>0)+vA|0)|0,g=(A=a)+(a=(2097151&rA)<<11|XA>>>21)|0,A=(rA>>21)+B|0,A=g>>>0<a>>>0?A+1|0:A,a=g,kA=A,fA=g=A-((g>>>0<4293918720)-1|0)|0,nA=(2097151&g)<<11|(EA=a- -1048576|0)>>>21,g=(g>>21)+IA|0,HA=B=nA+gA|0,gA=g=B>>>0<nA>>>0?g+1|0:g,g=qA(B,g,-683901,-1),B=h+QA|0,B=(A=g+hA|0)>>>0<g>>>0?B+1|0:B,g=(IA=qA(bA,iA,-997805,-1))+A|0,A=h+B|0,A=g>>>0<IA>>>0?A+1|0:A,B=(IA=qA(NA,aA,136657,0))+g|0,g=h+A|0,vA=B,cA=B>>>0<IA>>>0?g+1|0:g,A=qA(v,0,M,0),B=h,g=(IA=qA(b,0,Y,0))+A|0,A=h+B|0,A=g>>>0<IA>>>0?A+1|0:A,B=(IA=qA(m,0,P,0))+g|0,g=h+A|0,g=B>>>0<IA>>>0?g+1|0:g,A=(IA=qA(N,0,S,0))+B|0,B=h+g|0,g=A,A=A>>>0<IA>>>0?B+1|0:B,CA=g=(B=AA>>>7&2097151)+g|0,QA=g>>>0<B>>>0?A+1|0:A,A=qA(M,0,P,0),g=h,B=qA(v,0,Y,0),g=h+g|0,g=(A=B+A|0)>>>0<B>>>0?g+1|0:g,IA=qA(N,0,m,0),B=h+g|0,B=(A=IA+A|0)>>>0<IA>>>0?B+1|0:B,g=A,IA=2097151&((3&(A=$))<<30|Z>>>2),A=B,A=(g=g+IA|0)>>>0<IA>>>0?A+1|0:A,IA=g,nA=A,tA=A=A-((g>>>0<4293918720)-1|0)|0,g=A>>>21|0,A=(B=CA)+(CA=(2097151&A)<<11|(rA=IA- -1048576|0)>>>21)|0,B=g+QA|0,QA=A,FA=B=A>>>0<CA>>>0?B+1|0:B,hA=A=B-((A>>>0<4293918720)-1|0)|0,B=C+((2097151&A)<<11|(CA=QA- -1048576|0)>>>21)|0,A=TA+(A>>>21|0)|0,A=B>>>0<C>>>0?A+1|0:A,g=(eA=qA(V,uA,666643,0))+(B-(C=-2097152&PA)|0)|0,B=h+(A-((B>>>0<C>>>0)+KA|0)|0)|0,A=(C=qA(X,sA,470296,0))+g|0,g=h+(g>>>0<eA>>>0?B+1|0:B)|0,g=A>>>0<C>>>0?g+1|0:g,B=(C=qA(HA,gA,136657,0))+A|0,A=h+g|0,A=B>>>0<C>>>0?A+1|0:A,g=B,B=qA(bA,iA,654183,0),A=h+A|0,A=(g=g+B|0)>>>0<B>>>0?A+1|0:A,B=(C=qA(NA,aA,-997805,-1))+g|0,g=h+A|0,eA=B,uA=g=B>>>0<C>>>0?g+1|0:g,GA=g=g-((B>>>0<4293918720)-1|0)|0,C=(2097151&g)<<11|(pA=B- -1048576|0)>>>21,g=(g>>21)+cA|0,C=g=(B=C+vA|0)>>>0<C>>>0?g+1|0:g,vA=g=g-((B>>>0<4293918720)-1|0)|0,PA=(2097151&g)<<11|(cA=B- -1048576|0)>>>21,g=(g>>21)+yA|0,mA=DA=PA+DA|0,DA=DA>>>0<PA>>>0?g+1|0:g,PA=C,g=a-(A=-2097152&EA)|0,C=kA-((A>>>0>a>>>0)+fA|0)|0,A=(a=(2097151&oA)<<11|xA>>>21)+g|0,g=(oA>>21)+C|0,C=A,kA=g=A>>>0<a>>>0?g+1|0:g,fA=A=g-((A>>>0<4293918720)-1|0)|0,EA=g=A>>21,a=B,B=qA(yA=(2097151&A)<<11|(oA=C- -1048576|0)>>>21,g,-683901,-1),A=h+PA|0,A=(g=a+B|0)>>>0<B>>>0?A+1|0:A,PA=g-(B=-2097152&cA)|0,vA=A-((g>>>0<B>>>0)+vA|0)|0,B=qA(yA,EA,136657,0),g=h+uA|0,g=(A=B+eA|0)>>>0<B>>>0?g+1|0:g,wA=A-(B=-2097152&pA)|0,lA=g-((A>>>0<B>>>0)+GA|0)|0,a=qA(X,sA,666643,0),B=h+(FA-(((g=-2097152&CA)>>>0>QA>>>0)+hA|0)|0)|0,B=(A=a+(QA-g|0)|0)>>>0<a>>>0?B+1|0:B,g=(a=qA(HA,gA,-997805,-1))+A|0,A=h+B|0,A=g>>>0<a>>>0?A+1|0:A,B=(a=qA(bA,iA,470296,0))+g|0,g=h+A|0,g=B>>>0<a>>>0?g+1|0:g,A=B,B=qA(NA,aA,654183,0),g=h+g|0,hA=A=A+B|0,CA=A>>>0<B>>>0?g+1|0:g,eA=IA,pA=nA,A=qA(N,0,M,0),B=h,g=(a=qA(P,0,Y,0))+A|0,A=h+B|0,A=g>>>0<a>>>0?A+1|0:A,B=(g=(a=O>>>5&2097151)+g|0)>>>0<a>>>0?A+1|0:A,IA=g,a=2097151&W,g=qA(N,0,Y,0)+a|0,A=h,A=g>>>0<a>>>0?A+1|0:A,a=g,cA=A,uA=A=A-((g>>>0<4293918720)-1|0)|0,g=(g=A>>>21|0)+B|0,g=(A=(nA=IA)+(IA=(2097151&A)<<11|(QA=a- -1048576|0)>>>21)|0)>>>0<IA>>>0?g+1|0:g,IA=A,FA=g,sA=A=g-((A>>>0<4293918720)-1|0)|0,g=eA,eA=(2097151&A)<<11|(nA=IA- -1048576|0)>>>21,A=(A>>>21|0)+pA|0,A=(B=g+eA|0)>>>0<eA>>>0?A+1|0:A,B=(eA=qA(HA,gA,654183,0))+((g=B)-(rA&=-2097152)|0)|0,g=h+(A-((16383&tA)+(g>>>0<rA>>>0)|0)|0)|0,g=B>>>0<eA>>>0?g+1|0:g,A=B,B=qA(bA,iA,666643,0),g=h+g|0,g=(A=A+B|0)>>>0<B>>>0?g+1|0:g,B=(iA=qA(NA,aA,470296,0))+A|0,A=h+g|0,A=B>>>0<iA>>>0?A+1|0:A,iA=B,eA=A,pA=A=A-((B>>>0<4293918720)-1|0)|0,tA=(2097151&A)<<11|(rA=B- -1048576|0)>>>21,A=(A>>21)+CA|0,tA=A=(B=tA+hA|0)>>>0<tA>>>0?A+1|0:A,hA=A=A-((B>>>0<4293918720)-1|0)|0,g=wA,wA=(2097151&A)<<11|(CA=B- -1048576|0)>>>21,A=(A>>21)+lA|0,A=wA>>>0>(GA=g+wA|0)>>>0?A+1|0:A,wA=GA,GA=A,A=(g=qA(yA,EA,-997805,-1))+B|0,B=h+tA|0,B=A>>>0<g>>>0?B+1|0:B,CA=A-(g=-2097152&CA)|0,tA=B-((A>>>0<g>>>0)+hA|0)|0,B=qA(yA,EA,654183,0),g=h+eA|0,g=(A=B+iA|0)>>>0<B>>>0?g+1|0:g,eA=A-(B=-2097152&rA)|0,pA=g-((A>>>0<B>>>0)+pA|0)|0,g=(B=qA(HA,gA,470296,0))+(IA-(A=-2097152&nA)|0)|0,A=h+(FA-((16383&sA)+(A>>>0>IA>>>0)|0)|0)|0,A=g>>>0<B>>>0?A+1|0:A,B=(IA=qA(NA,aA,666643,0))+g|0,g=h+A|0,iA=B,IA=B>>>0<IA>>>0?g+1|0:g,A=(B=qA(HA,gA,666643,0))+(a-(g=-2097152&QA)|0)|0,g=h+(cA-((4095&uA)+(g>>>0>a>>>0)|0)|0)|0,g=A>>>0<B>>>0?g+1|0:g,B=A,nA=g,gA=g=g-((A>>>0<4293918720)-1|0)|0,QA=iA,iA=(2097151&g)<<11|(a=A- -1048576|0)>>>21,g=(g>>21)+IA|0,iA=g=(IA=QA=QA+iA|0)>>>0<iA>>>0?g+1|0:g,rA=g=g-((IA>>>0<4293918720)-1|0)|0,A=eA,eA=(2097151&g)<<11|(QA=IA- -1048576|0)>>>21,g=(g>>21)+pA|0,g=(aA=A+eA|0)>>>0<eA>>>0?g+1|0:g,eA=aA,aA=g,g=(A=IA)+(IA=qA(yA,EA,470296,0))|0,A=h+iA|0,A=g>>>0<IA>>>0?A+1|0:A,QA=g-(IA=-2097152&QA)|0,IA=A-((g>>>0<IA>>>0)+rA|0)|0,iA=QA,A=(B-(g=-2097152&a)|0)+(a=qA(yA,EA,666643,0))|0,g=h+(nA-((g>>>0>B>>>0)+gA|0)|0)|0,QA=A,B=A,A=(A=(g=A>>>0<a>>>0?g+1|0:g)>>21)+IA|0,A=(g=iA+(B=(2097151&g)<<11|B>>>21)|0)>>>0<B>>>0?A+1|0:A,nA=g,B=g,g=(g=A>>21)+aA|0,EA=A=(B=(2097151&A)<<11|B>>>21)+eA|0,a=(2097151&(g=A>>>0<B>>>0?g+1|0:g))<<11|(B=A)>>>21,B=(A=g>>21)+tA|0,iA=g=a+CA|0,a=(2097151&(B=(A=g)>>>0<a>>>0?B+1|0:B))<<11|A>>>21,A=(g=B>>21)+GA|0,rA=B=a+wA|0,a=(2097151&(A=(g=B)>>>0<a>>>0?A+1|0:A))<<11|g>>>21,g=(B=A>>21)+vA|0,aA=A=a+PA|0,B=A,A=(A=(g=A>>>0<a>>>0?g+1|0:g)>>21)+DA|0,A=(g=(B=(2097151&g)<<11|B>>>21)+mA|0)>>>0<B>>>0?A+1|0:A,CA=g,B=g,g=(g=A>>21)+SA|0,eA=A=(B=(2097151&A)<<11|B>>>21)+jA|0,a=(2097151&(g=A>>>0<B>>>0?g+1|0:g))<<11|(B=A)>>>21,B=(A=g>>21)+LA|0,pA=g=a+RA|0,a=(2097151&(B=(A=g)>>>0<a>>>0?B+1|0:B))<<11|A>>>21,A=(g=B>>21)+JA|0,cA=B=a+_A|0,a=(2097151&(A=(g=B)>>>0<a>>>0?A+1|0:A))<<11|g>>>21,g=(B=A>>21)+BI|0,uA=A=a+zA|0,B=A,A=(g=A>>>0<a>>>0?g+1|0:g)>>21,B=(2097151&g)<<11|B>>>21,a=C-(g=-2097152&oA)|0,g=(kA-((g>>>0>C>>>0)+fA|0)|0)+A|0,oA=B=B+a|0,a=B=(g=(A=B)>>>0<a>>>0?g+1|0:g)>>21,A=qA(gA=(2097151&g)<<11|A>>>21,B,666643,0),g=h,IA=A=A+(B=2097151&QA)|0,C=g=A>>>0<B>>>0?g+1|0:g,Q[0|E]=A,Q[E+1|0]=(255&g)<<24|A>>>8,B=2097151&nA,g=qA(gA,a,470296,0)+B|0,A=h,QA=(nA=(2097151&C)<<11|IA>>>21)+g|0,g=(C>>21)+(A=g>>>0<B>>>0?A+1|0:A)|0,g=QA>>>0<nA>>>0?g+1|0:g,Q[E+4|0]=(2047&g)<<21|QA>>>11,A=g,Q[E+3|0]=(7&A)<<29|QA>>>3,nA=2097151&EA,B=qA(gA,a,654183,0)+nA|0,g=h,EA=(2097151&A)<<11|QA>>>21,A=(A>>21)+(g=B>>>0<nA>>>0?g+1|0:g)|0,g=A=EA>>>0>(B=nA=EA+B|0)>>>0?A+1|0:A,Q[E+6|0]=(63&A)<<26|B>>>6,nA=0,A=QA&=2097151,Q[E+2|0]=31&((65535&C)<<16|IA>>>16)|A<<5,IA=2097151&iA,C=qA(gA,a,-997805,-1)+IA|0,A=h,EA=(2097151&g)<<11|B>>>21,g=(g>>21)+(A=C>>>0<IA>>>0?A+1|0:A)|0,g=(A=IA=EA+C|0)>>>0<EA>>>0?g+1|0:g,Q[E+9|0]=(511&g)<<23|A>>>9,Q[E+8|0]=(1&g)<<31|A>>>1,C=0,IA=(B=EA=2097151&B)<<2,B=nA,Q[E+5|0]=IA|(524287&B)<<13|QA>>>19,QA=2097151&rA,IA=qA(gA,a,136657,0)+QA|0,B=h,B=IA>>>0<QA>>>0?B+1|0:B,QA=IA,IA=B,B=g,g=(g>>=21)+IA|0,g=(B=(iA=QA)+(QA=(2097151&B)<<11|A>>>21)|0)>>>0<QA>>>0?g+1|0:g,Q[E+12|0]=(4095&g)<<20|B>>>12,Q[E+11|0]=(15&g)<<28|B>>>4,IA=0,QA=(A=nA=2097151&A)<<7,A=C,C=EA,Q[E+7|0]=QA|(16383&A)<<18|C>>>14,C=(A=qA(gA,a,-683901,-1))+(a=2097151&aA)|0,A=h,A=C>>>0<a>>>0?A+1|0:A,a=C,C=A,QA=(2097151&(A=g))<<11|B>>>21,A=(g=A>>21)+C|0,A=(a=QA+a|0)>>>0<QA>>>0?A+1|0:A,Q[E+14|0]=(127&A)<<25|a>>>7,QA=0,B=(g=gA=2097151&B)<<4,g=IA,Q[E+10|0]=B|(131071&g)<<15|nA>>>17,g=A,A>>=21,C=B=(IA=(2097151&g)<<11|a>>>21)+(2097151&CA)|0,g=B>>>0<IA>>>0?A+1|0:A,Q[E+17|0]=(1023&g)<<22|B>>>10,Q[E+16|0]=(3&g)<<30|B>>>2,IA=0,a=(A=nA=2097151&a)<<1,A=QA,Q[E+13|0]=a|(1048575&A)<<12|gA>>>20,A=g>>21,B=(g=(a=(2097151&g)<<11|B>>>21)+(2097151&eA)|0)>>>0<a>>>0?A+1|0:A,a=g,Q[E+20|0]=(8191&B)<<19|g>>>13,Q[E+19|0]=(31&B)<<27|g>>>5,g=(A=gA=2097151&C)<<6,A=IA,Q[E+15|0]=g|(32767&A)<<17|nA>>>15,g=B>>21,nA=C=(IA=(2097151&B)<<11|a>>>21)+(2097151&pA)|0,C=C>>>0<IA>>>0?g+1|0:g,Q[E+21|0]=nA,g=(A=a)<<3,A=QA,Q[E+18|0]=g|(262143&A)<<14|gA>>>18,A=nA,Q[E+22|0]=(255&C)<<24|A>>>8,g=C>>21,g=(A=(a=(2097151&C)<<11|A>>>21)+(2097151&cA)|0)>>>0<a>>>0?g+1|0:g,a=A,Q[E+25|0]=(2047&g)<<21|A>>>11,Q[E+24|0]=(7&g)<<29|A>>>3,A=g>>21,B=(g=(IA=(2097151&g)<<11|a>>>21)+(2097151&uA)|0)>>>0<IA>>>0?A+1|0:A,IA=g,Q[E+27|0]=(63&B)<<26|g>>>6,A=a&=2097151,Q[E+23|0]=31&((65535&C)<<16|nA>>>16)|A<<5,A=B>>21,A=(g=(B=(2097151&B)<<11|g>>>21)+(2097151&oA)|0)>>>0<B>>>0?A+1|0:A,Q[E+31|0]=(131071&A)<<15|g>>>17,Q[E+30|0]=(511&A)<<23|g>>>9,Q[E+29|0]=(1&A)<<31|g>>>1,C=0,A=(B=IA&=2097151)<<2,B=QA,Q[E+26|0]=A|(524287&B)<<13|a>>>19,A=C,Q[E+28|0]=(16383&A)<<18|IA>>>14|g<<7,Dg(d,64),Dg(r,64),I&&(i[I>>2]=64,i[I+4>>2]=0),s=R+560|0,0}function F(A,I,g,B){for(var C=0,Q=0,E=0,a=0,r=0,o=0,t=0,e=0,f=0,c=0,y=0,s=0,w=0,D=0,p=0,u=0,F=0,l=0,_=0,k=0,H=0,G=0,U=0,S=0,b=0,m=0,v=0,M=0,P=0,Y=0,N=0,R=0,d=0,J=0,x=0,L=0,K=0,X=0,T=0,V=0;a=(C=t<<3)+g|0,k=n[4+(C=I+C|0)|0]|n[C+5|0]<<8|n[C+6|0]<<16|n[C+7|0]<<24,E=(o=c=n[0|C]|n[C+1|0]<<8|n[C+2|0]<<16|n[C+3|0]<<24)<<24|o<<8&16711680,i[a>>2]=-16777216&((255&k)<<24|o>>>8)|16711680&((16777215&k)<<8|o>>>24)|k>>>8&65280|k>>>24,C=0,i[a+4>>2]=65280&(k<<24|o>>>8)|255&(k<<8|o>>>24)|E|C|C,16!=(0|(t=t+1|0)););for(I=eI(B,A,64);;){if(C=i[(B=k=(H=L<<3)+g|0)>>2],B=i[B+4>>2],a=pA(w=i[I+32>>2],e=i[I+36>>2],14),E=h,a=pA(w,e,18)^a,E^=h,a=pA(w,e,41)^a,B=(h^E)+B|0,B=(C=a+C|0)>>>0<a>>>0?B+1|0:B,Q=i[I+48>>2],C=(E=i[(a=H+34144|0)>>2])+C|0,B=i[a+4>>2]+B|0,B=C>>>0<E>>>0?B+1|0:B,a=(E=Q^((s=i[I+40>>2])^Q)&w)+C|0,C=(((D=i[I+52>>2])^(p=i[I+44>>2]))&e^D)+B|0,C=E>>>0>a>>>0?C+1|0:C,a=(E=i[I+56>>2])+a|0,B=i[I+60>>2]+C|0,B=E>>>0>a>>>0?B+1|0:B,E=a+(t=i[I+24>>2])|0,C=i[I+28>>2]+B|0,o=E,f=C=E>>>0<t>>>0?C+1|0:C,i[I+24>>2]=E,i[I+28>>2]=C,C=pA(F=i[I>>2],t=i[I+4>>2],28),c=h,C=pA(F,t,34)^C,E=h^c,c=a+(pA(F,t,39)^C)|0,C=B+(h^E)|0,C=a>>>0>c>>>0?C+1|0:C,c=(u=F&((a=i[I+16>>2])|(r=i[I+8>>2]))|a&r)+c|0,B=(B=C)+(t&((C=i[I+20>>2])|(E=i[I+12>>2]))|C&E)|0,B=c>>>0<u>>>0?B+1|0:B,u=c,c=B,i[I+56>>2]=u,i[I+60>>2]=B,B=C,C=pA(o,f,14),y=h,l=pA(o,f,18)^C,y^=h,S=a,a=(C=Q)+(Q=(s^w)&o^s)|0,C=((e^p)&f^p)+D|0,C=a>>>0<Q>>>0?C+1|0:C,Q=pA(o,f,41)^l,C=(h^y)+C|0,C=(a=Q+a|0)>>>0<Q>>>0?C+1|0:C,a=(y=i[(D=v=(Q=8|H)+g|0)>>2])+a|0,C=i[D+4>>2]+C|0,C=a>>>0<y>>>0?C+1|0:C,a=(D=i[(Q=Q+34144|0)>>2])+a|0,C=i[Q+4>>2]+C|0,C=a>>>0<D>>>0?C+1|0:C,y=a,D=B,B=C,C=D+C|0,C=(a=S+(Q=a)|0)>>>0<Q>>>0?C+1|0:C,Q=a,D=C,i[I+16>>2]=Q,i[I+20>>2]=C,C=pA(u,c,28),a=h,l=pA(u,c,34)^C,_=h^a,a=(C=y)+(y=(r|F)&u|r&F)|0,C=((E|t)&c|E&t)+B|0,C=a>>>0<y>>>0?C+1|0:C,y=pA(u,c,39)^l,B=(h^_)+C|0,B=(a=y+a|0)>>>0<y>>>0?B+1|0:B,y=a,a=B,i[I+48>>2]=y,i[I+52>>2]=B,B=pA(Q,D,14),C=h,l=pA(Q,D,18)^B,_=h^C,S=r,C=((e^f)&D^e)+p|0,C=(B=(r=(o^w)&Q^w)+s|0)>>>0<r>>>0?C+1|0:C,r=pA(Q,D,41)^l,C=(h^_)+C|0,C=(B=r+B|0)>>>0<r>>>0?C+1|0:C,r=(r=B)+(p=i[(B=M=(s=16|H)+g|0)>>2])|0,B=i[B+4>>2]+C|0,B=r>>>0<p>>>0?B+1|0:B,r=(s=i[(C=s+34144|0)>>2])+r|0,C=i[C+4>>2]+B|0,C=r>>>0<s>>>0?C+1|0:C,p=r,s=r,B=C,C=C+E|0,s=C=(r=S+r|0)>>>0<s>>>0?C+1|0:C,i[I+8>>2]=r,i[I+12>>2]=C,C=pA(y,a,28),E=h,l=pA(y,a,34)^C,E^=h,B=((t|c)&a|t&c)+B|0,B=(C=(C=p)+(p=(u|F)&y|u&F)|0)>>>0<p>>>0?B+1|0:B,p=pA(y,a,39)^l,B=(h^E)+B|0,B=(C=p+C|0)>>>0<p>>>0?B+1|0:B,p=C,E=B,i[I+40>>2]=C,i[I+44>>2]=B,B=pA(r,s,14),C=h,l=pA(r,s,18)^B,_=h^C,S=F,C=(f^(f^D)&s)+e|0,C=(B=(F=o^(Q^o)&r)+w|0)>>>0<F>>>0?C+1|0:C,e=(F=pA(r,s,41)^l)+B|0,B=(h^_)+C|0,B=e>>>0<F>>>0?B+1|0:B,e=(w=i[(C=P=(F=24|H)+g|0)>>2])+e|0,C=i[C+4>>2]+B|0,C=e>>>0<w>>>0?C+1|0:C,B=(B=e)+(F=i[(e=F+34144|0)>>2])|0,C=i[e+4>>2]+C|0,w=B,e=S+B|0,B=(C=B>>>0<F>>>0?C+1|0:C)+t|0,F=B=e>>>0<w>>>0?B+1|0:B,i[I>>2]=e,i[I+4>>2]=B,B=pA(p,E,28),t=h,l=pA(p,E,34)^B,_=h^t,C=((a|c)&E|a&c)+C|0,C=(B=(t=(y|u)&p|y&u)+w|0)>>>0<t>>>0?C+1|0:C,t=(w=pA(p,E,39)^l)+B|0,B=(h^_)+C|0,B=t>>>0<w>>>0?B+1|0:B,w=t,t=B,i[I+32>>2]=w,i[I+36>>2]=B,B=pA(e,F,14),C=h,l=pA(e,F,18)^B,_=h^C,b=u,C=f+(D^(s^D)&F)|0,C=(B=o+(Q^(Q^r)&e)|0)>>>0<o>>>0?C+1|0:C,o=pA(e,F,41)^l,C=(h^_)+C|0,C=(B=o+B|0)>>>0<o>>>0?C+1|0:C,B=(u=i[(f=S=(o=32|H)+g|0)>>2])+B|0,C=i[f+4>>2]+C|0,C=B>>>0<u>>>0?C+1|0:C,B=(f=i[(o=o+34144|0)>>2])+B|0,C=i[o+4>>2]+C|0,C=B>>>0<f>>>0?C+1|0:C,u=B,f=B,o=b+B|0,B=C,C=C+c|0,f=C=o>>>0<f>>>0?C+1|0:C,i[I+56>>2]=o,i[I+60>>2]=C,C=pA(w,t,28),c=h,l=pA(w,t,34)^C,_=h^c,c=(C=u)+(u=(y|p)&w|y&p)|0,C=((E|a)&t|E&a)+B|0,C=c>>>0<u>>>0?C+1|0:C,u=pA(w,t,39)^l,B=(h^_)+C|0,B=(c=u+c|0)>>>0<u>>>0?B+1|0:B,u=c,c=B,i[I+24>>2]=u,i[I+28>>2]=B,B=pA(o,f,14),C=h,l=pA(o,f,18)^B,_=h^C,b=y,C=D+(s^(s^F)&f)|0,C=(B=Q+(r^(r^e)&o)|0)>>>0<Q>>>0?C+1|0:C,Q=pA(o,f,41)^l,C=(h^_)+C|0,C=(B=Q+B|0)>>>0<Q>>>0?C+1|0:C,Q=(Q=B)+(y=i[(B=U=(D=40|H)+g|0)>>2])|0,B=i[B+4>>2]+C|0,B=Q>>>0<y>>>0?B+1|0:B,Q=(D=i[(C=D+34144|0)>>2])+Q|0,C=i[C+4>>2]+B|0,y=Q,B=C=Q>>>0<D>>>0?C+1|0:C,C=C+a|0,D=C=(Q=b+Q|0)>>>0<y>>>0?C+1|0:C,i[I+48>>2]=Q,i[I+52>>2]=C,C=pA(u,c,28),a=h,l=pA(u,c,34)^C,a^=h,B=((E|t)&c|E&t)+B|0,B=(C=(C=y)+(y=(p|w)&u|p&w)|0)>>>0<y>>>0?B+1|0:B,y=pA(u,c,39)^l,B=(h^a)+B|0,B=(C=y+C|0)>>>0<y>>>0?B+1|0:B,y=C,a=B,i[I+16>>2]=C,i[I+20>>2]=B,B=pA(Q,D,14),C=h,l=pA(Q,D,18)^B,_=h^C,G=p,C=s+(F^(f^F)&D)|0,C=(B=r+(e^(o^e)&Q)|0)>>>0<r>>>0?C+1|0:C,r=(s=pA(Q,D,41)^l)+B|0,B=(h^_)+C|0,B=r>>>0<s>>>0?B+1|0:B,r=(p=i[(C=b=(s=48|H)+g|0)>>2])+r|0,C=i[C+4>>2]+B|0,C=r>>>0<p>>>0?C+1|0:C,B=(B=r)+(s=i[(r=s+34144|0)>>2])|0,C=i[r+4>>2]+C|0,C=B>>>0<s>>>0?C+1|0:C,p=B,s=B,r=G+B|0,B=C+E|0,s=B=r>>>0<s>>>0?B+1|0:B,i[I+40>>2]=r,i[I+44>>2]=B,B=pA(y,a,28),E=h,l=pA(y,a,34)^B,_=h^E,C=((t|c)&a|t&c)+C|0,C=(B=(E=(u|w)&y|u&w)+p|0)>>>0<E>>>0?C+1|0:C,E=(p=pA(y,a,39)^l)+B|0,B=(h^_)+C|0,B=E>>>0<p>>>0?B+1|0:B,p=E,E=B,i[I+8>>2]=p,i[I+12>>2]=B,B=pA(r,s,14),C=h,l=pA(r,s,18)^B,_=h^C,G=w,C=F+(f^(f^D)&s)|0,C=(B=e+(o^(Q^o)&r)|0)>>>0<e>>>0?C+1|0:C,e=pA(r,s,41)^l,C=(h^_)+C|0,C=(B=e+B|0)>>>0<e>>>0?C+1|0:C,B=(w=i[(F=R=(e=56|H)+g|0)>>2])+B|0,C=i[F+4>>2]+C|0,C=B>>>0<w>>>0?C+1|0:C,B=(F=i[(e=e+34144|0)>>2])+B|0,C=i[e+4>>2]+C|0,w=B,e=G+B|0,B=C=B>>>0<F>>>0?C+1|0:C,C=C+t|0,F=C=e>>>0<w>>>0?C+1|0:C,i[I+32>>2]=e,i[I+36>>2]=C,C=pA(p,E,28),t=h,l=pA(p,E,34)^C,_=h^t,t=(C=w)+(w=(y|u)&p|y&u)|0,C=((a|c)&E|a&c)+B|0,C=t>>>0<w>>>0?C+1|0:C,w=pA(p,E,39)^l,B=(h^_)+C|0,B=(t=w+t|0)>>>0<w>>>0?B+1|0:B,w=t,t=B,i[I>>2]=w,i[I+4>>2]=B,B=pA(e,F,14),C=h,l=pA(e,F,18)^B,_=h^C,G=u,C=f+(D^(s^D)&F)|0,C=(B=o+(Q^(Q^r)&e)|0)>>>0<o>>>0?C+1|0:C,o=pA(e,F,41)^l,C=(h^_)+C|0,C=(B=o+B|0)>>>0<o>>>0?C+1|0:C,o=(o=B)+(u=i[(B=K=(f=64|H)+g|0)>>2])|0,B=i[B+4>>2]+C|0,B=o>>>0<u>>>0?B+1|0:B,o=(f=i[(C=f+34144|0)>>2])+o|0,C=i[C+4>>2]+B|0,C=o>>>0<f>>>0?C+1|0:C,f=o,B=C,C=C+c|0,u=C=(o=G+o|0)>>>0<f>>>0?C+1|0:C,i[I+24>>2]=o,i[I+28>>2]=C,C=pA(w,t,28),c=h,l=pA(w,t,34)^C,c^=h,B=((E|a)&t|E&a)+B|0,B=(C=(C=f)+(f=(y|p)&w|y&p)|0)>>>0<f>>>0?B+1|0:B,f=pA(w,t,39)^l,B=(h^c)+B|0,l=C=f+C|0,c=B=C>>>0<f>>>0?B+1|0:B,i[I+56>>2]=C,i[I+60>>2]=B,B=pA(o,u,14),C=h,f=pA(o,u,18)^B,_=h^C,C=D+(s^(s^F)&u)|0,C=(B=Q+(r^(r^e)&o)|0)>>>0<Q>>>0?C+1|0:C,Q=(f=pA(o,u,41)^f)+B|0,B=(h^_)+C|0,B=Q>>>0<f>>>0?B+1|0:B,Q=(D=i[(C=G=(f=72|H)+g|0)>>2])+Q|0,C=i[C+4>>2]+B|0,C=Q>>>0<D>>>0?C+1|0:C,B=(B=Q)+(f=i[(Q=f+34144|0)>>2])|0,C=i[Q+4>>2]+C|0,C=B>>>0<f>>>0?C+1|0:C,f=B,Q=B+y|0,B=C+a|0,y=B=Q>>>0<f>>>0?B+1|0:B,i[I+16>>2]=Q,i[I+20>>2]=B,B=pA(l,c,28),a=h,D=pA(l,c,34)^B,_=h^a,C=((E|t)&c|E&t)+C|0,C=(B=(a=(p|w)&l|p&w)+f|0)>>>0<a>>>0?C+1|0:C,a=(f=pA(l,c,39)^D)+B|0,B=(h^_)+C|0,_=a,a=B=a>>>0<f>>>0?B+1|0:B,i[I+48>>2]=_,i[I+52>>2]=B,B=pA(Q,y,14),C=h,f=pA(Q,y,18)^B,D=h^C,C=s+(F^(u^F)&y)|0,C=(B=r+(e^(o^e)&Q)|0)>>>0<r>>>0?C+1|0:C,r=pA(Q,y,41)^f,C=(h^D)+C|0,C=(B=r+B|0)>>>0<r>>>0?C+1|0:C,B=(D=i[(f=m=(r=80|H)+g|0)>>2])+B|0,C=i[f+4>>2]+C|0,C=B>>>0<D>>>0?C+1|0:C,B=(f=i[(r=r+34144|0)>>2])+B|0,C=i[r+4>>2]+C|0,C=B>>>0<f>>>0?C+1|0:C,f=B,r=B+p|0,B=C,C=C+E|0,s=C=r>>>0<f>>>0?C+1|0:C,i[I+8>>2]=r,i[I+12>>2]=C,C=pA(_,a,28),E=h,D=pA(_,a,34)^C,p=h^E,E=(C=f)+(f=(w|l)&_|w&l)|0,C=((t|c)&a|t&c)+B|0,C=E>>>0<f>>>0?C+1|0:C,f=pA(_,a,39)^D,B=(h^p)+C|0,f=B=(E=f+E|0)>>>0<f>>>0?B+1|0:B,i[I+40>>2]=E,i[I+44>>2]=B,B=pA(r,s,14),C=h,D=pA(r,s,18)^B,p=h^C,C=F+(u^(y^u)&s)|0,C=(B=e+(o^(Q^o)&r)|0)>>>0<e>>>0?C+1|0:C,e=pA(r,s,41)^D,C=(h^p)+C|0,C=(B=e+B|0)>>>0<e>>>0?C+1|0:C,e=(e=B)+(F=i[(B=N=(D=88|H)+g|0)>>2])|0,B=i[B+4>>2]+C|0,B=e>>>0<F>>>0?B+1|0:B,e=(D=i[(C=D+34144|0)>>2])+e|0,C=i[C+4>>2]+B|0,C=e>>>0<D>>>0?C+1|0:C,D=e,B=C,C=C+t|0,F=C=(e=e+w|0)>>>0<D>>>0?C+1|0:C,i[I>>2]=e,i[I+4>>2]=C,C=pA(E,f,28),t=h,p=pA(E,f,34)^C,t^=h,B=((a|c)&f|a&c)+B|0,B=(C=(C=D)+(D=(l|_)&E|l&_)|0)>>>0<D>>>0?B+1|0:B,D=pA(E,f,39)^p,B=(h^t)+B|0,t=C=D+C|0,D=B=C>>>0<D>>>0?B+1|0:B,i[I+32>>2]=C,i[I+36>>2]=B,B=pA(e,F,14),C=h,p=pA(e,F,18)^B,w=h^C,C=u+(y^(s^y)&F)|0,C=(B=o+(Q^(Q^r)&e)|0)>>>0<o>>>0?C+1|0:C,o=(u=pA(e,F,41)^p)+B|0,B=(h^w)+C|0,B=o>>>0<u>>>0?B+1|0:B,o=(p=i[(C=X=(u=96|H)+g|0)>>2])+o|0,C=i[C+4>>2]+B|0,C=o>>>0<p>>>0?C+1|0:C,B=(B=o)+(u=i[(o=u+34144|0)>>2])|0,C=i[o+4>>2]+C|0,C=B>>>0<u>>>0?C+1|0:C,u=B,o=B+l|0,B=C+c|0,p=o,o=B=o>>>0<u>>>0?B+1|0:B,i[I+56>>2]=p,i[I+60>>2]=B,B=pA(t,D,28),c=h,w=pA(t,D,34)^B,l=h^c,C=((a|f)&D|a&f)+C|0,C=(B=(c=(E|_)&t|E&_)+u|0)>>>0<c>>>0?C+1|0:C,c=(u=pA(t,D,39)^w)+B|0,B=(h^l)+C|0,B=c>>>0<u>>>0?B+1|0:B,u=c,c=B,i[I+24>>2]=u,i[I+28>>2]=B,B=pA(p,o,14),C=h,w=pA(p,o,18)^B,l=h^C,C=y+(s^(s^F)&o)|0,C=(B=Q+(r^(r^e)&p)|0)>>>0<Q>>>0?C+1|0:C,Q=pA(p,o,41)^w,C=(h^l)+C|0,C=(B=Q+B|0)>>>0<Q>>>0?C+1|0:C,B=(w=i[(y=T=(Q=104|H)+g|0)>>2])+B|0,C=i[y+4>>2]+C|0,C=B>>>0<w>>>0?C+1|0:C,B=(y=i[(Q=Q+34144|0)>>2])+B|0,C=i[Q+4>>2]+C|0,C=B>>>0<y>>>0?C+1|0:C,y=B,Q=B+_|0,B=C,C=C+a|0,w=Q,Q=C=Q>>>0<y>>>0?C+1|0:C,i[I+48>>2]=w,i[I+52>>2]=C,C=pA(u,c,28),a=h,l=pA(u,c,34)^C,_=h^a,a=(C=y)+(y=(E|t)&u|E&t)|0,C=((f|D)&c|f&D)+B|0,C=a>>>0<y>>>0?C+1|0:C,y=pA(u,c,39)^l,B=(h^_)+C|0,B=(a=y+a|0)>>>0<y>>>0?B+1|0:B,y=a,a=B,i[I+16>>2]=y,i[I+20>>2]=B,B=pA(w,Q,14),C=h,l=pA(w,Q,18)^B,_=h^C,C=s+(F^(o^F)&Q)|0,C=(B=r+(e^(e^p)&w)|0)>>>0<r>>>0?C+1|0:C,r=pA(w,Q,41)^l,C=(h^_)+C|0,C=(B=r+B|0)>>>0<r>>>0?C+1|0:C,r=(r=B)+(_=i[(B=l=(s=112|H)+g|0)>>2])|0,B=i[B+4>>2]+C|0,B=r>>>0<_>>>0?B+1|0:B,r=(s=i[(C=s+34144|0)>>2])+r|0,C=i[C+4>>2]+B|0,C=r>>>0<s>>>0?C+1|0:C,s=r,B=C,C=f+C|0,f=r=E+r|0,E=C=E>>>0>r>>>0?C+1|0:C,i[I+40>>2]=r,i[I+44>>2]=C,C=pA(y,a,28),r=h,_=pA(y,a,34)^C,r^=h,B=((c|D)&a|c&D)+B|0,B=(C=(C=s)+(s=(t|u)&y|t&u)|0)>>>0<s>>>0?B+1|0:B,s=pA(y,a,39)^_,B=(h^r)+B|0,B=(C=s+C|0)>>>0<s>>>0?B+1|0:B,s=C,r=B,i[I+8>>2]=C,i[I+12>>2]=B,B=pA(f,E,14),C=h,_=pA(f,E,18)^B,Y=h^C,C=F+(o^(Q^o)&E)|0,C=(B=e+(p^(p^w)&f)|0)>>>0<e>>>0?C+1|0:C,E=(o=pA(f,E,41)^_)+B|0,B=(h^Y)+C|0,B=E>>>0<o>>>0?B+1|0:B,E=(e=i[(C=o=(Q=120|H)+g|0)>>2])+E|0,C=i[C+4>>2]+B|0,C=E>>>0<e>>>0?C+1|0:C,B=(B=E)+(Q=i[(E=Q+34144|0)>>2])|0,C=i[E+4>>2]+C|0,C=B>>>0<Q>>>0?C+1|0:C,Q=B,E=t+B|0,B=C+D|0,i[I+32>>2]=E,i[I+36>>2]=E>>>0<t>>>0?B+1|0:B,B=pA(s,r,28),E=h,t=pA(s,r,34)^B,E^=h,C=((a|c)&r|a&c)+C|0,c=(B=(B=Q)+(Q=(y|u)&s|y&u)|0)+(a=pA(s,r,39)^t)|0,B=(h^E)+(B>>>0<Q>>>0?C+1|0:C)|0,i[I>>2]=c,i[I+4>>2]=a>>>0>c>>>0?B+1|0:B,64==(0|L)){for(;g=(B=V<<3)+A|0,B=(k=i[(C=I+B|0)>>2])+i[g>>2]|0,C=i[g+4>>2]+i[C+4>>2]|0,i[g>>2]=B,i[g+4>>2]=B>>>0<k>>>0?C+1|0:C,8!=(0|(V=V+1|0)););break}t=((L=L+16|0)<<3)+g|0,f=B=i[l+4>>2],C=B>>>6|0,B=((63&B)<<26|(Y=i[l>>2])>>>6)^pA(Y,B,19),C^=h,B=(B=pA(Y,f,61)^B)+(c=d=i[G>>2])|0,C=(w=i[G+4>>2])+(h^C)|0,C=B>>>0<c>>>0?C+1|0:C,B=(c=i[k>>2])+B|0,C=i[k+4>>2]+C|0,Q=B,B=B>>>0<c>>>0?C+1|0:C,C=(a=c=i[v+4>>2])>>>7|0,c=((127&a)<<25|(E=i[v>>2])>>>7)^pA(E,a,1),C^=h,r=Q,Q=pA(E,a,8)^c,C=(h^C)+B|0,G=c=r+Q|0,c=C=Q>>>0>c>>>0?C+1|0:C,i[t>>2]=G,i[t+4>>2]=C,B=(B=E)+(E=J=i[m>>2])|0,C=(l=i[m+4>>2])+a|0,C=B>>>0<E>>>0?C+1|0:C,E=B,B=C,D=a=i[o+4>>2],C=a>>>6|0,a=((63&a)<<26|(m=i[o>>2])>>>6)^pA(m,a,19),t=h^C,a=pA(m,D,61)^a,B=(h^t)+B|0,o=C=a+E|0,C=C>>>0<a>>>0?B+1|0:B,B=(E=a=i[M+4>>2])>>>7|0,a=((127&E)<<25|(t=i[M>>2])>>>7)^pA(t,E,1),Q=h^B,a=pA(t,E,8)^a,C=(h^Q)+C|0,p=B=a+o|0,a=C=B>>>0<a>>>0?C+1|0:C,i[k+136>>2]=B,i[k+140>>2]=C,B=(_=i[N+4>>2])+E|0,E=C=(C=t)+(t=x=i[N>>2])|0,C=C>>>0<t>>>0?B+1|0:B,B=pA(G,c,19),t=h,o=pA(G,c,61)^((63&c)<<26|G>>>6)^B,C=(h^c>>>6^t)+C|0,Q=E=o+E|0,B=E>>>0<o>>>0?C+1|0:C,t=E=i[P+4>>2],C=E>>>7|0,E=((127&E)<<25|(o=i[P>>2])>>>7)^pA(o,E,1),C^=h,r=Q,Q=pA(o,t,8)^E,C=(h^C)+B|0,s=E=r+Q|0,E=C=E>>>0<Q>>>0?C+1|0:C,i[k+144>>2]=s,i[k+148>>2]=C,B=(v=i[X+4>>2])+t|0,t=C=(C=o)+(o=N=i[X>>2])|0,C=C>>>0<o>>>0?B+1|0:B,B=pA(p,a,19),o=h,Q=pA(p,a,61)^((63&a)<<26|p>>>6)^B,C=(h^a>>>6^o)+C|0,B=Q>>>0>(r=t=Q+t|0)>>>0?C+1|0:C,C=(o=t=i[S+4>>2])>>>7|0,t=((127&o)<<25|(Q=i[S>>2])>>>7)^pA(Q,o,1),C^=h,y=r,r=pA(Q,o,8)^t,C=(h^C)+B|0,F=t=y+r|0,t=C=t>>>0<r>>>0?C+1|0:C,i[k+152>>2]=F,i[k+156>>2]=C,B=(P=i[T+4>>2])+o|0,o=C=(C=Q)+(Q=M=i[T>>2])|0,C=C>>>0<Q>>>0?B+1|0:B,B=pA(s,E,19),Q=h,r=pA(s,E,61)^((63&E)<<26|s>>>6)^B,B=(h^E>>>6^Q)+C|0,e=o=r+o|0,C=o>>>0<r>>>0?B+1|0:B,r=o=i[U+4>>2],B=o>>>7|0,o=((127&o)<<25|(Q=i[U>>2])>>>7)^pA(Q,o,1),u=h^B,o=pA(Q,r,8)^o,C=(h^u)+C|0,u=B=o+e|0,o=C=B>>>0<o>>>0?C+1|0:C,i[k+160>>2]=B,i[k+164>>2]=C,B=r+f|0,B=(C=Q+Y|0)>>>0<Q>>>0?B+1|0:B,Q=C,C=B,B=pA(F,t,19),r=h,e=pA(F,t,61)^((63&t)<<26|F>>>6)^B,C=(h^t>>>6^r)+C|0,C=(Q=e+Q|0)>>>0<e>>>0?C+1|0:C,e=Q,Q=C,C=(r=i[b+4>>2])>>>7|0,y=((127&r)<<25|(B=i[b>>2])>>>7)^pA(B,r,1),C^=h,y=pA(B,r,8)^y,C=(h^C)+Q|0,C=(e=y+e|0)>>>0<y>>>0?C+1|0:C,y=e,Q=C,i[k+168>>2]=e,i[k+172>>2]=C,C=B,B=r+D|0,C=C>>>0>(r=e=C+m|0)>>>0?B+1|0:B,B=pA(u,o,19),e=h,H=pA(u,o,61)^((63&o)<<26|u>>>6)^B,C=(h^o>>>6^e)+C|0,S=r=H+r|0,B=r>>>0<H>>>0?C+1|0:C,H=r=i[R+4>>2],C=r>>>7|0,r=((127&r)<<25|(e=i[R>>2])>>>7)^pA(e,r,1),U=h^C,r=pA(e,H,8)^r,B=(h^U)+B|0,S=C=r+S|0,r=B=C>>>0<r>>>0?B+1|0:B,i[k+176>>2]=C,i[k+180>>2]=B,B=c+H|0,B=(C=e+G|0)>>>0<e>>>0?B+1|0:B,e=C,C=B,B=pA(y,Q,19),H=h,U=pA(y,Q,61)^((63&Q)<<26|y>>>6)^B,C=(h^Q>>>6^H)+C|0,b=e=U+e|0,e=e>>>0<U>>>0?C+1|0:C,U=H=i[K+4>>2],C=H>>>7|0,H=((127&H)<<25|(B=i[K>>2])>>>7)^pA(B,H,1),C^=h,R=b,b=pA(B,U,8)^H,C=(h^C)+e|0,e=C=(H=R+b|0)>>>0<b>>>0?C+1|0:C,i[k+184>>2]=H,i[k+188>>2]=C,C=B,B=a+U|0,C=C>>>0>(a=p=C+p|0)>>>0?B+1|0:B,B=pA(S,r,19),p=h,U=pA(S,r,61)^((63&r)<<26|S>>>6)^B,B=(h^r>>>6^p)+C|0,C=B=(a=U+a|0)>>>0<U>>>0?B+1|0:B,B=pA(d,w,1),p=h,U=pA(d,w,8)^((127&w)<<25|d>>>7)^B,C=(h^w>>>7^p)+C|0,p=a=U+a|0,a=C=a>>>0<U>>>0?C+1|0:C,i[k+192>>2]=p,i[k+196>>2]=C,B=E+w|0,E=C=s+d|0,C=B=C>>>0<s>>>0?B+1|0:B,B=pA(H,e,19),s=h,w=pA(H,e,61)^((63&e)<<26|H>>>6)^B,B=(h^e>>>6^s)+C|0,C=B=(E=w+E|0)>>>0<w>>>0?B+1|0:B,B=pA(J,l,1),s=h,w=pA(J,l,8)^((127&l)<<25|J>>>7)^B,C=(h^l>>>7^s)+C|0,s=E=w+E|0,E=C=E>>>0<w>>>0?C+1|0:C,i[k+200>>2]=s,i[k+204>>2]=C,B=t+l|0,t=C=F+J|0,C=B=C>>>0<F>>>0?B+1|0:B,B=pA(p,a,19),F=h,w=pA(p,a,61)^((63&a)<<26|p>>>6)^B,B=(h^a>>>6^F)+C|0,C=B=(t=w+t|0)>>>0<w>>>0?B+1|0:B,B=pA(x,_,1),F=h,w=pA(x,_,8)^((127&_)<<25|x>>>7)^B,C=(h^_>>>7^F)+C|0,F=t=w+t|0,t=C=t>>>0<w>>>0?C+1|0:C,i[k+208>>2]=F,i[k+212>>2]=C,B=o+_|0,o=C=u+x|0,C=B=C>>>0<u>>>0?B+1|0:B,B=pA(s,E,19),u=h,w=o,o=B,B=E>>>6|0,o=pA(s,E,61)^o^((63&E)<<26|s>>>6),B=(h^B^u)+C|0,C=B=(E=w+o|0)>>>0<o>>>0?B+1|0:B,B=pA(N,v,1),o=h,s=pA(N,v,8)^((127&v)<<25|N>>>7)^B,C=(h^v>>>7^o)+C|0,o=E=s+E|0,E=C=E>>>0<s>>>0?C+1|0:C,i[k+216>>2]=o,i[k+220>>2]=C,B=Q+v|0,Q=C=y+N|0,C=B=C>>>0<y>>>0?B+1|0:B,B=pA(F,t,19),s=h,y=Q,Q=B,B=t>>>6|0,Q=pA(F,t,61)^Q^((63&t)<<26|F>>>6),B=(h^B^s)+C|0,C=B=Q>>>0>(t=y+Q|0)>>>0?B+1|0:B,B=pA(M,P,1),Q=h,s=pA(M,P,8)^((127&P)<<25|M>>>7)^B,C=(h^P>>>7^Q)+C|0,t=C=(Q=t=s+t|0)>>>0<s>>>0?C+1|0:C,i[k+224>>2]=Q,i[k+228>>2]=C,B=r+P|0,r=C=S+M|0,C=B=C>>>0<M>>>0?B+1|0:B,B=pA(o,E,19),s=h,y=B,B=E>>>6|0,o=pA(o,E,61)^y^((63&E)<<26|o>>>6),B=(h^B^s)+C|0,C=B=(E=o+r|0)>>>0<o>>>0?B+1|0:B,B=pA(Y,f,1),o=h,r=pA(Y,f,8)^((127&f)<<25|Y>>>7)^B,C=(h^f>>>7^o)+C|0,o=E=r+E|0,E=C=E>>>0<r>>>0?C+1|0:C,i[k+232>>2]=o,i[k+236>>2]=C,B=e+f|0,r=C=H+Y|0,C=B=C>>>0<H>>>0?B+1|0:B,B=pA(Q,t,19),e=h,f=B,B=t>>>6|0,Q=pA(Q,t,61)^f^((63&t)<<26|Q>>>6),B=(h^B^e)+C|0,B=Q>>>0>(t=Q+r|0)>>>0?B+1|0:B,Q=t,C=B,B=pA(m,D,1),r=h,Q=(e=pA(m,D,8)^((127&D)<<25|m>>>7)^B)+Q|0,C=(h^D>>>7^r)+C|0,i[(t=k)+240>>2]=Q,i[t+244>>2]=Q>>>0<e>>>0?C+1|0:C,B=a+D|0,a=C=p+m|0,C=B=C>>>0<p>>>0?B+1|0:B,B=pA(o,E,19),t=h,Q=B,B=E>>>6|0,E=pA(o,E,61)^Q^((63&E)<<26|o>>>6),B=(h^B^t)+C|0,C=B=E>>>0>(a=E+a|0)>>>0?B+1|0:B,B=pA(G,c,1),E=h,t=B,B=c>>>7|0,c=(Q=a)+(a=pA(G,c,8)^t^((127&c)<<25|G>>>7))|0,C=(h^B^E)+C|0,i[k+248>>2]=c,i[k+252>>2]=a>>>0>c>>>0?C+1|0:C}}function l(A){var I,g,B,C,E,i,a,r,o,t,e,f,c,y,s,w,D,p=0,u=0,F=0,l=0,_=0,k=0,H=0,G=0,U=0,S=0,b=0,m=0,v=0,M=0,P=0,Y=0,N=0,R=0,d=0,J=0,x=0,L=0,K=0,X=0,T=0,V=0,q=0,z=0,j=0,W=0,O=0,Z=0,$=0,AA=0,IA=0,gA=0,BA=0,CA=0,QA=0,EA=0;f=uI(A),gA=n[A+2|0]|n[A+3|0]<<8|n[A+4|0]<<16|n[A+5|0]<<24,c=uI(A+5|0),z=h,BA=n[A+7|0]|n[A+8|0]<<8|n[A+9|0]<<16|n[A+10|0]<<24,Z=n[A+10|0]|n[A+11|0]<<8|n[A+12|0]<<16|n[A+13|0]<<24,y=uI(A+13|0),O=h,L=n[A+15|0]|n[A+16|0]<<8|n[A+17|0]<<16|n[A+18|0]<<24,j=uI(A+18|0),M=h,G=uI(A+21|0),k=n[A+23|0]|n[A+24|0]<<8|n[A+25|0]<<16|n[A+26|0]<<24,F=uI(A+26|0),p=h,K=n[A+28|0]|n[A+29|0]<<8|n[A+30|0]<<16|n[A+31|0]<<24,$=n[A+31|0]|n[A+32|0]<<8|n[A+33|0]<<16|n[A+34|0]<<24,s=uI(A+34|0),q=h,X=n[A+36|0]|n[A+37|0]<<8|n[A+38|0]<<16|n[A+39|0]<<24,W=uI(A+39|0),Y=h,H=uI(A+42|0),l=n[A+44|0]|n[A+45|0]<<8|n[A+46|0]<<16|n[A+47|0]<<24,_=uI(A+47|0),F=2097151&((3&p)<<30|F>>>2),p=qA(I=2097151&((3&(u=h))<<30|_>>>2),0,136657,0)+F|0,u=h,u=p>>>0<F>>>0?u+1|0:u,F=(_=qA(g=(n[A+49|0]|n[A+50|0]<<8|n[A+51|0]<<16|n[A+52|0]<<24)>>>7&2097151,0,-997805,-1))+p|0,p=h+u|0,p=F>>>0<_>>>0?p+1|0:p,u=(_=qA(B=(n[A+52|0]|n[A+53|0]<<8|n[A+54|0]<<16|n[A+55|0]<<24)>>>4&2097151,0,654183,0))+F|0,F=h+p|0,F=u>>>0<_>>>0?F+1|0:F,m=u,u=uI(A+55|0),_=qA(C=2097151&((1&(p=h))<<31|u>>>1),0,470296,0),p=h+F|0,p=(u=m+_|0)>>>0<_>>>0?p+1|0:p,F=(_=qA(E=(n[A+57|0]|n[A+58|0]<<8|n[A+59|0]<<16|n[A+60|0]<<24)>>>6&2097151,0,666643,0))+u|0,u=h+p|0,u=F>>>0<_>>>0?u+1|0:u,_=F,U=u,F=u,b=l>>>5&2097151,l=2097151&H,u=qA(i=(n[A+60|0]|n[A+61|0]<<8|n[A+62|0]<<16|n[A+63|0]<<24)>>>3|0,0,-683901,-1)+l|0,p=h,p=u>>>0<l>>>0?p+1|0:p,l=u,d=p,T=u=p-((u>>>0<4293918720)-1|0)|0,p=b,b=(2097151&u)<<11|(m=l- -1048576|0)>>>21,u>>=21,r=H=p+b|0,S=u=H>>>0<b>>>0?u+1|0:u,H=qA(H,u,-683901,-1),u=h+F|0,J=p=H+_|0,b=p>>>0<H>>>0?u+1|0:u,u=qA(I,x,-997805,-1),p=h,p=(u=(F=k>>>5&2097151)+u|0)>>>0<F>>>0?p+1|0:p,k=qA(g,0,654183,0),F=h+p|0,F=(u=k+u|0)>>>0<k>>>0?F+1|0:F,p=(k=qA(B,0,470296,0))+u|0,u=h+F|0,u=p>>>0<k>>>0?u+1|0:u,F=(k=qA(C,P,666643,0))+p|0,p=h+u|0,H=F,F=F>>>0<k>>>0?p+1|0:p,k=2097151&G,p=qA(I,x,654183,0)+k|0,u=h,u=p>>>0<k>>>0?u+1|0:u,k=(G=qA(g,0,470296,0))+p|0,p=h+u|0,p=k>>>0<G>>>0?p+1|0:p,G=qA(B,0,666643,0),u=h+p|0,G=u=(k=G+k|0)>>>0<G>>>0?u+1|0:u,V=u=u-((k>>>0<4293918720)-1|0)|0,F=(p=u>>>21|0)+F|0,F=(u=(N=H)+(H=(2097151&u)<<11|(v=k- -1048576|0)>>>21)|0)>>>0<H>>>0?F+1|0:F,H=u,N=F,R=u=F-((u>>>0<4293918720)-1|0)|0,U=U-((_>>>0<4293918720)-1|0)|0,t=_- -1048576|0,p=J,J=(2097151&u)<<11|(F=H- -1048576|0)>>>21,u=(u>>21)+b|0,u=((p=_=p+J|0)>>>0<J>>>0?u+1|0:u)-(((_=-2097152&t)>>>0>p>>>0)+U|0)|0,CA=(p=p-_|0)-(_=-2097152&(e=p- -1048576|0))|0,QA=u-((b=u-((p>>>0<4293918720)-1|0)|0)+(p>>>0<_>>>0)|0)|0,u=qA(r,S,136657,0)+H|0,p=N+h|0,J=u-(F&=-2097152)|0,R=(p=u>>>0<H>>>0?p+1|0:p)-((u>>>0<F>>>0)+R|0)|0,m=l-(p=-2097152&m)|0,AA=d-((p>>>0>l>>>0)+T|0)|0,F=2097151&((7&(p=Y))<<29|W>>>3),p=qA(i,0,136657,0)+F|0,u=h,u=p>>>0<F>>>0?u+1|0:u,F=(_=qA(E,0,-683901,-1))+p|0,p=h+u|0,H=F,l=F>>>0<_>>>0?p+1|0:p,p=qA(C,P,-683901,-1),u=h,u=(p=(F=X>>>6&2097151)+p|0)>>>0<F>>>0?u+1|0:u,_=qA(i,0,-997805,-1),F=h+u|0,F=(p=_+p|0)>>>0<_>>>0?F+1|0:F,u=(_=qA(E,0,136657,0))+p|0,p=h+F|0,p=u>>>0<_>>>0?p+1|0:p,_=u,d=p,T=p=p-((u>>>0<4293918720)-1|0)|0,X=u- -1048576|0,u=(F=p>>21)+l|0,l=p=(Y=H)+(H=(2097151&p)<<11|X>>>21)|0,Y=u=p>>>0<H>>>0?u+1|0:u,N=p=u-((p>>>0<4293918720)-1|0)|0,u=m,m=(2097151&p)<<11|(H=l- -1048576|0)>>>21,p=(p>>21)+AA|0,o=u=u+m|0,m=p=u>>>0<m>>>0?p+1|0:p,F=qA(u,p,-683901,-1),p=h+R|0,EA=u=F+J|0,R=u>>>0<F>>>0?p+1|0:p,W=k,J=G,F=2097151&((7&(p=M))<<29|j>>>3),p=qA(I,x,470296,0)+F|0,u=h,u=p>>>0<F>>>0?u+1|0:u,F=qA(g,0,666643,0),u=h+u|0,G=p=F+p|0,F=p>>>0<F>>>0?u+1|0:u,u=qA(I,x,666643,0),p=h,p=(u=(k=L>>>6&2097151)+u|0)>>>0<k>>>0?p+1|0:p,k=u,j=p,AA=p=p-((u>>>0<4293918720)-1|0)|0,u=(u=p>>>21|0)+F|0,F=p=(M=G)+(G=(2097151&p)<<11|(L=k- -1048576|0)>>>21)|0,IA=u=p>>>0<G>>>0?u+1|0:u,w=p=u-((p>>>0<4293918720)-1|0)|0,G=Y-(((u=-2097152&H)>>>0>l>>>0)+N|0)|0,a=l-u|0,H=(2097151&p)<<11|(M=F- -1048576|0)>>>21,p=(p>>>21|0)+J|0,p=(l=H+W|0)>>>0<H>>>0?p+1|0:p,l=((u=l)-(H=-2097152&v)|0)+(v=qA(r,S,-997805,-1))|0,u=h+(p-((8191&V)+(u>>>0<H>>>0)|0)|0)|0,u=l>>>0<v>>>0?u+1|0:u,p=l,l=qA(o,m,136657,0),u=h+u|0,u=(p=p+l|0)>>>0<l>>>0?u+1|0:u,l=(H=qA(a,G,-683901,-1))+p|0,p=h+u|0,V=p=l>>>0<H>>>0?p+1|0:p,N=u=p-((l>>>0<4293918720)-1|0)|0,Y=(2097151&u)<<11|(v=l- -1048576|0)>>>21,u=(u>>21)+R|0,R=u=(H=Y+EA|0)>>>0<Y>>>0?u+1|0:u,p=(p=(u=u-((H>>>0<4293918720)-1|0)|0)>>21)+QA|0,p=(J=(2097151&u)<<11|(Y=H- -1048576|0)>>>21)>>>0>(W=J+CA|0)>>>0?p+1|0:p,J=W,W=p,CA=H-(p=-2097152&Y)|0,QA=R-((p>>>0>H>>>0)+u|0)|0,EA=l-(p=-2097152&v)|0,D=V-((p>>>0>l>>>0)+N|0)|0,p=(l=qA(r,S,654183,0))+(F-(u=-2097152&M)|0)|0,F=h+(IA-((8191&w)+(u>>>0>F>>>0)|0)|0)|0,F=p>>>0<l>>>0?F+1|0:F,u=(l=qA(o,m,-997805,-1))+p|0,p=h+F|0,p=u>>>0<l>>>0?p+1|0:p,F=(l=qA(a,G,136657,0))+u|0,u=h+p|0,V=F,M=F>>>0<l>>>0?u+1|0:u,H=_-(p=-2097152&X)|0,T=d-((p>>>0>_>>>0)+T|0)|0,_=2097151&((1&(p=q))<<31|s>>>1),u=qA(B,0,-683901,-1)+_|0,p=h,p=u>>>0<_>>>0?p+1|0:p,F=qA(C,P,136657,0),p=h+p|0,p=(u=F+u|0)>>>0<F>>>0?p+1|0:p,F=(_=qA(i,0,654183,0))+u|0,u=h+p|0,u=F>>>0<_>>>0?u+1|0:u,p=F,F=qA(E,0,-997805,-1),u=h+u|0,v=p=p+F|0,l=p>>>0<F>>>0?u+1|0:u,p=qA(g,0,-683901,-1),F=h,F=(p=(u=$>>>4&2097151)+p|0)>>>0<u>>>0?F+1|0:F,u=(_=qA(B,0,136657,0))+p|0,p=h+F|0,p=u>>>0<_>>>0?p+1|0:p,F=(_=qA(C,P,-997805,-1))+u|0,u=h+p|0,u=F>>>0<_>>>0?u+1|0:u,_=qA(i,0,470296,0),p=h+u|0,p=(F=_+F|0)>>>0<_>>>0?p+1|0:p,_=qA(E,0,654183,0),u=h+p|0,u=(F=_+F|0)>>>0<_>>>0?u+1|0:u,_=F,Y=u,$=u=u-((F>>>0<4293918720)-1|0)|0,p=(p=u>>21)+l|0,l=u=(F=(2097151&u)<<11|(X=F- -1048576|0)>>>21)+v|0,q=p=u>>>0<F>>>0?p+1|0:p,d=u=p-((u>>>0<4293918720)-1|0)|0,p=H,H=(2097151&u)<<11|(v=l- -1048576|0)>>>21,u=(u>>21)+T|0,N=F=p+H|0,H=u=F>>>0<H>>>0?u+1|0:u,u=qA(F,u,-683901,-1),F=h+M|0,T=p=u+V|0,M=p>>>0<u>>>0?F+1|0:F,v=q-(((p=-2097152&v)>>>0>l>>>0)+d|0)|0,R=l-p|0,p=(F=qA(r,S,470296,0))+(k-(u=-2097152&L)|0)|0,u=h+(j-((2047&AA)+(u>>>0>k>>>0)|0)|0)|0,u=p>>>0<F>>>0?u+1|0:u,F=qA(o,m,654183,0),u=h+u|0,u=(p=F+p|0)>>>0<F>>>0?u+1|0:u,l=qA(a,G,-997805,-1),F=h+u|0,F=(p=l+p|0)>>>0<l>>>0?F+1|0:F,u=(l=qA(N,H,136657,0))+p|0,p=h+F|0,p=u>>>0<l>>>0?p+1|0:p,F=(l=qA(R,v,-683901,-1))+u|0,u=h+p|0,q=u=F>>>0<l>>>0?u+1|0:u,d=u=u-((F>>>0<4293918720)-1|0)|0,p=(p=u>>21)+M|0,p=(u=(l=(2097151&u)<<11|(k=F- -1048576|0)>>>21)+T|0)>>>0<l>>>0?p+1|0:p,l=u,M=p,T=u=p-((u>>>0<4293918720)-1|0)|0,j=(2097151&u)<<11|(L=l- -1048576|0)>>>21,u=(u>>21)+D|0,u=(V=j+EA|0)>>>0<j>>>0?u+1|0:u,j=V,V=u,AA=l-(p=-2097152&L)|0,T=M-((p>>>0>l>>>0)+T|0)|0,IA=F-(p=-2097152&k)|0,q=q-((p>>>0>F>>>0)+d|0)|0,l=2097151&((1&(p=O))<<31|y>>>1),u=qA(r,S,666643,0)+l|0,p=h,p=u>>>0<l>>>0?p+1|0:p,F=(l=qA(o,m,470296,0))+u|0,u=h+p|0,u=F>>>0<l>>>0?u+1|0:u,l=qA(a,G,654183,0),p=h+u|0,p=(F=l+F|0)>>>0<l>>>0?p+1|0:p,u=(l=qA(N,H,-997805,-1))+F|0,F=h+p|0,F=u>>>0<l>>>0?F+1|0:F,p=(l=qA(R,v,136657,0))+u|0,u=h+F|0,k=p,l=p>>>0<l>>>0?u+1|0:u,S=_-(p=-2097152&X)|0,M=Y-((p>>>0>_>>>0)+$|0)|0,p=qA(I,x,-683901,-1),u=h,u=(p=(F=K>>>7&2097151)+p|0)>>>0<F>>>0?u+1|0:u,_=qA(g,0,136657,0),F=h+u|0,F=(p=_+p|0)>>>0<_>>>0?F+1|0:F,u=(_=qA(B,0,-997805,-1))+p|0,p=h+F|0,p=u>>>0<_>>>0?p+1|0:p,F=(_=qA(C,P,654183,0))+u|0,u=h+p|0,u=F>>>0<_>>>0?u+1|0:u,_=qA(i,0,666643,0),p=h+u|0,p=(F=_+F|0)>>>0<_>>>0?p+1|0:p,_=qA(E,0,470296,0),u=h+p|0,p=u=(F=_+F|0)>>>0<_>>>0?u+1|0:u,u=U>>21,_=(U=(2097151&U)<<11|t>>>21)+F|0,F=p+u|0,X=F=_>>>0<U>>>0?F+1|0:F,L=p=F-((_>>>0<4293918720)-1|0)|0,U=(2097151&p)<<11|(x=_- -1048576|0)>>>21,p=(p>>21)+M|0,O=F=U+S|0,U=p=F>>>0<U>>>0?p+1|0:p,F=qA(F,p,-683901,-1),u=h+l|0,k=p=F+k|0,l=p>>>0<F>>>0?u+1|0:u,p=qA(o,m,666643,0),F=h,F=(p=(u=Z>>>4&2097151)+p|0)>>>0<u>>>0?F+1|0:F,u=(P=qA(a,G,470296,0))+p|0,p=h+F|0,p=u>>>0<P>>>0?p+1|0:p,F=(P=qA(N,H,654183,0))+u|0,u=h+p|0,u=F>>>0<P>>>0?u+1|0:u,p=F,F=qA(R,v,-997805,-1),u=h+u|0,u=(p=p+F|0)>>>0<F>>>0?u+1|0:u,F=(P=qA(O,U,136657,0))+p|0,p=h+u|0,m=p=F>>>0<P>>>0?p+1|0:p,M=p=p-((F>>>0<4293918720)-1|0)|0,S=(2097151&p)<<11|(P=F- -1048576|0)>>>21,p=(p>>21)+l|0,k=p=(l=k=S+k|0)>>>0<S>>>0?p+1|0:p,Y=p=p-((l>>>0<4293918720)-1|0)|0,K=(2097151&p)<<11|(S=l- -1048576|0)>>>21,p=(p>>21)+q|0,$=Z=K+IA|0,Z=K>>>0>Z>>>0?p+1|0:p,u=_-(p=-2097152&x)|0,_=X-((p>>>0>_>>>0)+L|0)|0,p=(p=b>>21)+_|0,_=u=(b=(2097151&b)<<11|e>>>21)+u|0,X=p=u>>>0<b>>>0?p+1|0:p,L=u=p-((u>>>0<4293918720)-1|0)|0,b=p=u>>21,d=l,l=qA(K=(2097151&u)<<11|(x=_- -1048576|0)>>>21,p,-683901,-1),u=h+k|0,u=(p=d+l|0)>>>0<l>>>0?u+1|0:u,q=p-(l=-2097152&S)|0,Y=u-((p>>>0<l>>>0)+Y|0)|0,u=qA(K,b,136657,0)+F|0,p=m+h|0,p=u>>>0<F>>>0?p+1|0:p,d=u-(F=-2097152&P)|0,IA=p-((u>>>0<F>>>0)+M|0)|0,p=qA(a,G,666643,0),u=h,u=(p=(F=BA>>>7&2097151)+p|0)>>>0<F>>>0?u+1|0:u,l=qA(N,H,470296,0),F=h+u|0,F=(p=l+p|0)>>>0<l>>>0?F+1|0:F,u=(l=qA(R,v,654183,0))+p|0,p=h+F|0,p=u>>>0<l>>>0?p+1|0:p,F=qA(O,U,-997805,-1),p=h+p|0,S=u=F+u|0,F=u>>>0<F>>>0?p+1|0:p,l=2097151&((3&(p=z))<<30|c>>>2),p=qA(N,H,666643,0)+l|0,u=h,u=p>>>0<l>>>0?u+1|0:u,l=qA(R,v,470296,0),u=h+u|0,u=(p=l+p|0)>>>0<l>>>0?u+1|0:u,l=(k=qA(O,U,654183,0))+p|0,p=h+u|0,G=p=l>>>0<k>>>0?p+1|0:p,P=p=p-((l>>>0<4293918720)-1|0)|0,u=S,S=(2097151&p)<<11|(k=l- -1048576|0)>>>21,p=(p>>21)+F|0,S=p=(F=H=u+S|0)>>>0<S>>>0?p+1|0:p,m=p=p-((F>>>0<4293918720)-1|0)|0,z=(2097151&p)<<11|(H=F- -1048576|0)>>>21,p=(p>>21)+IA|0,p=(M=z+d|0)>>>0<z>>>0?p+1|0:p,z=M,M=p,p=(u=qA(K,b,-997805,-1))+F|0,F=h+S|0,F=p>>>0<u>>>0?F+1|0:F,BA=p-(u=-2097152&H)|0,d=F-((p>>>0<u>>>0)+m|0)|0,p=qA(K,b,654183,0)+l|0,u=G+h|0,m=p-(F=-2097152&k)|0,N=(u=p>>>0<l>>>0?u+1|0:u)-((p>>>0<F>>>0)+P|0)|0,p=qA(R,v,666643,0),F=h,F=(p=(u=gA>>>5&2097151)+p|0)>>>0<u>>>0?F+1|0:F,u=(l=qA(O,U,470296,0))+p|0,p=h+F|0,k=u,F=u>>>0<l>>>0?p+1|0:p,l=2097151&f,u=qA(O,U,666643,0)+l|0,p=h,p=u>>>0<l>>>0?p+1|0:p,l=u,G=p,U=p=p-((u>>>0<4293918720)-1|0)|0,F=(u=p>>21)+F|0,F=(p=(S=k)+(k=(2097151&p)<<11|(H=l- -1048576|0)>>>21)|0)>>>0<k>>>0?F+1|0:F,k=p,P=F,S=p=F-((p>>>0<4293918720)-1|0)|0,v=(2097151&p)<<11|(F=k- -1048576|0)>>>21,p=(p>>21)+N|0,p=(m=v+m|0)>>>0<v>>>0?p+1|0:p,v=m,m=p,p=qA(K,b,470296,0)+k|0,u=P+h|0,u=p>>>0<k>>>0?u+1|0:u,k=p-(F&=-2097152)|0,F=u-((p>>>0<F>>>0)+S|0)|0,S=k,u=(k=qA(K,b,666643,0))+(l-(p=-2097152&H)|0)|0,p=h+(G-((p>>>0>l>>>0)+U|0)|0)|0,p=u>>>0<k>>>0?p+1|0:p,k=u,l=u,u=(u=p>>21)+F|0,H=p=S+(l=(2097151&p)<<11|l>>>21)|0,l=(2097151&(u=p>>>0<l>>>0?u+1|0:u))<<11|(F=p)>>>21,F=(p=u>>21)+m|0,G=u=l+v|0,l=(2097151&(F=(p=u)>>>0<l>>>0?F+1|0:F))<<11|p>>>21,p=(u=F>>21)+d|0,P=F=l+BA|0,l=(2097151&(p=(u=F)>>>0<l>>>0?p+1|0:p))<<11|u>>>21,u=(F=p>>21)+M|0,S=p=l+z|0,F=p,p=(p=(u=p>>>0<l>>>0?u+1|0:u)>>21)+Y|0,p=(u=(F=(2097151&u)<<11|F>>>21)+q|0)>>>0<F>>>0?p+1|0:p,m=u,F=u,u=(u=p>>21)+Z|0,v=p=(F=(2097151&p)<<11|F>>>21)+$|0,l=(2097151&(u=p>>>0<F>>>0?u+1|0:u))<<11|(F=p)>>>21,F=(p=u>>21)+T|0,M=u=l+AA|0,l=(2097151&(F=(p=u)>>>0<l>>>0?F+1|0:F))<<11|p>>>21,p=(u=F>>21)+V|0,Y=F=l+j|0,l=(2097151&(p=(u=F)>>>0<l>>>0?p+1|0:p))<<11|u>>>21,u=(F=p>>21)+QA|0,gA=p=l+CA|0,F=p,p=(p=(u=p>>>0<l>>>0?u+1|0:u)>>21)+W|0,p=(u=(F=(2097151&u)<<11|F>>>21)+J|0)>>>0<F>>>0?p+1|0:p,z=u,F=u,u=p>>21,p=(2097151&p)<<11|F>>>21,l=_-(F=-2097152&x)|0,F=(X-((F>>>0>_>>>0)+L|0)|0)+u|0,x=p=p+l|0,b=(2097151&(F=p>>>0<l>>>0?F+1|0:F))<<11|p>>>21,l=p=F>>21,F=2097151&k,u=qA(b,p,666643,0)+F|0,p=h,k=u,_=p=u>>>0<F>>>0?p+1|0:p,Q[0|A]=u,Q[A+1|0]=(255&p)<<24|u>>>8,F=2097151&H,p=qA(b,l,470296,0)+F|0,u=h,F=(_>>21)+(u=p>>>0<F>>>0?u+1|0:u)|0,F=(H=(U=(2097151&_)<<11|k>>>21)+p|0)>>>0<U>>>0?F+1|0:F,Q[A+4|0]=(2047&F)<<21|H>>>11,Q[A+3|0]=(7&F)<<29|H>>>3,G&=2097151,u=qA(b,l,654183,0)+G|0,p=h,p=u>>>0<G>>>0?p+1|0:p,G=u,u=p,u=(p=F>>21)+u|0,u=(F=(U=G)+(G=(2097151&F)<<11|H>>>21)|0)>>>0<G>>>0?u+1|0:u,G=F,p=u,Q[A+6|0]=(63&p)<<26|F>>>6,U=0,F=31&((65535&_)<<16|k>>>16),u=k=2097151&H,Q[A+2|0]=F|u<<5,_=2097151&P,F=qA(b,l,-997805,-1)+_|0,u=h,u=F>>>0<_>>>0?u+1|0:u,_=F,F=u,F=(u=p>>21)+F|0,u=p=(H=_)+(_=(2097151&p)<<11|G>>>21)|0,F=p>>>0<_>>>0?F+1|0:F,Q[A+9|0]=(511&F)<<23|p>>>9,Q[A+8|0]=(1&F)<<31|p>>>1,_=0,H=(p=G&=2097151)<<2,p=U,Q[A+5|0]=H|(524287&p)<<13|k>>>19,H=2097151&S,k=qA(b,l,136657,0)+H|0,p=h,p=k>>>0<H>>>0?p+1|0:p,H=k,k=p,U=(2097151&(p=F))<<11|u>>>21,p=(F=p>>21)+k|0,p=(F=H=U+H|0)>>>0<U>>>0?p+1|0:p,Q[A+12|0]=(4095&p)<<20|F>>>12,Q[A+11|0]=(15&p)<<28|F>>>4,k=0,S=(u=H=2097151&u)<<7,u=_,_=G,Q[A+7|0]=S|(16383&u)<<18|_>>>14,_=(u=qA(b,l,-683901,-1))+(l=2097151&m)|0,u=h,u=l>>>0>_>>>0?u+1|0:u,l=_,_=u,G=(2097151&(u=p))<<11|F>>>21,u=(p>>=21)+_|0,u=(p=l=G+l|0)>>>0<G>>>0?u+1|0:u,Q[A+14|0]=(127&u)<<25|p>>>7,l=(F=G=2097151&F)<<4,F=k,Q[A+10|0]=l|(131071&F)<<15|H>>>17,k=(2097151&(F=u))<<11|p>>>21,F=(u>>=21)+(l=0)|0,F=(_=k+(2097151&v)|0)>>>0<k>>>0?F+1|0:F,Q[A+17|0]=(1023&F)<<22|_>>>10,Q[A+16|0]=(3&F)<<30|_>>>2,k=0,u=(p=U=2097151&p)<<1,p=l,Q[A+13|0]=u|(1048575&p)<<12|G>>>20,p=u=F>>21,p=(F=(l=(2097151&F)<<11|_>>>21)+(2097151&M)|0)>>>0<l>>>0?p+1|0:p,l=F,Q[A+20|0]=(8191&p)<<19|F>>>13,F=p,Q[A+19|0]=(31&p)<<27|l>>>5,H=0,u=(p=b=2097151&_)<<6,p=k,Q[A+15|0]=u|(32767&p)<<17|U>>>15,p=F>>21,G=_=(k=(2097151&F)<<11|l>>>21)+(2097151&Y)|0,_=_>>>0<k>>>0?p+1|0:p,Q[A+21|0]=G,u=(p=l)<<3,p=H,Q[A+18|0]=u|(262143&p)<<14|b>>>18,u=G,Q[A+22|0]=(255&_)<<24|u>>>8,F=_>>21,F=(u=(l=(2097151&_)<<11|u>>>21)+(2097151&gA)|0)>>>0<l>>>0?F+1|0:F,l=u,Q[A+25|0]=(2047&F)<<21|u>>>11,Q[A+24|0]=(7&F)<<29|u>>>3,p=u=F>>21,p=(F=(k=(2097151&F)<<11|l>>>21)+(2097151&z)|0)>>>0<k>>>0?p+1|0:p,Q[A+27|0]=(63&p)<<26|F>>>6,k=0,u=l&=2097151,Q[A+23|0]=31&((65535&_)<<16|G>>>16)|u<<5,u=p>>21,u=(p=(H=(2097151&p)<<11|F>>>21)+(2097151&x)|0)>>>0<H>>>0?u+1|0:u,Q[A+31|0]=(131071&u)<<15|p>>>17,Q[A+30|0]=(511&u)<<23|p>>>9,Q[A+29|0]=(1&u)<<31|p>>>1,_=0,u=(F=H=2097151&F)<<2,F=k,Q[A+26|0]=u|(524287&F)<<13|l>>>19,u=A,A=_,Q[u+28|0]=p<<7|(16383&A)<<18|H>>>14}function _(A,I,g,B,C,E,t,e,f,c,y,p){var u,F,l=0,_=0,H=0,G=0,U=0,m=0,M=0,P=0,Y=0,N=0,d=0,J=0,x=0,L=0,K=0,X=0,T=0,V=0,q=0,z=0,j=0,W=0,O=0,$=0,AA=0,IA=0,gA=0,BA=0,CA=0,QA=0,EA=0,iA=0,aA=0,rA=0,oA=0,tA=0,eA=0,fA=0,cA=0,yA=0,sA=0,wA=0,DA=0,hA=0,uA=0;if(s=u=s+-64|0,F=k(f)){if(i[u+32>>2]=0,i[u+36>>2]=0,i[u+24>>2]=0,i[u+28>>2]=0,i[u+20>>2]=t,i[u+16>>2]=E,i[u+12>>2]=C,i[u+8>>2]=B,i[u+4>>2]=f,i[u>>2]=F,i[u+56>>2]=0,i[u+52>>2]=g,i[u+48>>2]=g,i[u+44>>2]=I,i[u+40>>2]=A,A=0,s=U=s-48|0,!((I=nA(u))||(I=-26,p-3>>>0<4294967294))){if(g=i[u+44>>2],I=i[u+48>>2],i[U>>2]=0,B=i[u+40>>2],i[U+28>>2]=I,i[U+12>>2]=-1,i[U+8>>2]=B,I=((B=g>>>0>(B=I<<3)>>>0?g:B)>>>0)/((g=I<<2)>>>0)|0,i[U+20>>2]=I,i[U+24>>2]=I<<2,i[U+16>>2]=r(I,g),I=i[u+52>>2],i[U+36>>2]=p,i[U+32>>2]=I,s=B=s-80|0,C=-25,!(!U|!u))if(I=k(i[U+20>>2]<<3),i[U+4>>2]=I,I){s=t=s-16|0,C=-22;A:if(!(!U|!(I=i[U+16>>2]))&&1024==(((E=I<<10)>>>0)/(I>>>0)|0)&&(I=k(12),i[U>>2]=I,I)){i[I>>2]=0,i[I+4>>2]=0,E>>>0>4294967168?I=48:(E>>>0>=4294967168?(i[8952]=48,g=0):(g=0,(I=k(76+(x=E>>>0<11?16:E+11&-8)|0))&&(g=I-8|0,63&I?(d=(-8&(M=i[(H=I-4|0)>>2]))-(m=(I=((I=(I+63&-64)-8|0)-g>>>0>15?0:64)+I|0)-g|0)|0,3&M?(i[I+4>>2]=d|1&i[I+4>>2]|2,i[4+(d=I+d|0)>>2]=1|i[d+4>>2],i[H>>2]=m|1&i[H>>2]|2,i[4+(d=g+m|0)>>2]=1|i[d+4>>2],v(g,m)):(g=i[g>>2],i[I+4>>2]=d,i[I>>2]=g+m)):I=g,3&(g=i[I+4>>2])&&((m=-8&g)>>>0<=x+16>>>0||(i[I+4>>2]=x|1&g|2,g=I+x|0,x=m-x|0,i[g+4>>2]=3|x,i[4+(m=I+m|0)>>2]=1|i[m+4>>2],v(g,x))),g=I+8|0)),(I=g)?(i[t+12>>2]=I,I=0):I=48),i[8952]=I;I:{if(I)i[t+12>>2]=0;else if(I=i[t+12>>2])break I;b(i[U>>2]),i[U>>2]=0;break A}i[i[U>>2]>>2]=I,i[i[U>>2]+4>>2]=I,i[i[U>>2]+8>>2]=E,C=0}if(s=t+16|0,C)RA(U,i[u+56>>2]);else{if(E=i[U+36>>2],t=I=s,s=I=I-448&-64,!B|!u||(OA(C=I- -64|0,0,0,64),bI(g=I+60|0,i[u+48>>2]),Cg(C,g,4,0),bI(g,i[u+4>>2]),Cg(C,g,4,0),bI(g,i[u+44>>2]),Cg(C,g,4,0),bI(g,i[u+40>>2]),Cg(C,g,4,0),bI(g,19),Cg(C,g,4,0),bI(g,E),Cg(C,g,4,0),bI(g,i[u+12>>2]),Cg(C,g,4,0),(g=i[u+8>>2])&&(Cg(I- -64|0,g,i[u+12>>2],0),1&Q[u+56|0]&&(Dg(i[u+8>>2],i[u+12>>2]),i[u+12>>2]=0)),bI(g=I+60|0,i[u+20>>2]),Cg(I- -64|0,g,4,0),(g=i[u+16>>2])&&Cg(I- -64|0,g,i[u+20>>2],0),bI(g=I+60|0,i[u+28>>2]),Cg(I- -64|0,g,4,0),(g=i[u+24>>2])&&(Cg(I- -64|0,g,i[u+28>>2],0),2&n[u+56|0]&&(Dg(i[u+24>>2],i[u+28>>2]),i[u+28>>2]=0)),bI(g=I+60|0,i[u+36>>2]),Cg(I- -64|0,g,4,0),(g=i[u+32>>2])&&Cg(I- -64|0,g,i[u+36>>2],0),UI(I- -64|0,B,64)),s=t,Dg(B- -64|0,8),C=0,s=I=s-1024|0,i[U+28>>2])for(E=B+68|0,g=B- -64|0;bI(g,0),bI(E,C),R(I,1024,B,72),KA(i[i[U>>2]+4>>2]+(r(i[U+24>>2],C)<<10)|0,I),bI(g,1),R(I,1024,B,72),KA(1024+(i[i[U>>2]+4>>2]+(r(i[U+24>>2],C)<<10)|0)|0,I),(C=C+1|0)>>>0<a[U+28>>2];);Dg(I,1024),s=I+1024|0,Dg(B,72),C=0}}else C=-22;if(s=B+80|0,!(I=C)){if(i[U+8>>2])for(;;){if(B=A,cA=0,s=C=s-32|0,!(!U|!i[U+28>>2]))for(i[C+16>>2]=B,I=1;;){if(Q[C+24|0]=cA,yA=0,A=0,I)for(;;){i[C+28>>2]=0,A=i[C+28>>2],i[C+8>>2]=i[C+24>>2],i[C+12>>2]=A,i[C+20>>2]=yA,A=i[C+20>>2],i[C>>2]=i[C+16>>2],i[C+4>>2]=A,A=0;A:if(U){I:{if(2==i[U+36>>2]){if(sA=i[U+4>>2],wA=1,(t=i[C>>2])|(E=n[C+8|0])>>>0>1)break I}else sA=i[U+4>>2];if(s=I=s-4096|0,wg(I+3072|0),wg(I+2048|0),!(!U|!C)&&(i[I+2048>>2]=i[C>>2],i[I+2052>>2]=0,i[I+2056>>2]=i[C+4>>2],i[I+2060>>2]=0,i[I+2064>>2]=n[C+8|0],i[I+2068>>2]=0,i[I+2072>>2]=i[U+16>>2],i[I+2076>>2]=0,i[I+2080>>2]=i[U+8>>2],i[I+2084>>2]=0,i[I+2088>>2]=i[U+36>>2],i[I+2092>>2]=0,i[U+20>>2]))for(;(g=127&A)||(t=E=i[I+2100>>2],H=E+1|0,t=(E=i[I+2096>>2]+1|0)?t:H,i[I+2096>>2]=E,i[I+2100>>2]=t,wg(I),wg(E=I+1024|0),S(t=I+3072|0,I+2048|0,I),S(t,I,E)),E=i[4+(g=(I+1024|0)+(g<<3)|0)>>2],i[(t=(A<<3)+sA|0)>>2]=i[g>>2],i[t+4>>2]=E,(A=A+1|0)>>>0<a[U+20>>2];);s=I+4096|0,E=n[C+8|0],t=i[C>>2],wA=0}if(A=255&E,!((t=t?0:!A<<1)>>>0>=(g=i[U+20>>2])>>>0))for(I=i[U+24>>2],A=(E=(r(I,i[C+4>>2])+t|0)+r(A,g)|0)+((E>>>0)%(I>>>0)|0?-1:I-1|0)|0;;){DA=1==((E>>>0)%(I>>>0)|0)?E-1|0:A,x=i[U+28>>2],wA?(A=i[U>>2],m=i[A+4>>2]+(DA<<10)|0):(A=i[U>>2],m=(t<<3)+sA|0),g=i[m>>2],m=i[m+4>>2],i[C+12>>2]=t,x=(m>>>0)%(x>>>0)|0,m=i[C+4>>2],d=n[C+8|0]?x:m,_=i[A+4>>2],G=i[C>>2],Y=_+(r(I,A=G?x:d)<<10)|0,A=(0|A)==(0|m);I:if(i[C>>2])I=i[U+24>>2],x=i[U+20>>2],I=A?i[C+12>>2]+(I+(-1^x)|0)|0:(I-x|0)-!i[C+12>>2]|0,H=0,3!=(0|(A=n[C+8|0]))&&(H=r(x,A+1|0));else{if(!(I=n[C+8|0])){I=i[C+12>>2]-1|0,H=0;break I}if(I=r(I,i[U+20>>2]),x=i[C+12>>2],A){I=(I+x|0)-1|0,H=0;break I}I=I-!x|0,H=0}A=H+(d=I-1|0)|0,qA(g,0,g,0),qA(I,0,h,0),m=A-(I=h)|0,x=i[U+24>>2],l=0;I:{g:{B:{C:{Q:{E:{i:{n:{a:{r:{if(I=(A>>>0<d>>>0)-(A>>>0<I>>>0)|0){if(!x)break r;break a}w=m-r((m>>>0)/(x>>>0)|0,x)|0,D=0,h=0;break I}if(!m)break n;break i}if(!((A=x-1|0)&x))break E;H=0-(d=(o(x)+33|0)-o(I)|0)|0;break C}w=0,D=I,h=0;break I}if((A=32-o(I)|0)>>>0<31)break Q;break B}if(w=A&m,D=0,1==(0|x))break g;A=x?31-o(x-1^x)|0:32,h=(63&A)>>>0>=32?0:I>>>A|0;break I}d=A+1|0,H=63-A|0}if(g=31&(A=63&d),A>>>0>=32?(A=0,M=I>>>g|0):(A=I>>>g|0,M=((1<<g)-1&I)<<32-g|m>>>g),g=A,H=31&(A=63&H),A>>>0>=32?(A=m<<H,m=0):(A=(1<<H)-1&m>>>32-H|I<<H,m<<=H),I=A,d)for(N=-1!=(0|(H=x-1|0))?0:-1;M=(A=M<<1|I>>>31)-(X=x&(L=N-((g=g<<1|M>>>31)+(A>>>0>H>>>0)|0)>>31))|0,g=g-(A>>>0<X>>>0)|0,I=I<<1|m>>>31,m=l|m<<1,l=1&L,d=d-1|0;);w=M,D=g,h=I<<1|m>>>31;break I}w=m,D=I,I=0}h=I}if(h=D,A=(w<<10)+Y|0,x=_+(DA<<10)|0,g=_+(E<<10)|0,G)S(x,A,g);else{for(s=I=s-2048|0,yg(m=I+1024|0,A),AI(m,x),yg(I,m),x=0,m=0;H=i[(d=(A=(I+1024|0)+(m<<7)|0)- -64|0)>>2],M=i[A+100>>2],P=H,N=i[d+4>>2],J=i[A+96>>2],H=i[A+32>>2],_=i[A+36>>2],M=pA(J^(l=CI(i[A>>2],i[A+4>>2],H,_)),M^(G=h),32),_=pA(P=(N=CI(P,N,M,Y=h))^H,_^(H=h),24),P=H,AA=pA((X=CI(l,G,_,H=h))^M,(T=h)^Y,16),H=pA(_^(gA=CI(N,P,AA,IA=h)),(rA=h)^H,63),M=h,_=i[A+108>>2],K=i[A+72>>2],J=i[A+76>>2],P=i[A+104>>2],l=i[A+40>>2],G=i[A+44>>2],_=pA(P^(Y=CI(i[A+8>>2],i[A+12>>2],l,G)),_^(N=h),32),G=pA(P=(BA=CI(K,J,_,L=h))^l,G^(l=h),24),J=BA,tA=pA((P=_)^(BA=CI(Y,N,G,_=h)),(oA=h)^L,16),_=pA(G^(CA=CI(J,l,tA,eA=h)),(QA=h)^_,63),l=h,G=i[A+116>>2],K=i[A+80>>2],J=i[A+84>>2],P=i[A+112>>2],Y=i[A+48>>2],N=i[A+52>>2],G=pA(P^(L=CI(i[A+16>>2],i[A+20>>2],Y,N)),G^(j=h),32),N=pA(J=(P=CI(K,J,G,EA=h))^Y,N^(Y=h),24),K=P,J=Y,EA=pA(G^(j=CI(L,j,N,Y=h)),EA^(P=h),16),G=pA(N^(J=CI(K,J,EA,iA=h)),(W=h)^Y,63),Y=h,N=i[A+124>>2],aA=i[A+88>>2],O=i[A+92>>2],K=i[A+120>>2],L=i[A+56>>2],V=i[A+60>>2],N=pA(K^(q=CI(i[A+24>>2],i[A+28>>2],L,V)),N^(z=h),32),O=V=pA(K=(fA=CI(aA,O,N,$=h))^L,V^(L=h),24),z=pA((K=N)^(V=CI(q,z,V,N=h)),(q=h)^$,16),N=pA(O^(fA=CI(fA,L,z,$=h)),(aA=h)^N,63),L=h,O=J,K=W,J=pA(z^(X=CI(X,T,_,l)),$^(T=h),32),_=pA((z=CI(O,K,J,W=h))^_,(K=l)^(l=h),24),T=CI(K=X,T,_,X=h),i[A>>2]=T,$=h,i[A+4>>2]=$,T=pA(T^J,W^$,16),i[A+120>>2]=T,J=h,i[A+124>>2]=J,l=CI(z,l,T,J),i[A+80>>2]=l,T=h,i[A+84>>2]=T,hA=A,uA=pA(_^l,X^T,63),i[hA+40>>2]=uA,i[A+44>>2]=h,T=pA(AA^(l=CI(BA,oA,G,Y)),IA^(X=h),32),_=pA(J=G^(IA=CI(fA,aA,T,AA=h)),Y^(G=h),24),Y=CI(J=l,X,_,l=h),i[A+8>>2]=Y,X=h,i[A+12>>2]=X,Y=pA(Y^T,X^AA,16),i[A+96>>2]=Y,X=h,i[A+100>>2]=X,G=CI(IA,G,Y,X),i[A+88>>2]=G,Y=h,i[A+92>>2]=Y,hA=A,uA=pA(_^G,l^Y,63),i[hA+48>>2]=uA,i[A+52>>2]=h,Y=pA(tA^(l=CI(j,P,N,L)),eA^(G=h),32),_=pA(P=N^(T=CI(gA,rA,Y,X=h)),L^(N=h),24),G=CI(P=l,G,_,l=h),i[A+16>>2]=G,L=h,i[A+20>>2]=L,G=pA(G^Y,L^X,16),i[A+104>>2]=G,Y=h,i[A+108>>2]=Y,G=CI(T,N,G,Y),i[d>>2]=G,P=d,d=h,i[P+4>>2]=d,hA=A,uA=pA(_^G,l^d,63),i[hA+56>>2]=uA,i[A+60>>2]=h,_=CI(V,q,H,M),N=CI(CA,QA,G=pA(EA^_,iA^(l=h),32),Y=h),_=CI(_,l,d=pA(P=H^N,M^(H=h),24),M=h),i[A+24>>2]=_,l=h,i[A+28>>2]=l,_=pA(_^G,l^Y,16),i[A+112>>2]=_,l=h,i[A+116>>2]=l,H=CI(N,H,_,l),i[A+72>>2]=H,_=h,i[A+76>>2]=_,hA=A,uA=pA(H^d,_^M,63),i[hA+32>>2]=uA,i[A+36>>2]=h,8!=(0|(m=m+1|0)););for(;m=i[512+(A=(I+1024|0)+(x<<4)|0)>>2],d=i[A+772>>2],P=m,J=i[A+516>>2],l=i[A+768>>2],m=i[A+256>>2],H=i[A+260>>2],d=pA(l^(M=CI(i[A>>2],i[A+4>>2],m,H)),d^(_=h),32),H=pA(P=(G=CI(P,J,d,l=h))^m,H^(m=h),24),P=m,X=pA((N=CI(M,_,H,m=h))^d,(L=h)^l,16),m=pA(H^(AA=CI(G,P,X,T=h)),(IA=h)^m,63),d=h,H=i[A+780>>2],K=i[A+520>>2],J=i[A+524>>2],P=i[A+776>>2],M=i[A+264>>2],_=i[A+268>>2],H=pA(P^(l=CI(i[A+8>>2],i[A+12>>2],M,_)),H^(G=h),32),_=pA(P=(gA=CI(K,J,H,Y=h))^M,_^(M=h),24),J=gA,BA=pA((P=H)^(gA=CI(l,G,_,H=h)),(rA=h)^Y,16),H=pA(_^(tA=CI(J,M,BA,oA=h)),(eA=h)^H,63),M=h,_=i[A+900>>2],K=i[A+640>>2],J=i[A+644>>2],P=i[A+896>>2],l=i[A+384>>2],G=i[A+388>>2],_=pA(P^(Y=CI(i[A+128>>2],i[A+132>>2],l,G)),_^(CA=h),32),G=pA(P=(j=CI(K,J,_,QA=h))^l,G^(l=h),24),J=j,P=l,QA=pA(_^(CA=CI(Y,CA,G,l=h)),QA^(j=h),16),_=pA(G^(P=CI(J,P,QA,EA=h)),(iA=h)^l,63),l=h,G=i[A+908>>2],aA=i[A+648>>2],O=i[A+652>>2],K=i[A+904>>2],Y=i[A+392>>2],J=i[A+396>>2],G=pA(K^(W=CI(i[A+136>>2],i[A+140>>2],Y,J)),G^(V=h),32),O=J=pA(K=(z=CI(aA,O,G,q=h))^Y,J^(Y=h),24),V=pA((K=G)^(J=CI(W,V,J,G=h)),(W=h)^q,16),G=pA(O^(z=CI(z,Y,V,q=h)),($=h)^G,63),Y=h,O=P,K=iA,P=pA(V^(N=CI(N,L,H,M)),q^(L=h),32),H=pA((V=CI(O,K,P,iA=h))^H,(K=M)^(M=h),24),L=CI(K=N,L,H,N=h),i[A>>2]=L,q=h,i[A+4>>2]=q,L=pA(L^P,q^iA,16),i[A+904>>2]=L,P=h,i[A+908>>2]=P,M=CI(V,M,L,P),i[A+640>>2]=M,L=h,i[A+644>>2]=L,hA=A,uA=pA(H^M,N^L,63),i[hA+264>>2]=uA,i[A+268>>2]=h,L=pA(X^(M=CI(gA,rA,_,l)),T^(N=h),32),H=pA(H=_^(T=CI(z,$,L,X=h)),l^(_=h),24),l=CI(l=M,N,H,M=h),i[A+8>>2]=l,N=h,i[A+12>>2]=N,l=pA(l^L,N^X,16),i[A+768>>2]=l,N=h,i[A+772>>2]=N,_=CI(T,_,l,N),i[A+648>>2]=_,l=h,i[A+652>>2]=l,hA=A,uA=pA(_^H,l^M,63),i[hA+384>>2]=uA,i[A+388>>2]=h,M=CI(CA,j,G,Y),L=CI(AA,IA,l=pA(BA^M,oA^(_=h),32),N=h),_=CI(P=M,_,H=pA(H=G^L,Y^(G=h),24),M=h),i[A+128>>2]=_,Y=h,i[A+132>>2]=Y,_=pA(_^l,Y^N,16),i[A+776>>2]=_,l=h,i[A+780>>2]=l,_=CI(L,G,_,l),i[A+512>>2]=_,l=h,i[A+516>>2]=l,hA=A,uA=pA(_^H,l^M,63),i[hA+392>>2]=uA,i[A+396>>2]=h,_=pA(QA^(H=CI(J,W,m,d)),EA^(M=h),32),m=pA((G=CI(tA,eA,_,l=h))^m,(P=d)^(d=h),24),M=CI(P=H,M,m,H=h),i[A+136>>2]=M,Y=h,i[A+140>>2]=Y,M=pA(_^M,l^Y,16),i[A+896>>2]=M,_=h,i[A+900>>2]=_,d=CI(G,d,M,_),i[A+520>>2]=d,M=h,i[A+524>>2]=M,hA=A,uA=pA(m^d,H^M,63),i[hA+256>>2]=uA,i[A+260>>2]=h,8!=(0|(x=x+1|0)););yg(g,I),AI(g,I+1024|0),s=I+2048|0}if((t=t+1|0)>>>0>=a[U+20>>2])break A;E=E+1|0,A=DA+1|0,I=i[U+24>>2]}}if(!((A=i[U+28>>2])>>>0>(yA=yA+1|0)>>>0))break}if(I=A,4==(0|(cA=cA+1|0)))break}if(s=C+32|0,!((A=B+1|0)>>>0<a[U+8>>2]))break}if(s=I=s-2048|0,!(!u|!U)){if(yg(I+1024|0,(i[i[U>>2]+4>>2]+(i[U+24>>2]<<10)|0)-1024|0),a[U+28>>2]>=2)for(A=1;g=i[U+24>>2],AI(I+1024|0,(i[i[U>>2]+4>>2]+(r(g,A)+g<<10)|0)-1024|0),(A=A+1|0)>>>0<a[U+28>>2];);for(g=I+1024|0,A=0;QI(C=(B=A<<3)+I|0,i[(B=g+B|0)>>2],i[B+4>>2]),128!=(0|(A=A+1|0)););R(i[u>>2],i[u+4>>2],I,1024),Dg(g,1024),Dg(I,1024),RA(U,i[u+56>>2])}s=I+2048|0,I=0}}s=U+48|0,g=I;A:if(I)Dg(F,f);else{if(!(!c|!y)){s=A=s-16|0,I=-31;I:{g:{B:{C:switch(p-1|0){case 1:if(y>>>0<13)break g;I=n[1347]|n[1348]<<8|n[1349]<<16|n[1350]<<24,g=n[1343]|n[1344]<<8|n[1345]<<16|n[1346]<<24,Q[0|c]=g,Q[c+1|0]=g>>>8,Q[c+2|0]=g>>>16,Q[c+3|0]=g>>>24,Q[c+4|0]=I,Q[c+5|0]=I>>>8,Q[c+6|0]=I>>>16,Q[c+7|0]=I>>>24,I=n[1352]|n[1353]<<8|n[1354]<<16|n[1355]<<24,g=n[1348]|n[1349]<<8|n[1350]<<16|n[1351]<<24,Q[c+5|0]=g,Q[c+6|0]=g>>>8,Q[c+7|0]=g>>>16,Q[c+8|0]=g>>>24,Q[c+9|0]=I,Q[c+10|0]=I>>>8,Q[c+11|0]=I>>>16,Q[c+12|0]=I>>>24,B=-12,g=12;break B;case 0:break C;default:break I}if(y>>>0<12)break g;I=n[1335]|n[1336]<<8|n[1337]<<16|n[1338]<<24,g=n[1331]|n[1332]<<8|n[1333]<<16|n[1334]<<24,Q[0|c]=g,Q[c+1|0]=g>>>8,Q[c+2|0]=g>>>16,Q[c+3|0]=g>>>24,Q[c+4|0]=I,Q[c+5|0]=I>>>8,Q[c+6|0]=I>>>16,Q[c+7|0]=I>>>24,I=n[1339]|n[1340]<<8|n[1341]<<16|n[1342]<<24,Q[c+8|0]=I,Q[c+9|0]=I>>>8,Q[c+10|0]=I>>>16,Q[c+11|0]=I>>>24,B=-11,g=11}if(I=nA(u))break I;if(dA(I=A+5|0,19),!((B=B+y|0)>>>0<=(I=mA(I))>>>0)&&(g=eI(g+c|0,A+5|0,I+1|0),!((B=B-I|0)>>>0<4)&&(Q[0|(I=I+g|0)]=36,Q[I+1|0]=109,Q[I+2|0]=61,Q[I+3|0]=0,dA(g=A+5|0,i[u+44>>2]),!((B=B-3|0)>>>0<=(g=mA(g))>>>0)&&(I=eI(I+3|0,A+5|0,g+1|0),!((B=B-g|0)>>>0<4)&&(Q[0|(I=I+g|0)]=44,Q[I+1|0]=116,Q[I+2|0]=61,Q[I+3|0]=0,dA(g=A+5|0,i[u+40>>2]),!((B=B-3|0)>>>0<=(g=mA(g))>>>0)&&(I=eI(I+3|0,A+5|0,g+1|0),!((B=B-g|0)>>>0<4)&&(Q[0|(I=I+g|0)]=44,Q[I+1|0]=112,Q[I+2|0]=61,Q[I+3|0]=0,dA(g=A+5|0,i[u+48>>2]),!((B=B-3|0)>>>0<=(g=mA(g))>>>0)&&(I=eI(I+3|0,A+5|0,g+1|0),!((B=B-g|0)>>>0<2)&&(Q[0|(I=I+g|0)]=36,Q[I+1|0]=0,Z(g=I+1|0,B=B-1|0,i[u+16>>2],i[u+20>>2],3)))))))))){if(I=-31,(C=(C=B)-(B=mA(g))|0)>>>0<2)break I;Q[0|(I=g+B|0)]=36,Q[I+1|0]=0,I=Z(I+1|0,C-1|0,i[u>>2],i[u+4>>2],3)?0:-31;break I}}I=-31}if(s=A+16|0,I){Dg(F,f),Dg(c,y),g=-31;break A}}e&&eI(e,F,f),Dg(F,f),g=0}b(F)}else g=-22;return s=u- -64|0,g}function k(A){var I,g=0,B=0,C=0,Q=0,E=0,r=0,o=0,t=0,e=0,f=0,c=0,y=0;s=I=s-16|0;A:{I:{g:{B:{C:{Q:{E:{i:{n:{a:{r:{if((A|=0)>>>0<=244){if(3&(g=(Q=i[8965])>>>(B=(r=A>>>0<11?16:A+11&-8)>>>3|0)|0)){A=(E=i[35908+(g=(C=B+(1&(-1^g))|0)<<3)>>2])+8|0,(0|(B=i[E+8>>2]))!=(0|(g=g+35900|0))?(i[B+12>>2]=g,i[g+8>>2]=B):(c=35860,y=lI(-2,C)&Q,i[c>>2]=y),g=C<<3,i[E+4>>2]=3|g,i[4+(g=g+E|0)>>2]=1|i[g+4>>2];break A}if((f=i[8967])>>>0>=r>>>0)break r;if(g){B=A=(g=(0-(A=(0-(A=2<<B)|A)&g<<B)&A)-1|0)>>>12&16,B|=A=(g=g>>>A|0)>>>5&8,B|=A=(g=g>>>A|0)>>>2&4,e=i[35908+(A=(B=((B|=A=(g=g>>>A|0)>>>1&2)|(A=(g=g>>>A|0)>>>1&1))+(g>>>A|0)|0)<<3)>>2],(0|(g=i[e+8>>2]))!=(0|(A=A+35900|0))?(i[g+12>>2]=A,i[A+8>>2]=g):(Q=lI(-2,B)&Q,i[8965]=Q),A=e+8|0,i[e+4>>2]=3|r,E=(g=B<<3)-r|0,i[4+(C=r+e|0)>>2]=1|E,i[g+e>>2]=E,f&&(B=35900+((g=f>>>3|0)<<3)|0,e=i[8970],(g=1<<g)&Q?g=i[B+8>>2]:(i[8965]=g|Q,g=B),i[B+8>>2]=e,i[g+12>>2]=e,i[e+12>>2]=B,i[e+8>>2]=g),i[8970]=C,i[8967]=E;break A}if(!(o=i[8966]))break r;for(B=A=(g=(0-o&o)-1|0)>>>12&16,B|=A=(g=g>>>A|0)>>>5&8,B|=A=(g=g>>>A|0)>>>2&4,g=i[36164+(((B|=A=(g=g>>>A|0)>>>1&2)|(A=(g=g>>>A|0)>>>1&1))+(g>>>A|0)<<2)>>2],C=(-8&i[g+4>>2])-r|0,B=g;(A=i[B+16>>2])||(A=i[B+20>>2]);)C=(E=(B=(-8&i[A+4>>2])-r|0)>>>0<C>>>0)?B:C,g=E?A:g,B=A;if(t=i[g+24>>2],(0|(E=i[g+12>>2]))!=(0|g)){A=i[g+8>>2],i[A+12>>2]=E,i[E+8>>2]=A;break I}if(!(A=i[(B=g+20|0)>>2])){if(!(A=i[g+16>>2]))break a;B=g+16|0}for(;e=B,E=A,(A=i[(B=A+20|0)>>2])||(B=E+16|0,A=i[E+16>>2]););i[e>>2]=0;break I}if(r=-1,!(A>>>0>4294967231)&&(r=-8&(A=A+11|0),t=i[8966])){C=0-r|0,Q=0,r>>>0<256||(Q=31,r>>>0>16777215||(A=A>>>8|0,A<<=e=A+1048320>>>16&8,Q=28+((A=((A<<=B=A+520192>>>16&4)<<(g=A+245760>>>16&2)>>>15|0)-(g|B|e)|0)<<1|r>>>A+21&1)|0));o:{t:{if(B=i[36164+(Q<<2)>>2])for(A=0,g=r<<(31==(0|Q)?0:25-(Q>>>1|0)|0);;){if(!((e=(o=-8&i[B+4>>2])-r|0)>>>0>=C>>>0)&&(C=e,E=B,(0|r)==(0|o))){C=0,A=B;break t}if(e=i[B+20>>2],B=i[16+((g>>>29&4)+B|0)>>2],A=e?(0|e)==(0|B)?A:e:A,g<<=1,!B)break}else A=0;if(!(A|E)){if(E=0,!(A=(0-(A=2<<Q)|A)&t))break r;B=A=(g=(A&0-A)-1|0)>>>12&16,B|=A=(g=g>>>A|0)>>>5&8,B|=A=(g=g>>>A|0)>>>2&4,A=i[36164+(((B|=A=(g=g>>>A|0)>>>1&2)|(A=(g=g>>>A|0)>>>1&1))+(g>>>A|0)<<2)>>2]}if(!A)break o}for(;C=(B=(g=(-8&i[A+4>>2])-r|0)>>>0<C>>>0)?g:C,E=B?A:E,A=(g=i[A+16>>2])||i[A+20>>2];);}if(!(!E|i[8967]-r>>>0<=C>>>0)){if(Q=i[E+24>>2],(0|E)!=(0|(g=i[E+12>>2]))){A=i[E+8>>2],i[A+12>>2]=g,i[g+8>>2]=A;break g}if(!(A=i[(B=E+20|0)>>2])){if(!(A=i[E+16>>2]))break n;B=E+16|0}for(;e=B,g=A,(A=i[(B=A+20|0)>>2])||(B=g+16|0,A=i[g+16>>2]););i[e>>2]=0;break g}}}if((B=i[8967])>>>0>=r>>>0){C=i[8970],(g=B-r|0)>>>0>=16?(i[8967]=g,A=C+r|0,i[8970]=A,i[A+4>>2]=1|g,i[B+C>>2]=g,i[C+4>>2]=3|r):(i[8970]=0,i[8967]=0,i[C+4>>2]=3|B,i[4+(A=B+C|0)>>2]=1|i[A+4>>2]),A=C+8|0;break A}if((t=i[8968])>>>0>r>>>0){g=t-r|0,i[8968]=g,A=(B=i[8971])+r|0,i[8971]=A,i[A+4>>2]=1|g,i[B+4>>2]=3|r,A=B+8|0;break A}if(A=0,o=r+47|0,i[9083]?B=i[9085]:(i[9086]=-1,i[9087]=-1,i[9084]=4096,i[9085]=4096,i[9083]=I+12&-16^1431655768,i[9088]=0,i[9076]=0,B=4096),(B=(e=o+B|0)&(E=0-B|0))>>>0<=r>>>0)break A;if((C=i[9075])&&(Q=(g=i[9073])+B|0)>>>0>C>>>0|g>>>0>=Q>>>0)break A;if(4&n[36304])break Q;r:{o:{if(C=i[8971])for(A=36308;;){if((g=i[A>>2])>>>0<=C>>>0&C>>>0<g+i[A+4>>2]>>>0)break o;if(!(A=i[A+8>>2]))break}if(-1==(0|(g=$A(0))))break E;if(Q=B,(A=(C=i[9084])-1|0)&g&&(Q=(B-g|0)+(A+g&0-C)|0),Q>>>0<=r>>>0|Q>>>0>2147483646)break E;if((C=i[9075])&&C>>>0<(E=(A=i[9073])+Q|0)>>>0|A>>>0>=E>>>0)break E;if((0|g)!=(0|(A=$A(Q))))break r;break C}if((Q=E&e-t)>>>0>2147483646)break E;if((0|(g=$A(Q)))==(i[A>>2]+i[A+4>>2]|0))break i;A=g}if(!(-1==(0|A)|r+48>>>0<=Q>>>0)){if((g=(g=i[9085])+(o-Q|0)&0-g)>>>0>2147483646){g=A;break C}if(-1!=(0|$A(g))){Q=g+Q|0,g=A;break C}$A(0-Q|0);break E}if(g=A,-1!=(0|A))break C;break E}E=0;break I}g=0;break g}if(-1!=(0|g))break C}i[9076]=4|i[9076]}if(B>>>0>2147483646)break B;if(-1==(0|(g=$A(B)))|-1==(0|(A=$A(0)))|A>>>0<=g>>>0)break B;if((Q=A-g|0)>>>0<=r+40>>>0)break B}A=i[9073]+Q|0,i[9073]=A,A>>>0>a[9074]&&(i[9074]=A);C:{Q:{E:{if(o=i[8971]){for(A=36308;;){if(((C=i[A>>2])+(B=i[A+4>>2])|0)==(0|g))break E;if(!(A=i[A+8>>2]))break}break Q}for((A=i[8969])>>>0<=g>>>0&&A||(i[8969]=g),A=0,i[9078]=Q,i[9077]=g,i[8973]=-1,i[8974]=i[9083],i[9080]=0;B=35900+(C=A<<3)|0,i[C+35908>>2]=B,i[C+35912>>2]=B,32!=(0|(A=A+1|0)););B=(C=Q-40|0)-(A=g+8&7?-8-g&7:0)|0,i[8968]=B,A=A+g|0,i[8971]=A,i[A+4>>2]=1|B,i[4+(g+C|0)>>2]=40,i[8972]=i[9087];break C}if(!(8&n[A+12|0]|C>>>0>o>>>0|g>>>0<=o>>>0)){i[A+4>>2]=B+Q,B=(A=o+8&7?-8-o&7:0)+o|0,i[8971]=B,A=(g=i[8968]+Q|0)-A|0,i[8968]=A,i[B+4>>2]=1|A,i[4+(g+o|0)>>2]=40,i[8972]=i[9087];break C}}a[8969]>g>>>0&&(i[8969]=g),B=g+Q|0,A=36308;Q:{E:{i:{n:{a:{r:{for(;;){if((0|B)!=i[A>>2]){if(A=i[A+8>>2])continue;break r}break}if(!(8&n[A+12|0]))break a}for(A=36308;;){if((B=i[A>>2])>>>0<=o>>>0&&(E=B+i[A+4>>2]|0)>>>0>o>>>0)break n;A=i[A+8>>2]}}if(i[A>>2]=g,i[A+4>>2]=i[A+4>>2]+Q,i[4+(e=(g+8&7?-8-g&7:0)+g|0)>>2]=3|r,r=(Q=B+(B+8&7?-8-B&7:0)|0)-(t=r+e|0)|0,(0|Q)==(0|o)){i[8971]=t,A=i[8968]+r|0,i[8968]=A,i[t+4>>2]=1|A;break E}if(i[8970]==(0|Q)){i[8970]=t,A=i[8967]+r|0,i[8967]=A,i[t+4>>2]=1|A,i[A+t>>2]=A;break E}if(1==(3&(A=i[Q+4>>2]))){E=-8&A;a:if(A>>>0<=255){if(B=i[Q+8>>2],A=A>>>3|0,(0|(g=i[Q+12>>2]))==(0|B)){c=35860,y=i[8965]&lI(-2,A),i[c>>2]=y;break a}i[B+12>>2]=g,i[g+8>>2]=B}else{if(o=i[Q+24>>2],(0|Q)==(0|(g=i[Q+12>>2])))if((C=i[(A=Q+20|0)>>2])||(C=i[(A=Q+16|0)>>2])){for(;B=A,(C=i[(A=(g=C)+20|0)>>2])||(A=g+16|0,C=i[g+16>>2]););i[B>>2]=0}else g=0;else A=i[Q+8>>2],i[A+12>>2]=g,i[g+8>>2]=A;if(o){B=i[Q+28>>2];r:{if(i[(A=36164+(B<<2)|0)>>2]==(0|Q)){if(i[A>>2]=g,g)break r;c=35864,y=i[8966]&lI(-2,B),i[c>>2]=y;break a}if(i[o+(i[o+16>>2]==(0|Q)?16:20)>>2]=g,!g)break a}i[g+24>>2]=o,(A=i[Q+16>>2])&&(i[g+16>>2]=A,i[A+24>>2]=g),(A=i[Q+20>>2])&&(i[g+20>>2]=A,i[A+24>>2]=g)}}r=E+r|0,Q=Q+E|0}if(i[Q+4>>2]=-2&i[Q+4>>2],i[t+4>>2]=1|r,i[r+t>>2]=r,r>>>0<=255){g=35900+((A=r>>>3|0)<<3)|0,(B=i[8965])&(A=1<<A)?A=i[g+8>>2]:(i[8965]=A|B,A=g),i[g+8>>2]=t,i[A+12>>2]=t,i[t+12>>2]=g,i[t+8>>2]=A;break E}if(A=31,r>>>0<=16777215&&(A=r>>>8|0,A<<=C=A+1048320>>>16&8,A=28+((A=((A<<=B=A+520192>>>16&4)<<(g=A+245760>>>16&2)>>>15|0)-(g|B|C)|0)<<1|r>>>A+21&1)|0),i[t+28>>2]=A,i[t+16>>2]=0,i[t+20>>2]=0,C=36164+(A<<2)|0,(B=i[8966])&(g=1<<A)){for(A=r<<(31==(0|A)?0:25-(A>>>1|0)|0),g=i[C>>2];;){if(B=g,(-8&i[g+4>>2])==(0|r))break i;if(g=A>>>29|0,A<<=1,!(g=i[16+(C=B+(4&g)|0)>>2]))break}i[C+16>>2]=t,i[t+24>>2]=B}else i[8966]=g|B,i[C>>2]=t,i[t+24>>2]=C;i[t+12>>2]=t,i[t+8>>2]=t;break E}for(B=(C=Q-40|0)-(A=g+8&7?-8-g&7:0)|0,i[8968]=B,A=A+g|0,i[8971]=A,i[A+4>>2]=1|B,i[4+(g+C|0)>>2]=40,i[8972]=i[9087],i[(B=(A=(E+(E-39&7?39-E&7:0)|0)-47|0)>>>0<o+16>>>0?o:A)+4>>2]=27,A=i[9080],i[B+16>>2]=i[9079],i[B+20>>2]=A,A=i[9078],i[B+8>>2]=i[9077],i[B+12>>2]=A,i[9079]=B+8,i[9078]=Q,i[9077]=g,i[9080]=0,A=B+24|0;i[A+4>>2]=7,g=A+8|0,A=A+4|0,g>>>0<E>>>0;);if((0|B)==(0|o))break C;if(i[B+4>>2]=-2&i[B+4>>2],E=B-o|0,i[o+4>>2]=1|E,i[B>>2]=E,E>>>0<=255){g=35900+((A=E>>>3|0)<<3)|0,(B=i[8965])&(A=1<<A)?A=i[g+8>>2]:(i[8965]=A|B,A=g),i[g+8>>2]=o,i[A+12>>2]=o,i[o+12>>2]=g,i[o+8>>2]=A;break C}if(A=31,i[o+16>>2]=0,i[o+20>>2]=0,E>>>0<=16777215&&(A=E>>>8|0,A<<=C=A+1048320>>>16&8,A=28+((A=((A<<=B=A+520192>>>16&4)<<(g=A+245760>>>16&2)>>>15|0)-(g|B|C)|0)<<1|E>>>A+21&1)|0),i[o+28>>2]=A,C=36164+(A<<2)|0,(B=i[8966])&(g=1<<A)){for(A=E<<(31==(0|A)?0:25-(A>>>1|0)|0),g=i[C>>2];;){if(B=g,(0|E)==(-8&i[g+4>>2]))break Q;if(g=A>>>29|0,A<<=1,!(g=i[16+(C=B+(4&g)|0)>>2]))break}i[C+16>>2]=o,i[o+24>>2]=B}else i[8966]=g|B,i[C>>2]=o,i[o+24>>2]=C;i[o+12>>2]=o,i[o+8>>2]=o;break C}A=i[B+8>>2],i[A+12>>2]=t,i[B+8>>2]=t,i[t+24>>2]=0,i[t+12>>2]=B,i[t+8>>2]=A}A=e+8|0;break A}A=i[B+8>>2],i[A+12>>2]=o,i[B+8>>2]=o,i[o+24>>2]=0,i[o+12>>2]=B,i[o+8>>2]=A}if(!((A=i[8968])>>>0<=r>>>0)){g=A-r|0,i[8968]=g,A=(B=i[8971])+r|0,i[8971]=A,i[A+4>>2]=1|g,i[B+4>>2]=3|r,A=B+8|0;break A}}i[8952]=48,A=0;break A}g:if(Q){B=i[E+28>>2];B:{if(i[(A=36164+(B<<2)|0)>>2]==(0|E)){if(i[A>>2]=g,g)break B;t=lI(-2,B)&t,i[8966]=t;break g}if(i[Q+(i[Q+16>>2]==(0|E)?16:20)>>2]=g,!g)break g}i[g+24>>2]=Q,(A=i[E+16>>2])&&(i[g+16>>2]=A,i[A+24>>2]=g),(A=i[E+20>>2])&&(i[g+20>>2]=A,i[A+24>>2]=g)}g:if(C>>>0<=15)A=C+r|0,i[E+4>>2]=3|A,i[4+(A=A+E|0)>>2]=1|i[A+4>>2];else if(i[E+4>>2]=3|r,i[4+(Q=E+r|0)>>2]=1|C,i[Q+C>>2]=C,C>>>0<=255)g=35900+((A=C>>>3|0)<<3)|0,(B=i[8965])&(A=1<<A)?A=i[g+8>>2]:(i[8965]=A|B,A=g),i[g+8>>2]=Q,i[A+12>>2]=Q,i[Q+12>>2]=g,i[Q+8>>2]=A;else{A=31,C>>>0<=16777215&&(A=C>>>8|0,A<<=e=A+1048320>>>16&8,A=28+((A=((A<<=B=A+520192>>>16&4)<<(g=A+245760>>>16&2)>>>15|0)-(g|B|e)|0)<<1|C>>>A+21&1)|0),i[Q+28>>2]=A,i[Q+16>>2]=0,i[Q+20>>2]=0,g=36164+(A<<2)|0;B:{if((B=1<<A)&t){for(A=C<<(31==(0|A)?0:25-(A>>>1|0)|0),B=i[g>>2];;){if((-8&i[(g=B)+4>>2])==(0|C))break B;if(B=A>>>29|0,A<<=1,!(B=i[16+(e=(4&B)+g|0)>>2]))break}i[e+16>>2]=Q}else i[8966]=B|t,i[g>>2]=Q;i[Q+24>>2]=g,i[Q+12>>2]=Q,i[Q+8>>2]=Q;break g}A=i[g+8>>2],i[A+12>>2]=Q,i[g+8>>2]=Q,i[Q+24>>2]=0,i[Q+12>>2]=g,i[Q+8>>2]=A}A=E+8|0;break A}I:if(t){B=i[g+28>>2];g:{if(i[(A=36164+(B<<2)|0)>>2]==(0|g)){if(i[A>>2]=E,E)break g;c=35864,y=lI(-2,B)&o,i[c>>2]=y;break I}if(i[t+(i[t+16>>2]==(0|g)?16:20)>>2]=E,!E)break I}i[E+24>>2]=t,(A=i[g+16>>2])&&(i[E+16>>2]=A,i[A+24>>2]=E),(A=i[g+20>>2])&&(i[E+20>>2]=A,i[A+24>>2]=E)}C>>>0<=15?(A=C+r|0,i[g+4>>2]=3|A,i[4+(A=A+g|0)>>2]=1|i[A+4>>2]):(i[g+4>>2]=3|r,i[4+(E=g+r|0)>>2]=1|C,i[C+E>>2]=C,f&&(B=35900+((A=f>>>3|0)<<3)|0,e=i[8970],(A=1<<A)&Q?A=i[B+8>>2]:(i[8965]=A|Q,A=B),i[B+8>>2]=e,i[A+12>>2]=e,i[e+12>>2]=B,i[e+8>>2]=A),i[8970]=E,i[8967]=C),A=g+8|0}return s=I+16|0,0|A}function H(A,I,g){var B,C,Q,E,n,a,o,t,e,f,c,y,s,w,D,p,u,F,l,_,k,H,G,U,S,b,m,v,M,P,Y,N,R,d,J,x,L,K,X,T,V,q,z,j,W,O,Z,$,AA,IA,gA,BA,CA=0,QA=0,EA=0,iA=0,nA=0,aA=0,rA=0,oA=0,tA=0,eA=0,fA=0,cA=0,yA=0,sA=0,wA=0,DA=0,hA=0,pA=0,uA=0,FA=0,lA=0,_A=0,kA=0,HA=0,GA=0,UA=0;B=CA=GA=i[g+4>>2],e=CA>>31,d=CA=(FA=i[I+20>>2])<<1,CA=qA(B,e,CA,k=CA>>31),EA=h,QA=CA,C=CA=i[g>>2],Q=CA>>31,f=CA=i[I+24>>2],cA=qA(C,Q,CA,E=CA>>31),CA=h+EA|0,CA=(QA=QA+cA|0)>>>0<cA>>>0?CA+1|0:CA,EA=QA,J=QA=iA=i[g+8>>2],p=QA>>31,c=QA=i[I+16>>2],QA=EA+(cA=qA(iA,p,QA,n=QA>>31))|0,EA=h+CA|0,EA=QA>>>0<cA>>>0?EA+1|0:EA,x=CA=nA=i[g+12>>2],u=CA>>31,L=CA=(cA=i[I+12>>2])<<1,CA=(yA=qA(nA,u,CA,H=CA>>31))+QA|0,QA=h+EA|0,QA=CA>>>0<yA>>>0?QA+1|0:QA,EA=CA,W=CA=DA=i[g+16>>2],l=CA>>31,y=CA=i[I+8>>2],yA=qA(DA,l,CA,a=CA>>31),CA=h+QA|0,CA=(EA=EA+yA|0)>>>0<yA>>>0?CA+1|0:CA,lA=EA,O=QA=oA=i[g+20>>2],G=QA>>31,K=QA=(yA=i[I+4>>2])<<1,EA=qA(oA,G,QA,U=QA>>31),CA=h+CA|0,CA=(QA=lA+EA|0)>>>0<EA>>>0?CA+1|0:CA,EA=QA,Z=QA=tA=i[g+24>>2],X=QA>>31,s=QA=i[I>>2],uA=qA(tA,X,QA,o=QA>>31),QA=h+CA|0,QA=(EA=EA+uA|0)>>>0<uA>>>0?QA+1|0:QA,S=i[g+28>>2],sA=CA=r(S,19),F=CA>>31,T=CA=(uA=i[I+36>>2])<<1,CA=(wA=qA(sA,F,CA,b=CA>>31))+EA|0,EA=h+QA|0,EA=CA>>>0<wA>>>0?EA+1|0:EA,QA=CA,V=i[g+32>>2],eA=CA=r(V,19),aA=CA>>31,w=CA=i[I+32>>2],wA=qA(eA,aA,CA,t=CA>>31),CA=h+EA|0,CA=(QA=QA+wA|0)>>>0<wA>>>0?CA+1|0:CA,$=i[g+36>>2],fA=g=r($,19),D=g>>31,q=I=(wA=i[I+28>>2])<<1,g=qA(g,D,I,m=I>>31),CA=h+CA|0,HA=I=g+QA|0,I=I>>>0<g>>>0?CA+1|0:CA,g=qA(c,n,B,e),CA=h,QA=qA(C,Q,FA,v=FA>>31),EA=h+CA|0,EA=(g=QA+g|0)>>>0<QA>>>0?EA+1|0:EA,CA=qA(iA,p,cA,M=cA>>31),QA=h+EA|0,QA=(g=CA+g|0)>>>0<CA>>>0?QA+1|0:QA,EA=qA(y,a,nA,u),CA=h+QA|0,CA=(g=EA+g|0)>>>0<EA>>>0?CA+1|0:CA,QA=qA(DA,l,yA,P=yA>>31),CA=h+CA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,QA=qA(s,o,oA,G),CA=h+CA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,EA=g,_A=g=r(tA,19),g=EA+(QA=qA(g,_=g>>31,uA,Y=uA>>31))|0,EA=h+CA|0,EA=g>>>0<QA>>>0?EA+1|0:EA,CA=qA(w,t,sA,F),QA=h+EA|0,QA=(g=CA+g|0)>>>0<CA>>>0?QA+1|0:QA,EA=qA(eA,aA,wA,N=wA>>31),CA=h+QA|0,CA=(g=EA+g|0)>>>0<EA>>>0?CA+1|0:CA,QA=qA(fA,D,f,E),CA=h+CA|0,lA=g=QA+g|0,g=g>>>0<QA>>>0?CA+1|0:CA,CA=qA(B,e,L,H),EA=h,QA=(tA=qA(C,Q,c,n))+CA|0,CA=h+EA|0,CA=QA>>>0<tA>>>0?CA+1|0:CA,tA=qA(y,a,iA,p),EA=h+CA|0,EA=(QA=tA+QA|0)>>>0<tA>>>0?EA+1|0:EA,CA=(tA=qA(nA,u,K,U))+QA|0,QA=h+EA|0,QA=CA>>>0<tA>>>0?QA+1|0:QA,EA=(tA=qA(s,o,DA,l))+CA|0,CA=h+QA|0,CA=EA>>>0<tA>>>0?CA+1|0:CA,hA=EA,z=QA=r(oA,19),EA=qA(QA,R=QA>>31,T,b),CA=h+CA|0,CA=(QA=hA+EA|0)>>>0<EA>>>0?CA+1|0:CA,EA=qA(w,t,_A,_),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,oA=qA(sA,F,q,m),EA=h+CA|0,EA=(QA=oA+QA|0)>>>0<oA>>>0?EA+1|0:EA,CA=(oA=qA(eA,aA,f,E))+QA|0,QA=h+EA|0,QA=CA>>>0<oA>>>0?QA+1|0:QA,EA=(oA=qA(fA,D,d,k))+CA|0,CA=h+QA|0,CA=EA>>>0<oA>>>0?CA+1|0:CA,oA=EA,IA=CA,tA=QA=EA+33554432|0,gA=CA=QA>>>0<33554432?CA+1|0:CA,EA=lA,lA=(67108863&CA)<<6|QA>>>26,CA=(CA>>26)+g|0,CA=(EA=EA+lA|0)>>>0<lA>>>0?CA+1|0:CA,BA=g=(lA=EA)+16777216|0,CA=I+(QA=(EA=g>>>0<16777216?CA+1|0:CA)>>25)|0,CA=(g=(EA=(33554431&EA)<<7|g>>>25)+HA|0)>>>0<EA>>>0?CA+1|0:CA,kA=I=g+33554432|0,I=CA=I>>>0<33554432?CA+1|0:CA,CA=-67108864&kA,i[A+24>>2]=g-CA,g=qA(B,e,K,U),CA=h,QA=qA(C,Q,y,a),EA=h+CA|0,EA=(g=QA+g|0)>>>0<QA>>>0?EA+1|0:EA,QA=qA(s,o,iA,p),CA=h+EA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,EA=g,nA=g=r(nA,19),QA=qA(g,HA=g>>31,T,b),CA=h+CA|0,CA=(g=EA+QA|0)>>>0<QA>>>0?CA+1|0:CA,QA=g,AA=g=r(DA,19),g=QA+(EA=qA(w,t,g,j=g>>31))|0,QA=h+CA|0,QA=g>>>0<EA>>>0?QA+1|0:QA,EA=qA(q,m,z,R),CA=h+QA|0,CA=(g=EA+g|0)>>>0<EA>>>0?CA+1|0:CA,QA=qA(f,E,_A,_),EA=h+CA|0,EA=(g=QA+g|0)>>>0<QA>>>0?EA+1|0:EA,QA=qA(sA,F,d,k),CA=h+EA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,QA=qA(eA,aA,c,n),CA=h+CA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,EA=qA(fA,D,L,H),QA=h+CA|0,hA=g=EA+g|0,g=g>>>0<EA>>>0?QA+1|0:QA,CA=qA(s,o,B,e),EA=h,QA=(DA=qA(C,Q,yA,P))+CA|0,CA=h+EA|0,CA=QA>>>0<DA>>>0?CA+1|0:CA,EA=QA,DA=QA=r(iA,19),QA=EA+(iA=qA(QA,rA=QA>>31,uA,Y))|0,EA=h+CA|0,EA=QA>>>0<iA>>>0?EA+1|0:EA,iA=qA(w,t,nA,HA),CA=h+EA|0,CA=(QA=iA+QA|0)>>>0<iA>>>0?CA+1|0:CA,EA=qA(AA,j,wA,N),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,EA=(iA=qA(f,E,z,R))+QA|0,QA=h+CA|0,QA=EA>>>0<iA>>>0?QA+1|0:QA,iA=qA(_A,_,FA,v),CA=h+QA|0,CA=(EA=iA+EA|0)>>>0<iA>>>0?CA+1|0:CA,QA=(iA=qA(c,n,sA,F))+EA|0,EA=h+CA|0,EA=QA>>>0<iA>>>0?EA+1|0:EA,iA=qA(eA,aA,cA,M),CA=h+EA|0,CA=(QA=iA+QA|0)>>>0<iA>>>0?CA+1|0:CA,EA=qA(fA,D,y,a),CA=h+CA|0,UA=QA=EA+QA|0,iA=QA>>>0<EA>>>0?CA+1|0:CA,CA=qA(CA=r(B,19),CA>>31,T,b),QA=h,EA=qA(C,Q,s,o),QA=h+QA|0,QA=(CA=EA+CA|0)>>>0<EA>>>0?QA+1|0:QA,EA=(GA=qA(w,t,DA,rA))+CA|0,CA=h+QA|0,QA=(nA=qA(nA,HA,q,m))+EA|0,EA=h+(EA>>>0<GA>>>0?CA+1|0:CA)|0,EA=QA>>>0<nA>>>0?EA+1|0:EA,nA=qA(f,E,AA,j),CA=h+EA|0,CA=(QA=nA+QA|0)>>>0<nA>>>0?CA+1|0:CA,EA=qA(d,k,z,R),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,EA=(nA=qA(c,n,_A,_))+QA|0,QA=h+CA|0,QA=EA>>>0<nA>>>0?QA+1|0:QA,nA=qA(sA,F,L,H),CA=h+QA|0,CA=(EA=nA+EA|0)>>>0<nA>>>0?CA+1|0:CA,QA=(nA=qA(eA,aA,y,a))+EA|0,EA=h+CA|0,EA=QA>>>0<nA>>>0?EA+1|0:EA,nA=qA(fA,D,K,U),CA=h+EA|0,CA=(QA=nA+QA|0)>>>0<nA>>>0?CA+1|0:CA,nA=QA,GA=CA,HA=QA=QA+33554432|0,DA=CA=QA>>>0<33554432?CA+1|0:CA,rA=(67108863&CA)<<6|QA>>>26,QA=(EA=CA>>26)+iA|0,iA=CA=rA+UA|0,CA=CA>>>0<rA>>>0?QA+1|0:QA,UA=QA=iA+16777216|0,EA=hA,hA=(33554431&(CA=QA>>>0<16777216?CA+1|0:CA))<<7|QA>>>25,CA=(CA>>25)+g|0,CA=(QA=EA+hA|0)>>>0<hA>>>0?CA+1|0:CA,hA=g=QA+33554432|0,g=CA=g>>>0<33554432?CA+1|0:CA,CA=-67108864&hA,i[A+8>>2]=QA-CA,CA=qA(f,E,B,e),EA=h,QA=(rA=qA(C,Q,wA,N))+CA|0,CA=h+EA|0,CA=QA>>>0<rA>>>0?CA+1|0:CA,EA=qA(J,p,FA,v),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,EA=qA(c,n,x,u),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,rA=qA(W,l,cA,M),EA=h+CA|0,EA=(QA=rA+QA|0)>>>0<rA>>>0?EA+1|0:EA,CA=(rA=qA(y,a,O,G))+QA|0,QA=h+EA|0,QA=CA>>>0<rA>>>0?QA+1|0:QA,EA=(rA=qA(yA,P,Z,X))+CA|0,CA=h+QA|0,CA=EA>>>0<rA>>>0?CA+1|0:CA,QA=EA,EA=qA(s,o,S,rA=S>>31),CA=h+CA|0,CA=(QA=QA+EA|0)>>>0<EA>>>0?CA+1|0:CA,EA=qA(eA,aA,uA,Y),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,pA=qA(fA,D,w,t),EA=h+CA|0,CA=I>>26,I=(kA=(67108863&I)<<6|kA>>>26)+(QA=pA+QA|0)|0,QA=CA+(EA=QA>>>0<pA>>>0?EA+1|0:EA)|0,CA=QA=I>>>0<kA>>>0?QA+1|0:QA,kA=I=(EA=I)+16777216|0,I=CA=I>>>0<16777216?CA+1|0:CA,CA=-33554432&kA,i[A+28>>2]=EA-CA,CA=qA(y,a,B,e),QA=h,pA=qA(C,Q,cA,M),EA=h+QA|0,EA=(CA=pA+CA|0)>>>0<pA>>>0?EA+1|0:EA,pA=qA(J,p,yA,P),QA=h+EA|0,QA=(CA=pA+CA|0)>>>0<pA>>>0?QA+1|0:QA,EA=(pA=qA(s,o,x,u))+CA|0,CA=h+QA|0,CA=EA>>>0<pA>>>0?CA+1|0:CA,QA=EA,EA=qA(AA,j,uA,Y),CA=h+CA|0,CA=(QA=QA+EA|0)>>>0<EA>>>0?CA+1|0:CA,EA=qA(w,t,z,R),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,QA=(_A=qA(_A,_,wA,N))+QA|0,EA=h+CA|0,CA=(sA=qA(f,E,sA,F))+QA|0,QA=h+(QA>>>0<_A>>>0?EA+1|0:EA)|0,EA=(eA=qA(eA,aA,FA,v))+CA|0,CA=h+(CA>>>0<sA>>>0?QA+1|0:QA)|0,CA=EA>>>0<eA>>>0?CA+1|0:CA,QA=EA,EA=qA(fA,D,c,n),CA=h+CA|0,eA=QA=QA+EA|0,CA=(CA=QA>>>0<EA>>>0?CA+1|0:CA)+(QA=g>>26)|0,CA=(g=eA+(EA=(67108863&g)<<6|hA>>>26)|0)>>>0<EA>>>0?CA+1|0:CA,eA=g=(QA=g)+16777216|0,g=EA=g>>>0<16777216?CA+1|0:CA,CA=-33554432&eA,i[A+12>>2]=QA-CA,CA=qA(B,e,q,m),EA=h,QA=(aA=qA(C,Q,w,t))+CA|0,CA=h+EA|0,CA=QA>>>0<aA>>>0?CA+1|0:CA,EA=qA(f,E,J,p),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,aA=qA(x,u,d,k),EA=h+CA|0,EA=(QA=aA+QA|0)>>>0<aA>>>0?EA+1|0:EA,CA=(aA=qA(c,n,W,l))+QA|0,QA=h+EA|0,QA=CA>>>0<aA>>>0?QA+1|0:QA,EA=(aA=qA(L,H,O,G))+CA|0,CA=h+QA|0,CA=EA>>>0<aA>>>0?CA+1|0:CA,QA=EA,EA=qA(y,a,Z,X),CA=h+CA|0,CA=(QA=QA+EA|0)>>>0<EA>>>0?CA+1|0:CA,EA=qA(S,rA,K,U),CA=h+CA|0,CA=(QA=EA+QA|0)>>>0<EA>>>0?CA+1|0:CA,QA=(sA=qA(s,o,V,aA=V>>31))+QA|0,EA=h+CA|0,CA=(fA=qA(fA,D,T,b))+QA|0,QA=h+(QA>>>0<sA>>>0?EA+1|0:EA)|0,QA=CA>>>0<fA>>>0?QA+1|0:QA,hA=CA,CA=(CA=I>>25)+QA|0,CA=(I=hA+(EA=(33554431&I)<<7|kA>>>25)|0)>>>0<EA>>>0?CA+1|0:CA,fA=I=(QA=I)+33554432|0,I=CA=I>>>0<33554432?CA+1|0:CA,CA=-67108864&fA,i[A+32>>2]=QA-CA,EA=QA=oA-(CA=-67108864&tA)|0,CA=(CA=IA-((CA>>>0>oA>>>0)+gA|0)|0)+(QA=g>>25)|0,CA=(g=EA+(oA=(33554431&g)<<7|eA>>>25)|0)>>>0<oA>>>0?CA+1|0:CA,CA=(lA-(-33554432&BA)|0)+((67108863&(CA=(QA=g+33554432|0)>>>0<33554432?CA+1|0:CA))<<6|QA>>>26)|0,i[A+20>>2]=CA,CA=-67108864&QA,i[A+16>>2]=g-CA,g=qA(w,t,B,e),CA=h,QA=qA(C,Q,uA,Y),CA=h+CA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,EA=qA(J,p,wA,N),QA=h+CA|0,QA=(g=EA+g|0)>>>0<EA>>>0?QA+1|0:QA,CA=qA(f,E,x,u),EA=h+QA|0,EA=(g=CA+g|0)>>>0<CA>>>0?EA+1|0:EA,QA=qA(W,l,FA,v),CA=h+EA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,QA=qA(c,n,O,G),CA=h+CA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,QA=qA(cA,M,Z,X),CA=h+CA|0,CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA,EA=qA(y,a,S,rA),QA=h+CA|0,QA=(g=EA+g|0)>>>0<EA>>>0?QA+1|0:QA,CA=qA(V,aA,yA,P),EA=h+QA|0,EA=(g=CA+g|0)>>>0<CA>>>0?EA+1|0:EA,QA=qA(s,o,$,$>>31),CA=h+EA|0,CA=(CA=(g=QA+g|0)>>>0<QA>>>0?CA+1|0:CA)+(QA=I>>26)|0,CA=(I=(EA=g)+(g=(67108863&I)<<6|fA>>>26)|0)>>>0<g>>>0?CA+1|0:CA,CA=(g=I+16777216|0)>>>0<16777216?CA+1|0:CA,QA=-33554432&g,i[A+36>>2]=I-QA,EA=iA-(-33554432&UA)|0,QA=nA-(I=-67108864&HA)|0,FA=GA-((I>>>0>nA>>>0)+DA|0)|0,I=(g=qA((33554431&(I=CA))<<7|g>>>25,CA>>=25,19,0))+QA|0,QA=h+FA|0,CA=QA=I>>>0<g>>>0?QA+1|0:QA,g=((67108863&(CA=(g=I+33554432|0)>>>0<33554432?CA+1|0:CA))<<6|(QA=g)>>>26)+EA|0,i[A+4>>2]=g,g=A,A=-67108864&QA,i[g>>2]=I-A}function G(A,I){var g,B,C,Q,E,n,a,o,t,e,f,c,y,w,D,p,u,F,l,_,k,H,G,S,b,m,v,M,P,Y,N,R,d,J,x,L,K,X,T,V,q,z=0,j=0,W=0,O=0,Z=0,$=0,AA=0,IA=0,gA=0,BA=0,CA=0,QA=0,EA=0,iA=0,nA=0,aA=0,rA=0,oA=0,tA=0,eA=0,fA=0;s=H=s-48|0,U(A,I),U(F=A+80|0,N=I+40|0),g=A+120|0,a=z=(rA=i[I+92>>2])<<1,o=z>>31,t=z=(CA=i[I+84>>2])<<1,z=qA(a,o,z,B=z>>31),Z=h,j=z,m=z=$=i[I+88>>2],W=qA(z,AA=z>>31,z,AA),z=h+Z|0,z=(j=j+W|0)>>>0<W>>>0?z+1|0:z,W=j,C=j=i[I+96>>2],e=j>>31,f=j=(EA=i[I+80>>2])<<1,Z=qA(C,e,j,Q=j>>31),z=h+z|0,z=(j=W+Z|0)>>>0<Z>>>0?z+1|0:z,O=j,Z=i[I+108>>2],G=j=r(Z,38),R=Z,W=qA(j,l=j>>31,Z,v=Z>>31),z=h+z|0,z=(j=O+W|0)>>>0<W>>>0?z+1|0:z,W=j,D=i[I+112>>2],oA=qA(c=j=r(D,19),y=j>>31,j=(gA=i[I+104>>2])<<1,j>>31),j=h+z|0,j=(W=W+oA|0)>>>0<oA>>>0?j+1|0:j,O=W,oA=i[I+116>>2],E=z=r(oA,38),n=z>>31,_=z=(W=i[I+100>>2])<<1,aA=qA(E,n,z,p=z>>31),j=h+j|0,j=(z=O+aA|0)>>>0<aA>>>0?j+1|0:j,aA=z,K=z=j<<1|z>>>31,d=j=33554432+(aA<<=1)|0,X=z=j>>>0<33554432?z+1|0:z,j=z>>26,z=(67108863&z)<<6|d>>>26,tA=j,j=qA(t,B,C,e),IA=h,O=z,k=z=$<<1,rA=qA(z,u=z>>31,$=rA,M=$>>31),z=h+IA|0,z=(j=rA+j|0)>>>0<rA>>>0?z+1|0:z,rA=W,IA=(BA=qA(W,S=W>>31,f,Q))+j|0,j=h+z|0,j=IA>>>0<BA>>>0?j+1|0:j,QA=IA,J=z=Z<<1,IA=qA(c,y,z,P=z>>31),z=h+j|0,z=(Z=QA+IA|0)>>>0<IA>>>0?z+1|0:z,j=Z,Z=qA(E,n,gA,w=gA>>31),z=h+z|0,z=(j=j+Z|0)>>>0<Z>>>0?z+1|0:z,Z=j,j=(j=z<<1|j>>>31)+tA|0,tA=z=O+(Z<<=1)|0,z=z>>>0<Z>>>0?j+1|0:j,T=j=tA+16777216|0,Z=j,j=(z=j>>>0<16777216?z+1|0:z)>>25,z=(33554431&z)<<7|Z>>>25,Z=j,j=qA(a,o,$,M),IA=h,O=z,BA=qA(C,e,k,u),z=h+IA|0,z=(j=BA+j|0)>>>0<BA>>>0?z+1|0:z,IA=qA(t,B,_,p),z=h+z|0,z=(j=IA+j|0)>>>0<IA>>>0?z+1|0:z,IA=(BA=qA(f,Q,gA,w))+j|0,j=h+z|0,j=IA>>>0<BA>>>0?j+1|0:j,BA=qA(c,y,D,b=D>>31),z=h+j|0,z=(IA=BA+IA|0)>>>0<BA>>>0?z+1|0:z,BA=qA(E,n,J,P),j=h+z|0,j=(IA=BA+IA|0)>>>0<BA>>>0?j+1|0:j,BA=(z=IA)<<1,z=(j<<1|z>>>31)+Z|0,z=(IA=O+BA|0)>>>0<BA>>>0?z+1|0:z,fA=Z=(j=IA)+33554432|0,Z=z=Z>>>0<33554432?z+1|0:z,z=-67108864&fA,i[g+24>>2]=j-z,z=qA(z=r(W,38),z>>31,W,S),j=h,O=z,W=qA(EA,z=EA>>31,EA,z),j=h+j|0,j=(z=O+W|0)>>>0<W>>>0?j+1|0:j,W=z,QA=z=r(gA,19),nA=z>>31,x=z=C<<1,EA=qA(QA,nA,z,Y=z>>31),z=h+j|0,z=(W=W+EA|0)>>>0<EA>>>0?z+1|0:z,j=W,W=qA(a,o,G,l),z=h+z|0,z=(j=j+W|0)>>>0<W>>>0?z+1|0:z,W=(EA=qA(c,y,k,u))+j|0,j=h+z|0,j=W>>>0<EA>>>0?j+1|0:j,EA=qA(t,B,E,n),z=h+j|0,z=(W=EA+W|0)>>>0<EA>>>0?z+1|0:z,EA=(j=W)<<1,q=z=z<<1|j>>>31,j=z,IA=z=EA+33554432|0,BA=j=z>>>0<33554432?j+1|0:j,z=j>>26,j=(67108863&j)<<6|IA>>>26,W=z,z=qA(QA,nA,_,p),iA=h,eA=j,j=(CA=qA(f,Q,O=CA,L=O>>31))+z|0,z=h+iA|0,z=j>>>0<CA>>>0?z+1|0:z,CA=(iA=qA(C,e,G,l))+j|0,j=h+z|0,j=CA>>>0<iA>>>0?j+1|0:j,iA=qA(a,o,c,y),z=h+j|0,z=(CA=iA+CA|0)>>>0<iA>>>0?z+1|0:z,iA=qA(E,n,m,AA),j=h+z|0,j=(CA=iA+CA|0)>>>0<iA>>>0?j+1|0:j,iA=(z=CA)<<1,z=(j<<1|z>>>31)+W|0,z=(CA=eA+iA|0)>>>0<iA>>>0?z+1|0:z,iA=j=CA+16777216|0,W=j,j=(z=j>>>0<16777216?z+1|0:z)>>25,z=(33554431&z)<<7|W>>>25,W=j,j=qA(f,Q,m,AA),V=h,eA=z,O=qA(O,L,t,B),z=h+V|0,z=(j=O+j|0)>>>0<O>>>0?z+1|0:z,O=(QA=qA(QA,nA,gA,w))+j|0,j=h+z|0,j=O>>>0<QA>>>0?j+1|0:j,QA=qA(_,p,G,l),z=h+j|0,z=(O=QA+O|0)>>>0<QA>>>0?z+1|0:z,j=O,O=qA(c,y,x,Y),z=h+z|0,z=(j=j+O|0)>>>0<O>>>0?z+1|0:z,O=(QA=qA(E,n,a,o))+j|0,j=h+z|0,z=(z=(j=O>>>0<QA>>>0?j+1|0:j)<<1|O>>>31)+W|0,z=(j=eA+(O<<=1)|0)>>>0<O>>>0?z+1|0:z,W=j,O=j,j=z,QA=z=W+33554432|0,W=j=z>>>0<33554432?j+1|0:j,z&=-67108864,i[g+8>>2]=O-z,z=qA(k,u,rA,S),j=h,O=qA(a,o,C,e),j=h+j|0,j=(z=O+z|0)>>>0<O>>>0?j+1|0:j,O=(nA=qA(t,B,gA,w))+z|0,z=h+j|0,z=O>>>0<nA>>>0?z+1|0:z,nA=qA(f,Q,R,v),j=h+z|0,j=(O=nA+O|0)>>>0<nA>>>0?j+1|0:j,nA=qA(E,n,D,b),z=h+j|0,eA=(j=O=nA+O|0)<<1,z=(z=(j>>>0<nA>>>0?z+1|0:z)<<1|j>>>31)+(j=Z>>26)|0,z=(Z=eA+(O=(67108863&Z)<<6|fA>>>26)|0)>>>0<O>>>0?z+1|0:z,O=Z,j=z,fA=z=Z+16777216|0,Z=j=z>>>0<16777216?j+1|0:j,z&=-33554432,i[g+28>>2]=O-z,z=qA(f,Q,$,M),$=h,j=(AA=qA(t,B,m,AA))+z|0,z=h+$|0,z=j>>>0<AA>>>0?z+1|0:z,AA=qA(gA,w,G,l),z=h+z|0,z=(j=AA+j|0)>>>0<AA>>>0?z+1|0:z,AA=($=qA(c,y,_,p))+j|0,j=h+z|0,j=$>>>0>AA>>>0?j+1|0:j,z=AA,AA=qA(E,n,C,e),j=h+j|0,j=(z=z+AA|0)>>>0<AA>>>0?j+1|0:j,AA=z,z=(z=j<<1|z>>>31)+(j=W>>26)|0,z=(W=(O=AA<<1)+(AA=(67108863&W)<<6|QA>>>26)|0)>>>0<AA>>>0?z+1|0:z,AA=W=(j=W)+16777216|0,W=z=W>>>0<16777216?z+1|0:z,z=-33554432&AA,i[g+12>>2]=j-z,z=qA(gA,w,k,u),$=h,j=(O=qA(C,e,C,e))+z|0,z=h+$|0,z=j>>>0<O>>>0?z+1|0:z,$=qA(a,o,_,p),z=h+z|0,z=(j=$+j|0)>>>0<$>>>0?z+1|0:z,$=qA(t,B,J,P),z=h+z|0,z=(j=$+j|0)>>>0<$>>>0?z+1|0:z,$=(O=qA(f,Q,D,b))+j|0,j=h+z|0,j=O>>>0>$>>>0?j+1|0:j,z=$,$=qA(E,n,oA,O=oA>>31),j=h+j|0,j=(z=z+$|0)>>>0<$>>>0?j+1|0:j,$=z,z=(z=j<<1|z>>>31)+(j=Z>>25)|0,z=(Z=(QA=$<<1)+($=(33554431&Z)<<7|fA>>>25)|0)>>>0<$>>>0?z+1|0:z,$=Z=(j=Z)+33554432|0,Z=z=Z>>>0<33554432?z+1|0:z,z=-67108864&$,i[g+32>>2]=j-z,j=aA-(z=-67108864&d)|0,aA=K-((z>>>0>aA>>>0)+X|0)|0,z=W>>25,W=(AA=(33554431&W)<<7|AA>>>25)+j|0,j=z+aA|0,z=j=W>>>0<AA>>>0?j+1|0:j,z=((67108863&(z=(j=W+33554432|0)>>>0<33554432?z+1|0:z))<<6|j>>>26)+(tA=tA-(-33554432&T)|0)|0,i[g+20>>2]=z,z=-67108864&j,i[g+16>>2]=W-z,z=qA(a,o,gA,w),j=h,W=qA(rA,S,x,Y),j=h+j|0,j=(z=W+z|0)>>>0<W>>>0?j+1|0:j,W=(gA=qA(k,u,R,v))+z|0,z=h+j|0,z=W>>>0<gA>>>0?z+1|0:z,gA=qA(t,B,D,b),j=h+z|0,j=(W=gA+W|0)>>>0<gA>>>0?j+1|0:j,gA=qA(f,Q,oA,O),z=h+j|0,O=(j=W=gA+W|0)<<1,z=(z=(j>>>0<gA>>>0?z+1|0:z)<<1|j>>>31)+(j=Z>>26)|0,j=z=(W=(67108863&Z)<<6|$>>>26)>>>0>(Z=O+W|0)>>>0?z+1|0:z,j=(z=Z+16777216|0)>>>0<16777216?j+1|0:j,W=-33554432&z,i[g+36>>2]=Z-W,gA=qA((33554431&j)<<7|z>>>25,j>>25,19,0),j=h+(q-(((W=-67108864&IA)>>>0>EA>>>0)+BA|0)|0)|0,j=(z=gA+(EA-W|0)|0)>>>0<gA>>>0?j+1|0:j,j=(CA-(-33554432&iA)|0)+((67108863&(j=(Z=z+33554432|0)>>>0<33554432?j+1|0:j))<<6|Z>>>26)|0,i[g+4>>2]=j,j=-67108864&Z,i[g>>2]=z-j,yA(z=A+40|0,I,N),U(H,z),yA(z,F,A),cA(F,F,A),cA(A,H,z),cA(g,g,F),s=H+48|0}function U(A,I){var g,B,C,Q,E,n,a,o,t,e,f,c,y,s,w,D,p,u,F,l,_,k,H,G,U,S,b,m,v,M,P,Y,N,R,d,J=0,x=0,L=0,K=0,X=0,T=0,V=0,q=0,z=0,j=0,W=0,O=0,Z=0,$=0,AA=0,IA=0,gA=0,BA=0,CA=0;e=x=(J=i[I+12>>2])<<1,z=J,J=qA(x,E=x>>31,J,U=J>>31),K=h,x=J,n=(J=g=i[I+16>>2])>>31,p=J=(V=i[I+8>>2])<<1,L=qA(g,n,J,y=J>>31),J=h+K|0,J=(x=x+L|0)>>>0<L>>>0?J+1|0:J,K=x,s=x=(L=i[I+20>>2])<<1,w=x>>31,a=x=(T=i[I+4>>2])<<1,W=qA(s,w,x,B=x>>31),x=h+J|0,x=(K=K+W|0)>>>0<W>>>0?x+1|0:x,l=J=X=i[I+24>>2],f=J>>31,o=J=(Z=i[I>>2])<<1,W=qA(X,f,J,C=J>>31),J=h+x|0,J=(K=W+K|0)>>>0<W>>>0?J+1|0:J,j=K,W=i[I+32>>2],D=x=r(W,19),K=qA(x,c=x>>31,W,_=W>>31),J=h+J|0,J=(x=j+K|0)>>>0<K>>>0?J+1|0:J,j=x,k=i[I+36>>2],t=x=r(k,38),Q=x>>31,M=I=(K=i[I+28>>2])<<1,gA=qA(x,Q,I,S=I>>31),I=h+J|0,j=x=j+gA|0,O=x>>>0<gA>>>0?I+1|0:I,I=qA(a,B,g,n),J=h,x=qA(p,y,z,U),J=h+J|0,J=(I=x+I|0)>>>0<x>>>0?J+1|0:J,gA=L,q=qA(L,H=L>>31,o,C),x=h+J|0,x=(I=q+I|0)>>>0<q>>>0?x+1|0:x,q=qA(D,c,M,S),J=h+x|0,J=(I=q+I|0)>>>0<q>>>0?J+1|0:J,x=qA(t,Q,X,f),J=h+J|0,$=I=x+I|0,BA=I>>>0<x>>>0?J+1|0:J,I=qA(a,B,e,E),x=h,J=(q=qA(V,u=V>>31,V,u))+I|0,I=h+x|0,I=J>>>0<q>>>0?I+1|0:I,x=(q=qA(o,C,g,n))+J|0,J=h+I|0,J=x>>>0<q>>>0?J+1|0:J,G=I=r(K,38),q=K,I=(K=qA(I,F=I>>31,K,b=K>>31))+x|0,x=h+J|0,x=I>>>0<K>>>0?x+1|0:x,I=(J=I)+(K=qA(D,c,I=X<<1,I>>31))|0,J=h+x|0,J=I>>>0<K>>>0?J+1|0:J,x=qA(t,Q,s,w),J=h+J|0,m=I=x+I|0,N=J=I>>>0<x>>>0?J+1|0:J,I=J,P=J=m+33554432|0,R=I=J>>>0<33554432?I+1|0:I,J=(J=I>>26)+BA|0,BA=I=(x=(67108863&I)<<6|P>>>26)+$|0,x=I>>>0<x>>>0?J+1|0:J,d=I=I+16777216|0,J=(J=(x=I>>>0<16777216?x+1|0:x)>>25)+O|0,J=(I=(x=(33554431&x)<<7|I>>>25)+j|0)>>>0<x>>>0?J+1|0:J,x=I,I=J,AA=J=x+33554432|0,K=I=J>>>0<33554432?I+1|0:I,I=-67108864&J,i[A+24>>2]=x-I,I=qA(o,C,V,u),J=h,j=qA(a,B,T,O=T>>31),x=h+J|0,x=(I=j+I|0)>>>0<j>>>0?x+1|0:x,J=I,j=I=r(X,19),I=J+(X=qA(I,$=I>>31,X,f))|0,J=h+x|0,J=I>>>0<X>>>0?J+1|0:J,x=(X=qA(s,w,G,F))+I|0,I=h+J|0,I=x>>>0<X>>>0?I+1|0:I,Y=J=g<<1,X=qA(D,c,J,v=J>>31),J=h+I|0,J=(x=X+x|0)>>>0<X>>>0?J+1|0:J,I=x,x=qA(t,Q,e,E),J=h+J|0,CA=I=I+x|0,X=I>>>0<x>>>0?J+1|0:J,I=qA(s,w,j,$),J=h,T=qA(o,C,T,O),x=h+J|0,x=(I=T+I|0)>>>0<T>>>0?x+1|0:x,T=qA(g,n,G,F),J=h+x|0,J=(I=T+I|0)>>>0<T>>>0?J+1|0:J,x=(T=qA(D,c,e,E))+I|0,I=h+J|0,I=x>>>0<T>>>0?I+1|0:I,T=qA(t,Q,V,u),J=h+I|0,IA=x=T+x|0,O=x>>>0<T>>>0?J+1|0:J,I=qA(I=r(L,38),I>>31,L,H),J=h,L=I,x=qA(Z,I=Z>>31,Z,I),J=h+J|0,J=(I=L+x|0)>>>0<x>>>0?J+1|0:J,L=qA(j,$,Y,v),x=h+J|0,x=(I=L+I|0)>>>0<L>>>0?x+1|0:x,L=qA(e,E,G,F),J=h+x|0,J=(I=L+I|0)>>>0<L>>>0?J+1|0:J,x=(L=qA(D,c,p,y))+I|0,I=h+J|0,I=x>>>0<L>>>0?I+1|0:I,L=qA(a,B,t,Q),J=h+I|0,T=x=L+x|0,j=J=x>>>0<L>>>0?J+1|0:J,Z=I=x+33554432|0,$=J=I>>>0<33554432?J+1|0:J,x=(I=J>>26)+O|0,O=J=(L=(67108863&J)<<6|Z>>>26)+IA|0,IA=CA,J=J>>>0<L>>>0?x+1|0:x,CA=I=O+16777216|0,L=(33554431&(J=I>>>0<16777216?J+1|0:J))<<7|I>>>25,J=(J>>25)+X|0,J=(x=IA+L|0)>>>0<L>>>0?J+1|0:J,X=x=(I=x)+33554432|0,L=J=x>>>0<33554432?J+1|0:J,J=-67108864&x,i[A+8>>2]=I-J,I=qA(p,y,gA,H),J=h,x=qA(g,n,e,E),J=h+J|0,J=(I=x+I|0)>>>0<x>>>0?J+1|0:J,x=qA(a,B,l,f),J=h+J|0,J=(I=x+I|0)>>>0<x>>>0?J+1|0:J,x=qA(o,C,q,b),J=h+J|0,J=(I=x+I|0)>>>0<x>>>0?J+1|0:J,x=(IA=qA(t,Q,W,_))+I|0,I=h+J|0,J=K>>26,K=(AA=(67108863&K)<<6|AA>>>26)+x|0,x=(I=x>>>0<IA>>>0?I+1|0:I)+J|0,J=(I=K)>>>0<AA>>>0?x+1|0:x,AA=x=I+16777216|0,K=J=x>>>0<16777216?J+1|0:J,J=-33554432&x,i[A+28>>2]=I-J,I=qA(o,C,z,U),x=h,J=(V=qA(a,B,V,u))+I|0,I=h+x|0,I=J>>>0<V>>>0?I+1|0:I,V=qA(l,f,G,F),x=h+I|0,x=(J=V+J|0)>>>0<V>>>0?x+1|0:x,I=(V=qA(D,c,s,w))+J|0,J=h+x|0,J=I>>>0<V>>>0?J+1|0:J,x=qA(t,Q,g,n),J=h+J|0,J=(J=(I=x+I|0)>>>0<x>>>0?J+1|0:J)+(x=L>>26)|0,x=I=(L=(67108863&L)<<6|X>>>26)+I|0,I=I>>>0<L>>>0?J+1|0:J,V=J=x+16777216|0,L=I=J>>>0<16777216?I+1|0:I,I=-33554432&J,i[A+12>>2]=x-I,I=qA(l,f,p,y),J=h,x=qA(g,n,g,n),J=h+J|0,J=(I=x+I|0)>>>0<x>>>0?J+1|0:J,x=qA(e,E,s,w),J=h+J|0,J=(I=x+I|0)>>>0<x>>>0?J+1|0:J,x=(z=qA(a,B,M,S))+I|0,I=h+J|0,I=x>>>0<z>>>0?I+1|0:I,J=(z=qA(o,C,W,_))+x|0,x=h+I|0,x=J>>>0<z>>>0?x+1|0:x,I=(z=qA(t,Q,k,X=k>>31))+J|0,J=h+x|0,J=I>>>0<z>>>0?J+1|0:J,x=I,J=(I=K>>25)+J|0,J=(x=x+(K=(33554431&K)<<7|AA>>>25)|0)>>>0<K>>>0?J+1|0:J,z=x=(I=x)+33554432|0,K=J=x>>>0<33554432?J+1|0:J,J=-67108864&x,i[A+32>>2]=I-J,J=L>>25,x=(L=(33554431&L)<<7|V>>>25)+(m-(I=-67108864&P)|0)|0,I=J+(N-((I>>>0>m>>>0)+R|0)|0)|0,J=I=x>>>0<L>>>0?I+1|0:I,L=I=x+33554432|0,I=((67108863&(J=I>>>0<33554432?J+1|0:J))<<6|I>>>26)+(BA=BA-(-33554432&d)|0)|0,i[A+20>>2]=I,I=-67108864&L,i[A+16>>2]=x-I,I=qA(e,E,l,f),x=h,J=(L=qA(gA,H,Y,v))+I|0,I=h+x|0,I=J>>>0<L>>>0?I+1|0:I,x=(L=qA(p,y,q,b))+J|0,J=h+I|0,J=x>>>0<L>>>0?J+1|0:J,I=(L=qA(a,B,W,_))+x|0,x=h+J|0,x=I>>>0<L>>>0?x+1|0:x,L=qA(o,C,k,X),J=h+x|0,x=I=L+I|0,J=(I=I>>>0<L>>>0?J+1|0:J)+(J=K>>26)|0,I=J=(x=(K=(67108863&K)<<6|z>>>26)+x|0)>>>0<K>>>0?J+1|0:J,I=(J=x+16777216|0)>>>0<16777216?I+1|0:I,K=-33554432&J,i[A+36>>2]=x-K,L=qA((33554431&I)<<7|J>>>25,I>>25,19,0),J=h+(j-(((x=-67108864&Z)>>>0>T>>>0)+$|0)|0)|0,x=I=L+(T-x|0)|0,I=I>>>0<L>>>0?J+1|0:J,I=(O-(-33554432&CA)|0)+((67108863&(I=(J=x+33554432|0)>>>0<33554432?I+1|0:I))<<6|J>>>26)|0,i[A+4>>2]=I,I=A,A=-67108864&J,i[I>>2]=x-A}function S(A,I,g){var B,C=0,Q=0,E=0,n=0,a=0,r=0,o=0,t=0,e=0,f=0,c=0,y=0,w=0,D=0,p=0,u=0,F=0,l=0,_=0,k=0,H=0,G=0,U=0,S=0,b=0,m=0,v=0,M=0,P=0,Y=0,N=0,R=0,d=0,J=0,x=0,L=0,K=0,X=0;for(s=B=s-2048|0,yg(w=B+1024|0,I),AI(w,A),yg(B,w),AI(B,g),I=0,w=0;r=i[(f=(A=(B+1024|0)+(w<<7)|0)- -64|0)>>2],Q=i[A+100>>2],a=r,t=i[f+4>>2],o=i[A+96>>2],r=i[A+32>>2],E=i[A+36>>2],n=pA(o^(C=CI(i[A>>2],i[A+4>>2],r,E)),(n=Q)^(Q=h),32),E=pA(t=(a=CI(a,t,n,o=h))^r,E^(r=h),24),t=r,U=pA((p=CI(C,Q,E,r=h))^n,(D=h)^o,16),r=pA(E^(b=CI(a,t,U,S=h)),(R=h)^r,63),Q=h,E=i[A+108>>2],t=i[A+72>>2],y=i[A+76>>2],c=i[A+104>>2],C=i[A+40>>2],n=i[A+44>>2],a=pA(c^(o=CI(i[A+8>>2],i[A+12>>2],C,n)),(a=E)^(E=h),32),n=pA(t=(m=CI(t,y,a,e=h))^C,n^(C=h),24),t=m,J=pA((m=CI(o,y=E,n,E=h))^a,(d=h)^e,16),E=pA(n^(v=CI(t,C,J,x=h)),(M=h)^E,63),C=h,n=i[A+116>>2],c=i[A+80>>2],u=i[A+84>>2],y=i[A+112>>2],o=i[A+48>>2],a=i[A+52>>2],y=pA(y^(e=CI(i[A+16>>2],i[A+20>>2],o,a)),(t=n)^(n=h),32),a=pA(t=(c=CI(c,u,y,P=h))^o,a^(o=h),24),t=c,c=pA((c=y)^(y=CI(e,y=n,a,n=h)),(e=P)^(P=h),16),n=pA(a^(t=CI(t,o,c,Y=h)),(k=h)^n,63),o=h,a=i[A+124>>2],H=i[A+88>>2],N=i[A+92>>2],F=i[A+120>>2],e=i[A+56>>2],u=i[A+60>>2],F=pA(F^(l=CI(i[A+24>>2],i[A+28>>2],e,u)),(_=a)^(a=h),32),_=u=pA(_=(N=CI(H,N,F,G=h))^e,u^(e=h),24),F=pA((u=CI(l,H=a,u,a=h))^F,(l=h)^G,16),a=pA(_^(N=CI(N,e,F,G=h)),(L=h)^a,63),e=h,_=t,H=k,t=pA(F^(p=CI(p,D,E,C)),G^(D=h),32),E=pA((F=CI(_,H,t,k=h))^E,(G=h)^C,24),C=CI(C=p,D,E,p=h),i[A>>2]=C,D=h,i[A+4>>2]=D,C=pA(C^t,D^k,16),i[A+120>>2]=C,D=h,i[A+124>>2]=D,C=CI(F,G,C,D),i[A+80>>2]=C,D=h,i[A+84>>2]=D,K=A,X=pA(C^E,D^p,63),i[K+40>>2]=X,i[A+44>>2]=h,E=n,p=pA(U^(C=CI(m,d,n,o)),S^(n=h),32),E=pA(E^(U=CI(N,L,p,D=h)),(t=o)^(o=h),24),C=CI(C,t=n,E,n=h),i[A+8>>2]=C,S=h,i[A+12>>2]=S,C=pA(C^p,D^S,16),i[A+96>>2]=C,p=h,i[A+100>>2]=p,C=CI(U,o,C,p),i[A+88>>2]=C,o=h,i[A+92>>2]=o,K=A,X=pA(C^E,n^o,63),i[K+48>>2]=X,i[A+52>>2]=h,E=a,o=pA(J^(C=CI(y,P,a,e)),x^(n=h),32),E=pA(E^(p=CI(b,R,o,a=h)),(t=e)^(e=h),24),C=CI(C,t=n,E,n=h),i[A+16>>2]=C,D=h,i[A+20>>2]=D,C=pA(C^o,a^D,16),i[A+104>>2]=C,o=h,i[A+108>>2]=o,C=CI(p,e,C,o),i[f>>2]=C,a=f,f=h,i[a+4>>2]=f,K=A,X=pA(C^E,n^f,63),i[K+56>>2]=X,i[A+60>>2]=h,a=r,C=pA(c^(r=CI(u,l,r,Q)),Y^(E=h),32),f=pA(a^(o=CI(v,M,C,n=h)),(f=Q)^(Q=h),24),r=CI(r,a=E,f,E=h),i[A+24>>2]=r,a=h,i[A+28>>2]=a,r=pA(C^r,n^a,16),i[A+112>>2]=r,C=h,i[A+116>>2]=C,r=CI(o,Q,r,C),i[A+72>>2]=r,Q=h,i[A+76>>2]=Q,K=A,X=pA(r^f,E^Q,63),i[K+32>>2]=X,i[A+36>>2]=h,8!=(0|(w=w+1|0)););for(;f=i[(w=512+(A=(B+1024|0)+(I<<4)|0)|0)>>2],r=i[A+772>>2],n=f,a=i[w+4>>2],o=i[A+768>>2],w=i[A+256>>2],f=i[A+260>>2],E=pA(o^(Q=CI(i[A>>2],i[A+4>>2],w,f)),(E=r)^(r=h),32),f=pA(a=(n=CI(n,a,E,C=h))^w,f^(w=h),24),o=w,p=pA((a=CI(Q,r,f,w=h))^E,(e=h)^C,16),w=pA(f^(U=CI(n,o,p,D=h)),(S=h)^w,63),f=h,r=i[A+780>>2],t=i[A+520>>2],y=i[A+524>>2],o=i[A+776>>2],Q=i[A+264>>2],E=i[A+268>>2],n=pA(o^(C=CI(i[A+8>>2],i[A+12>>2],Q,E)),(n=r)^(r=h),32),E=pA(t=(b=CI(t,y,n,o=h))^Q,E^(Q=h),24),t=b,m=pA((b=CI(C,y=r,E,r=h))^n,(R=h)^o,16),r=pA(E^(J=CI(t,Q,m,d=h)),(x=h)^r,63),Q=h,E=i[A+900>>2],y=i[A+640>>2],c=i[A+644>>2],u=i[A+896>>2],C=i[A+384>>2],n=i[A+388>>2],v=pA(u^(o=CI(i[A+128>>2],i[A+132>>2],C,n)),(t=E)^(E=h),32),n=pA(t=(y=CI(y,c,v,M=h))^C,n^(C=h),24),t=y,y=pA((y=v)^(v=CI(o,c=E,n,E=h)),(o=M)^(M=h),16),E=pA(n^(c=CI(t,C,y,P=h)),(Y=h)^E,63),C=h,n=i[A+908>>2],_=i[A+648>>2],H=i[A+652>>2],l=i[A+904>>2],o=i[A+392>>2],t=i[A+396>>2],u=pA(l^(k=CI(i[A+136>>2],i[A+140>>2],o,t)),(u=n)^(n=h),32),_=t=pA(_=(F=CI(_,H,u,l=h))^o,t^(o=h),24),u=pA((t=CI(k,H=n,t,n=h))^u,(k=h)^l,16),n=pA(_^(F=CI(F,o,u,l=h)),(G=h)^n,63),o=h,_=c,H=Y,c=pA(u^(a=CI(a,e,r,Q)),l^(e=h),32),r=pA((u=CI(_,H,c,Y=h))^r,(l=h)^Q,24),Q=CI(Q=a,e,r,a=h),i[A>>2]=Q,e=h,i[A+4>>2]=e,Q=pA(Q^c,e^Y,16),i[A+904>>2]=Q,e=h,i[A+908>>2]=e,Q=CI(u,l,Q,e),i[A+640>>2]=Q,e=h,i[A+644>>2]=e,K=A,X=pA(Q^r,a^e,63),i[K+264>>2]=X,i[A+268>>2]=h,r=E,a=pA(p^(Q=CI(b,R,E,C)),D^(E=h),32),r=pA(r^(p=CI(F,G,a,e=h)),(c=C)^(C=h),24),Q=CI(Q,c=E,r,E=h),i[A+8>>2]=Q,D=h,i[A+12>>2]=D,Q=pA(Q^a,e^D,16),i[A+768>>2]=Q,a=h,i[A+772>>2]=a,Q=CI(p,C,Q,a),i[A+648>>2]=Q,C=h,i[A+652>>2]=C,K=A,X=pA(Q^r,C^E,63),i[K+384>>2]=X,i[A+388>>2]=h,r=n,C=pA(m^(Q=CI(v,M,n,o)),d^(E=h),32),r=pA(r^(a=CI(U,S,C,n=h)),(c=o)^(o=h),24),Q=CI(Q,c=E,r,E=h),i[A+128>>2]=Q,e=h,i[A+132>>2]=e,Q=pA(C^Q,n^e,16),i[A+776>>2]=Q,C=h,i[A+780>>2]=C,Q=CI(a,o,Q,C),i[A+512>>2]=Q,C=h,i[A+516>>2]=C,K=A,X=pA(Q^r,C^E,63),i[K+392>>2]=X,i[A+396>>2]=h,r=CI(t,k,w,f),n=CI(J,x,E=pA(y^r,P^(Q=h),32),C=h),f=CI(a=r,Q,w=pA(n^w,(o=h)^f,24),r=h),i[A+136>>2]=f,Q=h,i[A+140>>2]=Q,f=pA(E^f,C^Q,16),i[A+896>>2]=f,Q=h,i[A+900>>2]=Q,f=CI(n,o,f,Q),i[A+520>>2]=f,Q=h,i[A+524>>2]=Q,K=A,X=pA(f^w,Q^r,63),i[K+256>>2]=X,i[A+260>>2]=h,8!=(0|(I=I+1|0)););yg(g,B),AI(g,B+1024|0),s=B+2048|0}function b(A){var I=0,g=0,B=0,C=0,Q=0,E=0,n=0,r=0,o=0;A:if(A|=0){Q=(B=A-8|0)+(A=-8&(I=i[A-4>>2]))|0;I:if(!(1&I)){if(!(3&I))break A;if((B=B-(I=i[B>>2])|0)>>>0<a[8969])break A;if(A=A+I|0,i[8970]==(0|B)){if(3==(3&(I=i[Q+4>>2])))return i[8967]=A,i[Q+4>>2]=-2&I,i[B+4>>2]=1|A,void(i[A+B>>2]=A)}else{if(I>>>0<=255){if(C=i[B+8>>2],I=I>>>3|0,(0|(g=i[B+12>>2]))==(0|C)){r=35860,o=i[8965]&lI(-2,I),i[r>>2]=o;break I}i[C+12>>2]=g,i[g+8>>2]=C;break I}if(n=i[B+24>>2],(0|B)==(0|(I=i[B+12>>2])))if((g=i[(C=B+20|0)>>2])||(g=i[(C=B+16|0)>>2])){for(;E=C,(g=i[(C=(I=g)+20|0)>>2])||(C=I+16|0,g=i[I+16>>2]););i[E>>2]=0}else I=0;else g=i[B+8>>2],i[g+12>>2]=I,i[I+8>>2]=g;if(!n)break I;C=i[B+28>>2];g:{if(i[(g=36164+(C<<2)|0)>>2]==(0|B)){if(i[g>>2]=I,I)break g;r=35864,o=i[8966]&lI(-2,C),i[r>>2]=o;break I}if(i[n+(i[n+16>>2]==(0|B)?16:20)>>2]=I,!I)break I}if(i[I+24>>2]=n,(g=i[B+16>>2])&&(i[I+16>>2]=g,i[g+24>>2]=I),!(g=i[B+20>>2]))break I;i[I+20>>2]=g,i[g+24>>2]=I}}if(!(B>>>0>=Q>>>0)&&1&(I=i[Q+4>>2])){I:{if(!(2&I)){if(i[8971]==(0|Q)){if(i[8971]=B,A=i[8968]+A|0,i[8968]=A,i[B+4>>2]=1|A,i[8970]!=(0|B))break A;return i[8967]=0,void(i[8970]=0)}if(i[8970]==(0|Q))return i[8970]=B,A=i[8967]+A|0,i[8967]=A,i[B+4>>2]=1|A,void(i[A+B>>2]=A);A=(-8&I)+A|0;g:if(I>>>0<=255){if(C=i[Q+8>>2],I=I>>>3|0,(0|(g=i[Q+12>>2]))==(0|C)){r=35860,o=i[8965]&lI(-2,I),i[r>>2]=o;break g}i[C+12>>2]=g,i[g+8>>2]=C}else{if(n=i[Q+24>>2],(0|Q)==(0|(I=i[Q+12>>2])))if((g=i[(C=Q+20|0)>>2])||(g=i[(C=Q+16|0)>>2])){for(;E=C,(g=i[(C=(I=g)+20|0)>>2])||(C=I+16|0,g=i[I+16>>2]););i[E>>2]=0}else I=0;else g=i[Q+8>>2],i[g+12>>2]=I,i[I+8>>2]=g;if(n){C=i[Q+28>>2];B:{if(i[(g=36164+(C<<2)|0)>>2]==(0|Q)){if(i[g>>2]=I,I)break B;r=35864,o=i[8966]&lI(-2,C),i[r>>2]=o;break g}if(i[n+(i[n+16>>2]==(0|Q)?16:20)>>2]=I,!I)break g}i[I+24>>2]=n,(g=i[Q+16>>2])&&(i[I+16>>2]=g,i[g+24>>2]=I),(g=i[Q+20>>2])&&(i[I+20>>2]=g,i[g+24>>2]=I)}}if(i[B+4>>2]=1|A,i[A+B>>2]=A,i[8970]!=(0|B))break I;return void(i[8967]=A)}i[Q+4>>2]=-2&I,i[B+4>>2]=1|A,i[A+B>>2]=A}if(A>>>0<=255)return I=35900+((A=A>>>3|0)<<3)|0,(g=i[8965])&(A=1<<A)?A=i[I+8>>2]:(i[8965]=A|g,A=I),i[I+8>>2]=B,i[A+12>>2]=B,i[B+12>>2]=I,void(i[B+8>>2]=A);C=31,i[B+16>>2]=0,i[B+20>>2]=0,A>>>0<=16777215&&(I=A>>>8|0,I<<=E=I+1048320>>>16&8,C=28+((I=((I<<=C=I+520192>>>16&4)<<(g=I+245760>>>16&2)>>>15|0)-(g|C|E)|0)<<1|A>>>I+21&1)|0),i[B+28>>2]=C,E=36164+(C<<2)|0;I:{g:{if((g=i[8966])&(I=1<<C)){for(C=A<<(31==(0|C)?0:25-(C>>>1|0)|0),I=i[E>>2];;){if(g=I,(-8&i[I+4>>2])==(0|A))break g;if(I=C>>>29|0,C<<=1,!(I=i[16+(E=g+(4&I)|0)>>2]))break}i[E+16>>2]=B,i[B+24>>2]=g}else i[8966]=I|g,i[E>>2]=B,i[B+24>>2]=E;i[B+12>>2]=B,i[B+8>>2]=B;break I}A=i[g+8>>2],i[A+12>>2]=B,i[g+8>>2]=B,i[B+24>>2]=0,i[B+12>>2]=g,i[B+8>>2]=A}A=i[8973]-1|0,i[8973]=A||-1}}}function m(A,I,g,B,C){var E,a,r,o,t,e,f,c,y,w,D,h,p,u,F,l=0,_=0,k=0,H=0,G=0,U=0,S=0,b=0,m=0,v=0,M=0,P=0,Y=0,N=0,R=0,d=0,J=0,x=0,L=0,K=0,X=0,T=0,V=0,q=0,z=0,j=0,W=0,O=0,Z=0,$=0,AA=0,IA=0,gA=0,BA=0;for(s=E=s+-64|0,a=i[A+60>>2],r=i[A+56>>2],L=i[A+52>>2],J=i[A+48>>2],o=i[A+44>>2],t=i[A+40>>2],e=i[A+36>>2],f=i[A+32>>2],c=i[A+28>>2],y=i[A+24>>2],w=i[A+20>>2],D=i[A+16>>2],h=i[A+12>>2],p=i[A+8>>2],u=i[A+4>>2],F=i[A>>2];;){if(!C&B>>>0>63|C)_=g;else{if(H=0,_=wI(E,0,64),B|C)for(;Q[_+H|0]=n[I+H|0],!C&(H=H+1|0)>>>0<B>>>0|C;);I=_,T=g}for(K=20,b=F,m=u,v=p,M=h,H=D,G=w,g=y,P=c,U=f,S=e,Y=t,N=a,d=r,l=L,k=J,x=o;R=H,b=cg((H=H+b|0)^k,16),k=cg(R^(U=b+U|0),12),R=U,U=cg((U=b)^(b=H+k|0),8),H=cg(k^(R=R+U|0),7),k=G,m=cg((G=G+m|0)^l,16),l=cg(k^(S=m+S|0),12),k=S,S=cg((S=m)^(m=G+l|0),8),G=cg(l^(X=k+S|0),7),l=g,v=cg((g=g+v|0)^d,16),l=d=cg(l^(Y=v+Y|0),12),d=cg((k=v)^(v=g+d|0),8),g=cg(l^(Y=d+Y|0),7),l=P,M=cg((P=P+M|0)^N,16),k=l=cg(l^(N=M+x|0),12),x=N,N=cg((N=M)^(M=P+l|0),8),P=cg(k^(l=x+N|0),7),k=Y,Y=cg((b=G+b|0)^N,16),G=cg((k=k+Y|0)^G,12),N=cg(Y^(b=G+b|0),8),G=cg(G^(Y=k+N|0),7),U=cg((m=g+m|0)^U,16),g=cg((l=U+l|0)^g,12),k=cg(U^(m=g+m|0),8),g=cg(g^(x=l+k|0),7),U=cg((v=P+v|0)^S,16),P=cg((S=U+R|0)^P,12),l=cg(U^(v=P+v|0),8),P=cg(P^(U=S+l|0),7),S=cg((M=H+M|0)^d,16),H=cg((R=S+X|0)^H,12),d=cg(S^(M=H+M|0),8),H=cg(H^(S=R+d|0),7),K=K-2|0;);if(K=n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24,R=n[I+8|0]|n[I+9|0]<<8|n[I+10|0]<<16|n[I+11|0]<<24,X=n[I+12|0]|n[I+13|0]<<8|n[I+14|0]<<16|n[I+15|0]<<24,V=n[I+16|0]|n[I+17|0]<<8|n[I+18|0]<<16|n[I+19|0]<<24,q=n[I+20|0]|n[I+21|0]<<8|n[I+22|0]<<16|n[I+23|0]<<24,z=n[I+24|0]|n[I+25|0]<<8|n[I+26|0]<<16|n[I+27|0]<<24,j=n[I+28|0]|n[I+29|0]<<8|n[I+30|0]<<16|n[I+31|0]<<24,W=n[I+32|0]|n[I+33|0]<<8|n[I+34|0]<<16|n[I+35|0]<<24,O=n[I+36|0]|n[I+37|0]<<8|n[I+38|0]<<16|n[I+39|0]<<24,Z=n[I+40|0]|n[I+41|0]<<8|n[I+42|0]<<16|n[I+43|0]<<24,$=n[I+44|0]|n[I+45|0]<<8|n[I+46|0]<<16|n[I+47|0]<<24,AA=n[I+48|0]|n[I+49|0]<<8|n[I+50|0]<<16|n[I+51|0]<<24,IA=n[I+52|0]|n[I+53|0]<<8|n[I+54|0]<<16|n[I+55|0]<<24,gA=n[I+56|0]|n[I+57|0]<<8|n[I+58|0]<<16|n[I+59|0]<<24,BA=n[I+60|0]|n[I+61|0]<<8|n[I+62|0]<<16|n[I+63|0]<<24,bI(_,b+F^(n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24)),bI(_+4|0,m+u^K),bI(_+8|0,v+p^R),bI(_+12|0,M+h^X),bI(_+16|0,H+D^V),bI(_+20|0,G+w^q),bI(_+24|0,g+y^z),bI(_+28|0,P+c^j),bI(_+32|0,U+f^W),bI(_+36|0,S+e^O),bI(_+40|0,Z^Y+t),bI(_+44|0,$^x+o),bI(_+48|0,AA^k+J),bI(_+52|0,IA^l+L),bI(_+56|0,gA^d+r),bI(_+60|0,BA^N+a),L=((J=(g=J)+1|0)>>>0<g>>>0)+L|0,!C&B>>>0<=64){if(!(!B|!C&B>>>0>63|0!=(0|C)))for(G=0;Q[G+T|0]=n[_+G|0],(0|B)!=(0|(G=G+1|0)););i[A+52>>2]=L,i[A+48>>2]=J,s=E- -64|0;break}I=I- -64|0,g=_- -64|0,C=C-1|0,C=(B=B+-64|0)>>>0<4294967232?C+1|0:C}}function v(A,I){var g,B=0,C=0,Q=0,E=0,n=0,a=0,r=0;g=A+I|0;A:{I:if(!(1&(B=i[A+4>>2]))){if(!(3&B))break A;I=(B=i[A>>2])+I|0;g:{if((0|(A=A-B|0))!=i[8970]){if(B>>>0<=255){if(Q=i[A+8>>2],B=B>>>3|0,(0|(C=i[A+12>>2]))!=(0|Q))break g;a=35860,r=i[8965]&lI(-2,B),i[a>>2]=r;break I}if(n=i[A+24>>2],(0|(B=i[A+12>>2]))==(0|A))if((C=i[(Q=A+20|0)>>2])||(C=i[(Q=A+16|0)>>2])){for(;E=Q,(C=i[(Q=(B=C)+20|0)>>2])||(Q=B+16|0,C=i[B+16>>2]););i[E>>2]=0}else B=0;else C=i[A+8>>2],i[C+12>>2]=B,i[B+8>>2]=C;if(!n)break I;Q=i[A+28>>2];B:{if(i[(C=36164+(Q<<2)|0)>>2]==(0|A)){if(i[C>>2]=B,B)break B;a=35864,r=i[8966]&lI(-2,Q),i[a>>2]=r;break I}if(i[n+(i[n+16>>2]==(0|A)?16:20)>>2]=B,!B)break I}if(i[B+24>>2]=n,(C=i[A+16>>2])&&(i[B+16>>2]=C,i[C+24>>2]=B),!(C=i[A+20>>2]))break I;i[B+20>>2]=C,i[C+24>>2]=B;break I}if(3!=(3&(B=i[g+4>>2])))break I;return i[8967]=I,i[g+4>>2]=-2&B,i[A+4>>2]=1|I,void(i[g>>2]=I)}i[Q+12>>2]=C,i[C+8>>2]=Q}I:{if(!(2&(B=i[g+4>>2]))){if(i[8971]==(0|g)){if(i[8971]=A,I=i[8968]+I|0,i[8968]=I,i[A+4>>2]=1|I,i[8970]!=(0|A))break A;return i[8967]=0,void(i[8970]=0)}if(i[8970]==(0|g))return i[8970]=A,I=i[8967]+I|0,i[8967]=I,i[A+4>>2]=1|I,void(i[A+I>>2]=I);I=(-8&B)+I|0;g:if(B>>>0<=255){if(Q=i[g+8>>2],B=B>>>3|0,(0|(C=i[g+12>>2]))==(0|Q)){a=35860,r=i[8965]&lI(-2,B),i[a>>2]=r;break g}i[Q+12>>2]=C,i[C+8>>2]=Q}else{if(n=i[g+24>>2],(0|g)==(0|(B=i[g+12>>2])))if((Q=i[(C=g+20|0)>>2])||(Q=i[(C=g+16|0)>>2])){for(;E=C,(Q=i[(C=(B=Q)+20|0)>>2])||(C=B+16|0,Q=i[B+16>>2]););i[E>>2]=0}else B=0;else C=i[g+8>>2],i[C+12>>2]=B,i[B+8>>2]=C;if(n){Q=i[g+28>>2];B:{if(i[(C=36164+(Q<<2)|0)>>2]==(0|g)){if(i[C>>2]=B,B)break B;a=35864,r=i[8966]&lI(-2,Q),i[a>>2]=r;break g}if(i[n+(i[n+16>>2]==(0|g)?16:20)>>2]=B,!B)break g}i[B+24>>2]=n,(C=i[g+16>>2])&&(i[B+16>>2]=C,i[C+24>>2]=B),(C=i[g+20>>2])&&(i[B+20>>2]=C,i[C+24>>2]=B)}}if(i[A+4>>2]=1|I,i[A+I>>2]=I,i[8970]!=(0|A))break I;return void(i[8967]=I)}i[g+4>>2]=-2&B,i[A+4>>2]=1|I,i[A+I>>2]=I}if(I>>>0<=255)return B=35900+((I=I>>>3|0)<<3)|0,(C=i[8965])&(I=1<<I)?I=i[B+8>>2]:(i[8965]=I|C,I=B),i[B+8>>2]=A,i[I+12>>2]=A,i[A+12>>2]=B,void(i[A+8>>2]=I);Q=31,i[A+16>>2]=0,i[A+20>>2]=0,I>>>0<=16777215&&(B=I>>>8|0,B<<=E=B+1048320>>>16&8,Q=28+((B=((B<<=Q=B+520192>>>16&4)<<(C=B+245760>>>16&2)>>>15|0)-(C|Q|E)|0)<<1|I>>>B+21&1)|0),i[A+28>>2]=Q,E=36164+(Q<<2)|0;I:{if((C=i[8966])&(B=1<<Q)){for(Q=I<<(31==(0|Q)?0:25-(Q>>>1|0)|0),B=i[E>>2];;){if(C=B,(-8&i[B+4>>2])==(0|I))break I;if(B=Q>>>29|0,Q<<=1,!(B=i[16+(E=C+(4&B)|0)>>2]))break}i[E+16>>2]=A,i[A+24>>2]=C}else i[8966]=B|C,i[E>>2]=A,i[A+24>>2]=E;return i[A+12>>2]=A,void(i[A+8>>2]=A)}I=i[C+8>>2],i[I+12>>2]=A,i[C+8>>2]=A,i[A+24>>2]=0,i[A+12>>2]=C,i[A+8>>2]=I}}function M(A,I,g,B){var C=0,Q=0,E=0,a=0,o=0,t=0,e=0,f=0,c=0,y=0,s=0,w=0,D=0,p=0,u=0,F=0,l=0,_=0,k=0,H=0,G=0,U=0,S=0,b=0,m=0;if(c=i[A+36>>2],a=i[A+32>>2],E=i[A+28>>2],Q=i[A+24>>2],o=i[A+20>>2],!B&g>>>0>=16|B)for(G=!n[A+80|0]<<24,s=i[A+4>>2],U=r(s,5),p=i[A+8>>2],H=r(p,5),_=i[A+12>>2],k=r(_,5),C=i[A+16>>2],u=r(C,5),S=C,w=i[A>>2];C=qA(t=((n[I+3|0]|n[I+4|0]<<8|n[I+5|0]<<16|n[I+6|0]<<24)>>>2&67108863)+Q|0,0,_,0),e=h,Q=(y=qA(o=(67108863&(n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24))+o|0,0,S,0))+C|0,C=h+e|0,C=Q>>>0<y>>>0?C+1|0:C,f=Q,Q=qA(e=((n[I+6|0]|n[I+7|0]<<8|n[I+8|0]<<16|n[I+9|0]<<24)>>>4&67108863)+E|0,0,p,0),C=h+C|0,C=Q>>>0>(E=f+Q|0)>>>0?C+1|0:C,Q=E,E=qA(y=((n[I+9|0]|n[I+10|0]<<8|n[I+11|0]<<16|n[I+12|0]<<24)>>>6|0)+a|0,0,s,0),C=h+C|0,C=E>>>0>(a=Q+E|0)>>>0?C+1|0:C,Q=a,a=qA(D=c+G+((n[I+12|0]|n[I+13|0]<<8|n[I+14|0]<<16|n[I+15|0]<<24)>>>8)|0,0,w,0),C=h+C|0,b=c=Q+a|0,c=a>>>0>c>>>0?C+1|0:C,C=qA(t,0,p,0),E=h,a=(Q=qA(o,0,_,0))+C|0,C=h+E|0,C=Q>>>0>a>>>0?C+1|0:C,E=qA(e,0,s,0),C=h+C|0,C=E>>>0>(a=E+a|0)>>>0?C+1|0:C,E=qA(y,0,w,0),C=h+C|0,C=E>>>0>(a=E+a|0)>>>0?C+1|0:C,E=qA(D,0,u,0),C=h+C|0,m=a=E+a|0,a=E>>>0>a>>>0?C+1|0:C,C=qA(t,0,s,0),Q=h,E=(F=qA(o,0,p,0))+C|0,C=h+Q|0,C=E>>>0<F>>>0?C+1|0:C,Q=qA(e,0,w,0),C=h+C|0,C=Q>>>0>(E=Q+E|0)>>>0?C+1|0:C,Q=qA(y,0,u,0),C=h+C|0,C=Q>>>0>(E=Q+E|0)>>>0?C+1|0:C,Q=qA(D,0,k,0),C=h+C|0,F=E=Q+E|0,E=Q>>>0>E>>>0?C+1|0:C,C=qA(t,0,w,0),f=h,Q=(l=qA(o,0,s,0))+C|0,C=h+f|0,C=Q>>>0<l>>>0?C+1|0:C,f=qA(e,0,u,0),C=h+C|0,C=(Q=f+Q|0)>>>0<f>>>0?C+1|0:C,f=qA(y,0,k,0),C=h+C|0,C=(Q=f+Q|0)>>>0<f>>>0?C+1|0:C,f=qA(D,0,H,0),C=h+C|0,C=(Q=f+Q|0)>>>0<f>>>0?C+1|0:C,f=Q,Q=C,C=qA(t,0,u,0),l=h,t=(o=qA(o,0,w,0))+C|0,C=h+l|0,C=t>>>0<o>>>0?C+1|0:C,o=qA(e,0,k,0),C=h+C|0,C=(t=o+t|0)>>>0<o>>>0?C+1|0:C,o=qA(y,0,H,0),C=h+C|0,C=(t=o+t|0)>>>0<o>>>0?C+1|0:C,o=qA(D,0,U,0),C=h+C|0,C=(t=o+t|0)>>>0<o>>>0?C+1|0:C,o=t,e=(67108863&C)<<6|t>>>26,C=Q,e=(67108863&(C=(t=e+f|0)>>>0<e>>>0?C+1|0:C))<<6|(Q=t)>>>26,C=E,C=(Q=e+F|0)>>>0<e>>>0?C+1|0:C,e=Q,Q=(67108863&C)<<6|Q>>>26,C=a,y=E=Q+m|0,E=(67108863&(C=Q>>>0>E>>>0?C+1|0:C))<<6|E>>>26,C=c,c=a=E+b|0,Q=(67108863&t)+((C=r((67108863&(E>>>0>a>>>0?C+1|0:C))<<6|a>>>26,5)+(67108863&o)|0)>>>26|0)|0,E=67108863&e,a=67108863&y,c&=67108863,o=67108863&C,I=I+16|0,!(B=B-(g>>>0<16)|0)&(g=g-16|0)>>>0>15|B;);i[A+20>>2]=o,i[A+36>>2]=c,i[A+32>>2]=a,i[A+28>>2]=E,i[A+24>>2]=Q}function P(A,I,g){var B,C,E,i,a=0,r=0,o=0,t=0,e=0;return s=E=s-160|0,_I(I,g,32,0),Q[0|I]=248&n[0|I],Q[I+31|0]=63&n[I+31|0]|64,BA(E,I),II(A,E),r=n[(C=g)+8|0]|n[C+9|0]<<8|n[C+10|0]<<16|n[C+11|0]<<24,a=n[C+12|0]|n[C+13|0]<<8|n[C+14|0]<<16|n[C+15|0]<<24,o=n[C+16|0]|n[C+17|0]<<8|n[C+18|0]<<16|n[C+19|0]<<24,t=n[C+20|0]|n[C+21|0]<<8|n[C+22|0]<<16|n[C+23|0]<<24,e=n[0|C]|n[C+1|0]<<8|n[C+2|0]<<16|n[C+3|0]<<24,g=n[C+4|0]|n[C+5|0]<<8|n[C+6|0]<<16|n[C+7|0]<<24,i=n[C+28|0]|n[C+29|0]<<8|n[C+30|0]<<16|n[C+31|0]<<24,B=I,I=n[C+24|0]|n[C+25|0]<<8|n[C+26|0]<<16|n[C+27|0]<<24,Q[B+24|0]=I,Q[B+25|0]=I>>>8,Q[B+26|0]=I>>>16,Q[B+27|0]=I>>>24,Q[B+28|0]=i,Q[B+29|0]=i>>>8,Q[B+30|0]=i>>>16,Q[B+31|0]=i>>>24,Q[B+16|0]=o,Q[B+17|0]=o>>>8,Q[B+18|0]=o>>>16,Q[B+19|0]=o>>>24,Q[B+20|0]=t,Q[B+21|0]=t>>>8,Q[B+22|0]=t>>>16,Q[B+23|0]=t>>>24,Q[B+8|0]=r,Q[B+9|0]=r>>>8,Q[B+10|0]=r>>>16,Q[B+11|0]=r>>>24,Q[B+12|0]=a,Q[B+13|0]=a>>>8,Q[B+14|0]=a>>>16,Q[B+15|0]=a>>>24,Q[0|B]=e,Q[B+1|0]=e>>>8,Q[B+2|0]=e>>>16,Q[B+3|0]=e>>>24,Q[B+4|0]=g,Q[B+5|0]=g>>>8,Q[B+6|0]=g>>>16,Q[B+7|0]=g>>>24,o=n[(a=A)+8|0]|n[a+9|0]<<8|n[a+10|0]<<16|n[a+11|0]<<24,t=n[a+12|0]|n[a+13|0]<<8|n[a+14|0]<<16|n[a+15|0]<<24,e=n[a+16|0]|n[a+17|0]<<8|n[a+18|0]<<16|n[a+19|0]<<24,g=n[a+20|0]|n[a+21|0]<<8|n[a+22|0]<<16|n[a+23|0]<<24,I=n[0|a]|n[a+1|0]<<8|n[a+2|0]<<16|n[a+3|0]<<24,A=n[a+4|0]|n[a+5|0]<<8|n[a+6|0]<<16|n[a+7|0]<<24,r=n[a+28|0]|n[a+29|0]<<8|n[a+30|0]<<16|n[a+31|0]<<24,a=n[a+24|0]|n[a+25|0]<<8|n[a+26|0]<<16|n[a+27|0]<<24,Q[B+56|0]=a,Q[B+57|0]=a>>>8,Q[B+58|0]=a>>>16,Q[B+59|0]=a>>>24,Q[B+60|0]=r,Q[B+61|0]=r>>>8,Q[B+62|0]=r>>>16,Q[B+63|0]=r>>>24,Q[B+48|0]=e,Q[B+49|0]=e>>>8,Q[B+50|0]=e>>>16,Q[B+51|0]=e>>>24,Q[B+52|0]=g,Q[B+53|0]=g>>>8,Q[B+54|0]=g>>>16,Q[B+55|0]=g>>>24,Q[B+40|0]=o,Q[B+41|0]=o>>>8,Q[B+42|0]=o>>>16,Q[B+43|0]=o>>>24,Q[B+44|0]=t,Q[B+45|0]=t>>>8,Q[B+46|0]=t>>>16,Q[B+47|0]=t>>>24,Q[B+32|0]=I,Q[B+33|0]=I>>>8,Q[B+34|0]=I>>>16,Q[B+35|0]=I>>>24,Q[B+36|0]=A,Q[B+37|0]=A>>>8,Q[B+38|0]=A>>>16,Q[B+39|0]=A>>>24,s=E+160|0,0}function Y(A,I,g){var B,C=0,E=0;s=B=s+-64|0;A:{if((g-65&255)>>>0>191){if(C=-1,!(n[A+80|0]|n[A+81|0]<<8|n[A+82|0]<<16|n[A+83|0]<<24|n[A+84|0]|n[A+85|0]<<8|n[A+86|0]<<16|n[A+87|0]<<24)){if((C=n[A+352|0]|n[A+353|0]<<8|n[A+354|0]<<16|n[A+355|0]<<24)>>>0>=129){if(CA(A,128),p(A,E=A+96|0),C=(n[A+352|0]|n[A+353|0]<<8|n[A+354|0]<<16|n[A+355|0]<<24)-128|0,Q[A+352|0]=C,Q[A+353|0]=C>>>8,Q[A+354|0]=C>>>16,Q[A+355|0]=C>>>24,C>>>0>=129)break A;eI(E,A+224|0,C),C=n[A+352|0]|n[A+353|0]<<8|n[A+354|0]<<16|n[A+355|0]<<24}CA(A,C),n[A+356|0]&&(Q[A+88|0]=255,Q[A+89|0]=255,Q[A+90|0]=255,Q[A+91|0]=255,Q[A+92|0]=255,Q[A+93|0]=255,Q[A+94|0]=255,Q[A+95|0]=255),Q[A+80|0]=255,Q[A+81|0]=255,Q[A+82|0]=255,Q[A+83|0]=255,Q[A+84|0]=255,Q[A+85|0]=255,Q[A+86|0]=255,Q[A+87|0]=255,wI((C=A+96|0)+(E=n[A+352|0]|n[A+353|0]<<8|n[A+354|0]<<16|n[A+355|0]<<24)|0,0,256-E|0),p(A,C),QI(B,n[0|A]|n[A+1|0]<<8|n[A+2|0]<<16|n[A+3|0]<<24,n[A+4|0]|n[A+5|0]<<8|n[A+6|0]<<16|n[A+7|0]<<24),QI(8|B,n[A+8|0]|n[A+9|0]<<8|n[A+10|0]<<16|n[A+11|0]<<24,n[A+12|0]|n[A+13|0]<<8|n[A+14|0]<<16|n[A+15|0]<<24),QI(B+16|0,n[A+16|0]|n[A+17|0]<<8|n[A+18|0]<<16|n[A+19|0]<<24,n[A+20|0]|n[A+21|0]<<8|n[A+22|0]<<16|n[A+23|0]<<24),QI(B+24|0,n[A+24|0]|n[A+25|0]<<8|n[A+26|0]<<16|n[A+27|0]<<24,n[A+28|0]|n[A+29|0]<<8|n[A+30|0]<<16|n[A+31|0]<<24),QI(B+32|0,n[A+32|0]|n[A+33|0]<<8|n[A+34|0]<<16|n[A+35|0]<<24,n[A+36|0]|n[A+37|0]<<8|n[A+38|0]<<16|n[A+39|0]<<24),QI(B+40|0,n[A+40|0]|n[A+41|0]<<8|n[A+42|0]<<16|n[A+43|0]<<24,n[A+44|0]|n[A+45|0]<<8|n[A+46|0]<<16|n[A+47|0]<<24),QI(B+48|0,n[A+48|0]|n[A+49|0]<<8|n[A+50|0]<<16|n[A+51|0]<<24,n[A+52|0]|n[A+53|0]<<8|n[A+54|0]<<16|n[A+55|0]<<24),QI(B+56|0,n[A+56|0]|n[A+57|0]<<8|n[A+58|0]<<16|n[A+59|0]<<24,n[A+60|0]|n[A+61|0]<<8|n[A+62|0]<<16|n[A+63|0]<<24),eI(I,B,g),Dg(A,64),Dg(C,256),C=0}return s=B- -64|0,C}xI(),t()}e(1299,1161,306,1086),t()}function N(A,I){var g,B,C,Q,E,a,r,o,t,e=0,f=0,c=0,y=0,s=0,w=0,D=0,p=0,u=0,F=0;g=n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24,u=uI(I+4|0),e=h,w=uI(I+7|0),y=h,p=uI(I+10|0),f=h,B=uI(I+13|0),s=h,c=n[I+16|0]|n[I+17|0]<<8|n[I+18|0]<<16|n[I+19|0]<<24,C=uI(I+20|0),Q=h,E=uI(I+23|0),a=h,r=uI(I+26|0),o=h,t=uI(I+29|0),I=f<<3|p>>>29,F=f=p<<3,p=f=f+16777216|0,f=I=f>>>0<16777216?I+1|0:I,D=w<<5,y=I=y<<5|w>>>27,e=I=e<<6|(w=u)>>>26,u=I=16777216+(w<<=6)|0,I=(I=(e=I>>>0<16777216?e+1|0:e)>>25)+y|0,I=(e=D+(D=(33554431&e)<<7|u>>>25)|0)>>>0<D>>>0?I+1|0:I,I=(F-(-33554432&p)|0)+((67108863&(I=(y=e+33554432|0)>>>0<33554432?I+1|0:I))<<6|y>>>26)|0,i[A+12>>2]=I,I=-67108864&y,i[A+8>>2]=e-I,I=0,y=c=(e=c)+16777216|0,c=I=c>>>0<16777216?1:I,F=e-(-33554432&y)|0,I=s<<2|(e=B)>>>30,s=e<<2,e=I,I=(I=f>>25)+e|0,e=I=(f=(D=s)+(s=(33554431&f)<<7|p>>>25)|0)>>>0<s>>>0?I+1|0:I,s=I=f+33554432|0,I=((67108863&(e=I>>>0<33554432?e+1|0:e))<<6|I>>>26)+F|0,i[A+20>>2]=I,I=-67108864&s,i[A+16>>2]=f-I,f=(e=C)<<7,I=(I=Q<<7|e>>>25)+(e=c>>25)|0,I=(f=f+(c=(33554431&c)<<7|y>>>25)|0)>>>0<c>>>0?I+1|0:I,f=e=f,c=e=e+33554432|0,e=I=e>>>0<33554432?I+1|0:I,I=-67108864&c,i[A+24>>2]=f-I,I=a<<5|(f=E)>>>27,s=f<<=5,y=f=f+16777216|0,f=I=f>>>0<16777216?I+1|0:I,I=(s-(-33554432&y)|0)+((67108863&e)<<6|c>>>26)|0,i[A+28>>2]=I,c=(e=r)<<4,e=I=o<<4|e>>>28,I=(I=f>>25)+e|0,I=(f=(s=c)+(c=(33554431&f)<<7|y>>>25)|0)>>>0<c>>>0?I+1|0:I,f=e=f,c=e=e+33554432|0,e=I=e>>>0<33554432?I+1|0:I,I=-67108864&c,i[A+32>>2]=f-I,I=0,y=f=(f=t)<<2&33554428,I=(f=f+16777216|0)>>>0<16777216?I+1|0:I,e=(y-(33554432&f)|0)+((67108863&e)<<6|c>>>26)|0,i[A+36>>2]=e,f=qA((33554431&I)<<7|f>>>25,I>>>25|0,19,0),I=h,I=(e=f+g|0)>>>0<f>>>0?I+1|0:I,I=(w-(-33554432&u)|0)+((67108863&(I=(f=e+33554432|0)>>>0<33554432?I+1|0:I))<<6|f>>>26)|0,i[A+4>>2]=I,I=A,A=-67108864&f,i[I>>2]=e-A}function R(A,I,g,B){var C,E=0;C=E=s,s=E=E-576&-64,i[E+188>>2]=0,bI(E+188|0,I);A:if(I>>>0<=64){if((0|OA(E+192|0,0,0,I))<0)break A;if((0|Cg(E+192|0,E+188|0,4,0))<0)break A;if((0|Cg(E+192|0,g,B,0))<0)break A;UI(E+192|0,A,I)}else if(!((0|OA(E+192|0,0,0,64))<0||(0|Cg(E+192|0,E+188|0,4,0))<0||(0|Cg(E+192|0,g,B,0))<0||(0|UI(E+192|0,E+112|0,64))<0)){if(g=i[E+116>>2],B=i[E+112>>2],Q[0|A]=B,Q[A+1|0]=B>>>8,Q[A+2|0]=B>>>16,Q[A+3|0]=B>>>24,Q[A+4|0]=g,Q[A+5|0]=g>>>8,Q[A+6|0]=g>>>16,Q[A+7|0]=g>>>24,g=i[E+124>>2],B=i[E+120>>2],Q[A+8|0]=B,Q[A+9|0]=B>>>8,Q[A+10|0]=B>>>16,Q[A+11|0]=B>>>24,Q[A+12|0]=g,Q[A+13|0]=g>>>8,Q[A+14|0]=g>>>16,Q[A+15|0]=g>>>24,g=i[E+140>>2],B=i[E+136>>2],Q[A+24|0]=B,Q[A+25|0]=B>>>8,Q[A+26|0]=B>>>16,Q[A+27|0]=B>>>24,Q[A+28|0]=g,Q[A+29|0]=g>>>8,Q[A+30|0]=g>>>16,Q[A+31|0]=g>>>24,g=i[E+132>>2],B=i[E+128>>2],Q[A+16|0]=B,Q[A+17|0]=B>>>8,Q[A+18|0]=B>>>16,Q[A+19|0]=B>>>24,Q[A+20|0]=g,Q[A+21|0]=g>>>8,Q[A+22|0]=g>>>16,Q[A+23|0]=g>>>24,A=A+32|0,(I=I-32|0)>>>0>=65)for(;;){if(eI(g=E+48|0,B=E+112|0,64),(0|vA(B,64,g,64,0,0,0))<0)break A;if(g=i[E+116>>2],B=i[E+112>>2],Q[0|A]=B,Q[A+1|0]=B>>>8,Q[A+2|0]=B>>>16,Q[A+3|0]=B>>>24,Q[A+4|0]=g,Q[A+5|0]=g>>>8,Q[A+6|0]=g>>>16,Q[A+7|0]=g>>>24,g=i[E+124>>2],B=i[E+120>>2],Q[A+8|0]=B,Q[A+9|0]=B>>>8,Q[A+10|0]=B>>>16,Q[A+11|0]=B>>>24,Q[A+12|0]=g,Q[A+13|0]=g>>>8,Q[A+14|0]=g>>>16,Q[A+15|0]=g>>>24,g=i[E+140>>2],B=i[E+136>>2],Q[A+24|0]=B,Q[A+25|0]=B>>>8,Q[A+26|0]=B>>>16,Q[A+27|0]=B>>>24,Q[A+28|0]=g,Q[A+29|0]=g>>>8,Q[A+30|0]=g>>>16,Q[A+31|0]=g>>>24,g=i[E+132>>2],B=i[E+128>>2],Q[A+16|0]=B,Q[A+17|0]=B>>>8,Q[A+18|0]=B>>>16,Q[A+19|0]=B>>>24,Q[A+20|0]=g,Q[A+21|0]=g>>>8,Q[A+22|0]=g>>>16,Q[A+23|0]=g>>>24,A=A+32|0,!((I=I-32|0)>>>0>64))break}eI(g=E+48|0,B=E+112|0,64),(0|vA(B,I,g,64,0,0,0))<0||eI(A,E+112|0,I)}Dg(E+192|0,384),s=C}function d(A,I,g){var B,C,Q,E,i,a,r,o,t,e,f,c,y=0,s=0,w=0,D=0,h=0,p=0,u=0,F=0,l=0,_=0,k=0,H=0,G=0,U=0,S=0,b=0,m=0,v=0,M=0,P=0,Y=0;for(B=n[g+4|0]|n[g+5|0]<<8|n[g+6|0]<<16|n[g+7|0]<<24,C=n[g+8|0]|n[g+9|0]<<8|n[g+10|0]<<16|n[g+11|0]<<24,Q=n[g+12|0]|n[g+13|0]<<8|n[g+14|0]<<16|n[g+15|0]<<24,E=n[g+16|0]|n[g+17|0]<<8|n[g+18|0]<<16|n[g+19|0]<<24,i=n[g+20|0]|n[g+21|0]<<8|n[g+22|0]<<16|n[g+23|0]<<24,a=n[g+24|0]|n[g+25|0]<<8|n[g+26|0]<<16|n[g+27|0]<<24,r=n[g+28|0]|n[g+29|0]<<8|n[g+30|0]<<16|n[g+31|0]<<24,k=1634760805,g=o=n[0|g]|n[g+1|0]<<8|n[g+2|0]<<16|n[g+3|0]<<24,w=B,S=C,D=Q,H=857760878,h=t=n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24,p=e=n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24,u=f=n[I+8|0]|n[I+9|0]<<8|n[I+10|0]<<16|n[I+11|0]<<24,_=c=n[I+12|0]|n[I+13|0]<<8|n[I+14|0]<<16|n[I+15|0]<<24,G=2036477234,I=E,F=1797285236,l=r,y=a,s=i;D=cg(s+k|0,7)^D,u=cg(D+k|0,9)^u,b=cg(u+D|0,13)^s,M=cg(u+b|0,18),s=cg(g+H|0,7)^_,U=cg(s+H|0,9)^y,g=cg(s+U|0,13)^g,_=cg(U+g|0,18),l=cg(h+G|0,7)^l,w=cg(l+G|0,9)^w,h=cg(l+w|0,13)^h,P=cg(w+h|0,18),y=cg(I+F|0,7)^S,p=cg(y+F|0,9)^p,m=cg(y+p|0,13)^I,Y=cg(p+m|0,18),g=cg((I=k^M)+y|0,7)^g,w=cg(g+I|0,9)^w,S=cg(g+w|0,13)^y,k=cg(w+S|0,18)^I,h=cg((I=H^_)+D|0,7)^h,p=cg(h+I|0,9)^p,D=cg(p+h|0,13)^D,H=cg(p+D|0,18)^I,I=cg((y=G^P)+s|0,7)^m,u=cg(I+y|0,9)^u,_=cg(I+u|0,13)^s,G=cg(u+_|0,18)^y,s=cg((F^=Y)+l|0,7)^b,y=cg(s+F|0,9)^U,l=cg(y+s|0,13)^l,F=cg(y+l|0,18)^F,U=v>>>0<18,v=v+2|0,U;);bI(A,k+1634760805|0),bI(A+4|0,g+o|0),bI(A+8|0,w+B|0),bI(A+12|0,S+C|0),bI(A+16|0,D+Q|0),bI(A+20|0,H+857760878|0),bI(A+24|0,h+t|0),bI(A+28|0,p+e|0),bI(A+32|0,u+f|0),bI(A+36|0,_+c|0),bI(A+40|0,G+2036477234|0),bI(A+44|0,I+E|0),bI(A+48|0,s+i|0),bI(A+52|0,y+a|0),bI(A+56|0,l+r|0),bI(A+60|0,F+1797285236|0)}function J(A,I,g,B,C,E){var i,a=0,o=0,t=0,e=0,f=0,c=0,y=0,w=0,D=0;for(s=i=s-592|0,e=-1,f=A+32|0,a=32,o=1;t=(c=n[f+(a=a-1|0)|0])-(y=n[a+2752|0])>>8&o|255&t,o&=65535+(c^y)>>>8,a;);if(t&&!sA(A)){for(a=127&(-1^n[C+31|0]),t=30;a=-1^n[C+t|0]|a,t=t-1|0;);if(((255&a)-1&236-n[0|C])<<23>>31!=-1&&!sA(C)&&!V(i+128|0,C)){WI(a=i+384|0,E),z(a,A,32,0),z(a,C,32,0),z(a,I,g,B),MA(a,I=i+320|0),l(I),s=B=s-2272|0,oA(B+2016|0,I),oA(B+1760|0,f),DI(g=B+480|0,C=i+128|0),fI(I=B+320|0,C),tI(B,I),xA(I,B,g),tI(g=B+160|0,I),DI(C=B+640|0,g),xA(I,B,C),tI(g,I),DI(C=B+800|0,g),xA(I,B,C),tI(g,I),DI(C=B+960|0,g),xA(I,B,C),tI(g,I),DI(C=B+1120|0,g),xA(I,B,C),tI(g,I),DI(C=B+1280|0,g),xA(I,B,C),tI(g,I),DI(C=B+1440|0,g),xA(I,B,C),tI(g,I),DI(B+1600|0,g),hg(E=i+8|0),ng(E+40|0),ng(E+80|0),C=255;A:{for(;;){if(!(n[(I=C)+(B+2016|0)|0]|n[(B+1760|0)+I|0])){if(C=I-1|0,I)continue;break A}break}if(!((0|I)<0))for(;G(B+320|0,E),g=I,(0|(I=Q[(B+2016|0)+I|0]))>0?(tI(C=B+160|0,a=B+320|0),xA(a,C,(B+480|0)+r((254&I)>>>1|0,160)|0)):(0|I)>=0||(tI(C=B+160|0,a=B+320|0),JA(a,C,(B+480|0)+r((0-I&254)>>>1|0,160)|0)),(0|(o=Q[g+(B+1760|0)|0]))>0?(tI(I=B+160|0,C=B+320|0),TA(C,I,r((254&o)>>>1|0,120)+1568|0)):(0|o)>=0||(tI(C=B+160|0,I=B+320|0),s=t=s-48|0,yA(I,e=C+40|0,C),cA(a=I+40|0,e,C),H(e=I+80|0,I,40+(f=r((0-o&254)>>>1|0,120)+1568|0)|0),H(a,a,f),H(o=I+120|0,f+80|0,C+120|0),yA(t,C=C+80|0,C),cA(I,e,a),yA(a,e,a),cA(e,t,o),yA(o,t,o),s=t+48|0),hI(E,B+320|0),I=g-1|0,(0|g)>0;);}s=B+2272|0,II(I=i+288|0,E),w=-1,D=eg(I,A),e=((0|A)==(0|I)?w:D)|zA(A,I,32)}}return s=i+592|0,e}function x(A,I,g){var B=0,C=0,Q=0,E=0,i=0,a=0,r=0,o=0,t=0,e=0,f=0,c=0,y=0,s=0,w=0,D=0,h=0,p=0,u=0;for(Q=2036477234,t=857760878,e=1634760805,E=1797285236,o=n[0|g]|n[g+1|0]<<8|n[g+2|0]<<16|n[g+3|0]<<24,B=n[g+4|0]|n[g+5|0]<<8|n[g+6|0]<<16|n[g+7|0]<<24,C=n[g+8|0]|n[g+9|0]<<8|n[g+10|0]<<16|n[g+11|0]<<24,a=n[g+12|0]|n[g+13|0]<<8|n[g+14|0]<<16|n[g+15|0]<<24,c=n[g+16|0]|n[g+17|0]<<8|n[g+18|0]<<16|n[g+19|0]<<24,y=n[g+20|0]|n[g+21|0]<<8|n[g+22|0]<<16|n[g+23|0]<<24,w=n[g+24|0]|n[g+25|0]<<8|n[g+26|0]<<16|n[g+27|0]<<24,D=n[g+28|0]|n[g+29|0]<<8|n[g+30|0]<<16|n[g+31|0]<<24,g=n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24,f=n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24,i=n[I+8|0]|n[I+9|0]<<8|n[I+10|0]<<16|n[I+11|0]<<24,I=n[I+12|0]|n[I+13|0]<<8|n[I+14|0]<<16|n[I+15|0]<<24;r=o,e=cg((s=g)^(g=o+e|0),16),r=c=cg(r^(o=e+c|0),12),c=cg((s=e)^(e=g+c|0),8),o=cg(r^(h=c+o|0),7),r=B,t=cg((g=B+t|0)^f,16),r=f=cg(r^(B=t+y|0),12),f=cg((s=t)^(t=g+f|0),8),g=cg(r^(y=f+B|0),7),r=C,B=cg((Q=Q+C|0)^i,16),r=i=cg(r^(C=B+w|0),12),s=cg(B^(i=Q+i|0),8),Q=cg(r^(B=s+C|0),7),E=cg((C=I)^(I=E+a|0),16),a=cg((C=E+D|0)^a,12),I=cg(E^(p=I+a|0),8),E=cg(a^(C=I+C|0),7),r=B,B=cg((B=I)^(I=g+e|0),16),g=cg((a=r+B|0)^g,12),I=cg(B^(e=I+g|0),8),B=cg(g^(w=a+I|0),7),r=C,C=cg((g=Q+t|0)^c,16),Q=cg((a=r+C|0)^Q,12),g=cg(C^(t=g+Q|0),8),C=cg(Q^(D=a+g|0),7),a=cg((Q=E+i|0)^f,16),E=cg((i=a+h|0)^E,12),f=cg(a^(Q=Q+E|0),8),a=cg(E^(c=i+f|0),7),i=cg((E=o+p|0)^s,16),o=cg((y=i+y|0)^o,12),i=cg(i^(E=E+o|0),8),o=cg(o^(y=y+i|0),7),10!=(0|(u=u+1|0)););bI(A,e),bI(A+4|0,t),bI(A+8|0,Q),bI(A+12|0,E),bI(A+16|0,g),bI(A+20|0,f),bI(A+24|0,i),bI(A+28|0,I)}function L(A,I,g,B,C,E,n,a){A|=0,I|=0,g|=0,B|=0,C|=0,E|=0,n|=0;var r,o=0,t=0,e=0,f=0,c=0,y=0,w=0,D=0,h=0;s=r=s-16|0,ag(a|=0);A:{I:if(B){D=4&a;g:for(;;){for(t=f;;){o=Q[g+t|0];B:{if(D?(e=o+4&(o+65488>>>8^-1)&(57-o>>>8^-1)&255|((e=o-65|0)>>>8^-1)&e&(90-o>>>8^-1)&255|o+185&(o+65439>>>8^-1)&(122-o>>>8^-1)&255|63&(1+(16288^o)>>>8^-1)|62&(1+(16338^o)>>>8^-1),e|=(0-e>>>8^-1)&1+(65470^o)>>>8&255):(e=o+4&(o+65488>>>8^-1)&(57-o>>>8^-1)&255|((e=o-65|0)>>>8^-1)&e&(90-o>>>8^-1)&255|o+185&(o+65439>>>8^-1)&(122-o>>>8^-1)&255|63&(1+(16336^o)>>>8^-1)|62&(1+(16340^o)>>>8^-1),e|=(0-e>>>8^-1)&1+(65470^o)>>>8&255),255==(0|e)){if(!C)break I;if(DA(C,o))break B;f=t;break I}if(w=e+(w<<6)|0,(f=c+6|0)>>>0<8)c=f;else{if(c=c-2|0,I>>>0<=y>>>0){i[r+12>>2]=t,i[8952]=68,h=1;break A}Q[A+y|0]=w>>>c,y=y+1|0}if((f=t+1|0)>>>0<B>>>0)continue g;break I}if(!((t=t+1|0)>>>0<B>>>0))break}break}f=(A=f+1|0)>>>0<B>>>0?B:A}i[r+12>>2]=f}A:if(c>>>0>4)I=0,A=-1;else if(A=-1,I=0,!((-1<<c^-1)&w|h)){if(!(2&a)){I:{g:{if(a=c>>>1|0)for(A=i[r+12>>2];;){if(A>>>0>=B>>>0){t=68;break g}if(61!=(0|(f=Q[A+g|0]))){if(t=28,!C)break g;if(!DA(C,f))break g}else a=a-1|0;if(A=A+1|0,i[r+12>>2]=A,!a)break}A=0;break I}i[8952]=t,A=-1}if(A)break A}if(A=0,C){I:if(!((t=i[r+12>>2])>>>0>=B>>>0)){for(;;){if(!DA(C,Q[g+t|0]))break I;if((0|(t=t+1|0))==(0|B))break}t=B}i[r+12>>2]=t}I=y}return C=i[r+12>>2],n?i[n>>2]=g+C:(0|B)!=(0|C)&&(i[8952]=28,A=-1),E&&(i[E>>2]=I),s=r+16|0,0|A}function K(A,I,g){var B=0,C=0,Q=0,E=0,i=0,a=0,r=0,o=0,t=0,e=0,f=0,c=0,y=0,s=0,w=0,D=0,h=0,p=0,u=0,F=0,l=0;for(C=2036477234,Q=857760878,E=1634760805,i=1797285236,w=20,o=n[0|g]|n[g+1|0]<<8|n[g+2|0]<<16|n[g+3|0]<<24,s=n[g+4|0]|n[g+5|0]<<8|n[g+6|0]<<16|n[g+7|0]<<24,D=n[g+8|0]|n[g+9|0]<<8|n[g+10|0]<<16|n[g+11|0]<<24,c=n[g+12|0]|n[g+13|0]<<8|n[g+14|0]<<16|n[g+15|0]<<24,t=n[g+16|0]|n[g+17|0]<<8|n[g+18|0]<<16|n[g+19|0]<<24,a=n[g+20|0]|n[g+21|0]<<8|n[g+22|0]<<16|n[g+23|0]<<24,e=n[g+24|0]|n[g+25|0]<<8|n[g+26|0]<<16|n[g+27|0]<<24,f=n[g+28|0]|n[g+29|0]<<8|n[g+30|0]<<16|n[g+31|0]<<24,g=n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24,r=n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24,B=n[I+8|0]|n[I+9|0]<<8|n[I+10|0]<<16|n[I+11|0]<<24,I=n[I+12|0]|n[I+13|0]<<8|n[I+14|0]<<16|n[I+15|0]<<24;h=B,B=cg(E+a|0,7)^c,y=h^cg(B+E|0,9),p=cg(B+y|0,13)^a,c=cg(y+p|0,18),I=cg(Q+o|0,7)^I,e=cg(I+Q|0,9)^e,o=cg(I+e|0,13)^o,F=cg(e+o|0,18),f=cg(g+C|0,7)^f,a=cg(f+C|0,9)^s,u=cg(a+f|0,13)^g,l=cg(a+u|0,18),g=cg(i+t|0,7)^D,r=cg(g+i|0,9)^r,t=cg(g+r|0,13)^t,h=cg(r+t|0,18),o=cg((E^=c)+g|0,7)^o,s=cg(o+E|0,9)^a,D=cg(o+s|0,13)^g,E=cg(s+D|0,18)^E,g=cg((Q^=F)+B|0,7)^u,r=cg(g+Q|0,9)^r,c=cg(g+r|0,13)^B,Q=cg(r+c|0,18)^Q,t=cg((C^=l)+I|0,7)^t,B=cg(t+C|0,9)^y,I=cg(B+t|0,13)^I,C=cg(I+B|0,18)^C,a=cg((i^=h)+f|0,7)^p,e=cg(a+i|0,9)^e,f=cg(a+e|0,13)^f,i=cg(e+f|0,18)^i,y=w>>>0>2,w=w-2|0,y;);return bI(A,E),bI(A+4|0,Q),bI(A+8|0,C),bI(A+12|0,i),bI(A+16|0,g),bI(A+20|0,r),bI(A+24|0,B),bI(A+28|0,I),0}function X(A){var I,g=0,B=0;s=I=s-48|0,g=n[28+(A|=0)|0]|n[A+29|0]<<8|n[A+30|0]<<16|n[A+31|0]<<24,i[I+24>>2]=n[A+24|0]|n[A+25|0]<<8|n[A+26|0]<<16|n[A+27|0]<<24,i[I+28>>2]=g,g=n[A+20|0]|n[A+21|0]<<8|n[A+22|0]<<16|n[A+23|0]<<24,i[I+16>>2]=n[A+16|0]|n[A+17|0]<<8|n[A+18|0]<<16|n[A+19|0]<<24,i[I+20>>2]=g,g=n[A+4|0]|n[A+5|0]<<8|n[A+6|0]<<16|n[A+7|0]<<24,i[I>>2]=n[0|A]|n[A+1|0]<<8|n[A+2|0]<<16|n[A+3|0]<<24,i[I+4>>2]=g,g=n[A+12|0]|n[A+13|0]<<8|n[A+14|0]<<16|n[A+15|0]<<24,i[I+8>>2]=n[A+8|0]|n[A+9|0]<<8|n[A+10|0]<<16|n[A+11|0]<<24,i[I+12>>2]=g,g=n[A+40|0]|n[A+41|0]<<8|n[A+42|0]<<16|n[A+43|0]<<24,i[I+32>>2]=n[A+36|0]|n[A+37|0]<<8|n[A+38|0]<<16|n[A+39|0]<<24,i[I+36>>2]=g,vg[i[8752]](I,I,40,0,A+32|0,0,A),g=i[I+28>>2],B=i[I+24>>2],Q[A+24|0]=B,Q[A+25|0]=B>>>8,Q[A+26|0]=B>>>16,Q[A+27|0]=B>>>24,Q[A+28|0]=g,Q[A+29|0]=g>>>8,Q[A+30|0]=g>>>16,Q[A+31|0]=g>>>24,g=i[I+20>>2],B=i[I+16>>2],Q[A+16|0]=B,Q[A+17|0]=B>>>8,Q[A+18|0]=B>>>16,Q[A+19|0]=B>>>24,Q[A+20|0]=g,Q[A+21|0]=g>>>8,Q[A+22|0]=g>>>16,Q[A+23|0]=g>>>24,g=i[I+12>>2],B=i[I+8>>2],Q[A+8|0]=B,Q[A+9|0]=B>>>8,Q[A+10|0]=B>>>16,Q[A+11|0]=B>>>24,Q[A+12|0]=g,Q[A+13|0]=g>>>8,Q[A+14|0]=g>>>16,Q[A+15|0]=g>>>24,g=i[I+4>>2],B=i[I>>2],Q[0|A]=B,Q[A+1|0]=B>>>8,Q[A+2|0]=B>>>16,Q[A+3|0]=B>>>24,Q[A+4|0]=g,Q[A+5|0]=g>>>8,Q[A+6|0]=g>>>16,Q[A+7|0]=g>>>24,g=i[I+36>>2],B=i[I+32>>2],Q[A+36|0]=B,Q[A+37|0]=B>>>8,Q[A+38|0]=B>>>16,Q[A+39|0]=B>>>24,Q[A+40|0]=g,Q[A+41|0]=g>>>8,Q[A+42|0]=g>>>16,Q[A+43|0]=g>>>24,YI(A),s=I+48|0}function T(A,I){var g,B,C,E,n,a,o,t,e=0,f=0;s=g=s-48|0,B=i[I+28>>2],C=i[I+24>>2],E=i[I+20>>2],n=i[I+16>>2],a=i[I+12>>2],o=i[I+8>>2],t=i[I+4>>2],e=i[I>>2],f=i[I+36>>2],I=i[I+32>>2],e=r(((B+(C+(E+(n+(a+(o+(t+(e+(r(f,19)+16777216>>>25|0)>>26)>>25)>>26)>>25)>>26)>>25)>>26)>>25)+I>>26)+f>>25,19)+e|0,i[g>>2]=67108863&e,e=t+(e>>26)|0,i[g+4>>2]=33554431&e,e=o+(e>>25)|0,i[g+8>>2]=67108863&e,e=a+(e>>26)|0,i[g+12>>2]=33554431&e,e=n+(e>>25)|0,i[g+16>>2]=67108863&e,e=E+(e>>26)|0,i[g+20>>2]=33554431&e,e=C+(e>>25)|0,i[g+24>>2]=67108863&e,e=B+(e>>26)|0,i[g+28>>2]=33554431&e,I=I+(e>>25)|0,i[g+32>>2]=67108863&I,i[g+36>>2]=f+(I>>26)&33554431,I=i[g>>2],Q[0|A]=I,Q[A+2|0]=I>>>16,Q[A+1|0]=I>>>8,f=i[g+4>>2],Q[A+5|0]=f>>>14,Q[A+4|0]=f>>>6,Q[A+3|0]=f<<2|I>>>24,I=i[g+8>>2],Q[A+8|0]=I>>>13,Q[A+7|0]=I>>>5,Q[A+6|0]=I<<3|f>>>22,f=i[g+12>>2],Q[A+11|0]=f>>>11,Q[A+10|0]=f>>>3,Q[A+9|0]=f<<5|I>>>21,I=i[g+16>>2],Q[A+15|0]=I>>>18,Q[A+14|0]=I>>>10,Q[A+13|0]=I>>>2,Q[A+12|0]=I<<6|f>>>19,I=i[g+20>>2],Q[A+16|0]=I,Q[A+18|0]=I>>>16,Q[A+17|0]=I>>>8,f=i[g+24>>2],Q[A+21|0]=f>>>15,Q[A+20|0]=f>>>7,Q[A+19|0]=f<<1|I>>>24,I=i[g+28>>2],Q[A+24|0]=I>>>13,Q[A+23|0]=I>>>5,Q[A+22|0]=I<<3|f>>>23,f=i[g+32>>2],Q[A+27|0]=f>>>12,Q[A+26|0]=f>>>4,Q[A+25|0]=f<<4|I>>>21,I=i[g+36>>2],Q[A+31|0]=I>>>18,Q[A+30|0]=I>>>10,Q[A+29|0]=I>>>2,Q[A+28|0]=I<<6|f>>>20,s=g+48|0}function V(A,I){var g,B,C,Q,E,i=0,a=0,r=0;for(s=g=s-288|0,N(E=A+40|0,I),ng(a=A+80|0),U(B=g+240|0,E),H(C=g+192|0,B,1424),cA(B,B,a),yA(C,C,a),U(Q=g+144|0,C),H(Q,Q,C),U(A,Q),H(A,A,C),H(A,A,B),s=a=s-144|0,U(i=a+96|0,A),U(r=a+48|0,i),U(r,r),H(r,A,r),H(i,i,r),U(i,i),H(i,r,i),U(r,i),i=1;U(r=a+48|0,r),5!=(0|(i=i+1|0)););for(H(i=a+96|0,r=a+48|0,i),U(r,i),i=1;U(r=a+48|0,r),10!=(0|(i=i+1|0)););for(H(i=a+48|0,i,a+96|0),U(a,i),i=1;U(a,a),20!=(0|(i=i+1|0)););for(H(i=a+48|0,a,i),i=1;U(r=a+48|0,r),11!=(0|(i=i+1|0)););for(H(i=a+96|0,r=a+48|0,i),U(r,i),i=1;U(r=a+48|0,r),50!=(0|(i=i+1|0)););for(H(i=a+48|0,i,a+96|0),U(a,i),i=1;U(a,a),100!=(0|(i=i+1|0)););for(H(i=a+48|0,a,i),i=1;U(r=a+48|0,r),51!=(0|(i=i+1|0)););H(i=a+96|0,a+48|0,i),U(i,i),U(i,i),H(A,i,A),s=a+144|0,H(A,A,Q),H(A,A,B),U(a=g+96|0,A),H(a,a,C),cA(i=g+48|0,a,B);A:{if(!mI(i)){if(yA(g,g+96|0,g+240|0),a=-1,!mI(g))break A;H(A,A,1472)}(0|vI(A))==(n[I+31|0]>>>7|0)&&kA(A,A),H(A+120|0,A,E),a=0}return s=g+288|0,a}function q(A,I,g,B,C){var E,a,r=0,o=0,t=0;for(s=E=(s=a=s-416|0)-192|0,GI(a),wI(E- -64|0,54,128),Q[E+64|0]=54^n[0|C],r=1;Q[0|(o=(E- -64|0)+r|0)]=n[0|o]^n[C+r|0],32!=(0|(r=r+1|0)););for(z(a,r=E- -64|0,128,0),GI(o=a+208|0),wI(r,92,128),Q[E+64|0]=92^n[0|C],r=1;Q[0|(t=(E- -64|0)+r|0)]=n[0|t]^n[C+r|0],32!=(0|(r=r+1|0)););return z(o,C=E- -64|0,128,0),Dg(C,128),Dg(E,64),s=E+192|0,z(a,I,g,B),s=g=(s=I=s+-64|0)-64|0,MA(a,g),z(B=a+208|0,g,64,0),MA(B,I),Dg(g,64),s=g- -64|0,g=i[I+28>>2],B=i[I+24>>2],Q[A+24|0]=B,Q[A+25|0]=B>>>8,Q[A+26|0]=B>>>16,Q[A+27|0]=B>>>24,Q[A+28|0]=g,Q[A+29|0]=g>>>8,Q[A+30|0]=g>>>16,Q[A+31|0]=g>>>24,g=i[I+20>>2],B=i[I+16>>2],Q[A+16|0]=B,Q[A+17|0]=B>>>8,Q[A+18|0]=B>>>16,Q[A+19|0]=B>>>24,Q[A+20|0]=g,Q[A+21|0]=g>>>8,Q[A+22|0]=g>>>16,Q[A+23|0]=g>>>24,g=i[I+12>>2],B=i[I+8>>2],Q[A+8|0]=B,Q[A+9|0]=B>>>8,Q[A+10|0]=B>>>16,Q[A+11|0]=B>>>24,Q[A+12|0]=g,Q[A+13|0]=g>>>8,Q[A+14|0]=g>>>16,Q[A+15|0]=g>>>24,g=i[I+4>>2],B=i[I>>2],Q[0|A]=B,Q[A+1|0]=B>>>8,Q[A+2|0]=B>>>16,Q[A+3|0]=B>>>24,Q[A+4|0]=g,Q[A+5|0]=g>>>8,Q[A+6|0]=g>>>16,Q[A+7|0]=g>>>24,s=I- -64|0,s=a+416|0,0}function z(A,I,g,B){var C,E=0,a=0,r=0,o=0,t=0,e=0;s=C=s-704|0;A:if(g|B){if(r=B<<3|(E=g)>>>29,a=(t=i[A+72>>2])+(e=E<<3)|0,E=r+(o=i[A+76>>2])|0,i[A+72>>2]=a,E=a>>>0<e>>>0?E+1|0:E,i[A+76>>2]=E,r=(e=(0|E)==(0|o)&a>>>0<t>>>0|E>>>0<o>>>0)+i[(a=A- -64|0)>>2]|0,E=i[a+4>>2],E=r>>>0<e>>>0?E+1|0:E,r=(e=B>>>29|0)+r|0,i[a>>2]=r,i[a+4>>2]=r>>>0<e>>>0?E+1|0:E,a=0,E=0,(0|(r=0-((o=127&((7&o)<<29|t>>>3))>>>0>128)|0))==(0|B)&g>>>0<(t=128-o|0)>>>0|B>>>0<r>>>0)for(;;)if(Q[80+(A+(t=a+o|0)|0)|0]=n[I+a|0],!((0|g)!=(0|(a=a+1|0))|(0|B)!=(0|(E=a?E:E+1|0))))break A;for(;Q[80+(A+(e=a+o|0)|0)|0]=n[I+a|0],(0|t)!=(0|(a=a+1|0))|(0|(E=a?E:E+1|0))!=(0|r););if(F(A,A+80|0,C,E=C+640|0),I=I+t|0,!(B=B-((g>>>0<t>>>0)+r|0)|0)&(g=g-t|0)>>>0>127|B)for(;F(A,I,C,E),I=I+128|0,!(B=B-(g>>>0<128)|0)&(g=g-128|0)>>>0>127|B;);if(g|B)for(a=0,E=0;Q[80+(A+a|0)|0]=n[I+a|0],(0|g)!=(0|(a=o=a+1|0))|(0|B)!=(0|(E=o?E:E+1|0)););Dg(C,704)}return s=C+704|0,0}function j(A,I,g){var B,C,Q,E=0;s=B=s-16|0,C=i[A+20>>2],i[A+20>>2]=0,Q=i[A+4>>2],i[A+4>>2]=0,E=-26;A:{I:{g:switch(g-1|0){case 1:if(E=-32,LA(I,1109,9))break A;I=I+9|0;break I;case 0:break g;default:break A}if(E=-32,LA(I,1100,8))break A;I=I+8|0}if(!LA(I,1352,3)&&(I=_A(I+3|0,B+12|0))){if(E=-26,19!=i[B+12>>2])break A;if(!LA(I,1364,3)&&(I=_A(I+3|0,B+12|0))&&(i[A+44>>2]=i[B+12>>2],!LA(I,1356,3)&&(I=_A(I+3|0,B+12|0))&&(i[A+40>>2]=i[B+12>>2],!LA(I,1360,3)&&(I=_A(I+3|0,B+12|0))&&(g=i[B+12>>2],i[A+48>>2]=g,i[A+52>>2]=g,36==(0|(g=n[0|I]))&&(i[B+12>>2]=C,I=I+(36==(0|g))|0,!L(i[A+16>>2],C,I,mA(I),0,B+12|0,B+8|0,3)&&(i[A+20>>2]=i[B+12>>2],I=i[B+8>>2],36==(0|(g=n[0|I]))&&(i[B+12>>2]=Q,I=I+(36==(0|g))|0,!L(i[A>>2],Q,I,mA(I),0,B+12|0,B+8|0,3)))))))){if(i[A+4>>2]=i[B+12>>2],I=i[B+8>>2],E=nA(A))break A;E=n[0|I]?-32:0;break A}}E=-32}return s=B+16|0,E}function W(A,I){var g,B,C,E,n,a,o,t,e,f,c,y=0,s=0,w=0,D=0,h=0,p=0;(s=i[A+56>>2])|(y=i[A+60>>2])&&(Q[(D=A+s|0)- -64|0]=1,!(y=(w=s+1|0)?y:y+1|0)&w>>>0<=15&&wI(D+65|0,0,15-s|0),Q[A+80|0]=1,M(A,A- -64|0,16,0)),e=i[A+52>>2],f=i[A+48>>2],c=i[A+44>>2],h=i[A+24>>2],w=i[A+28>>2]+(h>>>26|0)|0,s=i[A+32>>2]+(w>>>26|0)|0,C=i[A+36>>2]+(s>>>26|0)|0,a=67108863&s,w=(s=(67108863&h)+((y=i[A+20>>2]+r(C>>>26|0,5)|0)>>>26|0)|0)&(g=(E=(-67108864|C)+((o=a+((h=(p=67108863&w)+((y=s+((n=5+(D=67108863&y)|0)>>>26|0)|0)>>>26|0)|0)>>>26|0)|0)>>>26|0)|0)>>31)|(B=67108863&(t=(E>>>31|0)-1|0))&y,y=0,y=(s=w<<26|B&n|D&g)>>>0>(D=s+i[A+40>>2]|0)>>>0?1:y,bI(I,D),s=0,s=(w=(p=p&g|h&B)<<20|w>>>6)>>>0>(h=w+c|0)>>>0?1:s,w=y,h=y+h|0,y=s,y=w>>>0>h>>>0?y+1|0:y,bI(I+4|0,h),s=0,s=(w=(D=g&a|B&o)<<14|p>>>12)>>>0>(p=w+f|0)>>>0?1:s,w=y,p=y+p|0,y=s,y=w>>>0>p>>>0?y+1|0:y,bI(I+8|0,p),bI(s=I+12|0,y=y+(D=(I=(E&t|g&C)<<8|D>>>18)+e|0)|0),Dg(A,88)}function O(A,I){var g,B,C=0;for(s=g=s-192|0,U(B=g+144|0,I),U(C=g+96|0,B),U(C,C),H(C,I,C),H(B,B,C),U(I=g+48|0,B),H(C,C,I),U(I,C),I=1;U(C=g+48|0,C),5!=(0|(I=I+1|0)););for(H(I=g+96|0,C=g+48|0,I),U(C,I),I=1;U(C=g+48|0,C),10!=(0|(I=I+1|0)););for(H(I=g+48|0,I,g+96|0),U(g,I),I=1;U(g,g),20!=(0|(I=I+1|0)););for(H(I=g+48|0,g,I),I=1;U(C=g+48|0,C),11!=(0|(I=I+1|0)););for(H(I=g+96|0,C=g+48|0,I),U(C,I),I=1;U(C=g+48|0,C),50!=(0|(I=I+1|0)););for(H(I=g+48|0,I,g+96|0),U(g,I),I=1;U(g,g),100!=(0|(I=I+1|0)););for(H(I=g+48|0,g,I),I=1;U(C=g+48|0,C),51!=(0|(I=I+1|0)););for(H(I=g+96|0,g+48|0,I),I=1;U(C=g+96|0,C),6!=(0|(I=I+1|0)););H(A,g+96|0,g+144|0),s=g+192|0}function Z(A,I,g,B,C){A|=0,I|=0,g|=0,B|=0;var E=0,i=0,a=0,o=0,f=0,c=0,y=0,s=0;ag(C|=0),i=(E=(B>>>0)/3|0)<<2,(E=r(E,-3)+B|0)&&(i=2&C?(2|i)+(E>>>1|0)|0:i+4|0);A:{I:{g:{if(I>>>0>i>>>0){if(!(4&C)){if(C=0,!B)break A;E=0;break g}if(C=0,!B)break A;for(E=0;;){for(f=(o=n[g+a|0])|f<<8,E=E+8|0;c=E,y=A+C|0,s=Qg(f>>>(E=E-6|0)&63),Q[0|y]=s,C=C+1|0,E>>>0>5;);if((0|(a=a+1|0))==(0|B))break}if(!E)break A;g=Qg(o<<12-c&63);break I}xI(),t()}for(;;){for(f=(o=n[g+a|0])|f<<8,E=E+8|0;c=E,y=A+C|0,s=Eg(f>>>(E=E-6|0)&63),Q[0|y]=s,C=C+1|0,E>>>0>5;);if((0|(a=a+1|0))==(0|B))break}if(!E)break A;g=Eg(o<<12-c&63)}Q[A+C|0]=g,C=C+1|0}A:{I:{if(C>>>0<=i>>>0){if(C>>>0<i>>>0)break I;i=C;break A}e(1048,1145,230,1375),t()}wI(A+C|0,61,i-C|0)}return wI(A+i|0,0,(I>>>0>(g=i+1|0)>>>0?I:g)-i|0),0|A}function $(A,I,g,B){var C=0,E=0,a=0,r=0,o=0,t=0;A:{if((r=i[A+56>>2])|(o=i[A+60>>2])){if(t=C=(a=(0|(C=0-((r>>>0>16)+o|0)|0))==(0|B)&g>>>0>(E=16-r|0)>>>0|B>>>0>C>>>0)?C:B,C|(E=a?E:g))for(a=0,C=0;Q[(A+(o=a+r|0)|0)- -64|0]=n[I+a|0],r=i[A+56>>2],o=i[A+60>>2],(0|E)!=(0|(a=a+1|0))|(0|(C=a?C:C+1|0))!=(0|t););if(C=o+t|0,C=(r=E+r|0)>>>0<E>>>0?C+1|0:C,i[A+56>>2]=r,i[A+60>>2]=C,!C&r>>>0<16)break A;M(A,A- -64|0,16,0),i[A+56>>2]=0,i[A+60>>2]=0,g=(C=g)-E|0,B=B-((C>>>0<E>>>0)+t|0)|0,I=I+E|0}if(!B&g>>>0>=16|B&&(M(A,I,C=-16&g,B),g&=15,B=0,I=I+C|0),g|B){for(a=0,C=0;E=a+i[A+56>>2]|0,Q[(A+E|0)- -64|0]=n[I+a|0],a=E=a+1|0,(0|g)!=(0|E)|(0|B)!=(0|(C=E?C:C+1|0)););I=B+i[A+60>>2]|0,I=(C=g+i[A+56>>2]|0)>>>0<g>>>0?I+1|0:I,i[A+56>>2]=C,i[A+60>>2]=I}}}function AA(A,I,g){var B,C,Q,E,n,a,r,o,t,e,f,c,y=0,s=0,w=0,D=0,h=0,p=0,u=0,F=0,l=0;B=i[I+4>>2],C=i[A+4>>2],Q=i[I+8>>2],s=i[A+8>>2],E=i[I+12>>2],w=i[A+12>>2],n=i[I+16>>2],D=i[A+16>>2],a=i[I+20>>2],h=i[A+20>>2],r=i[I+24>>2],p=i[A+24>>2],o=i[I+28>>2],u=i[A+28>>2],t=i[I+32>>2],F=i[A+32>>2],e=i[I+36>>2],l=i[A+36>>2],c=(g=0-g|0)&((f=i[I>>2])^(y=i[A>>2])),i[A>>2]=c^y,y=l,l=g&(l^e),i[A+36>>2]=y^l,y=F,F=g&(F^t),i[A+32>>2]=y^F,y=u,u=g&(u^o),i[A+28>>2]=y^u,y=p,p=g&(p^r),i[A+24>>2]=y^p,y=h,h=g&(h^a),i[A+20>>2]=y^h,y=D,D=g&(D^n),i[A+16>>2]=y^D,y=w,w=g&(w^E),i[A+12>>2]=y^w,y=s,s=g&(s^Q),i[A+8>>2]=y^s,y=A,A=g&(B^C),i[y+4>>2]=A^C,i[I+36>>2]=l^e,i[I+32>>2]=F^t,i[I+28>>2]=u^o,i[I+24>>2]=p^r,i[I+20>>2]=h^a,i[I+16>>2]=D^n,i[I+12>>2]=w^E,i[I+8>>2]=s^Q,i[I+4>>2]=A^B,i[I>>2]=f^c}function IA(A,I){var g;i[A>>2]=67108863&(n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24),i[A+4>>2]=(n[I+3|0]|n[I+4|0]<<8|n[I+5|0]<<16|n[I+6|0]<<24)>>>2&67108611,i[A+8>>2]=(n[I+6|0]|n[I+7|0]<<8|n[I+8|0]<<16|n[I+9|0]<<24)>>>4&67092735,i[A+12>>2]=(n[I+9|0]|n[I+10|0]<<8|n[I+11|0]<<16|n[I+12|0]<<24)>>>6&66076671,g=n[I+12|0]|n[I+13|0]<<8|n[I+14|0]<<16|n[I+15|0]<<24,i[A+20>>2]=0,i[A+24>>2]=0,i[A+28>>2]=0,i[A+32>>2]=0,i[A+36>>2]=0,i[A+16>>2]=g>>>8&1048575,i[A+40>>2]=n[I+16|0]|n[I+17|0]<<8|n[I+18|0]<<16|n[I+19|0]<<24,i[A+44>>2]=n[I+20|0]|n[I+21|0]<<8|n[I+22|0]<<16|n[I+23|0]<<24,i[A+48>>2]=n[I+24|0]|n[I+25|0]<<8|n[I+26|0]<<16|n[I+27|0]<<24,I=n[I+28|0]|n[I+29|0]<<8|n[I+30|0]<<16|n[I+31|0]<<24,Q[A+80|0]=0,i[A+56>>2]=0,i[A+60>>2]=0,i[A+52>>2]=I}function gA(A,I,g,B){var C=0,E=0,i=0,a=0,r=0,o=0;if(g|B){if(!B&(E=256-(C=n[A+352|0]|n[A+353|0]<<8|n[A+354|0]<<16|n[A+355|0]<<24)|0)>>>0<g>>>0|B)for(o=A+224|0,a=A+96|0;eI(96+(A+C|0)|0,I,E),i=(n[A+352|0]|n[A+353|0]<<8|n[A+354|0]<<16|n[A+355|0]<<24)+E|0,Q[A+352|0]=i,Q[A+353|0]=i>>>8,Q[A+354|0]=i>>>16,Q[A+355|0]=i>>>24,CA(A,128),p(A,a),eI(a,o,128),C=(r=n[A+352|0]|n[A+353|0]<<8|n[A+354|0]<<16|n[A+355|0]<<24)-128|0,Q[A+352|0]=C,Q[A+353|0]=C>>>8,Q[A+354|0]=C>>>16,Q[A+355|0]=C>>>24,I=I+E|0,i=g,g=g-E|0,!(B=B-(E>>>0>i>>>0)|0)&(E=384-r|0)>>>0<g>>>0|B;);eI(96+(A+C|0)|0,I,g),I=g+(n[A+352|0]|n[A+353|0]<<8|n[A+354|0]<<16|n[A+355|0]<<24)|0,Q[A+352|0]=I,Q[A+353|0]=I>>>8,Q[A+354|0]=I>>>16,Q[A+355|0]=I>>>24}return 0}function BA(A,I){var g,B=0,C=0,E=0,i=0;for(s=g=s-464|0;C=(g+400|0)+(B<<1)|0,i=n[I+B|0],Q[C+1|0]=i>>>4,Q[0|C]=15&i,32!=(0|(B=B+1|0)););for(B=0;I=((C=(I=B)+n[0|(B=(g+400|0)+E|0)]|0)<<24)- -134217728|0,Q[0|B]=C-(I>>24&240),B=I>>28,63!=(0|(E=E+1|0)););for(Q[g+463|0]=n[g+463|0]+B,LI(A),B=1;FA(g,B>>>1|0,Q[(g+400|0)+B|0]),TA(I=g+240|0,A,g),tI(A,I),I=B>>>0<62,B=B+2|0,I;);for(fI(I=g+240|0,A),hI(B=g+120|0,I),G(I,B),hI(B,I),G(I,B),hI(B,I),G(I,B),tI(A,I),B=0;FA(g,B>>>1|0,Q[(g+400|0)+B|0]),TA(I=g+240|0,A,g),tI(A,I),I=B>>>0<62,B=B+2|0,I;);s=g+464|0}function CA(A,I){var g,B,C,E=0,i=0;C=1+(i=g=n[4+(E=A- -64|0)|0]|n[E+5|0]<<8|n[E+6|0]<<16|n[E+7|0]<<24)|0,i=(I=I+(i=B=n[0|E]|n[E+1|0]<<8|n[E+2|0]<<16|n[E+3|0]<<24)|0)>>>0<i>>>0?C:g,Q[0|E]=I,Q[E+1|0]=I>>>8,Q[E+2|0]=I>>>16,Q[E+3|0]=I>>>24,Q[E+4|0]=i,Q[E+5|0]=i>>>8,Q[E+6|0]=i>>>16,Q[E+7|0]=i>>>24,I=(E=(0|i)==(0|g)&I>>>0<B>>>0|i>>>0<g>>>0)+(n[A+72|0]|n[A+73|0]<<8|n[A+74|0]<<16|n[A+75|0]<<24)|0,i=n[A+76|0]|n[A+77|0]<<8|n[A+78|0]<<16|n[A+79|0]<<24,E=I>>>0<E>>>0?i+1|0:i,Q[A+72|0]=I,Q[A+73|0]=I>>>8,Q[A+74|0]=I>>>16,Q[A+75|0]=I>>>24,Q[A+76|0]=E,Q[A+77|0]=E>>>8,Q[A+78|0]=E>>>16,Q[A+79|0]=E>>>24}function QA(A,I){i[A>>2]=1634760805,i[A+4>>2]=857760878,i[A+8>>2]=2036477234,i[A+12>>2]=1797285236,i[A+16>>2]=n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24,i[A+20>>2]=n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24,i[A+24>>2]=n[I+8|0]|n[I+9|0]<<8|n[I+10|0]<<16|n[I+11|0]<<24,i[A+28>>2]=n[I+12|0]|n[I+13|0]<<8|n[I+14|0]<<16|n[I+15|0]<<24,i[A+32>>2]=n[I+16|0]|n[I+17|0]<<8|n[I+18|0]<<16|n[I+19|0]<<24,i[A+36>>2]=n[I+20|0]|n[I+21|0]<<8|n[I+22|0]<<16|n[I+23|0]<<24,i[A+40>>2]=n[I+24|0]|n[I+25|0]<<8|n[I+26|0]<<16|n[I+27|0]<<24,i[A+44>>2]=n[I+28|0]|n[I+29|0]<<8|n[I+30|0]<<16|n[I+31|0]<<24}function EA(A,I,g,B,C,Q,E){var n,a,r,o,t,e=0;return s=n=s-352|0,K(n,Q,E),!((!C&B>>>0>A-g>>>0|0!=(0|C))&A>>>0>g>>>0)&(!C&B>>>0<=g-A>>>0|A>>>0>=g>>>0)||(g=gI(A,g,B)),i[n+56>>2]=0,i[n+60>>2]=0,i[n+48>>2]=0,i[n+52>>2]=0,i[n+40>>2]=0,i[n+44>>2]=0,i[n+32>>2]=0,i[n+36>>2]=0,(r=!((E=(e=!C&B>>>0<32)?B:32)|(e=e?C:0)))||eI(n- -64|0,g,E),o=Q+16|0,XI(a=n+32|0,a,t=E+32|0,Q=t>>>0<32?e+1|0:e,o,n),og(n+96|0,a),r||eI(A,n- -64|0,E),Dg(n+32|0,64),!C&B>>>0>=33|C&&KI(A+E|0,g+E|0,B-E|0,C-(e+(B>>>0<E>>>0)|0)|0,o,n),Dg(n,32),gg(g=n+96|0,A,B,C),tg(g,I),Dg(g,256),s=n+352|0,0}function iA(A,I,g,B,C,Q,E){var n,a,r=0,o=0,t=0;s=n=s-96|0,K(n,Q,E),E=n+32|0,a=Q+16|0,vg[i[8760]](E,32,0,a,n),Q=-1;A:{if(!(0|vg[i[8754]](g,I,B,C,E))){if(Q=0,!A)break A;!((!C&B>>>0>I-A>>>0|0!=(0|C))&A>>>0<I>>>0)&(!C&B>>>0<=A-I>>>0|A>>>0<=I>>>0)||(I=gI(A,I,B)),g=(Q=!C&B>>>0<32)?B:32,E=Q=Q?C:0,g|Q?(o=eI(n- -64|0,I,g),r=Q=n+32|0,Q=E,XI(r,r,t=g+32|0,Q=t>>>0<32?Q+1|0:Q,a,n),eI(A,o,g)):(r=Q=n+32|0,Q=E,XI(r,r,o=g+32|0,Q=o>>>0<32?Q+1|0:Q,a,n)),Q=0,!C&B>>>0<33||KI(A+g|0,I+g|0,B-g|0,C-(E+(g>>>0>B>>>0)|0)|0,a,n)}Dg(n,32)}return s=n+96|0,Q}function nA(A){var I=0,g=0,B=0;if(!A)return-25;if(!i[A>>2])return-1;if(I=-2,!(a[A+4>>2]<16)&&(i[A+8>>2]||(I=-18,!i[A+12>>2]))){if(g=i[A+20>>2],!i[A+16>>2])return g?-19:-6;if(I=-6,!(g>>>0<8)&&(i[A+24>>2]||(I=-20,!i[A+28>>2]))&&(i[A+32>>2]||(I=-21,!i[A+36>>2]))){if(!(g=i[A+48>>2]))return-16;if(I=-17,!(g>>>0>16777215||(I=-14,(B=i[A+44>>2])>>>0<8||(I=-15,B>>>0>2097152||(I=-14,g<<3>>>0>B>>>0))))){if(!i[A+40>>2])return-12;if(!(A=i[A+52>>2]))return-28;I=A>>>0>16777215?-29:0}}}return I}function aA(A,I,g){var B,C,Q,E,n,a,r,o,t,e,f,c,y,s,w,D,h,p,u,F;f=i[I+4>>2],B=i[A+4>>2],c=i[I+8>>2],C=i[A+8>>2],y=i[I+12>>2],Q=i[A+12>>2],s=i[I+16>>2],E=i[A+16>>2],w=i[I+20>>2],n=i[A+20>>2],D=i[I+24>>2],a=i[A+24>>2],h=i[I+28>>2],r=i[A+28>>2],p=i[I+32>>2],o=i[A+32>>2],u=i[I+36>>2],t=i[A+36>>2],e=i[A>>2],F=i[I>>2]^e,I=0-g|0,i[A>>2]=e^F&I,i[A+36>>2]=I&(t^u)^t,i[A+32>>2]=I&(o^p)^o,i[A+28>>2]=I&(r^h)^r,i[A+24>>2]=I&(a^D)^a,i[A+20>>2]=I&(n^w)^n,i[A+16>>2]=I&(E^s)^E,i[A+12>>2]=I&(Q^y)^Q,i[A+8>>2]=I&(C^c)^C,i[A+4>>2]=I&(B^f)^B}function rA(A,I,g,B,C,Q,E,a,r,o){var t,e,f,c;return s=t=s-48|0,i[t+4>>2]=0,x(e=t+16|0,r,o),o=n[r+20|0]|n[r+21|0]<<8|n[r+22|0]<<16|n[r+23|0]<<24,i[t+8>>2]=n[r+16|0]|n[r+17|0]<<8|n[r+18|0]<<16|n[r+19|0]<<24,i[t+12>>2]=o,s=o=s-352|0,$I(f=o+32|0,64,c=t+4|0,e),og(r=o+96|0,f),Dg(f,64),gg(r,Q,E,a),gg(r,34960,0-E&15,0),gg(r,I,g,B),gg(r,34960,0-g&15,0),QI(Q=o+24|0,E,a),gg(r,Q,8,0),QI(Q,g,B),gg(r,Q,8,0),tg(r,o),Dg(r,256),C=rg(o,C),Dg(o,16),A&&(C?(wI(A,0,g),C=-1):(kI(A,I,g,B,c,1,e),C=0)),s=o+352|0,Dg(e,32),s=t+48|0,C}function oA(A,I){for(var g=0,B=0,C=0,E=0,i=0,a=0,r=0,o=0;Q[A+g|0]=n[(g>>>3|0)+I|0]>>>(7&g)&1,256!=(0|(g=g+1|0)););for(;;){a=(I=a)+1|0;A:if(n[0|(i=A+I|0)]&&(g=a,C=1,!(I>>>0>254)))for(;;){I:if(E=Q[0|(B=A+g|0)])if((0|(o=(r=Q[0|i])+(E<<=C)|0))<=15)Q[0|i]=o,Q[0|B]=0;else{if((0|(B=r-E|0))<-15)break A;for(Q[0|i]=B;;){if(!n[0|(B=A+g|0)]){Q[0|B]=1;break I}if(Q[0|B]=0,B=g>>>0<255,g=g+1|0,!B)break}}if(C>>>0>5)break A;if(!((g=I+(C=C+1|0)|0)>>>0<256))break}if(256==(0|a))break}}function tA(A,I,g,B){var C,Q,E,n,a=0;s=C=s+-64|0,wI(C+8|0,0,52),a=mA(A),i[C+20>>2]=a,i[C+36>>2]=a,i[C+4>>2]=a,Q=k(a),i[C+32>>2]=Q,E=k(a),i[C+16>>2]=E,n=k(a),i[C>>2]=n;A:if(!n|!Q|!E||!(a=k(a)))b(Q),b(E),b(n),A=-22;else{if(A=j(C,A,B)){b(i[C+32>>2]),b(i[C+16>>2]),b(i[C>>2]),b(a);break A}A=0,I=_(i[C+40>>2],i[C+44>>2],i[C+52>>2],I,g,i[C+16>>2],i[C+20>>2],a,i[C+4>>2],0,0,B),b(i[C+32>>2]),b(i[C+16>>2]),(I||zA(a,i[C>>2],i[C+4>>2]))&&(A=-35),b(a),b(i[C>>2])}return s=C- -64|0,A}function eA(A,I,g,B,C){var Q,E=0,a=0;s=Q=s+-64|0;A:{I:{if(!g&(a=mA(A))>>>0<128){if(i[Q+56>>2]=0,i[Q+48>>2]=0,i[Q+52>>2]=0,i[Q+40>>2]=0,i[Q+44>>2]=0,g=0,a&&(g=a),!(E=k(g))|!(3&n[E-4|0])||wI(E,0,g),E)break I}else i[8952]=28;A=-1;break A}i[Q+32>>2]=0,i[Q+36>>2]=0,i[Q+8>>2]=E,i[Q+16>>2]=E,i[Q+20>>2]=a,i[Q>>2]=E,i[Q+12>>2]=a,i[Q+24>>2]=0,i[Q+28>>2]=0,i[Q+4>>2]=a,j(Q,A,C)?(i[8952]=28,A=-1):A=(0|I)!=i[Q+40>>2]|i[Q+44>>2]!=(B>>>10|0),b(E)}return s=Q- -64|0,A}function fA(A,I,g,B,C,Q,E,a,r,o,t){var e,f,c,y;return s=e=s-48|0,i[e+4>>2]=0,x(f=e+16|0,o,t),t=n[o+20|0]|n[o+21|0]<<8|n[o+22|0]<<16|n[o+23|0]<<24,i[e+8>>2]=n[o+16|0]|n[o+17|0]<<8|n[o+18|0]<<16|n[o+19|0]<<24,i[e+12>>2]=t,s=t=s-336|0,$I(c=t+16|0,64,y=e+4|0,f),og(o=t+80|0,c),Dg(c,64),gg(o,E,a,r),gg(o,34960,0-a&15,0),kI(A,B,C,Q,y,1,f),gg(o,A,C,Q),gg(o,34960,0-C&15,0),QI(A=t+8|0,a,r),gg(o,A,8,0),QI(A,C,Q),gg(o,A,8,0),tg(o,I),Dg(o,256),g&&(i[g>>2]=16,i[g+4>>2]=0),s=t+336|0,Dg(f,32),s=e+48|0,0}function cA(A,I,g){var B,C,Q,E,n,a,r,o,t,e,f,c,y,s,w,D,h,p;B=i[g+4>>2],C=i[I+4>>2],Q=i[g+8>>2],E=i[I+8>>2],n=i[g+12>>2],a=i[I+12>>2],r=i[g+16>>2],o=i[I+16>>2],t=i[g+20>>2],e=i[I+20>>2],f=i[g+24>>2],c=i[I+24>>2],y=i[g+28>>2],s=i[I+28>>2],w=i[g+32>>2],D=i[I+32>>2],h=i[g+36>>2],p=i[I+36>>2],i[A>>2]=i[I>>2]-i[g>>2],i[A+36>>2]=p-h,i[A+32>>2]=D-w,i[A+28>>2]=s-y,i[A+24>>2]=c-f,i[A+20>>2]=e-t,i[A+16>>2]=o-r,i[A+12>>2]=a-n,i[A+8>>2]=E-Q,i[A+4>>2]=C-B}function yA(A,I,g){var B,C,Q,E,n,a,r,o,t,e,f,c,y,s,w,D,h,p;B=i[g+4>>2],C=i[I+4>>2],Q=i[g+8>>2],E=i[I+8>>2],n=i[g+12>>2],a=i[I+12>>2],r=i[g+16>>2],o=i[I+16>>2],t=i[g+20>>2],e=i[I+20>>2],f=i[g+24>>2],c=i[I+24>>2],y=i[g+28>>2],s=i[I+28>>2],w=i[g+32>>2],D=i[I+32>>2],h=i[g+36>>2],p=i[I+36>>2],i[A>>2]=i[g>>2]+i[I>>2],i[A+36>>2]=h+p,i[A+32>>2]=w+D,i[A+28>>2]=y+s,i[A+24>>2]=f+c,i[A+20>>2]=t+e,i[A+16>>2]=r+o,i[A+12>>2]=n+a,i[A+8>>2]=Q+E,i[A+4>>2]=B+C}function sA(A){var I,g=0,B=0,C=0,E=0;for(Q[11+(I=s-16|0)|0]=0,Q[I+12|0]=0,Q[I+13|0]=0,Q[I+14|0]=0,i[I+8>>2]=0;;){for(C=n[A+B|0],g=0;Q[0|(E=(I+8|0)+g|0)]=n[0|E]|C^n[(2528+(g<<5)|0)+B|0],7!=(0|(g=g+1|0)););if(31==(0|(B=B+1|0)))break}for(B=127&n[A+31|0],A=0,g=0;Q[0|(C=(I+8|0)+g|0)]=n[0|C]|B^n[2559+(g<<5)|0],7!=(0|(g=g+1|0)););for(g=0;g=n[(I+8|0)+A|0]-1|g,7!=(0|(A=A+1|0)););return g>>>8&1}function wA(A,I){var g=0,B=0,C=0,E=0;for(wI(eI(A,33984,64)- -64|0,0,293);B=(g=E<<3)+A|0,C=n[0|(g=I+g|0)]|n[g+1|0]<<8|n[g+2|0]<<16|n[g+3|0]<<24,g=(n[g+4|0]|n[g+5|0]<<8|n[g+6|0]<<16|n[g+7|0]<<24)^(n[B+4|0]|n[B+5|0]<<8|n[B+6|0]<<16|n[B+7|0]<<24),C^=n[0|B]|n[B+1|0]<<8|n[B+2|0]<<16|n[B+3|0]<<24,Q[0|B]=C,Q[B+1|0]=C>>>8,Q[B+2|0]=C>>>16,Q[B+3|0]=C>>>24,Q[B+4|0]=g,Q[B+5|0]=g>>>8,Q[B+6|0]=g>>>16,Q[B+7|0]=g>>>24,8!=(0|(E=E+1|0)););}function DA(A,I){var g=0,B=0;A:if(B=255&I){if(3&A)for(;;){if(!(g=n[0|A])|(0|g)==(255&I))break A;if(!(3&(A=A+1|0)))break}I:if(!((-1^(g=i[A>>2]))&g-16843009&-2139062144))for(B=r(B,16843009);;){if((-1^(g^=B))&g-16843009&-2139062144)break I;if(g=i[A+4>>2],A=A+4|0,g-16843009&(-1^g)&-2139062144)break}for(;g=A,(B=n[0|A])&&(A=g+1|0,(0|B)!=(255&I)););A=g}else A=mA(A)+A|0;return n[0|A]==(255&I)?A:0}function hA(A,I,g){var B=0,C=0,E=0,n=0,a=0,r=0;if(g>>>0>=8)for(n=g>>>3|0,g=0;E=(B=g<<3)+A|0,a=(B=i[4+(C=I+B|0)>>2])<<24|(C=i[C>>2])>>>8,r=B<<8|C>>>24,B=-16777216&((255&B)<<24|C>>>8)|16711680&((16777215&B)<<8|C>>>24)|B>>>8&65280|B>>>24,Q[0|E]=B,Q[E+1|0]=B>>>8,Q[E+2|0]=B>>>16,Q[E+3|0]=B>>>24,B=C<<8&16711680|C<<24|65280&a|255&r,Q[E+4|0]=B,Q[E+5|0]=B>>>8,Q[E+6|0]=B>>>16,Q[E+7|0]=B>>>24,(0|n)!=(0|(g=g+1|0)););}function pA(A,I,g){var B,C,Q=0,E=0,i=0;return B=A,A=31&(Q=i=63&g),Q>>>0>=32?(A=-1<<A,Q=0):A=(Q=-1<<A)|(1<<A)-1&-1>>>32-A,C=Q&B,E=A&I,Q=31&i,i>>>0>=32?(A=0,i=E>>>Q|0):(A=E>>>Q|0,i=((1<<Q)-1&E)<<32-Q|C>>>Q),Q=A,g=31&(E=0-g&63),E>>>0>=32?(A=0,g=-1>>>g|0):g=(A=-1>>>g|0)|(1<<g)-1<<32-g,g&=B,I&=A,A=31&E,E>>>0>=32?(I=g<<A,A=0):(I=(1<<A)-1&g>>>32-A|I<<A,A=g<<A),h=I|Q,A|i}function uA(A,I,g){var B=0,C=0,Q=0,E=0;return E=A,A=0,C=31&(B=Q=63&g),B=B>>>0>=32?-1>>>C|0:(A=-1>>>C|0)|(1<<C)-1<<32-C,B&=E,A&=I,C=31&Q,Q>>>0>=32?(A=B<<C,B=0):(A=(1<<C)-1&B>>>32-C|A<<C,B<<=C),C=A,A=31&(g=0-g&63),g>>>0>=32?(A=-1<<A,Q=0):A=(Q=-1<<A)|(1<<A)-1&-1>>>32-A,E&=Q,I&=A,A=31&g,g>>>0>=32?(g=0,A=I>>>A|0):(g=I>>>A|0,A=((1<<A)-1&I)<<32-A|E>>>A),h=g|C,A|B}function FA(A,I,g){var B,C,Q,E;s=B=s-128|0,ng(A),ng(C=A+40|0),hg(Q=A+80|0),MI(A,I=r(I,960)+2784|0,Ag(g=g-((0-(E=(128&g)>>>7|0)&g)<<1)<<24>>24,1)),MI(A,I+120|0,Ag(g,2)),MI(A,I+240|0,Ag(g,3)),MI(A,I+360|0,Ag(g,4)),MI(A,I+480|0,Ag(g,5)),MI(A,I+600|0,Ag(g,6)),MI(A,I+720|0,Ag(g,7)),MI(A,I+840|0,Ag(g,8)),UA(I=B+8|0,C),UA(B+48|0,A),kA(B+88|0,Q),MI(A,I,E),s=B+128|0}function lA(A,I,g,B,C,Q,E,i,n,a){var r,o,t;return s=o=s-352|0,fg(t=o+32|0,64,n,a),og(r=o+96|0,t),Dg(t,64),gg(r,Q,E,i),gg(r,34064,0-E&15,0),gg(r,I,g,B),gg(r,34064,0-g&15,0),QI(Q=o+24|0,E,i),gg(r,Q,8,0),QI(Q,g,B),gg(r,Q,8,0),tg(r,o),Dg(r,256),C=rg(o,C),Dg(o,16),A&&(C?(wI(A,0,g),C=-1):(WA(A,I,g,B,n,1,a),C=0)),s=o+352|0,C}function _A(A,I){var g,B=0,C=0,Q=0,E=0,a=0;A:if(!(((g=n[0|A])-58&255)>>>0<246)){for(C=g,B=A;;){if(E=B,Q>>>0>429496729)break A;if((C=(255&C)-48|0)>>>0>(-1^(B=r(Q,10)))>>>0)break A;if(Q=B+C|0,!(((C=n[0|(B=E+1|0)])-58&255)>>>0>245))break}48==(0|g)&(0|A)!=(0|E)|(0|A)==(0|B)||(i[I>>2]=Q,a=B)}return a}function kA(A,I){var g,B,C,Q,E,n,a,r,o;g=i[I+4>>2],B=i[I+8>>2],C=i[I+12>>2],Q=i[I+16>>2],E=i[I+20>>2],n=i[I+24>>2],a=i[I+28>>2],r=i[I+32>>2],o=i[I+36>>2],i[A>>2]=0-i[I>>2],i[A+36>>2]=0-o,i[A+32>>2]=0-r,i[A+28>>2]=0-a,i[A+24>>2]=0-n,i[A+20>>2]=0-E,i[A+16>>2]=0-Q,i[A+12>>2]=0-C,i[A+8>>2]=0-B,i[A+4>>2]=0-g}function HA(A,I,g,B,C,Q,E,n,a,r,o){var t,e,f;return s=e=s-336|0,fg(f=e+16|0,64,r,o),og(t=e+80|0,f),Dg(f,64),gg(t,E,n,a),gg(t,34064,0-n&15,0),WA(A,B,C,Q,r,1,o),gg(t,A,C,Q),gg(t,34064,0-C&15,0),QI(A=e+8|0,n,a),gg(t,A,8,0),QI(A,C,Q),gg(t,A,8,0),tg(t,I),Dg(t,256),g&&(i[g>>2]=16,i[g+4>>2]=0),s=e+336|0,0}function GA(A,I,g,B,C,Q,E,i,n,a){var r,o,t;return s=r=s-352|0,Ig(t=r+32|0,n,a),og(o=r+96|0,t),Dg(t,64),gg(o,Q,E,i),QI(Q=r+24|0,E,i),gg(o,Q,8,0),gg(o,I,g,B),QI(Q,g,B),gg(o,Q,8,0),tg(o,r),Dg(o,256),C=rg(r,C),Dg(r,16),A&&(C?(wI(A,0,g),C=-1):(HI(A,I,g,B,n,a),C=0)),s=r+352|0,C}function UA(A,I){var g,B,C,Q,E,n,a,r,o;g=i[I+8>>2],B=i[I+12>>2],C=i[I+16>>2],Q=i[I+20>>2],E=i[I+24>>2],n=i[I+28>>2],a=i[I>>2],r=i[I+4>>2],o=i[I+36>>2],i[A+32>>2]=i[I+32>>2],i[A+36>>2]=o,i[A+24>>2]=E,i[A+28>>2]=n,i[A+16>>2]=C,i[A+20>>2]=Q,i[A+8>>2]=g,i[A+12>>2]=B,i[A>>2]=a,i[A+4>>2]=r}function SA(A,I,g){g?(i[A+48>>2]=n[0|g]|n[g+1|0]<<8|n[g+2|0]<<16|n[g+3|0]<<24,g=n[g+4|0]|n[g+5|0]<<8|n[g+6|0]<<16|n[g+7|0]<<24):(i[A+48>>2]=0,g=0),i[A+52>>2]=g,i[A+56>>2]=n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24,i[A+60>>2]=n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24}function bA(A,I,g,B){var C;if(s=C=s-192|0,!(!g|(I-65&255)>>>0<=191|(B-65&255)>>>0<=191))return E[C+130>>1]=257,Q[C+129|0]=B,Q[C+128|0]=I,RI(4|(I=C+128|0)),QI(8|I,0,0),wI(C+144|0,0,48),wA(A,I),wI(B+C|0,0,B<<24>>24<0?0:128-B|0),gA(I=A,A=eI(C,g,B),128,0),Dg(A,128),s=A+192|0,0;xI(),t()}function mA(A){var I=0,g=0,B=0;A:{if(3&(I=A))for(;;){if(!n[0|I])break A;if(!(3&(I=I+1|0)))break}for(;g=I,I=I+4|0,!((-1^(B=i[g>>2]))&B-16843009&-2139062144););if(!(255&B))return g-A|0;for(;B=n[g+1|0],g=I=g+1|0,B;);}return I-A|0}function vA(A,I,g,B,C,Q,E){var i=0,n=0;return I-65>>>0<4294967232|E>>>0>64?A=-1:(n=i=s,s=i=i-384&-64,!(!(B|C)||g)|!A|((I&=255)-65&255)>>>0<=191|!(!(E&=255)||Q)|E>>>0>=65?(xI(),t()):(E?bA(i,I,Q,E):jA(i,I),gA(i,g,B,C),Y(i,A,I),s=n),A=0),A}function MA(A,I){var g,B,C=0;s=g=s-704|0,(B=i[A+72>>2]>>>3&127)>>>0<=111?eI(80+(A+B|0)|0,34784,112-B|0):(eI((C=A+80|0)+B|0,34784,128-B|0),F(A,C,g,g+640|0),wI(C,0,112)),hA(A+192|0,A- -64|0,16),F(A,A+80|0,g,g+640|0),hA(I,A,64),Dg(g,704),Dg(A,208),s=g+704|0}function PA(A,I,g,B,C,Q,E,n,a,r,o){var t,e,f;return s=e=s-336|0,Ig(f=e+16|0,r,o),og(t=e+80|0,f),Dg(f,64),gg(t,E,n,a),QI(E=e+8|0,n,a),gg(t,E,8,0),HI(A,B,C,Q,r,o),gg(t,A,C,Q),QI(E,C,Q),gg(t,E,8,0),tg(t,I),Dg(t,256),g&&(i[g>>2]=16,i[g+4>>2]=0),s=e+336|0,0}function YA(A,I,g){i[A+48>>2]=g?n[0|g]|n[g+1|0]<<8|n[g+2|0]<<16|n[g+3|0]<<24:0,i[A+52>>2]=n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24,i[A+56>>2]=n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24,i[A+60>>2]=n[I+8|0]|n[I+9|0]<<8|n[I+10|0]<<16|n[I+11|0]<<24}function NA(A,I,g,B,C,Q,E){var n;return s=n=s-16|0,A=wI(A,0,128),!(B|Q)&E>>>0<2147483649?!!(C|Q)&E>>>0>8191?(EI(n,16),A=_(C,E>>>10|0,1,I,g,n,16,0,32,A,128,2)?-1:0):(i[8952]=28,A=-1):(i[8952]=22,A=-1),s=n+16|0,A}function RA(A,I){var g=0;4&I&&((I=i[A>>2])&&Dg(i[I+4>>2],i[A+16>>2]<<10),(I=i[A+4>>2])&&Dg(I,i[A+20>>2]<<3)),b(i[A+4>>2]),i[A+4>>2]=0,(I=i[A>>2])&&(g=i[I>>2])&&b(g),b(I),i[A>>2]=0}function dA(A,I){var g,B,C=0,E=0,i=0,n=0;for(s=g=s-16|0,C=10;n=C,i=(I>>>0)/10|0,Q[0|(E=(C=C-1|0)+(g+6|0)|0)]=I-r(i,10)|48,!(I>>>0<10)&&(I=i,C););B=eI(I=A,E,A=11-n|0)+A|0,Q[0|B]=0,s=g+16|0}function JA(A,I,g){var B,C,Q,E=0;s=C=s-48|0,yA(A,E=I+40|0,I),cA(B=A+40|0,E,I),H(E=A+80|0,A,g+40|0),H(B,B,g),H(Q=A+120|0,g+120|0,I+120|0),H(A,I+80|0,g+80|0),yA(C,A,A),cA(A,E,B),yA(B,E,B),cA(E,C,Q),yA(Q,C,Q),s=C+48|0}function xA(A,I,g){var B,C,Q,E=0;s=C=s-48|0,yA(A,E=I+40|0,I),cA(B=A+40|0,E,I),H(E=A+80|0,A,g),H(B,B,g+40|0),H(Q=A+120|0,g+120|0,I+120|0),H(A,I+80|0,g+80|0),yA(C,A,A),cA(A,E,B),yA(B,E,B),yA(E,C,Q),cA(Q,C,Q),s=C+48|0}function LA(A,I,g){var B=0,C=0,Q=0;if(!g)return 0;A:if(B=n[0|A]){for(;;){if((C=n[0|I])&&!(!(g=g-1|0)|(0|B)!=(0|C))){if(I=I+1|0,B=n[A+1|0],A=A+1|0,B)continue;break A}break}Q=B}return(255&Q)-n[0|I]|0}function KA(A,I){for(var g=0,B=0,C=0,Q=0;C=(g=B<<3)+A|0,Q=n[0|(g=I+g|0)]|n[g+1|0]<<8|n[g+2|0]<<16|n[g+3|0]<<24,g=n[g+4|0]|n[g+5|0]<<8|n[g+6|0]<<16|n[g+7|0]<<24,i[C>>2]=Q,i[C+4>>2]=g,128!=(0|(B=B+1|0)););}function XA(A,I,g){var B;if(i[12+(B=s-16|0)>>2]=A,i[B+8>>2]=I,I=0,i[B+4>>2]=0,(0|g)>0)for(;i[B+4>>2]=i[B+4>>2]|n[i[B+8>>2]+I|0]^n[i[B+12>>2]+I|0],(0|g)!=(0|(I=I+1|0)););return(i[B+4>>2]-1>>>8&1)-1|0}function TA(A,I,g){var B,C,Q,E=0;s=C=s-48|0,yA(A,E=I+40|0,I),cA(B=A+40|0,E,I),H(E=A+80|0,A,g),H(B,B,g+40|0),H(Q=A+120|0,g+80|0,I+120|0),yA(C,I=I+80|0,I),cA(A,E,B),yA(B,E,B),yA(E,C,Q),cA(Q,C,Q),s=C+48|0}function VA(A,I,g){var B,C=0,E=0;if(s=B=s-16|0,Q[B+15|0]=0,E=-1,!(0|vg[i[8758]](A,I,g))){for(;Q[B+15|0]=n[A+C|0]|n[B+15|0],32!=(0|(C=C+1|0)););E=(n[B+15|0]<<23)-8388608>>31}return s=B+16|0,E}function qA(A,I,g,B){var C,Q,E,i,n=0,a=0;return i=r(n=g>>>16|0,a=A>>>16|0),n=(65535&(a=((E=r(C=65535&g,Q=65535&A))>>>16|0)+r(a,C)|0))+r(n,Q)|0,h=(r(I,g)+i|0)+r(A,B)+(a>>>16)+(n>>>16)|0,65535&E|n<<16}function zA(A,I,g){var B;if(i[12+(B=s-16|0)>>2]=A,i[B+8>>2]=I,I=0,Q[B+7|0]=0,g)for(;Q[B+7|0]=n[B+7|0]|n[i[B+8>>2]+I|0]^n[i[B+12>>2]+I|0],(0|g)!=(0|(I=I+1|0)););return(n[B+7|0]-1>>>8&1)-1|0}function jA(A,I){var g;return s=g=s+-64|0,(I-65&255)>>>0<=191&&(xI(),t()),Q[g+3|0]=1,Q[g+1|0]=0,Q[g+2|0]=1,Q[0|g]=I,RI(4|g),QI(8|g,0,0),wI(g+16|0,0,48),wA(A,g),s=g- -64|0,0}function WA(A,I,g,B,C,Q,E){var i=0,n=0;i=B,1==(((i=(n=g+63|0)>>>0<63?i+1|0:i)>>>6|0)+(0!=(0|(i=(63&i)<<26|n>>>6)))|0)&Q>>>0>(n=0-i|0)>>>0&&(xI(),t()),kI(A,I,g,B,C,Q,E)}function OA(A,I,g,B){var C=0;C=-1;A:if(!(B-65>>>0<4294967232|g>>>0>64)){I:{if(!g||!I){if(!jA(A,255&B))break I;break A}if(bA(A,255&B,I,255&g))break A}C=0}return C}function ZA(A,I,g,B){return(B=(1+(A^B)>>>8^-1)&g|(1+(16321^A)>>>8^-1)&I|(I=A+65510>>>8&255)&A+65)|(g=A+65484>>>8|0)&A+71&(255^I)|A+252&A+65474>>>8&(-1^g)&255}function $A(A){var I,g;return(A=(I=i[8748])+(g=A+3&-4)|0)>>>0<=I>>>0&&g||A>>>0>Mg()<<16>>>0&&!(0|c(0|A))?(i[8952]=48,-1):(i[8748]=A,I)}function AI(A,I){for(var g=0,B=0,C=0,Q=0;B=(g=C<<3)+A|0,Q=i[(g=I+g|0)>>2],g=i[B+4>>2]^i[g+4>>2],i[B>>2]=i[B>>2]^Q,i[B+4>>2]=g,128!=(0|(C=C+1|0)););}function II(A,I){var g,B,C,E,i;s=g=s-144|0,O(B=g+96|0,I+80|0),H(C=g+48|0,I,B),H(g,I+40|0,B),T(A,g),E=A,i=vI(C)<<7^n[A+31|0],Q[E+31|0]=i,s=g+144|0}function gI(A,I,g){var B=0;if(A>>>0<I>>>0)return eI(A,I,g);if(g)for(B=A+g|0,I=I+g|0;I=I-1|0,Q[0|(B=B-1|0)]=n[0|I],g=g-1|0;);return A}function BI(A,I){var g,B=0;if(Q[15+(g=s-16|0)|0]=0,I)for(;Q[g+15|0]=n[A+B|0]|n[g+15|0],(0|(B=B+1|0))!=(0|I););return n[g+15|0]-1>>>8&1}function CI(A,I,g,B){var C;return B=I+B|0,B=(C=A+g|0)>>>0<g>>>0?B+1|0:B,g=qA(A<<1&-2,1&(I=I<<1|A>>>31),g,0),A=h+B|0,h=A=(I=g+C|0)>>>0<g>>>0?A+1|0:A,I}function QI(A,I,g){Q[0|A]=I,Q[A+1|0]=I>>>8,Q[A+2|0]=I>>>16,Q[A+3|0]=I>>>24,Q[A+4|0]=g,Q[A+5|0]=g>>>8,Q[A+6|0]=g>>>16,Q[A+7|0]=g>>>24}function EI(A,I){A|=0;var g=0,B=0,C=0;if(I|=0)for(;B=A+g|0,C=FI(),Q[0|B]=C,(0|(g=g+1|0))!=(0|I););}function iI(A,I,g,B,C){var Q,E;return A|=0,I|=0,g|=0,B|=0,s=Q=(E=s)-128&-64,IA(Q,C|=0),$(Q,I,g,B),W(Q,A),s=E,0}function nI(A){var I=0,g=0,B=0;for(I=1;I=n[0|(B=A+g|0)]+I|0,Q[0|B]=I,I=I>>>8|0,4!=(0|(g=g+1|0)););}function aI(A,I,g,B,C,Q,E,i){var n,a=0;return s=n=s-32|0,a=-1,oI(n,E,i)||(a=zI(A,I,g,B,C,Q,n),Dg(n,32)),s=n+32|0,a}function rI(A,I,g,B,C,Q,E,i){var n,a=0;return s=n=s-32|0,a=-1,oI(n,E,i)||(a=jI(A,I,g,B,C,Q,n),Dg(n,32)),s=n+32|0,a}function oI(A,I,g){A|=0;var B,C=0;return s=B=s-32|0,C=-1,VA(B,g|=0,I|=0)||(C=K(A,34976,B)),s=B+32|0,0|C}function tI(A,I){var g,B,C;H(A,I,g=I+120|0),H(A+40|0,B=I+40|0,C=I+80|0),H(A+80|0,C,g),H(A+120|0,I,B)}function eI(A,I,g){var B=0;if(g)for(B=A;Q[0|B]=n[0|I],B=B+1|0,I=I+1|0,g=g-1|0;);return A}function fI(A,I){var g,B;s=B=s-128|0,UA(g=B+8|0,I),UA(g+40|0,I+40|0),UA(g+80|0,I+80|0),G(A,g),s=B+128|0}function cI(A,I,g,B,C,Q,E){return!B&g>>>0>=16|B?rI(A,I+16|0,I,g-16|0,B-(g>>>0<16)|0,C,Q,E):-1}function yI(A,I){for(var g=0,B=0;Q[0|(B=A+g|0)]=n[0|B]^n[I+g|0],8!=(0|(g=g+1|0)););}function sI(A,I,g){var B,C;s=B=(C=s)-384&-64,PI(B,0,0,24),ig(B,I,32,0),ig(B,g,32,0),dI(B,A,24),s=C}function wI(A,I,g){var B=0;if(g)for(B=A;Q[0|B]=I,B=B+1|0,g=g-1|0;);return A}function DI(A,I){var g;yA(A,g=I+40|0,I),cA(A+40|0,g,I),UA(A+80|0,I+80|0),H(A+120|0,I+120|0,1520)}function hI(A,I){var g;H(A,I,g=I+120|0),H(A+40|0,I+40|0,I=I+80|0),H(A+80|0,I,g)}function pI(A,I,g,B,C,Q,E){return!B&g>>>0>=4294967280|B&&(xI(),t()),aI(A+16|0,A,I,g,B,C,Q,E)}function uI(A){var I;return I=n[0|A]|n[A+1|0]<<8,A=n[A+2|0],h=A>>>16|0,I|A<<16}function FI(){var A,I;return s=A=s-16|0,Q[A+15|0]=0,I=0|f(35048,A+15|0,0),s=A+16|0,0|I}function lI(A,I){var g=0;return(-1>>>(g=31&I)&A)<<g|((g=A)&-1<<(A=0-I&31))>>>A}function _I(A,I,g,B){var C;return s=C=s-208|0,GI(C),z(C,I,g,B),MA(C,A),s=C+208|0,0}function kI(A,I,g,B,C,Q,E){1==(0|B)|B>>>0>1&&(xI(),t()),vg[i[8752]](A,I,g,B,C,Q,E)}function HI(A,I,g,B,C,Q){1==(0|B)|B>>>0>1&&(xI(),t()),vg[i[8751]](A,I,g,B,C,1,0,Q)}function GI(A){i[A+64>>2]=0,i[A+68>>2]=0,i[A+72>>2]=0,i[A+76>>2]=0,eI(A,34080,64)}function UI(A,I,g){return g>>>0>=256&&(e(1279,1206,107,1067),t()),Y(A,I,255&g)}function SI(){var A;s=A=s-16|0,Q[A+15|0]=0,f(35084,A+15|0,0),s=A+16|0}function bI(A,I){Q[0|A]=I,Q[A+1|0]=I>>>8,Q[A+2|0]=I>>>16,Q[A+3|0]=I>>>24}function mI(A){var I;return s=I=s-32|0,T(I,A),A=BI(I,32),s=I+32|0,A}function vI(A){var I;return s=I=s-32|0,T(I,A),s=I+32|0,1&Q[0|I]}function MI(A,I,g){aA(A,I,g),aA(A+40|0,I+40|0,g),aA(A+80|0,I+80|0,g)}function PI(A,I,g,B){return 0|OA(A|=0,I|=0,g|=0,B|=0)}function YI(A){Q[A+32|0]=1,Q[A+33|0]=0,Q[A+34|0]=0,Q[A+35|0]=0}function NI(A){i[A>>2]=0,i[A+4>>2]=0,i[A+8>>2]=0,i[A+12>>2]=0}function RI(A){Q[0|A]=0,Q[A+1|0]=0,Q[A+2|0]=0,Q[A+3|0]=0}function dI(A,I,g){return 0|UI(A|=0,I|=0,g|=0)}function JI(A,I,g){return 0|VA(A|=0,I|=0,g|=0)}function xI(){var A;(A=i[9098])&&vg[0|A](),y(),t()}function LI(A){hg(A),ng(A+40|0),ng(A+80|0),hg(A+120|0)}function KI(A,I,g,B,C,Q){vg[i[8761]](A,I,g,B,C,1,0,Q)}function XI(A,I,g,B,C,Q){vg[i[8761]](A,I,g,B,C,0,0,Q)}function TI(A,I){return A|=0,EI(I|=0,32),0|Bg(A,I)}function VI(A,I,g,B,C,Q){return u(A,I,g,B,C,Q,0),0}function qI(A,I,g,B,C,Q,E){return vA(A,I,g,B,C,Q,E)}function zI(A,I,g,B,C,Q,E){return EA(A,I,g,B,C,Q,E)}function jI(A,I,g,B,C,Q,E){return iA(A,I,g,B,C,Q,E)}function WI(A,I){GI(A),I&&z(A,34912,34,0)}function OI(A,I,g,B,C){return J(A,I,g,B,C,0)}function ZI(A,I){return 0|Bg(A|=0,I|=0)}function $I(A,I,g,B){vg[i[8750]](A,I,0,g,B)}function Ag(A,I){return(255&(A^I))-1>>>31|0}function Ig(A,I,g){vg[i[8749]](A,64,0,I,g)}function gg(A,I,g,B){vg[i[8756]](A,I,g,B)}function Bg(A,I){return 0|vg[i[8759]](A,I)}function Cg(A,I,g,B){return gA(A,I,g,B)}function Qg(A){return ZA(A,45,95,32704)}function Eg(A){return ZA(A,43,47,16320)}function ig(A,I,g,B){return Cg(A,I,g,B)}function ng(A){i[A>>2]=1,wI(A+4|0,0,36)}function ag(A){1!=(-7&A)&&(xI(),t())}function rg(A,I){return XA(A,I,16)}function og(A,I){vg[i[8755]](A,I)}function tg(A,I){vg[i[8757]](A,I)}function eg(A,I){return XA(A,I,32)}function fg(A,I,g,B){$I(A,I,g,B)}function cg(A,I){return lI(A,I)}function yg(A,I){eI(A,I,1024)}function sg(A){EI(A|=0,32)}function wg(A){wI(A,0,1024)}function Dg(A,I){wI(A,0,I)}function hg(A){wI(A,0,40)}function pg(){return 32}function ug(){return 24}function Fg(){return-17}function lg(){return 64}function _g(){return 16}function kg(){return 1}function Hg(){return 2}function Gg(){return 8}function Ug(){return 3}function Sg(){return 0}function bg(){return-1}C(I=n,1024,"TGlic29kaXVtRFJHcmFuZG9tYnl0ZXMAYjY0X3BvcyA8PSBiNjRfbGVuAGNyeXB0b19nZW5lcmljaGFzaF9ibGFrZTJiX2ZpbmFsACRhcmdvbjJpACRhcmdvbjJpZAByYW5kb21ieXRlcy9yYW5kb21ieXRlcy5jAHNvZGl1bS9jb2RlY3MuYwBjcnlwdG9fZ2VuZXJpY2hhc2gvYmxha2UyYi9yZWYvYmxha2UyYi1yZWYuYwBjcnlwdG9fZ2VuZXJpY2hhc2gvYmxha2UyYi9yZWYvZ2VuZXJpY2hhc2hfYmxha2UyYi5jAGJ1Zl9sZW4gPD0gU0laRV9NQVgAb3V0bGVuIDw9IFVJTlQ4X01BWABTLT5idWZsZW4gPD0gQkxBS0UyQl9CTE9DS0JZVEVTACRhcmdvbjJpJHY9ACRhcmdvbjJpZCR2PQAsdD0ALHA9ACRtPQAxLjAuMTgAc29kaXVtX2JpbjJiYXNlNjQAJGFyZ29uMmkkACRhcmdvbjJpZCQ="),C(I,1424,"tnhZ/4Vy0wC9bhX/DwpqACnAAQCY6Hn/vDyg/5lxzv8At+L+tA1I/wAAAAAAAAAAsKAO/tPJhv+eGI8Af2k1AGAMvQCn1/v/n0yA/mpl4f8e/AQAkgyu"),C(I,1520,"WfGy/grlpv973Sr+HhTUAFKAAwAw0fMAd3lA/zLjnP8AbsUBZxuQ"),C(I,1568,"hTuMAb3xJP/4JcMBYNw3ALdMPv/DQj0AMkykAeGkTP9MPaP/dT4fAFGRQP92QQ4AonPW/waKLgB85vT/CoqPADQawgC49EwAgY8pAb70E/97qnr/YoFEAHnVkwBWZR7/oWebAIxZQ//v5b4BQwu1AMbwif7uRbz/Q5fuABMqbP/lVXEBMkSH/xFqCQAyZwH/UAGoASOYHv8QqLkBOFno/2XS/AAp+kcAzKpP/w4u7/9QTe8AvdZL/xGN+QAmUEz/vlV1AFbkqgCc2NABw8+k/5ZCTP+v4RD/jVBiAUzb8gDGonIALtqYAJsr8f6boGj/M7ulAAIRrwBCVKAB9zoeACNBNf5F7L8ALYb1AaN73QAgbhT/NBelALrWRwDpsGAA8u82ATlZigBTAFT/iKBkAFyOeP5ofL4AtbE+//opVQCYgioBYPz2AJeXP/7vhT4AIDicAC2nvf+OhbMBg1bTALuzlv76qg7/0qNOACU0lwBjTRoA7pzV/9XA0QFJLlQAFEEpATbOTwDJg5L+qm8Y/7EhMv6rJsv/Tvd0ANHdmQCFgLIBOiwZAMknOwG9E/wAMeXSAXW7dQC1s7gBAHLbADBekwD1KTgAfQ3M/vStdwAs3SD+VOoUAPmgxgHsfur/L2Oo/qrimf9ms9gA4o16/3pCmf629YYA4+QZAdY56//YrTj/tefSAHeAnf+BX4j/bn4zAAKpt/8HgmL+RbBe/3QE4wHZ8pH/yq0fAWkBJ/8ur0UA5C86/9fgRf7POEX/EP6L/xfP1P/KFH7/X9Vg/wmwIQDIBc//8SqA/iMhwP/45cQBgRF4APtnl/8HNHD/jDhC/yji9f/ZRiX+rNYJ/0hDhgGSwNb/LCZwAES4S//OWvsAleuNALWqOgB09O8AXJ0CAGatYgDpiWABfzHLAAWblAAXlAn/03oMACKGGv/bzIgAhggp/+BTK/5VGfcAbX8A/qmIMADud9v/563VAM4S/v4Iugf/fgkHAW8qSABvNOz+YD+NAJO/f/7NTsD/DmrtAbvbTACv87v+aVmtAFUZWQGi85QAAnbR/iGeCQCLoy7/XUYoAGwqjv5v/I7/m9+QADPlp/9J/Jv/XnQM/5ig2v+c7iX/s+rP/8UAs/+apI0A4cRoAAojGf7R1PL/Yf3e/rhl5QDeEn8BpIiH/x7PjP6SYfMAgcAa/slUIf9vCk7/k1Gy/wQEGACh7tf/Bo0hADXXDv8ptdD/54udALPL3f//uXEAveKs/3FC1v/KPi3/ZkAI/06uEP6FdUT/"),C(I,2560,"AQ=="),C(I,2592,"JuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/AXHF2pwPU3YT7o8C3YNEGcPKiBT+iw5zMZOx/13kqwDeuz///////////////////////////////////////9/7f///////////////////////////////////////3/u////////////////////////////////////////f+3T9VwaYxJY1pz3ot753hQ="),C(I,2783,"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"),C(I,33756,"AQ=="),C(I,33792,"AQ=="),C(I,33824,"4Ot6fDtBuK4WVuP68Z/EatoJjeucMrH9hmIFFl9JuABfnJW8o1CMJLHQsVWcg+9bBERcxFgcjobYIk7d0J8RV+z///////////////////////////////////////9/7f///////////////////////////////////////3/u////////////////////////////////////////fwjJvPNn5glqO6fKhIWuZ7sr+JT+cvNuPPE2HV869U+l0YLmrX9SDlEfbD4rjGgFm2u9Qfur2YMfeSF+ExnN4Fs="),C(I,34080,"CMm882fmCWo7p8qEha5nuyv4lP5y82488TYdXzr1T6XRguatf1IOUR9sPiuMaAWba71B+6vZgx95IX4TGc3gWyKuKNeYL4pCzWXvI5FEN3EvO03sz/vAtbzbiYGl27XpOLVI81vCVjkZ0AW28RHxWZtPGa+kgj+SGIFt2tVeHKtCAgOjmKoH2L5vcEUBW4MSjLLkTr6FMSTitP/Vw30MVW+Je/J0Xb5ysZYWO/6x3oA1Esclpwbcm5Qmac908ZvB0krxnsFpm+TjJU84hke+77XVjIvGncEPZZysd8yhDCR1AitZbyzpLYPkpm6qhHRK1PtBvdypsFy1UxGD2oj5dqvfZu5SUT6YEDK0LW3GMag/IfuYyCcDsOQO777Hf1m/wo+oPfML4MYlpwqTR5Gn1W+CA+BRY8oGcG4OCmcpKRT8L9JGhQq3JybJJlw4IRsu7SrEWvxtLE3fs5WdEw04U95jr4tUcwplqLJ3PLsKanbmru1HLsnCgTs1ghSFLHKSZAPxTKHov6IBMEK8S2YaqJGX+NBwi0vCML5UBqNRbMcYUu/WGeiS0RCpZVUkBpnWKiBxV4U1DvS40bsycKBqEMjQ0rgWwaQZU6tBUQhsNx6Z647fTHdIJ6hIm+G1vLA0Y1rJxbMMHDnLikHjSqrYTnPjY3dPypxbo7iy1vNvLmj8su9d7oKPdGAvF0NvY6V4cqvwoRR4yITsOWQaCALHjCgeYyP6/76Q6b2C3utsUKQVecay96P5vitTcuPyeHHGnGEm6s4+J8oHwsAhx7iG0R7r4M3WfdrqeNFu7n9PffW6bxdyqmfwBqaYyKLFfWMKrg35vgSYPxEbRxwTNQtxG4R9BCP1d9sokyTHQHuryjK8vskVCr6ePEwNEJzEZx1DtkI+y77UxUwqfmX8nCl/Wez61jqrb8tfF1hHSowZRGyA"),C(I,34912,"U2lnRWQyNTUxOSBubyBFZDI1NTE5IGNvbGxpc2lvbnMB"),C(I,34992,"MI5QAAEAAAACAAAAAwAAAAQAAAAFAAAABgAAAAcAAAAIAAAACQAAAAoAAAALAAAADAAAAA0=");var mg,vg=(mg=[null,function(A,I,g,B,C){var Q;return A|=0,B|=0,s=Q=s+-64|0,(I|=0)|(g|=0)&&(QA(Q,C|=0),SA(Q,B,0),m(Q,A=wI(A,0,I),A,I,g),Dg(Q,64)),s=Q- -64|0,0},function(A,I,g,B,C){var Q;return A|=0,B|=0,s=Q=s+-64|0,(I|=0)|(g|=0)&&(QA(Q,C|=0),YA(Q,B,0),m(Q,A=wI(A,0,I),A,I,g),Dg(Q,64)),s=Q- -64|0,0},function(A,I,g,B,C,Q,E,i){A|=0,I|=0,C|=0,Q|=0,E|=0,i|=0;var n,a=0;return s=n=s-80|0,(g|=0)|(B|=0)&&(bI(a=n+8|0,Q),bI(n+12|0,E),QA(Q=n+16|0,i),SA(Q,C,a),m(Q,I,A,g,B),Dg(Q,64)),s=n+80|0,0},function(A,I,g,B,C,Q,E){A|=0,I|=0,C|=0,Q|=0,E|=0;var i,n=0;return s=i=s-80|0,(g|=0)|(B|=0)&&(bI(n=i+12|0,Q),QA(Q=i+16|0,E),YA(Q,C,n),m(Q,I,A,g,B),Dg(Q,64)),s=i+80|0,0},iI,function(A,I,g,B,C){var Q;return A|=0,s=Q=s-16|0,iI(Q,I|=0,g|=0,B|=0,C|=0),A=rg(A,Q),s=Q+16|0,0|A},function(A,I){return IA(A|=0,I|=0),0},function(A,I,g,B){return $(A|=0,I|=0,g|=0,B|=0),0},function(A,I){return W(A|=0,I|=0),0},function(A,I,g){A|=0,I|=0,g|=0;var B,C=0,E=0,a=0,r=0,o=0,t=0,e=0,f=0,c=0,y=0,w=0,D=0,p=0,u=0,F=0,l=0,_=0,k=0,G=0,S=0,b=0,m=0,v=0,M=0,P=0,Y=0,R=0,d=0,J=0;for(r=-1,Q[11+(E=(s=B=s-336|0)-16|0)|0]=0,Q[E+12|0]=0,Q[E+13|0]=0,Q[E+14|0]=0,i[E+8>>2]=0;;){for(e=n[g+a|0],C=0;Q[0|(o=(E+8|0)+C|0)]=n[0|o]|e^n[(33760+(C<<5)|0)+a|0],7!=(0|(C=C+1|0)););if(31==(0|(a=a+1|0)))break}for(e=127&n[g+31|0],a=0,C=0;Q[0|(o=(E+8|0)+C|0)]=n[0|o]|e^n[33791+(C<<5)|0],7!=(0|(C=C+1|0)););for(C=0;C=n[(E+8|0)+a|0]-1|C,7!=(0|(a=a+1|0)););if(!(C>>>8&1)){for(r=0;Q[A+r|0]=n[I+r|0],32!=(0|(r=r+1|0)););for(Q[0|A]=248&n[0|A],Q[A+31|0]=63&n[A+31|0]|64,N(I=B+288|0,g),ng(B+240|0),hg(B+192|0),UA(B+144|0,I),ng(B+96|0),g=254,I=0;C=I,AA(E=B+240|0,y=B+144|0,C^=I=n[(g>>>3|0)+A|0]>>>(7&g)&1),AA(t=B+192|0,r=B+96|0,C),m=g,g=g-1|0,cA(f=B+48|0,y,r),cA(B,E,t),yA(E,E,t),yA(t,y,r),H(r,f,E),H(t,t,B),U(f,B),U(B,E),yA(y,r,t),cA(t,r,t),H(E,B,f),cA(B,B,f),U(t,t),u=C=i[B+4>>2],F=C>>31,l=C=i[B+8>>2],v=C>>31,D=C=i[B+12>>2],p=C>>31,_=C=i[B+16>>2],M=C>>31,c=C=i[B+20>>2],w=C>>31,k=C=i[B+24>>2],P=C>>31,Y=C=i[B>>2],R=C>>31,E=qA(C=i[B+36>>2],C>>31,121666,0),C=h,d=a=E+16777216|0,e=C=a>>>0<16777216?C+1|0:C,G=E-(-33554432&a)|0,C=qA(C=i[B+32>>2],C>>31,121666,0),a=h,o=qA(E=i[B+28>>2],E>>31,121666,0),E=h,J=C,S=C=o+16777216|0,a=(C=(E=C>>>0<16777216?E+1|0:E)>>25)+a|0,C=a=(E=J+(b=(33554431&E)<<7|S>>>25)|0)>>>0<b>>>0?a+1|0:a,C=((67108863&(C=(a=E+33554432|0)>>>0<33554432?C+1|0:C))<<6|a>>>26)+G|0,i[r+36>>2]=C,C=-67108864&a,i[r+32>>2]=E-C,G=o-(-33554432&S)|0,E=qA(k,P,121666,0),k=h,a=qA(c,w,121666,0),C=h,o=E,c=E=a+16777216|0,w=(33554431&(C=E>>>0<16777216?C+1|0:C))<<7|E>>>25,C=(C>>25)+k|0,E=C=(o=o+w|0)>>>0<w>>>0?C+1|0:C,w=C=o+33554432|0,C=((67108863&(E=C>>>0<33554432?E+1|0:E))<<6|C>>>26)+G|0,i[r+28>>2]=C,C=-67108864&w,i[r+24>>2]=o-C,c=a-(-33554432&c)|0,C=qA(_,M,121666,0),_=h,o=qA(D,p,121666,0),E=h,a=C,D=C=o+16777216|0,p=(33554431&(E=C>>>0<16777216?E+1|0:E))<<7|C>>>25,E=(E>>25)+_|0,a=C=a+p|0,C=C>>>0<p>>>0?E+1|0:E,C=((67108863&(C=(E=a+33554432|0)>>>0<33554432?C+1|0:C))<<6|E>>>26)+c|0,i[r+20>>2]=C,C=-67108864&E,i[r+16>>2]=a-C,D=o-(-33554432&D)|0,C=qA(l,v,121666,0),l=h,o=qA(u,F,121666,0),a=h,c=C,u=C=o+16777216|0,E=C,C=(C=(a=C>>>0<16777216?a+1|0:a)>>25)+l|0,C=(E=c+(a=(33554431&a)<<7|E>>>25)|0)>>>0<a>>>0?C+1|0:C,a=E,E=C,F=C=a+33554432|0,C=((67108863&(E=C>>>0<33554432?E+1|0:E))<<6|C>>>26)+D|0,i[r+12>>2]=C,C=-67108864&F,i[r+8>>2]=a-C,C=qA((33554431&e)<<7|d>>>25,e>>25,19,0),a=h,E=(e=qA(Y,R,121666,0))+C|0,C=h+a|0,a=E,E=E>>>0<e>>>0?C+1|0:C,e=C=a+33554432|0,C=(o-(-33554432&u)|0)+((67108863&(E=C>>>0<33554432?E+1|0:E))<<6|C>>>26)|0,i[r+4>>2]=C,C=-67108864&e,i[r>>2]=a-C,U(y,y),yA(f,f,r),H(r,B+288|0,t),H(t,B,f),m;);AA(g=B+240|0,B+144|0,I),AA(C=B+192|0,B+96|0,I),O(C,C),H(g,g,C),T(A,g),r=0}return s=B+336|0,0|r},function(A,I){A|=0,I|=0;var g,B,C,E=0;for(s=g=s-208|0;Q[A+E|0]=n[I+E|0],32!=(0|(E=E+1|0)););return Q[0|A]=248&n[0|A],Q[A+31|0]=63&n[A+31|0]|64,BA(g+48|0,A),s=I=s-96|0,yA(E=I+48|0,B=g+128|0,C=g+88|0),cA(I,B,C),O(I,I),H(g,E,I),s=I+96|0,T(A,g),s=g+208|0,0},function(A,I,g,B,C){A|=0,B|=0,C|=0;var E,a=0;if(s=E=s-112|0,(I|=0)|(g|=0)){a=n[C+28|0]|n[C+29|0]<<8|n[C+30|0]<<16|n[C+31|0]<<24,i[E+24>>2]=n[C+24|0]|n[C+25|0]<<8|n[C+26|0]<<16|n[C+27|0]<<24,i[E+28>>2]=a,a=n[C+20|0]|n[C+21|0]<<8|n[C+22|0]<<16|n[C+23|0]<<24,i[E+16>>2]=n[C+16|0]|n[C+17|0]<<8|n[C+18|0]<<16|n[C+19|0]<<24,i[E+20>>2]=a,a=n[C+4|0]|n[C+5|0]<<8|n[C+6|0]<<16|n[C+7|0]<<24,i[E>>2]=n[0|C]|n[C+1|0]<<8|n[C+2|0]<<16|n[C+3|0]<<24,i[E+4>>2]=a,a=n[C+12|0]|n[C+13|0]<<8|n[C+14|0]<<16|n[C+15|0]<<24,i[E+8>>2]=n[C+8|0]|n[C+9|0]<<8|n[C+10|0]<<16|n[C+11|0]<<24,i[E+12>>2]=a,C=n[0|B]|n[B+1|0]<<8|n[B+2|0]<<16|n[B+3|0]<<24,B=n[B+4|0]|n[B+5|0]<<8|n[B+6|0]<<16|n[B+7|0]<<24,i[E+104>>2]=0,i[E+108>>2]=0,i[E+96>>2]=C,i[E+100>>2]=B;A:{if(!g&I>>>0>=64|g){for(;;){for(d(A,E+96|0,E),C=8,B=1;B=n[0|(a=(E+96|0)+C|0)]+B|0,Q[0|a]=B,B=B>>>8|0,16!=(0|(C=C+1|0)););if(A=A- -64|0,g=g-1|0,!(!(g=(I=I+-64|0)>>>0<4294967232?g+1|0:g)&I>>>0>63|g))break}if(!(I|g))break A}for(C=0,d(E+32|0,E+96|0,E);Q[A+C|0]=n[(E+32|0)+C|0],(0|I)!=(0|(C=C+1|0)););}Dg(E+32|0,64),Dg(E,32)}return s=E+112|0,0},function(A,I,g,B,C,E,a,r){A|=0,I|=0,C|=0,E|=0,a|=0,r|=0;var o,t=0,e=0;if(s=o=s-112|0,(g|=0)|(B|=0)){for(t=n[r+28|0]|n[r+29|0]<<8|n[r+30|0]<<16|n[r+31|0]<<24,i[o+24>>2]=n[r+24|0]|n[r+25|0]<<8|n[r+26|0]<<16|n[r+27|0]<<24,i[o+28>>2]=t,t=n[r+20|0]|n[r+21|0]<<8|n[r+22|0]<<16|n[r+23|0]<<24,i[o+16>>2]=n[r+16|0]|n[r+17|0]<<8|n[r+18|0]<<16|n[r+19|0]<<24,i[o+20>>2]=t,t=n[r+4|0]|n[r+5|0]<<8|n[r+6|0]<<16|n[r+7|0]<<24,i[o>>2]=n[0|r]|n[r+1|0]<<8|n[r+2|0]<<16|n[r+3|0]<<24,i[o+4>>2]=t,t=8,e=n[r+12|0]|n[r+13|0]<<8|n[r+14|0]<<16|n[r+15|0]<<24,i[o+8>>2]=n[r+8|0]|n[r+9|0]<<8|n[r+10|0]<<16|n[r+11|0]<<24,i[o+12>>2]=e,r=n[C+4|0]|n[C+5|0]<<8|n[C+6|0]<<16|n[C+7|0]<<24,i[o+96>>2]=n[0|C]|n[C+1|0]<<8|n[C+2|0]<<16|n[C+3|0]<<24,i[o+100>>2]=r;Q[(o+96|0)+t|0]=E,E=(255&a)<<24|E>>>8,a=a>>>8|0,16!=(0|(t=t+1|0)););if(!B&g>>>0>63|B)for(;;){for(t=0,d(o+32|0,o+96|0,o);Q[A+t|0]=n[(o+32|0)+t|0]^n[I+t|0],r=1,64!=(0|(t=t+1|0)););for(t=8;C=n[0|(E=(o+96|0)+t|0)]+r|0,Q[0|E]=C,r=C>>>8|0,16!=(0|(t=t+1|0)););if(I=I- -64|0,A=A- -64|0,B=B-1|0,!(!(B=(g=g+-64|0)>>>0<4294967232?B+1|0:B)&g>>>0>63|B))break}if(g|B)for(t=0,d(o+32|0,o+96|0,o);Q[A+t|0]=n[(o+32|0)+t|0]^n[I+t|0],(0|g)!=(0|(t=t+1|0)););Dg(o+32|0,64),Dg(o,32)}return s=o+112|0,0}],mg.grow=function(A){var I=this.length;return this.length=this.length+A,I},mg.set=function(A,I){this[A]=I},mg.get=function(A){return this[A]},mg);function Mg(){return B.byteLength/65536|0}return{f:function(){},g:function(A,I,g,B,C,Q,E,i,n,a,r,o){return 0|PA(A|=0,I|=0,g|=0,B|=0,(A=0)|(C|=0),Q|=0,E|=0,A|(i|=0),n|=0,r|=0,o|=0)},h:function(A,I,g,B,C,Q,E,n,a,r,o){return A|=0,I|=0,a|=0,a=B|=0,!(B=C|=0)&(C=0|a)>>>0<4294967280?(PA(A,A+C|0,0,g|=0,C,B,Q|=0,E|=0,n|=0,r|=0,o|=0),I&&(B=(A=C+16|0)>>>0<16?B+1|0:B,i[I>>2]=A,i[I+4>>2]=B)):(xI(),t()),0},i:function(A,I,g,B,C,Q,E,i,n,a,r,o){return 0|HA(A|=0,I|=0,g|=0,B|=0,(A=0)|(C|=0),Q|=0,E|=0,A|(i|=0),n|=0,r|=0,o|=0)},j:function(A,I,g,B,C,Q,E,n,a,r,o){return A|=0,I|=0,a|=0,a=B|=0,!(B=C|=0)&(C=0|a)>>>0<4294967280?(HA(A,A+C|0,0,g|=0,C,B,Q|=0,E|=0,n|=0,r|=0,o|=0),I&&(B=(A=C+16|0)>>>0<16?B+1|0:B,i[I>>2]=A,i[I+4>>2]=B)):(xI(),t()),0},k:function(A,I,g,B,C,Q,E,i,n,a,r){return 0|GA(A|=0,g|=0,(A=0)|(B|=0),C|=0,Q|=0,E|=0,A|(i|=0),n|=0,a|=0,r|=0)},l:function(A,I,g,B,C,Q,E,n,a,r,o){return I|=0,g|=0,B|=0,C|=0,n|=0,n|=0,g=-1,!(Q|=0)&(C|=0)>>>0>=16|Q&&(g=GA(A|=0,B,C-16|0,Q-(C>>>0<16)|0,(B+C|0)-16|0,E|=0,n,a|=0,r|=0,o|=0)),I&&(i[I>>2]=g?0:C-16|0,i[I+4>>2]=g?0:Q-(C>>>0<16)|0),0|g},m:function(A,I,g,B,C,Q,E,i,n,a,r){return 0|lA(A|=0,g|=0,(A=0)|(B|=0),C|=0,Q|=0,E|=0,A|(i|=0),n|=0,a|=0,r|=0)},n:function(A,I,g,B,C,Q,E,n,a,r,o){return I|=0,g|=0,B|=0,C|=0,n|=0,n|=0,g=-1,!(Q|=0)&(C|=0)>>>0>=16|Q&&(g=lA(A|=0,B,C-16|0,Q-(C>>>0<16)|0,(B+C|0)-16|0,E|=0,n,a|=0,r|=0,o|=0)),I&&(i[I>>2]=g?0:C-16|0,i[I+4>>2]=g?0:Q-(C>>>0<16)|0),0|g},o:pg,p:function(){return 12},q:Sg,r:_g,s:Fg,t:sg,u:pg,v:Gg,w:Sg,x:_g,y:Fg,z:sg,A:function(A,I,g,B,C,Q,E,i,n,a,r,o){return 0|fA(A|=0,I|=0,g|=0,B|=0,(A=0)|(C|=0),Q|=0,E|=0,A|(i|=0),n|=0,r|=0,o|=0)},B:function(A,I,g,B,C,Q,E,n,a,r,o){return A|=0,I|=0,a|=0,a=B|=0,!(B=C|=0)&(C=0|a)>>>0<4294967280?(fA(A,A+C|0,0,g|=0,C,B,Q|=0,E|=0,n|=0,r|=0,o|=0),I&&(B=(A=C+16|0)>>>0<16?B+1|0:B,i[I>>2]=A,i[I+4>>2]=B)):(xI(),t()),0},C:function(A,I,g,B,C,Q,E,i,n,a,r){return 0|rA(A|=0,g|=0,(A=0)|(B|=0),C|=0,Q|=0,E|=0,A|(i|=0),n|=0,a|=0,r|=0)},D:function(A,I,g,B,C,Q,E,n,a,r,o){return I|=0,g|=0,B|=0,C|=0,n|=0,n|=0,g=-1,!(Q|=0)&(C|=0)>>>0>=16|Q&&(g=rA(A|=0,B,C-16|0,Q-(C>>>0<16)|0,(B+C|0)-16|0,E|=0,n,a|=0,r|=0,o|=0)),I&&(i[I>>2]=g?0:C-16|0,i[I+4>>2]=g?0:Q-(C>>>0<16)|0),0|g},E:pg,F:ug,G:Sg,H:_g,I:Fg,J:sg,K:pg,L:pg,M:function(A,I,g,B,C){return 0|q(A|=0,I|=0,g|=0,B|=0,C|=0)},N:function(A,I,g,B,C){var Q;return A|=0,s=Q=s-32|0,q(Q,I|=0,g|=0,B|=0,C|=0),I=eg(A,Q),g=zA(Q,A,32),s=Q+32|0,g|((0|A)==(0|Q)?-1:I)},O:sg,P:pg,Q:pg,R:pg,S:pg,T:ug,U:_g,V:Fg,W:function(A,I,g){A|=0,I|=0;var B,C=0;return s=B=s+-64|0,_I(B,g|=0,32,0),g=i[B+28>>2],C=i[B+24>>2],Q[I+24|0]=C,Q[I+25|0]=C>>>8,Q[I+26|0]=C>>>16,Q[I+27|0]=C>>>24,Q[I+28|0]=g,Q[I+29|0]=g>>>8,Q[I+30|0]=g>>>16,Q[I+31|0]=g>>>24,g=i[B+20>>2],C=i[B+16>>2],Q[I+16|0]=C,Q[I+17|0]=C>>>8,Q[I+18|0]=C>>>16,Q[I+19|0]=C>>>24,Q[I+20|0]=g,Q[I+21|0]=g>>>8,Q[I+22|0]=g>>>16,Q[I+23|0]=g>>>24,g=i[B+12>>2],C=i[B+8>>2],Q[I+8|0]=C,Q[I+9|0]=C>>>8,Q[I+10|0]=C>>>16,Q[I+11|0]=C>>>24,Q[I+12|0]=g,Q[I+13|0]=g>>>8,Q[I+14|0]=g>>>16,Q[I+15|0]=g>>>24,g=i[B+4>>2],C=i[B>>2],Q[0|I]=C,Q[I+1|0]=C>>>8,Q[I+2|0]=C>>>16,Q[I+3|0]=C>>>24,Q[I+4|0]=g,Q[I+5|0]=g>>>8,Q[I+6|0]=g>>>16,Q[I+7|0]=g>>>24,Dg(B,64),A=Bg(A,I),s=B- -64|0,0|A},X:TI,Y:oI,Z:function(A,I,g,B,C,Q,E){return 0|zI(A|=0,I|=0,g|=0,B|=0,C|=0,Q|=0,E|=0)},_:function(A,I,g,B,C,Q,E,i){return 0|aI(A|=0,I|=0,g|=0,B|=0,C|=0,Q|=0,E|=0,i|=0)},$:function(A,I,g,B,C,Q){return A|=0,I|=0,C|=0,Q|=0,!(B|=0)&(g|=0)>>>0>=4294967280|B&&(xI(),t()),0|zI(A+16|0,A,I,g,B,C,Q)},aa:function(A,I,g,B,C,Q,E){return 0|pI(A|=0,I|=0,g|=0,B|=0,C|=0,Q|=0,E|=0)},ba:function(A,I,g,B,C,Q,E){return 0|jI(A|=0,I|=0,g|=0,B|=0,C|=0,Q|=0,E|=0)},ca:function(A,I,g,B,C,Q,E,i){return 0|rI(A|=0,I|=0,g|=0,B|=0,C|=0,Q|=0,E|=0,i|=0)},da:function(A,I,g,B,C,Q){return I|=0,0|(!(B|=0)&(g|=0)>>>0>=16|B?jI(A|=0,I+16|0,I,g-16|0,B-(g>>>0<16)|0,C|=0,Q|=0):-1)},ea:function(A,I,g,B,C,Q,E){return 0|cI(A|=0,I|=0,g|=0,B|=0,C|=0,Q|=0,E|=0)},fa:function(A,I,g,B,C){A|=0,I|=0,C|=0;var E,n,a=0,r=0;return n=g|=0,g=B|=0,s=E=s-96|0,B=-1,TI(E+32|0,E)||(sI(a=E- -64|0,r=E+32|0,C),B=pI(A+32|0,I,n,g,a,C,E),I=i[E+60>>2],g=i[E+56>>2],Q[A+24|0]=g,Q[A+25|0]=g>>>8,Q[A+26|0]=g>>>16,Q[A+27|0]=g>>>24,Q[A+28|0]=I,Q[A+29|0]=I>>>8,Q[A+30|0]=I>>>16,Q[A+31|0]=I>>>24,I=i[E+52>>2],g=i[E+48>>2],Q[A+16|0]=g,Q[A+17|0]=g>>>8,Q[A+18|0]=g>>>16,Q[A+19|0]=g>>>24,Q[A+20|0]=I,Q[A+21|0]=I>>>8,Q[A+22|0]=I>>>16,Q[A+23|0]=I>>>24,I=i[E+44>>2],g=i[E+40>>2],Q[A+8|0]=g,Q[A+9|0]=g>>>8,Q[A+10|0]=g>>>16,Q[A+11|0]=g>>>24,Q[A+12|0]=I,Q[A+13|0]=I>>>8,Q[A+14|0]=I>>>16,Q[A+15|0]=I>>>24,I=i[E+36>>2],g=i[E+32>>2],Q[0|A]=g,Q[A+1|0]=g>>>8,Q[A+2|0]=g>>>16,Q[A+3|0]=g>>>24,Q[A+4|0]=I,Q[A+5|0]=I>>>8,Q[A+6|0]=I>>>16,Q[A+7|0]=I>>>24,Dg(E,32),Dg(r,32),Dg(a,24)),s=E+96|0,0|B},ga:function(A,I,g,B,C,Q){A|=0,I|=0,Q|=0;var E,i=0;return s=E=s-32|0,i=-1,!(B|=0)&(g|=0)>>>0>=48|B&&(sI(E,I,C|=0),i=cI(A,I+32|0,g-32|0,B-(g>>>0<32)|0,E,I,Q)),s=E+32|0,0|i},ha:function(){return 48},ia:_g,ja:lg,ka:pg,la:_g,ma:lg,na:pg,oa:function(){return 384},pa:function(A,I,g,B,C,Q,E){return 0|qI(A|=0,I|=0,g|=0,B|=0,C|=0,Q|=0,E|=0)},qa:PI,ra:function(A,I,g,B){return 0|ig(A|=0,I|=0,g|=0,B|=0)},sa:dI,ta:sg,ua:lg,va:function(A,I,g,B){return 0|_I(A|=0,I|=0,g|=0,B|=0)},wa:_g,xa:lg,ya:Gg,za:pg,Aa:function(A,I,g,B,C,a){A|=0,I|=0,g|=0,B|=0,a|=0;var r,o=0,e=0,f=0,c=0;return s=r=s-32|0,f=n[0|(C|=0)]|n[C+1|0]<<8|n[C+2|0]<<16|n[C+3|0]<<24,C=n[C+4|0]|n[C+5|0]<<8|n[C+6|0]<<16|n[C+7|0]<<24,i[r+24>>2]=0,i[r+28>>2]=0,i[r+16>>2]=f,i[r+20>>2]=C,QI(r,g,B),i[r+8>>2]=0,i[r+12>>2]=0,I-65>>>0<=4294967246?(i[8952]=28,A=-1):(g=r+16|0,I-65>>>0<4294967232?A=-1:(s=c=(B=s)-384&-64,!a|!A|((C=255&I)-65&255)>>>0<=191?(xI(),t()):(s=e=s-192|0,!a|(C-65&255)>>>0<=191?(xI(),t()):(E[e+130>>1]=257,Q[e+129|0]=32,Q[e+128|0]=C,RI(4|(I=e+128|0)),QI(8|I,0,0),i[e+152>>2]=0,i[e+156>>2]=0,i[e+144>>2]=0,i[e+148>>2]=0,r?(f=n[r+4|0]|n[r+5|0]<<8|n[r+6|0]<<16|n[r+7|0]<<24,o=e+128|0,I=n[0|r]|n[r+1|0]<<8|n[r+2|0]<<16|n[r+3|0]<<24,Q[o+32|0]=I,Q[o+33|0]=I>>>8,Q[o+34|0]=I>>>16,Q[o+35|0]=I>>>24,Q[o+36|0]=f,Q[o+37|0]=f>>>8,Q[o+38|0]=f>>>16,Q[o+39|0]=f>>>24,f=n[r+12|0]|n[r+13|0]<<8|n[r+14|0]<<16|n[r+15|0]<<24,I=n[r+8|0]|n[r+9|0]<<8|n[r+10|0]<<16|n[r+11|0]<<24,Q[o+40|0]=I,Q[o+41|0]=I>>>8,Q[o+42|0]=I>>>16,Q[o+43|0]=I>>>24,Q[o+44|0]=f,Q[o+45|0]=f>>>8,Q[o+46|0]=f>>>16,Q[o+47|0]=f>>>24):(i[e+168>>2]=0,i[e+172>>2]=0,i[e+160>>2]=0,i[e+164>>2]=0),g?(f=n[g+4|0]|n[g+5|0]<<8|n[g+6|0]<<16|n[g+7|0]<<24,o=e+128|0,I=n[0|g]|n[g+1|0]<<8|n[g+2|0]<<16|n[g+3|0]<<24,Q[o+48|0]=I,Q[o+49|0]=I>>>8,Q[o+50|0]=I>>>16,Q[o+51|0]=I>>>24,Q[o+52|0]=f,Q[o+53|0]=f>>>8,Q[o+54|0]=f>>>16,Q[o+55|0]=f>>>24,f=n[g+12|0]|n[g+13|0]<<8|n[g+14|0]<<16|n[g+15|0]<<24,I=n[g+8|0]|n[g+9|0]<<8|n[g+10|0]<<16|n[g+11|0]<<24,Q[o+56|0]=I,Q[o+57|0]=I>>>8,Q[o+58|0]=I>>>16,Q[o+59|0]=I>>>24,Q[o+60|0]=f,Q[o+61|0]=f>>>8,Q[o+62|0]=f>>>16,Q[o+63|0]=f>>>24):(i[e+184>>2]=0,i[e+188>>2]=0,i[e+176>>2]=0,i[e+180>>2]=0),wA(c,e+128|0),wI(e+32|0,0,96),gA(c,I=eI(e,a,32),128,0),Dg(I,128),s=I+192|0),gA(c,0,0,0),Y(c,A,C),s=B),A=0)),s=r+32|0,0|A},Ba:sg,Ca:function(A,I,g){return A|=0,qI(I|=0,32,g|=0,32,0,0,0),0|ZI(A,I)},Da:function(A,I){return A|=0,EI(I|=0,32),0|ZI(A,I)},Ea:function(A,I,g,B,C){I|=0,g|=0,B|=0,C|=0;var E,i,a=0,r=0;if(i=a=s,s=a=a-512&-64,E=(A|=0)||I){if(r=-1,!JI(a+96|0,B,C)){for(B=I||A,A=0,PI(I=a+128|0,0,0,64),ig(I,r=a+96|0,32,0),Dg(r,32),ig(I,g,32,0),ig(I,C,32,0),dI(I,a+32|0,64),Dg(I,384);I=(a+32|0)+A|0,Q[A+E|0]=n[0|I],Q[A+B|0]=n[I+32|0],32!=(0|(A=A+1|0)););Dg(a+32|0,64),r=0}return s=i,0|r}xI(),t()},Fa:function(A,I,g,B,C){I|=0,g|=0,B|=0,C|=0;var E,i,a=0,r=0;if(i=a=s,s=a=a-512&-64,E=(A|=0)||I){if(r=-1,!JI(a+96|0,B,C)){for(B=I||A,A=0,PI(I=a+128|0,0,0,64),ig(I,r=a+96|0,32,0),Dg(r,32),ig(I,C,32,0),ig(I,g,32,0),dI(I,a+32|0,64),Dg(I,384);I=(a+32|0)+A|0,Q[A+B|0]=n[0|I],Q[A+E|0]=n[I+32|0],32!=(0|(A=A+1|0)););Dg(a+32|0,64),r=0}return s=i,0|r}xI(),t()},Ga:pg,Ha:pg,Ia:pg,Ja:pg,Ka:kg,La:Hg,Ma:Hg,Na:_g,Oa:bg,Pa:Sg,Qa:bg,Ra:_g,Sa:function(){return 128},Ta:function(){return 1403},Ua:kg,Va:bg,Wa:function(){return 8192},Xa:function(){return-2147483648},Ya:Hg,Za:function(){return 67108864},_a:Ug,$a:function(){return 268435456},ab:function(){return 4},bb:function(){return 1073741824},cb:function(A,I,g,B,C,Q,E,n,a,r,o){var t;A|=0,I|=0,g|=0,B|=0,Q|=0,E|=0,a|=0,r|=0,I|=0,t=0|(C|=0),C=0|(n|=0);A:{switch((o|=0)-1|0){case 0:A=wI(A,0,I);I:{if(1==(0|g)|g>>>0>1)i[8952]=22;else if(!g&I>>>0<=15)i[8952]=28;else if(!(Q|a)&r>>>0<2147483649)if((!a&C>>>0>=3|0!=(0|a))&r>>>0>8191){if((0|A)!=(0|B)){A=_(C,r>>>10|0,1,B,t,E,16,A,I,0,0,1)?-1:0;break I}i[8952]=28}else i[8952]=28;else i[8952]=22;A=-1}break A;case 1:A=wI(A,0,I);I:{if(1==(0|g)|g>>>0>1)i[8952]=22;else if(!g&I>>>0<=15)i[8952]=28;else if(!(Q|a)&r>>>0<2147483649)if(!!(C|a)&r>>>0>8191){if((0|A)!=(0|B)){A=_(C,r>>>10|0,1,B,t,E,16,A,I,0,0,2)?-1:0;break I}i[8952]=28}else i[8952]=28;else i[8952]=22;A=-1}break A}i[8952]=28,A=-1}return 0|A},db:function(A,I,g,B,C,Q,E){return 0|NA(A|=0,I|=0,(A=0)|(g|=0),B|=0,A|(C|=0),Q|=0,E|=0)},eb:function(A,I,g,B,C,Q,E,n){A|=0,I|=0,B|=0,Q|=0,E|=0;var a=0;a=g|=0,a|=g=0,g|=C|=0;A:{switch((n|=0)-1|0){case 1:A=NA(A,I,a,B,g,Q,E);break A;default:xI(),t();case 0:}s=C=s-16|0,A=wI(A,0,128),!(B|Q)&E>>>0<2147483649?(!Q&g>>>0>=3|0!=(0|Q))&E>>>0>8191?(EI(C,16),A=_(g,E>>>10|0,1,I,a,C,16,0,32,A,128,1)?-1:0):(i[8952]=28,A=-1):(i[8952]=22,A=-1),s=C+16|0}return 0|A},fb:function(A,I,g,B){I|=0,g|=0,B|=0;A:if(LA(A|=0,1403,10))if(LA(A,1393,9))i[8952]=28,A=-1;else{if(1==(0|B)|B>>>0>1)i[8952]=22;else{if(!(A=tA(A,I,g,1)))break A;-35==(0|A)&&(i[8952]=28)}A=-1}else{if(1==(0|B)|B>>>0>1)i[8952]=22;else{if(!(A=tA(A,I,g,2)))break A;-35==(0|A)&&(i[8952]=28)}A=-1}return 0|A},gb:function(A,I,g,B){return I|=0,g|=0,B|=0,LA(A|=0,1403,10)?LA(A,1393,9)?(i[8952]=28,A=-1):A=eA(A,I,g,B,1):A=eA(A,I,g,B,2),0|A},hb:ZI,ib:JI,jb:pg,kb:pg,lb:pg,mb:ug,nb:_g,ob:Fg,pb:sg,qb:zI,rb:function(A,I,g,B,C,Q){return A|=0,I|=0,C|=0,Q|=0,!(B|=0)&(g|=0)>>>0>=4294967280|B&&(xI(),t()),EA(A+16|0,A,I,g,B,C,Q),0},sb:jI,tb:function(A,I,g,B,C,Q){return I|=0,0|(!(B|=0)&(g|=0)>>>0>=16|B?iA(A|=0,I+16|0,I,g-16|0,B-(g>>>0<16)|0,C|=0,Q|=0):-1)},ub:sg,vb:function(A,I,g){return A|=0,g|=0,EI(I|=0,24),x(A,I,g),YI(A),g=n[I+16|0]|n[I+17|0]<<8|n[I+18|0]<<16|n[I+19|0]<<24,I=n[I+20|0]|n[I+21|0]<<8|n[I+22|0]<<16|n[I+23|0]<<24,Q[A+44|0]=0,Q[A+45|0]=0,Q[A+46|0]=0,Q[A+47|0]=0,Q[A+48|0]=0,Q[A+49|0]=0,Q[A+50|0]=0,Q[A+51|0]=0,Q[A+36|0]=g,Q[A+37|0]=g>>>8,Q[A+38|0]=g>>>16,Q[A+39|0]=g>>>24,Q[A+40|0]=I,Q[A+41|0]=I>>>8,Q[A+42|0]=I>>>16,Q[A+43|0]=I>>>24,0},wb:function(A,I,g){return x(A|=0,I|=0,g|=0),YI(A),g=n[I+16|0]|n[I+17|0]<<8|n[I+18|0]<<16|n[I+19|0]<<24,I=n[I+20|0]|n[I+21|0]<<8|n[I+22|0]<<16|n[I+23|0]<<24,Q[A+44|0]=0,Q[A+45|0]=0,Q[A+46|0]=0,Q[A+47|0]=0,Q[A+48|0]=0,Q[A+49|0]=0,Q[A+50|0]=0,Q[A+51|0]=0,Q[A+36|0]=g,Q[A+37|0]=g>>>8,Q[A+38|0]=g>>>16,Q[A+39|0]=g>>>24,Q[A+40|0]=I,Q[A+41|0]=I>>>8,Q[A+42|0]=I>>>16,Q[A+43|0]=I>>>24,0},xb:X,yb:function(A,I,g,B,C,E,a,r,o,e){A|=0,I|=0,B|=0,a|=0,r|=0,o|=0,e|=0;var f=0,c=0,y=0,w=0;return c=C|=0,C=E|=0,E=0|c,r|=f,s=c=s-336|0,(g|=0)&&(i[g>>2]=0,i[g+4>>2]=0),!C&E>>>0<4294967279?(fg(y=c+16|0,64,w=A+32|0,A),og(f=c+80|0,y),Dg(y,64),gg(f,a,r,o),gg(f,34048,0-r&15,0),wI(y,0,64),Q[c+16|0]=e,WA(y,y,64,0,w,1,A),gg(f,y,64,0),Q[0|I]=n[c+16|0],WA(a=I+1|0,B,E,C,w,2,A),gg(f,a,E,C),gg(f,34048,15&E,0),QI(I=c+8|0,r,o),gg(f,I,8,0),QI(I,E- -64|0,C-((E>>>0<4294967232)-1|0)|0),gg(f,I,8,0),tg(f,I=E+a|0),Dg(f,256),yI(A+36|0,I),nI(w),(2&e||BI(w,4))&&X(A),g&&(C=(A=E+17|0)>>>0<17?C+1|0:C,i[g>>2]=A,i[g+4>>2]=C),s=c+336|0):(xI(),t()),0},zb:function(A,I,g,B,C,E,a,r,o,e){A|=0,I|=0,B|=0,C|=0,E|=0,a|=0,r|=0,e|=0;var f,c=0,y=0,w=0,D=0,h=0,p=0;E|=0,f=(o|=0)|c,s=c=s-352|0,(g|=0)&&(i[g>>2]=0,i[g+4>>2]=0),B&&(Q[0|B]=255),p=-1;A:{I:{if(!(!a&E>>>0<17)){if(!(o=a-(E>>>0<17)|0)&(D=E-17|0)>>>0>=4294967279|o)break I;fg(y=c+32|0,64,h=A+32|0,A),og(w=c+96|0,y),Dg(y,64),gg(w,r,f,e),gg(w,34048,0-f&15,0),wI(y,0,64),Q[c+32|0]=n[0|C],WA(y,y,64,0,h,1,A),r=n[c+32|0],Q[c+32|0]=n[0|C],gg(w,y,64,0),gg(w,y=C+1|0,D,o),gg(w,34048,E-1&15,0),QI(C=c+24|0,f,e),gg(w,C,8,0),QI(C,E=E+47|0,a=E>>>0<47?a+1|0:a),gg(w,C,8,0),tg(w,c),Dg(w,256),zA(c,y+D|0,16)?Dg(c,16):(WA(I,y,D,o,h,2,A),yI(A+36|0,c),nI(h),(2&r||BI(h,4))&&X(A),g&&(i[g>>2]=D,i[g+4>>2]=o),p=0,B&&(Q[0|B]=r))}s=c+352|0;break A}xI(),t()}return 0|p},Ab:function(){return 52},Bb:function(){return 17},Cb:ug,Db:pg,Eb:function(){return-18},Fb:Sg,Gb:kg,Hb:Hg,Ib:Ug,Jb:Gg,Kb:_g,Lb:function(A,I,g,B,C){A|=0,I|=0,g|=0,B|=0;var Q=0,E=0,i=0,a=0,r=0,o=0,t=0,e=0,f=0,c=0,y=0,s=0,w=0,D=0,p=0,u=0;if(E=C|=0,C=n[C+4|0]|n[C+5|0]<<8|n[C+6|0]<<16|n[C+7|0]<<24,o=1886610805^(Q=n[0|E]|n[E+1|0]<<8|n[E+2|0]<<16|n[E+3|0]<<24),r=1936682341^C,Q^=1852142177,t=1819895653^C,C=1852075885^(i=n[E+8|0]|n[E+9|0]<<8|n[E+10|0]<<16|n[E+11|0]<<24),a=1685025377^(E=n[E+12|0]|n[E+13|0]<<8|n[E+14|0]<<16|n[E+15|0]<<24),e=2037671283^i,f=1952801890^E,E=g,(0|(i=(I+g|0)-(c=7&g)|0))!=(0|I)){for(;y=n[0|I]|n[I+1|0]<<8|n[I+2|0]<<16|n[I+3|0]<<24,u=n[I+4|0]|n[I+5|0]<<8|n[I+6|0]<<16|n[I+7|0]<<24,w=uA(C,a,13),B=h,g=a+r|0,a=g=(o=C+o|0)>>>0<C>>>0?g+1|0:g,o=uA(r=o,g,32),D=h,e=uA(C=e^y,g=f^u,16),g=g+t|0,g=(C=C+Q|0)>>>0<Q>>>0?g+1|0:g,Q=C,e=uA(C^=e,t=g^(f=h),21),f=h,w=uA(r^=w,B=a^=B,17),p=h,g=g+B|0,Q=uA(a=Q+r|0,g=a>>>0<Q>>>0?g+1|0:g,32),B=h,w=uA(r=a^w,g^=p,13),p=h,a=g,s=r,g=t+D|0,t=r=C+o|0,C=g=r>>>0<C>>>0?g+1|0:g,g=g+a|0,o=r=s+r|0,a=g=r>>>0<t>>>0?g+1|0:g,g=uA(r,g,32),D=h,r=C^=f,C=uA(t^=e,C,16),e=h,f=g,s=C,g=B+r|0,Q=g=(C=Q+t|0)>>>0<Q>>>0?g+1|0:g,g=(e^=g)+D|0,B=r=f+(t=s^C)|0,e=uA(t,e,21)^B,f=(r=B>>>0<t>>>0?g+1|0:g)^h,g=a^p,o=uA(a=o^w,g,17),g=g+Q|0,g=(a=C+a|0)>>>0<C>>>0?g+1|0:g,C=(Q=a)^o,a=g^(t=h),o=B^y,r^=u,Q=uA(Q,g,32),t=h,(0|i)!=(0|(I=I+8|0)););I=i}switch(g=E<<24,E=0,B=g,c-1|0){case 6:B|=n[I+6|0]<<16;case 5:B|=n[I+5|0]<<8;case 4:B|=n[I+4|0];case 3:E|=(i=n[I+3|0])<<24,B|=g=i>>>8|0;case 2:E|=(i=n[I+2|0])<<16,B|=g=i>>>16|0;case 1:E|=(i=n[I+1|0])<<8,B|=g=i>>>24|0;case 0:E=n[0|I]|E}return c=uA(C,a,13),y=h,g=a+r|0,i=I=C+o|0,C=g=I>>>0<C>>>0?g+1|0:g,a=uA(I,g,32),r=h,f=I=uA(o=E^e,g=I=B^f,16),g=g+t|0,g=(I=Q+o|0)>>>0<Q>>>0?g+1|0:g,Q=I,t=uA(I^=f,o=g^(e=h),21),e=h,c=uA(i^=c,C^=y,17),y=h,g=g+C|0,g=(C=Q+i|0)>>>0<Q>>>0?g+1|0:g,Q=C,C=uA(C,g,32),f=h,c=uA(i=Q^c,g^=y,13),y=h,Q=g,s=i,g=r+o|0,a=i=I+a|0,I=g=i>>>0<I>>>0?g+1|0:g,g=g+Q|0,Q=g=(i=s+i|0)>>>0<a>>>0?g+1|0:g,r=uA(i,g,32),o=h,e=I=uA(a^=t,g=I^=e,16),g=g+f|0,g=(I=C+a|0)>>>0<C>>>0?g+1|0:g,C=I,t=uA(I^=e,a=g^(t=h),21),e=h,c=uA(i^=c,Q^=y,17),y=h,g=g+Q|0,g=(Q=C+i|0)>>>0<C>>>0?g+1|0:g,i=uA(C=Q,g,32),f=h,c=uA(Q=C^c,g^=y,13),y=h,C=g,s=Q,g=a+o|0,g=(Q=I+r|0)>>>0<I>>>0?g+1|0:g,I=E,E=Q,a=I^Q,I=g,g=(g^B)+C|0,B=g=(Q=s+a|0)>>>0<a>>>0?g+1|0:g,a=uA(Q,g,32),r=h,g=I^e,C=uA(I=E^t,g,16),E=h,o=C,g=g+f|0,g=(C=I+(255^i)|0)>>>0<I>>>0?g+1|0:g,i=uA(I=o^C,E^=g,21),o=h,e=uA(Q^=c,B^=y,17),f=h,g=g+B|0,g=(B=C+Q|0)>>>0<C>>>0?g+1|0:g,B=uA(C=B,g,32),t=h,e=uA(Q=C^e,g^=f,13),f=h,C=g,s=Q,g=E+r|0,E=Q=I+a|0,I=g=Q>>>0<I>>>0?g+1|0:g,g=g+C|0,C=g=(Q=s+Q|0)>>>0<E>>>0?g+1|0:g,a=uA(Q,g,32),r=h,o=I=uA(E^=i,g=I^=o,16),g=g+t|0,g=(I=B+E|0)>>>0<B>>>0?g+1|0:g,B=I,i=uA(I^=o,E=g^(i=h),21),o=h,e=uA(Q^=e,C^=f,17),f=h,g=g+C|0,B=uA(C=B+Q|0,g=C>>>0<B>>>0?g+1|0:g,32),t=h,e=uA(Q=C^e,g^=f,13),f=h,C=g,s=Q,g=E+r|0,a=Q=I+a|0,E=Q,I=g=Q>>>0<I>>>0?g+1|0:g,g=g+C|0,g=(Q=s+Q|0)>>>0<E>>>0?g+1|0:g,E=Q,C=g,r=uA(Q,g,32),c=h,a=I=uA(Q=i^a,g=I^=o,16),g=g+t|0,g=(I=B+Q|0)>>>0<B>>>0?g+1|0:g,B=I,I^=a,a=Q=g^(i=h),i=uA(I,Q,21),Q=h,t=uA(E^=e,C^=f,17),e=h,g=g+C|0,B=uA(C=B+E|0,g=C>>>0<B>>>0?g+1|0:g,32),o=h,e=g^=e,t=uA(C^=t,g,13),E=h,f=i,g=a+c|0,a=i=I+r|0,I=g=i>>>0<I>>>0?g+1|0:g,f=Q=uA(i^=f,g^=Q,16),g=g+o|0,g=(Q=B+i|0)>>>0<B>>>0?g+1|0:g,B=Q,Q=g,g=uA(f^B,g^(r=h),21),r=h,o=g,g=I+e|0,g=Q+(E^=g=(i=C+a|0)>>>0<C>>>0?g+1|0:g)|0,g=(I=B+(C=i^t)|0)>>>0<B>>>0?g+1|0:g,B=o^I^uA(C,E,17),C=h^g^r,QI(A,uA(I,g,32)^B,h^C),0},Mb:function(A){EI(A|=0,16)},Nb:function(){return 208},Ob:lg,Pb:pg,Qb:pg,Rb:lg,Sb:function(){return-65},Tb:function(A,I,g){return 0|P(A|=0,I|=0,g|=0)},Ub:function(A,I){var g;return A|=0,I|=0,s=g=s-32|0,EI(g,32),P(A,I,g),Dg(g,32),s=g+32|0,0},Vb:function(A,I,g,B,C,Q){var E;return I|=0,C|=0,Q|=0,s=E=s-16|0,VI(A|=0,E+8|0,gI(A- -64|0,g|=0,g=B|=0),g,C,Q),64!=i[E+8>>2]|i[E+12>>2]?(I&&(i[I>>2]=0,i[I+4>>2]=0),wI(A,0,g- -64|0),A=-1):(A=0,I&&(i[I>>2]=g- -64,i[I+4>>2]=C-((g>>>0<4294967232)-1|0))),s=E+16|0,0|A},Wb:function(A,I,g,B,C,Q){A|=0,I|=0,g|=0;var E=0;A:{I:{if(E=B|=0,!(!(C|=0)&B>>>0<64||(B=C-1|0,E=C=E+-64|0,!(B=C>>>0<4294967232?B+1|0:B)&C>>>0>4294967231|B))){if(!OI(g,C=g- -64|0,E,B,Q|=0))break I;A&&wI(A,0,E)}if(g=-1,!I)break A;i[I>>2]=0,i[I+4>>2]=0;break A}I&&(i[I>>2]=E,i[I+4>>2]=B),g=0,A&&gI(A,C,E)}return 0|g},Xb:function(A,I,g,B,C,Q){return 0|VI(A|=0,I|=0,g|=0,B|=0,C|=0,Q|=0)},Yb:function(A,I,g,B,C){return 0|OI(A|=0,I|=0,g|=0,B|=0,C|=0)},Zb:function(A){return GI(A|=0),0},_b:function(A,I,g,B){return 0|z(A|=0,I|=0,g|=0,B|=0)},$b:function(A,I,g,B){var C;return I|=0,g|=0,B|=0,s=C=s+-64|0,MA(A|=0,C),A=u(I,g,C,64,0,B,1),s=C- -64|0,0|A},ac:function(A,I,g){var B;return I|=0,g|=0,s=B=s+-64|0,MA(A|=0,B),A=J(I,B,64,0,g,1),s=B- -64|0,0|A},bc:function(A,I){A|=0;var g,B=0,C=0,E=0,i=0,n=0,a=0;if(s=g=s-256|0,a=-1,!sA(I|=0)&&!V(g+96|0,I)){for(s=B=(s=i=s-160|0)-1760|0,DI(E=B+480|0,C=g+96|0),fI(I=B+320|0,C),tI(B,I),xA(I,B,E),tI(E=B+160|0,I),DI(C=B+640|0,E),xA(I,B,C),tI(E,I),DI(C=B+800|0,E),xA(I,B,C),tI(E,I),DI(C=B+960|0,E),xA(I,B,C),tI(E,I),DI(C=B+1120|0,E),xA(I,B,C),tI(E,I),DI(C=B+1280|0,E),xA(I,B,C),tI(E,I),DI(C=B+1440|0,E),xA(I,B,C),tI(E,I),DI(B+1600|0,E),LI(i),I=252;fI(B+320|0,i),E=I,(0|(I=Q[I+33504|0]))>0?(tI(C=B+160|0,n=B+320|0),xA(n,C,(B+480|0)+r((254&I)>>>1|0,160)|0)):(0|I)>=0||(tI(C=B+160|0,n=B+320|0),JA(n,C,(B+480|0)+r((0-I&254)>>>1|0,160)|0)),tI(i,B+320|0),I=E-1|0,E;);s=B+1760|0,I=mI(i),s=i+160|0,I&&(ng(g),cA(g,g,E=g+136|0),ng(I=g+48|0),yA(I,I,E),O(g,g),H(I,I,g),T(A,I),a=0)}return s=g+256|0,0|a},cc:function(A,I){A|=0;var g,B=0;return s=g=s+-64|0,_I(g,I|=0,32,0),Q[0|g]=248&n[0|g],Q[g+31|0]=63&n[g+31|0]|64,I=i[g+20>>2],B=i[g+16>>2],Q[A+16|0]=B,Q[A+17|0]=B>>>8,Q[A+18|0]=B>>>16,Q[A+19|0]=B>>>24,Q[A+20|0]=I,Q[A+21|0]=I>>>8,Q[A+22|0]=I>>>16,Q[A+23|0]=I>>>24,I=i[g+12>>2],B=i[g+8>>2],Q[A+8|0]=B,Q[A+9|0]=B>>>8,Q[A+10|0]=B>>>16,Q[A+11|0]=B>>>24,Q[A+12|0]=I,Q[A+13|0]=I>>>8,Q[A+14|0]=I>>>16,Q[A+15|0]=I>>>24,I=i[g+4>>2],B=i[g>>2],Q[0|A]=B,Q[A+1|0]=B>>>8,Q[A+2|0]=B>>>16,Q[A+3|0]=B>>>24,Q[A+4|0]=I,Q[A+5|0]=I>>>8,Q[A+6|0]=I>>>16,Q[A+7|0]=I>>>24,I=i[g+28>>2],B=i[g+24>>2],Q[A+24|0]=B,Q[A+25|0]=B>>>8,Q[A+26|0]=B>>>16,Q[A+27|0]=B>>>24,Q[A+28|0]=I,Q[A+29|0]=I>>>8,Q[A+30|0]=I>>>16,Q[A+31|0]=I>>>24,Dg(g,64),s=g- -64|0,0},dc:FI,ec:SI,fc:function(A){var I=0,g=0;if((A|=0)>>>0>=2){for(g=(0-A>>>0)%(A>>>0)|0;(I=FI())>>>0<g>>>0;);A=(I>>>0)%(A>>>0)|0}else A=0;return 0|A},gc:EI,hc:function(A,I,g){fg(A|=0,I|=0,1024,g|=0)},ic:pg,jc:function(){var A=0,I=0;return(A=i[9096])&&(A=i[A+20>>2])&&(I=0|vg[0|A]()),0|I},kc:function(A,I,g){A|=0,I|=0,1==(0|(g|=0))|g>>>0>1&&(e(1259,1119,197,1036),t()),EI(A,I)},lc:function(A,I,g,B){A|=0,g|=0;var C=0,E=0,i=0;if(!((B|=0)>>>0>2147483646|B<<1>>>0>=(I|=0)>>>0)){if(I=0,B){for(;C=(I<<1)+A|0,E=15&(i=n[I+g|0]),Q[C+1|0]=22272+((E<<8)+(E+65526&55552)|0)>>>8,E=C,C=i>>>4|0,Q[0|E]=87+((C+65526>>>8&217)+C|0),(0|B)!=(0|(I=I+1|0)););I=B<<1}else I=0;return Q[I+A|0]=0,0|A}xI(),t()},mc:function(A,I,g,B,C,E,a){A|=0,I|=0,g|=0,C|=0,E|=0,a|=0;var r=0,o=0,t=0,e=0,f=0,c=0,y=0,s=0,w=0,D=0,h=0;A:if(B|=0){I:{g:{B:for(;;){for(o=r;;){C:{if(!(255&((w=(65526+(y=(223&(c=n[g+o|0]))-55&255)^y+65520)>>>8|0)|(t=65526+(D=48^c)>>>8|0)))){if(t=1,!C|255&f)break g;if(DA(C,c))break C;r=o;break A}if(I>>>0<=e>>>0){i[8952]=68,t=0;break g}if(r=y&w|t&D,255&f?(Q[A+e|0]=r|h,e=e+1|0):h=r<<4,f^=-1,t=1,(r=o+1|0)>>>0<B>>>0)continue B;break I}if(f=0,!((o=o+1|0)>>>0<B>>>0))break}break}r=(A=r+1|0)>>>0<B>>>0?B:A;break A}r=o}255&f?(i[8952]=28,s=-1,r=r-1|0,e=0):t||(e=0,s=-1)}return a?i[a>>2]=g+r:(0|B)!=(0|r)&&(i[8952]=28,s=-1),E&&(i[E>>2]=e),0|s},nc:function(A,I){var g;return A|=0,ag(I|=0),A=r(g=(A>>>0)/3|0,-3)+A|0,1+(r(1&(A>>>1|A),2&I?A+1|0:4)+(g<<2)|0)|0},oc:Z,pc:L,qc:function(){var A=0;return i[9097]?A=1:(i[8954]=0,s=A=s-16|0,NI(A),i[A>>2]&&(NI(A),wI(35820,0,40)),s=A+16|0,i[8953]=1,SI(),EI(36368,16),i[9097]=1,A=0),0|A},rc:function(A,I,g,B,C){A|=0,I|=0,g|=0,C|=0;var E,a=0,r=0,o=0;s=E=s-16|0;A:{if(B|=0){if(o=-1,(a=(a=B-1|0)-(r=a&B?(g>>>0)%(B>>>0)|0:g&a)|0)>>>0>=(-1^g)>>>0)break A;if(!((g=g+a|0)>>>0>=C>>>0))for(A&&(i[A>>2]=g+1),A=I+g|0,o=0,Q[E+15|0]=0,g=0;C=I=A-g|0,r=n[0|I]&n[E+15|0],I=(g^a)-1>>>24|0,Q[0|C]=r|128&I,Q[E+15|0]=I|n[E+15|0],(0|B)!=(0|(g=g+1|0)););}else o=-1;return s=E+16|0,0|o}xI(),t()},sc:function(A,I,g,B){A|=0,I|=0,g|=0,B|=0;var C,Q=0,E=0,a=0,r=0,o=0;if(i[12+(C=s-16|0)>>2]=0,B-1>>>0<g>>>0){for(o=(Q=g-1|0)+I|0,g=0,I=0;r=((128^(E=n[o-g|0]))-1&i[C+12>>2]-1&a-1)>>>8&1,i[C+12>>2]=i[C+12>>2]|0-r&g,I|=r,a|=E,(0|B)!=(0|(g=g+1|0)););i[A>>2]=Q-i[C+12>>2],A=I-1|0}else A=-1;return 0|A},tc:function(){return 1368},uc:function(){return 10},vc:Ug,wc:kg,xc:k,yc:b,zc:vg}}(A)}(gA)},instantiate:function(A,I){return{then:function(I){var g=new D.Module(A);I({instance:new D.Instance(g)})}}},RuntimeError:Error};y=[],"object"!=typeof D&&d("no native wasm support detected");var h,p,u,F,l,_,k,H=!1,G="undefined"!=typeof TextDecoder?new TextDecoder("utf8"):void 0;function U(A,I){return A?function(A,I,g){for(var B=I+g,C=I;A[C]&&!(C>=B);)++C;if(C-I>16&&A.subarray&&G)return G.decode(A.subarray(I,C));for(var Q="";I<C;){var E=A[I++];if(128&E){var i=63&A[I++];if(192!=(224&E)){var n=63&A[I++];if((E=224==(240&E)?(15&E)<<12|i<<6|n:(7&E)<<18|i<<12|n<<6|63&A[I++])<65536)Q+=String.fromCharCode(E);else{var a=E-65536;Q+=String.fromCharCode(55296|a>>10,56320|1023&a)}}else Q+=String.fromCharCode((31&E)<<6|i)}else Q+=String.fromCharCode(E)}return Q}(u,A,I):""}function S(A){h=A,a.HEAP8=p=new Int8Array(A),a.HEAP16=F=new Int16Array(A),a.HEAP32=l=new Int32Array(A),a.HEAPU8=u=new Uint8Array(A),a.HEAPU16=new Uint16Array(A),a.HEAPU32=new Uint32Array(A),a.HEAPF32=_=new Float32Array(A),a.HEAPF64=k=new Float64Array(A)}var b,m=a.INITIAL_MEMORY||16777216;(w=a.wasmMemory?a.wasmMemory:new D.Memory({initial:m/65536,maximum:32768}))&&(h=w.buffer),m=h.byteLength,S(h);var v=[],M=[],P=[],Y=0,N=null,R=null;function d(A){throw a.onAbort&&a.onAbort(A),s(A="Aborted("+A+")"),H=!0,A+=". Build with -s ASSERTIONS=1 for more info.",new D.RuntimeError(A)}a.preloadedImages={},a.preloadedAudios={};var J,x,L,K,X="data:application/octet-stream;base64,";function T(A){return A.startsWith(X)}function V(A){return A.startsWith("file://")}function q(A){try{if(A==J&&y)return new Uint8Array(y);var I=AA(A);if(I)return I;if(Q)return Q(A);throw"both async and sync fetching of the wasm failed"}catch(A){d(A)}}T(J="<<< WASM_BINARY_FILE >>>")||(x=J,J=a.locateFile?a.locateFile(x,c):c+x);var z={35048:function(){return a.getRandomValue()},35084:function(){if(void 0===a.getRandomValue)try{var A="object"==typeof window?window:self,I=void 0!==A.crypto?A.crypto:A.msCrypto,g=function(){var A=new Uint32Array(1);return I.getRandomValues(A),A[0]>>>0};g(),a.getRandomValue=g}catch(A){try{var B=__nccwpck_require__(6113),C=function(){var A=B.randomBytes(4);return(A[0]<<24|A[1]<<16|A[2]<<8|A[3])>>>0};C(),a.getRandomValue=C}catch(A){throw"No secure random number generator found"}}}};function j(A){for(;A.length>0;){var I=A.shift();if("function"!=typeof I){var g=I.func;"number"==typeof g?void 0===I.arg?W(g)():W(g)(I.arg):g(void 0===I.arg?null:I.arg)}else I(a)}}function W(A){return b.get(A)}var O=[];function Z(A){try{return w.grow(A-h.byteLength+65535>>>16),S(w.buffer),1}catch(A){}}var $="function"==typeof atob?atob:function(A){var I,g,B,C,Q,E,i="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",n="",a=0;A=A.replace(/[^A-Za-z0-9\+\/\=]/g,"");do{I=i.indexOf(A.charAt(a++))<<2|(C=i.indexOf(A.charAt(a++)))>>4,g=(15&C)<<4|(Q=i.indexOf(A.charAt(a++)))>>2,B=(3&Q)<<6|(E=i.indexOf(A.charAt(a++))),n+=String.fromCharCode(I),64!==Q&&(n+=String.fromCharCode(g)),64!==E&&(n+=String.fromCharCode(B))}while(a<A.length);return n};function AA(A){if(T(A))return function(A){if("boolean"==typeof f&&f){var I=Buffer.from(A,"base64");return new Uint8Array(I.buffer,I.byteOffset,I.byteLength)}try{for(var g=$(A),B=new Uint8Array(g.length),C=0;C<g.length;++C)B[C]=g.charCodeAt(C);return B}catch(A){throw new Error("Converting base64 string to bytes failed.")}}(A.slice(X.length))}var IA,gA={b:function(A,I,g,B){d("Assertion failed: "+U(A)+", at: "+[I?U(I):"unknown filename",g,B?U(B):"unknown function"])},e:function(){d("")},c:function(A,I,g){var B=function(A,I){var g;for(O.length=0,I>>=2;g=u[A++];){var B=g<105;B&&1&I&&I++,O.push(B?k[I++>>1]:l[I]),++I}return O}(I,g);return z[A].apply(null,B)},d:function(A){var I,g=u.length,B=2147483648;if((A>>>=0)>B)return!1;for(var C=1;C<=4;C*=2){var Q=g*(1+.2/C);if(Q=Math.min(Q,A+100663296),Z(Math.min(B,(I=Math.max(A,Q))+(65536-I%65536)%65536)))return!0}return!1},a:w};function BA(A){function I(){IA||(IA=!0,a.calledRun=!0,H||(j(M),a.onRuntimeInitialized&&a.onRuntimeInitialized(),function(){if(a.postRun)for("function"==typeof a.postRun&&(a.postRun=[a.postRun]);a.postRun.length;)A=a.postRun.shift(),P.unshift(A);var A;j(P)}()))}A=A||o,Y>0||(function(){if(a.preRun)for("function"==typeof a.preRun&&(a.preRun=[a.preRun]);a.preRun.length;)A=a.preRun.shift(),v.unshift(A);var A;j(v)}(),Y>0||(a.setStatus?(a.setStatus("Running..."),setTimeout((function(){setTimeout((function(){a.setStatus("")}),1),I()}),1)):I()))}if(function(){var A={a:gA};function I(A,I){var g,B=A.exports;a.asm=B,b=a.asm.zc,g=a.asm.f,M.unshift(g),function(A){if(Y--,a.monitorRunDependencies&&a.monitorRunDependencies(Y),0==Y&&(null!==N&&(clearInterval(N),N=null),R)){var I=R;R=null,I()}}()}function g(A){I(A.instance)}function B(I){return function(){if(!y&&(t||e)){if("function"==typeof fetch&&!V(J))return fetch(J,{credentials:"same-origin"}).then((function(A){if(!A.ok)throw"failed to load wasm binary file at '"+J+"'";return A.arrayBuffer()})).catch((function(){return q(J)}));if(C)return new Promise((function(A,I){C(J,(function(I){A(new Uint8Array(I))}),I)}))}return Promise.resolve().then((function(){return q(J)}))}().then((function(I){return D.instantiate(I,A)})).then((function(A){return A})).then(I,(function(A){s("failed to asynchronously prepare wasm: "+A),d(A)}))}if(Y++,a.monitorRunDependencies&&a.monitorRunDependencies(Y),a.instantiateWasm)try{return a.instantiateWasm(A,I)}catch(A){return s("Module.instantiateWasm callback failed with error: "+A),!1}y||"function"!=typeof D.instantiateStreaming||T(J)||V(J)||"function"!=typeof fetch?B(g):fetch(J,{credentials:"same-origin"}).then((function(I){return D.instantiateStreaming(I,A).then(g,(function(A){return s("wasm streaming compile failed: "+A),s("falling back to ArrayBuffer instantiation"),B(g)}))}))}(),a.___wasm_call_ctors=function(){return(a.___wasm_call_ctors=a.asm.f).apply(null,arguments)},a._crypto_aead_chacha20poly1305_encrypt_detached=function(){return(a._crypto_aead_chacha20poly1305_encrypt_detached=a.asm.g).apply(null,arguments)},a._crypto_aead_chacha20poly1305_encrypt=function(){return(a._crypto_aead_chacha20poly1305_encrypt=a.asm.h).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_encrypt_detached=function(){return(a._crypto_aead_chacha20poly1305_ietf_encrypt_detached=a.asm.i).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_encrypt=function(){return(a._crypto_aead_chacha20poly1305_ietf_encrypt=a.asm.j).apply(null,arguments)},a._crypto_aead_chacha20poly1305_decrypt_detached=function(){return(a._crypto_aead_chacha20poly1305_decrypt_detached=a.asm.k).apply(null,arguments)},a._crypto_aead_chacha20poly1305_decrypt=function(){return(a._crypto_aead_chacha20poly1305_decrypt=a.asm.l).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_decrypt_detached=function(){return(a._crypto_aead_chacha20poly1305_ietf_decrypt_detached=a.asm.m).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_decrypt=function(){return(a._crypto_aead_chacha20poly1305_ietf_decrypt=a.asm.n).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_keybytes=function(){return(a._crypto_aead_chacha20poly1305_ietf_keybytes=a.asm.o).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_npubbytes=function(){return(a._crypto_aead_chacha20poly1305_ietf_npubbytes=a.asm.p).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_nsecbytes=function(){return(a._crypto_aead_chacha20poly1305_ietf_nsecbytes=a.asm.q).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_abytes=function(){return(a._crypto_aead_chacha20poly1305_ietf_abytes=a.asm.r).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_messagebytes_max=function(){return(a._crypto_aead_chacha20poly1305_ietf_messagebytes_max=a.asm.s).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_keygen=function(){return(a._crypto_aead_chacha20poly1305_ietf_keygen=a.asm.t).apply(null,arguments)},a._crypto_aead_chacha20poly1305_keybytes=function(){return(a._crypto_aead_chacha20poly1305_keybytes=a.asm.u).apply(null,arguments)},a._crypto_aead_chacha20poly1305_npubbytes=function(){return(a._crypto_aead_chacha20poly1305_npubbytes=a.asm.v).apply(null,arguments)},a._crypto_aead_chacha20poly1305_nsecbytes=function(){return(a._crypto_aead_chacha20poly1305_nsecbytes=a.asm.w).apply(null,arguments)},a._crypto_aead_chacha20poly1305_abytes=function(){return(a._crypto_aead_chacha20poly1305_abytes=a.asm.x).apply(null,arguments)},a._crypto_aead_chacha20poly1305_messagebytes_max=function(){return(a._crypto_aead_chacha20poly1305_messagebytes_max=a.asm.y).apply(null,arguments)},a._crypto_aead_chacha20poly1305_keygen=function(){return(a._crypto_aead_chacha20poly1305_keygen=a.asm.z).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_encrypt_detached=function(){return(a._crypto_aead_xchacha20poly1305_ietf_encrypt_detached=a.asm.A).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_encrypt=function(){return(a._crypto_aead_xchacha20poly1305_ietf_encrypt=a.asm.B).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_decrypt_detached=function(){return(a._crypto_aead_xchacha20poly1305_ietf_decrypt_detached=a.asm.C).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_decrypt=function(){return(a._crypto_aead_xchacha20poly1305_ietf_decrypt=a.asm.D).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_keybytes=function(){return(a._crypto_aead_xchacha20poly1305_ietf_keybytes=a.asm.E).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_npubbytes=function(){return(a._crypto_aead_xchacha20poly1305_ietf_npubbytes=a.asm.F).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_nsecbytes=function(){return(a._crypto_aead_xchacha20poly1305_ietf_nsecbytes=a.asm.G).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_abytes=function(){return(a._crypto_aead_xchacha20poly1305_ietf_abytes=a.asm.H).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_messagebytes_max=function(){return(a._crypto_aead_xchacha20poly1305_ietf_messagebytes_max=a.asm.I).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_keygen=function(){return(a._crypto_aead_xchacha20poly1305_ietf_keygen=a.asm.J).apply(null,arguments)},a._crypto_auth_bytes=function(){return(a._crypto_auth_bytes=a.asm.K).apply(null,arguments)},a._crypto_auth_keybytes=function(){return(a._crypto_auth_keybytes=a.asm.L).apply(null,arguments)},a._crypto_auth=function(){return(a._crypto_auth=a.asm.M).apply(null,arguments)},a._crypto_auth_verify=function(){return(a._crypto_auth_verify=a.asm.N).apply(null,arguments)},a._crypto_auth_keygen=function(){return(a._crypto_auth_keygen=a.asm.O).apply(null,arguments)},a._crypto_box_seedbytes=function(){return(a._crypto_box_seedbytes=a.asm.P).apply(null,arguments)},a._crypto_box_publickeybytes=function(){return(a._crypto_box_publickeybytes=a.asm.Q).apply(null,arguments)},a._crypto_box_secretkeybytes=function(){return(a._crypto_box_secretkeybytes=a.asm.R).apply(null,arguments)},a._crypto_box_beforenmbytes=function(){return(a._crypto_box_beforenmbytes=a.asm.S).apply(null,arguments)},a._crypto_box_noncebytes=function(){return(a._crypto_box_noncebytes=a.asm.T).apply(null,arguments)},a._crypto_box_macbytes=function(){return(a._crypto_box_macbytes=a.asm.U).apply(null,arguments)},a._crypto_box_messagebytes_max=function(){return(a._crypto_box_messagebytes_max=a.asm.V).apply(null,arguments)},a._crypto_box_seed_keypair=function(){return(a._crypto_box_seed_keypair=a.asm.W).apply(null,arguments)},a._crypto_box_keypair=function(){return(a._crypto_box_keypair=a.asm.X).apply(null,arguments)},a._crypto_box_beforenm=function(){return(a._crypto_box_beforenm=a.asm.Y).apply(null,arguments)},a._crypto_box_detached_afternm=function(){return(a._crypto_box_detached_afternm=a.asm.Z).apply(null,arguments)},a._crypto_box_detached=function(){return(a._crypto_box_detached=a.asm._).apply(null,arguments)},a._crypto_box_easy_afternm=function(){return(a._crypto_box_easy_afternm=a.asm.$).apply(null,arguments)},a._crypto_box_easy=function(){return(a._crypto_box_easy=a.asm.aa).apply(null,arguments)},a._crypto_box_open_detached_afternm=function(){return(a._crypto_box_open_detached_afternm=a.asm.ba).apply(null,arguments)},a._crypto_box_open_detached=function(){return(a._crypto_box_open_detached=a.asm.ca).apply(null,arguments)},a._crypto_box_open_easy_afternm=function(){return(a._crypto_box_open_easy_afternm=a.asm.da).apply(null,arguments)},a._crypto_box_open_easy=function(){return(a._crypto_box_open_easy=a.asm.ea).apply(null,arguments)},a._crypto_box_seal=function(){return(a._crypto_box_seal=a.asm.fa).apply(null,arguments)},a._crypto_box_seal_open=function(){return(a._crypto_box_seal_open=a.asm.ga).apply(null,arguments)},a._crypto_box_sealbytes=function(){return(a._crypto_box_sealbytes=a.asm.ha).apply(null,arguments)},a._crypto_generichash_bytes_min=function(){return(a._crypto_generichash_bytes_min=a.asm.ia).apply(null,arguments)},a._crypto_generichash_bytes_max=function(){return(a._crypto_generichash_bytes_max=a.asm.ja).apply(null,arguments)},a._crypto_generichash_bytes=function(){return(a._crypto_generichash_bytes=a.asm.ka).apply(null,arguments)},a._crypto_generichash_keybytes_min=function(){return(a._crypto_generichash_keybytes_min=a.asm.la).apply(null,arguments)},a._crypto_generichash_keybytes_max=function(){return(a._crypto_generichash_keybytes_max=a.asm.ma).apply(null,arguments)},a._crypto_generichash_keybytes=function(){return(a._crypto_generichash_keybytes=a.asm.na).apply(null,arguments)},a._crypto_generichash_statebytes=function(){return(a._crypto_generichash_statebytes=a.asm.oa).apply(null,arguments)},a._crypto_generichash=function(){return(a._crypto_generichash=a.asm.pa).apply(null,arguments)},a._crypto_generichash_init=function(){return(a._crypto_generichash_init=a.asm.qa).apply(null,arguments)},a._crypto_generichash_update=function(){return(a._crypto_generichash_update=a.asm.ra).apply(null,arguments)},a._crypto_generichash_final=function(){return(a._crypto_generichash_final=a.asm.sa).apply(null,arguments)},a._crypto_generichash_keygen=function(){return(a._crypto_generichash_keygen=a.asm.ta).apply(null,arguments)},a._crypto_hash_bytes=function(){return(a._crypto_hash_bytes=a.asm.ua).apply(null,arguments)},a._crypto_hash=function(){return(a._crypto_hash=a.asm.va).apply(null,arguments)},a._crypto_kdf_bytes_min=function(){return(a._crypto_kdf_bytes_min=a.asm.wa).apply(null,arguments)},a._crypto_kdf_bytes_max=function(){return(a._crypto_kdf_bytes_max=a.asm.xa).apply(null,arguments)},a._crypto_kdf_contextbytes=function(){return(a._crypto_kdf_contextbytes=a.asm.ya).apply(null,arguments)},a._crypto_kdf_keybytes=function(){return(a._crypto_kdf_keybytes=a.asm.za).apply(null,arguments)},a._crypto_kdf_derive_from_key=function(){return(a._crypto_kdf_derive_from_key=a.asm.Aa).apply(null,arguments)},a._crypto_kdf_keygen=function(){return(a._crypto_kdf_keygen=a.asm.Ba).apply(null,arguments)},a._crypto_kx_seed_keypair=function(){return(a._crypto_kx_seed_keypair=a.asm.Ca).apply(null,arguments)},a._crypto_kx_keypair=function(){return(a._crypto_kx_keypair=a.asm.Da).apply(null,arguments)},a._crypto_kx_client_session_keys=function(){return(a._crypto_kx_client_session_keys=a.asm.Ea).apply(null,arguments)},a._crypto_kx_server_session_keys=function(){return(a._crypto_kx_server_session_keys=a.asm.Fa).apply(null,arguments)},a._crypto_kx_publickeybytes=function(){return(a._crypto_kx_publickeybytes=a.asm.Ga).apply(null,arguments)},a._crypto_kx_secretkeybytes=function(){return(a._crypto_kx_secretkeybytes=a.asm.Ha).apply(null,arguments)},a._crypto_kx_seedbytes=function(){return(a._crypto_kx_seedbytes=a.asm.Ia).apply(null,arguments)},a._crypto_kx_sessionkeybytes=function(){return(a._crypto_kx_sessionkeybytes=a.asm.Ja).apply(null,arguments)},a._crypto_pwhash_alg_argon2i13=function(){return(a._crypto_pwhash_alg_argon2i13=a.asm.Ka).apply(null,arguments)},a._crypto_pwhash_alg_argon2id13=function(){return(a._crypto_pwhash_alg_argon2id13=a.asm.La).apply(null,arguments)},a._crypto_pwhash_alg_default=function(){return(a._crypto_pwhash_alg_default=a.asm.Ma).apply(null,arguments)},a._crypto_pwhash_bytes_min=function(){return(a._crypto_pwhash_bytes_min=a.asm.Na).apply(null,arguments)},a._crypto_pwhash_bytes_max=function(){return(a._crypto_pwhash_bytes_max=a.asm.Oa).apply(null,arguments)},a._crypto_pwhash_passwd_min=function(){return(a._crypto_pwhash_passwd_min=a.asm.Pa).apply(null,arguments)},a._crypto_pwhash_passwd_max=function(){return(a._crypto_pwhash_passwd_max=a.asm.Qa).apply(null,arguments)},a._crypto_pwhash_saltbytes=function(){return(a._crypto_pwhash_saltbytes=a.asm.Ra).apply(null,arguments)},a._crypto_pwhash_strbytes=function(){return(a._crypto_pwhash_strbytes=a.asm.Sa).apply(null,arguments)},a._crypto_pwhash_strprefix=function(){return(a._crypto_pwhash_strprefix=a.asm.Ta).apply(null,arguments)},a._crypto_pwhash_opslimit_min=function(){return(a._crypto_pwhash_opslimit_min=a.asm.Ua).apply(null,arguments)},a._crypto_pwhash_opslimit_max=function(){return(a._crypto_pwhash_opslimit_max=a.asm.Va).apply(null,arguments)},a._crypto_pwhash_memlimit_min=function(){return(a._crypto_pwhash_memlimit_min=a.asm.Wa).apply(null,arguments)},a._crypto_pwhash_memlimit_max=function(){return(a._crypto_pwhash_memlimit_max=a.asm.Xa).apply(null,arguments)},a._crypto_pwhash_opslimit_interactive=function(){return(a._crypto_pwhash_opslimit_interactive=a.asm.Ya).apply(null,arguments)},a._crypto_pwhash_memlimit_interactive=function(){return(a._crypto_pwhash_memlimit_interactive=a.asm.Za).apply(null,arguments)},a._crypto_pwhash_opslimit_moderate=function(){return(a._crypto_pwhash_opslimit_moderate=a.asm._a).apply(null,arguments)},a._crypto_pwhash_memlimit_moderate=function(){return(a._crypto_pwhash_memlimit_moderate=a.asm.$a).apply(null,arguments)},a._crypto_pwhash_opslimit_sensitive=function(){return(a._crypto_pwhash_opslimit_sensitive=a.asm.ab).apply(null,arguments)},a._crypto_pwhash_memlimit_sensitive=function(){return(a._crypto_pwhash_memlimit_sensitive=a.asm.bb).apply(null,arguments)},a._crypto_pwhash=function(){return(a._crypto_pwhash=a.asm.cb).apply(null,arguments)},a._crypto_pwhash_str=function(){return(a._crypto_pwhash_str=a.asm.db).apply(null,arguments)},a._crypto_pwhash_str_alg=function(){return(a._crypto_pwhash_str_alg=a.asm.eb).apply(null,arguments)},a._crypto_pwhash_str_verify=function(){return(a._crypto_pwhash_str_verify=a.asm.fb).apply(null,arguments)},a._crypto_pwhash_str_needs_rehash=function(){return(a._crypto_pwhash_str_needs_rehash=a.asm.gb).apply(null,arguments)},a._crypto_scalarmult_base=function(){return(a._crypto_scalarmult_base=a.asm.hb).apply(null,arguments)},a._crypto_scalarmult=function(){return(a._crypto_scalarmult=a.asm.ib).apply(null,arguments)},a._crypto_scalarmult_bytes=function(){return(a._crypto_scalarmult_bytes=a.asm.jb).apply(null,arguments)},a._crypto_scalarmult_scalarbytes=function(){return(a._crypto_scalarmult_scalarbytes=a.asm.kb).apply(null,arguments)},a._crypto_secretbox_keybytes=function(){return(a._crypto_secretbox_keybytes=a.asm.lb).apply(null,arguments)},a._crypto_secretbox_noncebytes=function(){return(a._crypto_secretbox_noncebytes=a.asm.mb).apply(null,arguments)},a._crypto_secretbox_macbytes=function(){return(a._crypto_secretbox_macbytes=a.asm.nb).apply(null,arguments)},a._crypto_secretbox_messagebytes_max=function(){return(a._crypto_secretbox_messagebytes_max=a.asm.ob).apply(null,arguments)},a._crypto_secretbox_keygen=function(){return(a._crypto_secretbox_keygen=a.asm.pb).apply(null,arguments)},a._crypto_secretbox_detached=function(){return(a._crypto_secretbox_detached=a.asm.qb).apply(null,arguments)},a._crypto_secretbox_easy=function(){return(a._crypto_secretbox_easy=a.asm.rb).apply(null,arguments)},a._crypto_secretbox_open_detached=function(){return(a._crypto_secretbox_open_detached=a.asm.sb).apply(null,arguments)},a._crypto_secretbox_open_easy=function(){return(a._crypto_secretbox_open_easy=a.asm.tb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_keygen=function(){return(a._crypto_secretstream_xchacha20poly1305_keygen=a.asm.ub).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_init_push=function(){return(a._crypto_secretstream_xchacha20poly1305_init_push=a.asm.vb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_init_pull=function(){return(a._crypto_secretstream_xchacha20poly1305_init_pull=a.asm.wb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_rekey=function(){return(a._crypto_secretstream_xchacha20poly1305_rekey=a.asm.xb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_push=function(){return(a._crypto_secretstream_xchacha20poly1305_push=a.asm.yb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_pull=function(){return(a._crypto_secretstream_xchacha20poly1305_pull=a.asm.zb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_statebytes=function(){return(a._crypto_secretstream_xchacha20poly1305_statebytes=a.asm.Ab).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_abytes=function(){return(a._crypto_secretstream_xchacha20poly1305_abytes=a.asm.Bb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_headerbytes=function(){return(a._crypto_secretstream_xchacha20poly1305_headerbytes=a.asm.Cb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_keybytes=function(){return(a._crypto_secretstream_xchacha20poly1305_keybytes=a.asm.Db).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_messagebytes_max=function(){return(a._crypto_secretstream_xchacha20poly1305_messagebytes_max=a.asm.Eb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_tag_message=function(){return(a._crypto_secretstream_xchacha20poly1305_tag_message=a.asm.Fb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_tag_push=function(){return(a._crypto_secretstream_xchacha20poly1305_tag_push=a.asm.Gb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_tag_rekey=function(){return(a._crypto_secretstream_xchacha20poly1305_tag_rekey=a.asm.Hb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_tag_final=function(){return(a._crypto_secretstream_xchacha20poly1305_tag_final=a.asm.Ib).apply(null,arguments)},a._crypto_shorthash_bytes=function(){return(a._crypto_shorthash_bytes=a.asm.Jb).apply(null,arguments)},a._crypto_shorthash_keybytes=function(){return(a._crypto_shorthash_keybytes=a.asm.Kb).apply(null,arguments)},a._crypto_shorthash=function(){return(a._crypto_shorthash=a.asm.Lb).apply(null,arguments)},a._crypto_shorthash_keygen=function(){return(a._crypto_shorthash_keygen=a.asm.Mb).apply(null,arguments)},a._crypto_sign_statebytes=function(){return(a._crypto_sign_statebytes=a.asm.Nb).apply(null,arguments)},a._crypto_sign_bytes=function(){return(a._crypto_sign_bytes=a.asm.Ob).apply(null,arguments)},a._crypto_sign_seedbytes=function(){return(a._crypto_sign_seedbytes=a.asm.Pb).apply(null,arguments)},a._crypto_sign_publickeybytes=function(){return(a._crypto_sign_publickeybytes=a.asm.Qb).apply(null,arguments)},a._crypto_sign_secretkeybytes=function(){return(a._crypto_sign_secretkeybytes=a.asm.Rb).apply(null,arguments)},a._crypto_sign_messagebytes_max=function(){return(a._crypto_sign_messagebytes_max=a.asm.Sb).apply(null,arguments)},a._crypto_sign_seed_keypair=function(){return(a._crypto_sign_seed_keypair=a.asm.Tb).apply(null,arguments)},a._crypto_sign_keypair=function(){return(a._crypto_sign_keypair=a.asm.Ub).apply(null,arguments)},a._crypto_sign=function(){return(a._crypto_sign=a.asm.Vb).apply(null,arguments)},a._crypto_sign_open=function(){return(a._crypto_sign_open=a.asm.Wb).apply(null,arguments)},a._crypto_sign_detached=function(){return(a._crypto_sign_detached=a.asm.Xb).apply(null,arguments)},a._crypto_sign_verify_detached=function(){return(a._crypto_sign_verify_detached=a.asm.Yb).apply(null,arguments)},a._crypto_sign_init=function(){return(a._crypto_sign_init=a.asm.Zb).apply(null,arguments)},a._crypto_sign_update=function(){return(a._crypto_sign_update=a.asm._b).apply(null,arguments)},a._crypto_sign_final_create=function(){return(a._crypto_sign_final_create=a.asm.$b).apply(null,arguments)},a._crypto_sign_final_verify=function(){return(a._crypto_sign_final_verify=a.asm.ac).apply(null,arguments)},a._crypto_sign_ed25519_pk_to_curve25519=function(){return(a._crypto_sign_ed25519_pk_to_curve25519=a.asm.bc).apply(null,arguments)},a._crypto_sign_ed25519_sk_to_curve25519=function(){return(a._crypto_sign_ed25519_sk_to_curve25519=a.asm.cc).apply(null,arguments)},a._randombytes_random=function(){return(a._randombytes_random=a.asm.dc).apply(null,arguments)},a._randombytes_stir=function(){return(a._randombytes_stir=a.asm.ec).apply(null,arguments)},a._randombytes_uniform=function(){return(a._randombytes_uniform=a.asm.fc).apply(null,arguments)},a._randombytes_buf=function(){return(a._randombytes_buf=a.asm.gc).apply(null,arguments)},a._randombytes_buf_deterministic=function(){return(a._randombytes_buf_deterministic=a.asm.hc).apply(null,arguments)},a._randombytes_seedbytes=function(){return(a._randombytes_seedbytes=a.asm.ic).apply(null,arguments)},a._randombytes_close=function(){return(a._randombytes_close=a.asm.jc).apply(null,arguments)},a._randombytes=function(){return(a._randombytes=a.asm.kc).apply(null,arguments)},a._sodium_bin2hex=function(){return(a._sodium_bin2hex=a.asm.lc).apply(null,arguments)},a._sodium_hex2bin=function(){return(a._sodium_hex2bin=a.asm.mc).apply(null,arguments)},a._sodium_base64_encoded_len=function(){return(a._sodium_base64_encoded_len=a.asm.nc).apply(null,arguments)},a._sodium_bin2base64=function(){return(a._sodium_bin2base64=a.asm.oc).apply(null,arguments)},a._sodium_base642bin=function(){return(a._sodium_base642bin=a.asm.pc).apply(null,arguments)},a._sodium_init=function(){return(a._sodium_init=a.asm.qc).apply(null,arguments)},a._sodium_pad=function(){return(a._sodium_pad=a.asm.rc).apply(null,arguments)},a._sodium_unpad=function(){return(a._sodium_unpad=a.asm.sc).apply(null,arguments)},a._sodium_version_string=function(){return(a._sodium_version_string=a.asm.tc).apply(null,arguments)},a._sodium_library_version_major=function(){return(a._sodium_library_version_major=a.asm.uc).apply(null,arguments)},a._sodium_library_version_minor=function(){return(a._sodium_library_version_minor=a.asm.vc).apply(null,arguments)},a._sodium_library_minimal=function(){return(a._sodium_library_minimal=a.asm.wc).apply(null,arguments)},a._malloc=function(){return(a._malloc=a.asm.xc).apply(null,arguments)},a._free=function(){return(a._free=a.asm.yc).apply(null,arguments)},a.setValue=function(A,I,g="i8",B){switch("*"===g.charAt(g.length-1)&&(g="i32"),g){case"i1":case"i8":p[A>>0]=I;break;case"i16":F[A>>1]=I;break;case"i32":l[A>>2]=I;break;case"i64":K=[I>>>0,(L=I,+Math.abs(L)>=1?L>0?(0|Math.min(+Math.floor(L/4294967296),4294967295))>>>0:~~+Math.ceil((L-+(~~L>>>0))/4294967296)>>>0:0)],l[A>>2]=K[0],l[A+4>>2]=K[1];break;case"float":_[A>>2]=I;break;case"double":k[A>>3]=I;break;default:d("invalid type for setValue: "+g)}},a.getValue=function(A,I="i8",g){switch("*"===I.charAt(I.length-1)&&(I="i32"),I){case"i1":case"i8":return p[A>>0];case"i16":return F[A>>1];case"i32":case"i64":return l[A>>2];case"float":return _[A>>2];case"double":return Number(k[A>>3]);default:d("invalid type for getValue: "+I)}return null},a.UTF8ToString=U,R=function A(){IA||BA(),IA||(R=A)},a.run=BA,a.preInit)for("function"==typeof a.preInit&&(a.preInit=[a.preInit]);a.preInit.length>0;)a.preInit.pop()();BA()}))};var g,C,Q,E,i,n,a=void 0!==a?a:{},r=Object.assign({},a),o=[],t="object"==typeof window,e="function"==typeof importScripts,f="object"==typeof process&&"object"==typeof process.versions&&"string"==typeof process.versions.node,c="";f?(c=e?(__nccwpck_require__(1017).dirname)(c)+"/":__dirname+"/",n=()=>{i||(E=__nccwpck_require__(7147),i=__nccwpck_require__(1017))},g=function(A,I){var g=Z(A);return g?I?g:g.toString():(n(),A=i.normalize(A),E.readFileSync(A,I?void 0:"utf8"))},Q=A=>{var I=g(A,!0);return I.buffer||(I=new Uint8Array(I)),I},C=(A,I,g)=>{var B=Z(A);B&&I(B),n(),A=i.normalize(A),E.readFile(A,(function(A,B){A?g(A):I(B.buffer)}))},process.argv.length>1&&process.argv[1].replace(/\\/g,"/"),o=process.argv.slice(2), true&&(module.exports=a),a.inspect=function(){return"[Emscripten Module object]"}):(t||e)&&(e?c=self.location.href:"undefined"!=typeof document&&document.currentScript&&(c=document.currentScript.src),c=0!==c.indexOf("blob:")?c.substr(0,c.replace(/[?#].*/,"").lastIndexOf("/")+1):"",g=A=>{try{var I=new XMLHttpRequest;return I.open("GET",A,!1),I.send(null),I.responseText}catch(I){var g=Z(A);if(g)return function(A){for(var I=[],g=0;g<A.length;g++){var B=A[g];B>255&&(B&=255),I.push(String.fromCharCode(B))}return I.join("")}(g);throw I}},e&&(Q=A=>{try{var I=new XMLHttpRequest;return I.open("GET",A,!1),I.responseType="arraybuffer",I.send(null),new Uint8Array(I.response)}catch(I){var g=Z(A);if(g)return g;throw I}}),C=(A,I,g)=>{var B=new XMLHttpRequest;B.open("GET",A,!0),B.responseType="arraybuffer",B.onload=()=>{if(200==B.status||0==B.status&&B.response)I(B.response);else{var C=Z(A);C?I(C.buffer):g()}},B.onerror=g,B.send(null)}),a.print;var y,s,w=a.printErr||void 0;Object.assign(a,r),r=null,a.arguments&&(o=a.arguments),a.thisProgram&&a.thisProgram,a.quit&&a.quit,a.wasmBinary&&(y=a.wasmBinary),a.noExitRuntime,"object"!=typeof WebAssembly&&N("no native wasm support detected");var D,h,p,u,F,l,_,k=!1,H="undefined"!=typeof TextDecoder?new TextDecoder("utf8"):void 0;function G(A,I){return A?function(A,I,g){for(var B=I+g,C=I;A[C]&&!(C>=B);)++C;if(C-I>16&&A.subarray&&H)return H.decode(A.subarray(I,C));for(var Q="";I<C;){var E=A[I++];if(128&E){var i=63&A[I++];if(192!=(224&E)){var n=63&A[I++];if((E=224==(240&E)?(15&E)<<12|i<<6|n:(7&E)<<18|i<<12|n<<6|63&A[I++])<65536)Q+=String.fromCharCode(E);else{var a=E-65536;Q+=String.fromCharCode(55296|a>>10,56320|1023&a)}}else Q+=String.fromCharCode((31&E)<<6|i)}else Q+=String.fromCharCode(E)}return Q}(p,A,I):""}function U(A){D=A,a.HEAP8=h=new Int8Array(A),a.HEAP16=u=new Int16Array(A),a.HEAP32=F=new Int32Array(A),a.HEAPU8=p=new Uint8Array(A),a.HEAPU16=new Uint16Array(A),a.HEAPU32=new Uint32Array(A),a.HEAPF32=l=new Float32Array(A),a.HEAPF64=_=new Float64Array(A)}a.INITIAL_MEMORY;var S,b=[],m=[],v=[],M=0,P=null,Y=null;function N(A){throw a.onAbort&&a.onAbort(A),w(A="Aborted("+A+")"),k=!0,A+=". Build with -s ASSERTIONS=1 for more info.",new WebAssembly.RuntimeError(A)}a.preloadedImages={},a.preloadedAudios={};var R,d,J,x,L="data:application/octet-stream;base64,";function K(A){return A.startsWith(L)}function X(A){return A.startsWith("file://")}function T(A){try{if(A==R&&y)return new Uint8Array(y);var I=Z(A);if(I)return I;if(Q)return Q(A);throw"both async and sync fetching of the wasm failed"}catch(A){N(A)}}K(R="data:application/octet-stream;base64,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ASgCPDYCPCABQUBrIQEgAkFAayICIAVNDQALCyACIARPDQEDQCACIAEoAgA2AgAgAUEEaiEBIAJBBGoiAiAESQ0ACwwBCyADQQRJBEAgACECDAELIAAgA0EEayIESwRAIAAhAgwBCyAAIQIDQCACIAEtAAA6AAAgAiABLQABOgABIAIgAS0AAjoAAiACIAEtAAM6AAMgAUEEaiEBIAJBBGoiAiAETQ0ACwsgAiADSQRAA0AgAiABLQAAOgAAIAFBAWohASACQQFqIgIgA0cNAAsLIAAL7AEBEn8gAigCBCEDIAEoAgQhBCACKAIIIQUgASgCCCEGIAIoAgwhByABKAIMIQggAigCECEJIAEoAhAhCiACKAIUIQsgASgCFCEMIAIoAhghDSABKAIYIQ4gAigCHCEPIAEoAhwhECACKAIgIREgASgCICESIAIoAiQhEyABKAIkIRQgACACKAIAIAEoAgBqNgIAIAAgEyAUajYCJCAAIBEgEmo2AiAgACAPIBBqNgIcIAAgDSAOajYCGCAAIAsgDGo2AhQgACAJIApqNgIQIAAgByAIajYCDCAAIAUgBmo2AgggACADIARqNgIEC0ABA38gACABIAFB+ABqIgIQCiAAQShqIAFBKGoiAyABQdAAaiIEEAogAEHQAGogBCACEAogAEH4AGogASADEAoLGAEBf0GonAIoAgAiAARAIAARDwALEAMAC+wBARJ/IAIoAgQhAyABKAIEIQQgAigCCCEFIAEoAgghBiACKAIMIQcgASgCDCEIIAIoAhAhCSABKAIQIQogAigCFCELIAEoAhQhDCACKAIYIQ0gASgCGCEOIAIoAhwhDyABKAIcIRAgAigCICERIAEoAiAhEiACKAIkIRMgASgCJCEUIAAgASgCACACKAIAazYCACAAIBQgE2s2AiQgACASIBFrNgIgIAAgECAPazYCHCAAIA4gDWs2AhggACAMIAtrNgIUIAAgCiAJazYCECAAIAggB2s2AgwgACAGIAVrNgIIIAAgBCADazYCBAsEAEEgCwoAIAAgASACEDgLzAwBB38CQCAARQ0AIABBCGsiAyAAQQRrKAIAIgFBeHEiAGohBQJAIAFBAXENACABQQNxRQ0BIAMgAygCACIBayIDQaSYAigCAEkNASAAIAFqIQAgA0GomAIoAgBHBEAgAUH/AU0EQCAD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IAAhAQJAIABBA3EEQANAIAEtAABFDQIgAUEBaiIBQQNxDQALCwNAIAEiAkEEaiEBIAIoAgAiA0F/cyADQYGChAhrcUGAgYKEeHFFDQALIANB/wFxRQRAIAIgAGsPCwNAIAItAAEhAyACQQFqIgEhAiADDQALCyABIABrCygAIAAgASACEFUgAEEoaiABQShqIAIQVSAAQdAAaiABQdAAaiACEFULEQAgACABQdSRAigCABEDABoLEQAgACABQcyRAigCABEDABoLCgAgACABIAIQFwsRACAAIAFzQf8BcUEBa0EfdguwAQEDfyMAQcAFayICJAACQCAAKAJIQQN2Qf8AcSIDQe8ATQRAIAAgA2pB0ABqQeCPAkHwACADaxARGgwBCyAAQdAAaiIEIANqQeCPAkGAASADaxARGiAAIAQgAiACQYAFahBHIARBAEHwABAPGgsgAEHAAWogAEFAa0EQEKUBIAAgAEHQAGogAiACQYAFahBHIAEgAEHAABClASACQcAFEAggAEHQARAIIAJBwAVqJAALCAAgAEEgEB0LRgEEfiABKQIIIQIgASkCECEDIAEpAhghBCABKQIAIQUgACABKQIgNwIgIAAgBDcCGCAAIAM3AhAgACACNwIIIAAgBTcCAAtSAQJ/QbCRAigCACIBIABBA2pBfHEiAmohAAJAIAJBACAAIAFNGw0AIAA/AEEQdEsEQCAAEAJFDQELQbCRAiAANgIAIAEPC0HglwJBMDYCAEF/CwwAIAAgAUGACBARGgv6BQEKfyMAQTBrIgIkACACIAEoAiAiAyABKAIcIgQgASgCGCIFIAEoAhQiBiABKAIQIgcgASgCDCIIIAEoAggiCSABKAIEIgogASgCACILIAEoAiQiAUETbEGAgIAIakEZdmpBGnVqQRl1akEadWpBGXVqQRp1akEZdWpBGnVqQRl1akEadSABakEZdUETbCALaiILQf///x9xNgIAIAIgCiALQRp1aiIKQf///w9xNgIEIAIgCSAKQRl1aiIJQf///x9xNgIIIAIgCCAJQRp1aiIIQf///w9xNgIMIAIgByAIQRl1aiIHQf///x9xNgIQIAIgBiAHQRp1aiIGQf///w9xNgIUIAIgBSAGQRl1aiIFQf///x9xNgIYIAIgBCAFQRp1aiIEQf///w9xNgIcIAIgAyAEQRl1aiID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IABBPGoiASAcKAIUEAkgAEFAayABQgQQFxogHCgCECIBBEAgAEFAayABIBw1AhQQFxoLIABBPGoiASAcKAIcEAkgAEFAayABQgQQFxoCQCAcKAIYIgFFDQAgAEFAayABIBw1AhwQFxogHC0AOEECcUUNACAcKAIYIBwoAhwQCCAcQQA2AhwLIABBPGoiASAcKAIkEAkgAEFAayABQgQQFxogHCgCICIBBEAgAEFAayABIBw1AiQQFxoLIABBQGsgBEHAABBMGgsgBiQAIARBQGtBCBAIQQAhAyMAQYAIayIAJAAgAigCHARAIARBxABqIQUgBEFAayEBA0AgAUEAEAkgBSADEAkgAEGACCAEQcgAEFogAigCACgCBCACKAIYIANsQQp0aiAAEIgBIAFBARAJIABBgAggBEHIABBaIAIoAgAoAgQgAigCGCADbEEKdGpBgAhqIAAQiAEgA0EBaiIDIAIoAhxJDQALCyAAQYAIEAggAEGACGokACAEQcgAEAhBACEDCyAEQdAAaiQAIAMiAA0AIAIoAggEQANAQQAhICMAQSBrIgMkAAJAIAJFDQAgAigCHEUNACADICU2AhBBASEBA0AgAyAgOgAYQQAhHkEAIQAgAQRAA0AgA0EANgIcIAMgAykDGDcDCCADIB42AhQgAyADKQMQNwMAQQAhAQJAIAJFDQACfwJAIAIoAiRBAkcEQCACKAIEIR8MAQsgAigCBCEfQQEgAygCACIFIAMtAAgiBEEBS3INARoLIwBBgCBrIgAkACAAQYAYahA+IABBgBBqED4CQCACRSADRXINACAAIAM1AgA3A4AQIAAgAzUCBDcDiBAgACADMQAINwOQECAAIAI1AhA3A5gQIAAgAjUCCDcDoBAgACACNQIkNwOoECACKAIURQ0AA0AgAUH/AHEiBEUEQCAAIAApA7AQQgF8NwOwECAAED4gAEGACGoiBRA+IABBgBhqIgYgAEGAEGogABBZIAYgACAFEFkLIB8gAUEDdGogAEGACGogBEEDdGopAwA3AwAgAUEBaiIBIAIoAhRJDQALCyAAQYAgaiQAIAMtAAghBCADKAIAIQVBAAshJkEAIARB/wFxIgFFQQF0IAUbIgUgAigCFCIETw0AQX8gAigCGCIAQQFrIAUgACADKAIEbGogASAEbGoiBCAAcBsgBGohAQNAIARB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AWsgHCgCACAcKAIEQQMQaBshAQwBC0FhIQELIABBEGokACABRQ0AICIgCBAIIAkgChAIQWEhAgwBCyAHBEAgByAiIAgQERoLICIgCBAIQQAhAgsgIhAYCyAcQUBrJAAgAgsrAQF/IwBB0AFrIgMkACADEDYgAyABIAIQGxogAyAAECcgA0HQAWokAEEACxwAIABCADcDQCAAQgA3A0ggAEGgigJBwAAQERoLBABBbwvBAQIFfwF+IAJQRQRAIAJBgAIgACgA4AIiBGsiA60iCFYEQCAAQeABaiEGIABB4ABqIQUDQCAAIARqQeAAaiABIAMQERogACAAKADgAiADajYA4AIgAEKAARBxIAAgBRB0IAUgBkGAARARGiAAIAAoAOACIgdBgAFrIgQ2AOACIAEgA2ohASACIAh9IgJBgAMgB2siA60iCFYNAAsLIAAgBGpB4ABqIAEgAqciARARGiAAIAAoAOACIAFqNgDgAgtBAAupAwEVfyABKAIEIQsgACgCBCEMIAEoAgghDSAAKAIIIQ4gASgCDCEPIAAoAgwhAyABKAIQIRAgACgCECEEIAEoAhQhESAAKAIUIQUgASgCGCESIAAoAhghBiABKAIcIRMgACgCHCEHIAEoAiAhFCAAKAIgIQggASgCJCEVIAAoAiQhCSAAQQAgAmsiAiABKAIAIhYgACgCACIKc3EiFyAKczYCACAAIAkgCSAVcyACcSIKczYCJCAAIAggCCAUcyACcSIJczYCICAAIAcgByATcyACcSIIczYCHCAAIAYgBiAScyACcSIHczYCGCAAIAUgBSARcyACcSIGczYCFCAAIAQgBCAQcyACcSIFczYCECAAIAMgAyAPcyACcSIEczYCDCAAIA4gDSAOcyACcSIDczYCCCAAIAwgCyAMcyACcSIAczYCBCABIAogFXM2AiQgASAJIBRzNgIgIAEgCCATczYCHCABIAcgEnM2AhggASAGIBFzNgIUIAEgBSAQczYCECABIAQgD3M2AgwgASADIA1zNgIIIAEgACALczYCBCABIBYgF3M2AgALQQECfyMAQYABayIDJAAgA0EIaiICIAEQKSACQShqIAFBKGoQKSACQdAAaiABQdAAahApIAAgAhAxIANBgAFqJAALMgEBfyAAIAEgAUH4AGoiAhAKIABBKGogAUEoaiABQdAAaiIB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KAIcIQkgASgCICETIAAoAiAhCiABKAIkIRQgACgCJCELIABBACACayICIAAoAgAiFSABKAIAc3EgFXM2AgAgACALIAsgFHMgAnFzNgIkIAAgCiAKIBNzIAJxczYCICAAIAkgCSAScyACcXM2AhwgACAIIAggEXMgAnFzNgIYIAAgByAHIBBzIAJxczYCFCAAIAYgBiAPcyACcXM2AhAgACAFIAUgDnMgAnFzNgIMIAAgBCAEIA1zIAJxczYCCCAAIAMgAyAMcyACcXM2AgQLJAEBfyMAQSBrIgEkACABIAAQLCABQSAQdSEAIAFBIGokACAAC6YEAg5+Cn8gACgCJCESIAAoAiAhEyAAKAIcIRQgACgCGCEVIAAoAhQhESACQhBaBEAgAC0AUEVBGHQhFiAAKAIEIhdBBWytIQ8gACgCCCIYQQVsrSENIAAoAgwiGUEFbK0hCyAAKAIQIhpBBWytIQkgGq0hECAZrSEOIBitIQwgF60hCiAANQIAIQgDQCABKAADQQJ2Qf///x9xIBVqrSIDIA5+IAEoAABB////H3EgEWqtIgQgEH58IAEoAAZBBHZB////H3EgFGqtIgUgDH58IAEoAAlBBnYgE2qtIgYgCn58IBIgFmogASgADEEIdmqtIgcgCH58IAMgDH4gBCAOfnwgBSAKfnwgBiAIfnwgByAJfnwgAyAKfiAEIAx+fCAFIAh+fCAGIAl+fCAHIAt+fCADIAh+IAQgCn58IAUgCX58IAYgC358IAcgDX58IAMgCX4gBCAIfnwgBSALfnwgBiANfnwgByAPfnwiA0IaiEL/////D4N8IgRCGohC/////w+DfCIFQhqIQv////8Pg3wiBkIaiEL/////D4N8IgdCGoinQQVsIAOnQf///x9xaiIRQRp2IASnQf///x9xaiEVIAWnQf///x9xIRQgBqdB////H3EhEyAHp0H///8fcSESIBFB////H3EhESABQRBqIQEgAkIQfSICQg9WDQALCyAAIBE2AhQgACASNgIkIAAgEzYCICAAIBQ2AhwgACAVNgIYC+8BAQJ/IABFBEBBZw8LIAAoAgBFBEBBfw8LAn9BfiAAKAIEQRBJDQAaIAAoAghFBEBBbiAAKAIMDQEaCyAAKAIUIQEgACgCEEUEQEFtQXogARsPC0F6IAFBCEkNABogACgCGEUEQEFs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IAEgFiAZhUEQEAUiFjcDcCABIBYgF3wiFjcDSCABIBMgFoVBPxAFNwMgIAAgASkDQCAeIAApAACFhTcAAEEBISEDQCAAICFBA3QiIGoiIiABICBqIiApAwAgIikAAIUgIEFAaykDAIU3AAAgIUEBaiIhQQhHDQALIAFBgAJqJAALRQECfyMAQRBrIgNBADoADyABBEADQCADIAAgAmotAAAgAy0AD3I6AA8gAkEBaiICIAFHDQALCyADLQAPQQFrQQh2QQFxCxkAIAAgASACIANCACAEQeSRAigCABESABoLEAAgACABQdyRAigCABEDAAsDAAEL9wEBBH8jAEGAAWsiAyQAIAAQHCAAQShqIgQQHCAAQdAAaiIFEDAgACABQcAHbEHgFWoiASACQQAgAkGAAXFBB3YiBmsgAnFBAXRrQRh0QRh1IgJBARAmECIgACABQfgAaiACQQIQJhAiIAAgAUHwAWogAkEDECYQIiAAIAFB6AJqIAJBBBAmECIgACABQeADaiACQQUQJhAiIAAgAUHYBGogAkEGECYQIiAAIAFB0AVqIAJBBxAmECIgACABQcgGaiACQQgQJhAiIANBCGoiASAEECkgA0EwaiAAECkgA0HYAGogBRCAASAAIAEgBhAiIANBgAFqJAALHQAgABAwIABBKGoQHCAAQdAAahAcIABB+ABqEDALgAIBCH8DQCAAIAJqIAEgAkEDdmotAAAgAkEHcXZBAXE6AAAgAkEBaiICQYACRw0ACwNAIAQiAUEBaiEEAkAgACABaiIGLQAARQ0AIAQhAkEBIQUgAUH+AUsNAANAAkAgACACaiIDLAAAIgdFDQAgByAFdCIHIAYsAAAiCGoiCUEPTARAIAYgCToAACADQQA6AAAMAQsgCCAHayIDQXFIDQIgBiADOgAAA0AgACACaiIDLQAARQRAIANBAToAAAwCCyADQQA6AAAgAkH/AUkhAyACQQFqIQIgAw0ACwsgBUEFSw0BIAVBAWoiBSABaiICQYACSQ0ACwsgBEGAAkcNAAsLlQEBBH8jAEEwayIFJAAgACABQShqIgMgARASIABBKGoiBCADIAEQFSAAQdAAaiIDIAAgAkEoahAKIAQgBCACEAogAEH4AGoiBiACQfgAaiABQfgAahAKIAAgAUHQAGogAkHQAGoQCiAFIAAgABASIAAgAyAE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AAAgA0IBfCIDIAJSDQALIAAgACkDOCACfDcDOAsLsgEBAX8gACABKAAAQf///x9xNgIAIAAgASgAA0ECdkGD/v8fcTYCBCAAIAEoAAZBBHZB/4H/H3E2AgggACABKAAJQQZ2Qf//wB9xNgIMIAEoAAwhAiAAQgA3AhQgAEIANwIcIABBADYCJCAAIAJBCHZB//8/cTYCECAAIAEoABA2AiggACABKAAUNgIsIAAgASgAGDYCMCABKAAcIQEgAEEAOgBQIABCADcDOCAAIAE2AjQLMAECfyMAIgVBgAFrQUBxIgQkACAEIAMQhAEgBCABIAIQgwEgBCAAEIIBIAUkAEEACwsAIAAgAUEgEIcBC2wBAX8jAEEQayIDIAA2AgwgAyABNgIIQQAhASADQQA2AgQgAkEASgRAA0AgAyADKAIEIAMoAgggAWotAAAgAygCDCABai0AAHNyNgIEIAFBAWoiASACRw0ACwsgAygCBEEBa0EIdkEBcUEBawspAQJ/A0AgACACQQN0IgNqIAEgA2opAAA3AwAgAkEBaiICQYABRw0ACwtyAQF/AkAgAUEEcUUNACAAKAIAIgEEQCABKAIEIAAoAhBBCnQQCAsgACgCBCIBRQ0AIAEgACgCFEEDdBAICyAAKAIEEBggAEEANgIEAkAgACgCACIBRQ0AIAEoAgAiAkUNACACEBgLIAEQGCAAQQA2AgALEAAgAEIANwIAIABCADcCCAspAQF/IwBBEGsiACQAIABBADoAD0GMkgIgAEEPakEAEAEaIABBEGokAAsoACACQoCAgIAQWgRAEBQACyAAIAEgAiADQgEgBEG8kQIoAgAREgAaCxYAIABCwAAgASACQbSRAigCABENABoLPQECfyMAIgRBgANrQUBxIgMkACADQQBBAEEYEEIaIAMgAUIgECUaIAMgAkIgECUaIAMgAEEYEEEaIAQkAAsqAQF/QX8hBiACQhBaBH8gACABQRBqIAEgAkIQfSADIAQgBRCQAQUgBgsLPAECfyMAQSBrIgckAEF/IQggByAFIAYQZEUEQCAAIAEgAiADIAQgBxBgIQggB0EgEAgLIAdBIGokACAICyUAIAJC8P///w9aBEAQFAALIABBEGogACABIAIgAyAEIAUQkgELPAECfyMAQSBrIgckAEF/IQggByAFIAYQZEUEQCAAIAEgAiAD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AUEgaiAIQiB9IAYgASAFEI8BIQcLIAZBIGokACAHC5kBAgJ/AX4gAq0gA61CIIaEIQcjAEHgAGsiAiQAQX8hAyACQSBqIAIQkwFFBEAgAkFAayIFIAJBIGoiBiAEEI4BIABBIGogASAHIAUgBCACEJEBIQMgACACKQM4NwAYIAAgAikDMDcAECAAIAIpAyg3AAggACACKQMgNwAAIAJBIBAIIAZBIBAIIAVBGBAICyACQeAAaiQAIAMLGQAgACABIAKtIAOtQiCGhCAEIAUgBhCPAQstAQF+IAKtIAOtQiCGhCIGQhBaBH8gACABQRBqIAEgBkIQfSAEIAUQYAVBfwsLGwAgACABIAIgA60gBK1CIIaEIAUgBiAHEJABCxgAIAAgASACIAOtIAStQiCGhCAFIAYQYAsZACAAIAEgAq0gA61CIIaEIAQgBSAGEJEBCy4BAX4gAq0gA61CIIaEIgZC8P///w9aBEAQFAALIABBEGogACABIAYgBCAFEGELGwAgACABIAIgA60gBK1CIIaEIAUgBiAHEJIBCxgAIAAgASACIAOtIAStQiCGhCAFIAYQYQtIAQF/IwBBIGsiBSQAIAUgASACrSADrUIghoQgBBCUARogACAFEIYBIQEgBSAAQSAQTyECIAVBIGokACACQX8gASAAIAVGG3ILFQAgACABIAKtIAOtQiCGhCAEEJQBC1sBAn4gB60gCK1CIIaEIQxBfyECIAStIAWtQiCGhCILQhBaBEAgACADIAtCEH0gAyALp2pBEGsgBiAMIAkgChCaASECCyABBEAgAUIAIAtCEH0gAhs3AwALIAILJQAgACACIAOtIAStQiCGhCAFIAYgB60gCK1CIIaEIAkgChCaAQtZAQJ+An8gBq0gB61CIIaEIQwgA60gBK1CIIaEIgtC8P///w9UBEAgACAAIAunakEAIAIgCyAFIAwgCSAKEJsBGiABBEAgASALQhB8NwMAC0EADAELEBQACwsnACAAIAEgAiADIAStIAWtQiCGhCAGIAetIAitQiCGhCAKIAsQmwELWwECfiAHrSAIrUIghoQhDEF/IQIgBK0gBa1CIIaEIgtCEFoEQCAAIAMgC0IQfSADIAunakEQayAGIAwgCSAKEKYBIQILIAEEQCABQgAgC0IQfSACGzcDAAsgAgslACAAIAIgA60gBK1CIIaEIAUgBiAHrSAIrUIghoQgCSAKEKYBC1sBAn4gB60gCK1CIIaEIQxBfyECIAStIAWtQiCGhCILQhBaBEAgACADIAtCEH0gAyALp2pBEGsgBiAMIAkgChCnASECCyABBEAgAUIAIAtCEH0gAhs3AwALIAILJQAgACACIAOtIAStQiCGhCAFIAYgB60gCK1CIIaEIAkgChCnAQtZAQJ+An8gBq0gB61CIIaEIQwgA60gBK1CIIaEIgtC8P///w9UBEAgACAAIAunakEAIAIgCyAFIAwgCSAKEKgBGiABBEAgASALQhB8NwMAC0EADAELEBQACwsnACAAIAEgAiADIAStIAWtQiCGhCAGIAetIAitQiCGhCAKIAsQqAELWQECfgJ/IAatIAetQiCGhCEMIAOtIAStQiCGhCILQvD///8PVARAIAAgACALp2pBACACIAsgBSAMIAkgChCpARogAQRAIAEgC0IQfDcDAAtBAAwBCxAUAAsLJwAgACABIAIgAyAErSAFrUIghoQgBiAHrSAIrUIghoQgCiALEKkBC08BAn8jAEHQAGsiBiQAIAJQRQRAIAZBDGoiByAEEAkgBkEQaiIEIAUQRSAEIAMgBxCVASAEIAEgACACEEMgBEHAABAICyAGQdAAaiQAQQAL2gEBBH8jACIFIQcgBUGABGtBQHEiBSQAIAAgASAAGyIIBEBBfyEGIAVB4ABqIAMgBBBeRQRAIAEgACABGyEBQQAhACAFQYABaiIDQQBBAEHAABBCGiADIAVB4ABqIgZCIBAlGiAGQSAQCCADIARCIBAlGiADIAJCIBAlGiADIAVBIGpBwAAQQRogA0GAAxAIA0AgACABaiAFQSBqIABqIgItAAA6AAAgACAIaiACLQAgOgAAIABBAWoiAEEgRw0ACyAFQSBqQcAAEAhBACEGCyAHJAAgBg8LEBQAC9oBAQR/IwAiBSEHIAVBgARrQUBxIgUkACAAIAEgABsiCARAQX8hBiAFQeAAaiADIAQQXkUEQCABIAAgARshAUEAIQAgBUGAAWoiA0EAQQBBwAAQQhogAyAFQeAAaiIGQiAQJRogBkEgEAggAyACQiAQJRogAyAEQiAQJRogAyAFQSBqQcAAEEEaIANBgAMQCANAIAAgCGogBUEgaiAAaiICLQAAOgAAIAAgAWogAi0AIDoAACAAQQFqIgBBIEcNAAsgBUEgakHAABAIQQAhBgsgByQAIAYPCxAUAAsOACABQSAQHSAAIAEQXwsYACABQSAgAkIgQQBBABCcARogACABEF8LBABBCgsFAEHYCgsIACAAQRAQHQsEAEEwC10BA38jAEHQAGsiBiQAIAJQRQRAIAZBCGoiCCAEpxAJIAZBDGogBEIgiKcQCSAGQRBqIgcgBRBFIAcgAyAIEJ8BIAcgASAAIAIQQyAHQcAAEAgLIAZB0ABqJABBAAtWAQF/IwBBQGoiAyQAIAMgAkIgEDUaIAEgAykDGDcAGCABIAMpAxA3ABAgASADKQMINwAIIAEgAykDADcAACADQcAAEAggACABEHchACADQUBrJAAgAAsIAEGAgICABAsEAEEECwgAQYCAgIABCwcAQYCAgCALCABBgICAgHgLBgBBgMAACwUAQfsKCwUAQYABC0YBAX8jAEFAaiIEJAAgAVBFBEAgBCADEEUgBCACQQAQlQEgBCAAQQAgAacQDyIAIAAgARBDIARBwAAQCAsgBEFAayQAQQALBQBBgAMLNwEBfyABEGkgAEEDbiICQX1sIABqIgBBAXYgAHJBAXEgAEEBakEEIAFBAnEbbCACQQJ0akEBagv0AgELfwJAIANFDQACQAJAA0AgByEIA0ACQCACIAhqLQAAIg1B3wFxQTdrQf8BcSIOQfb/A2ogDkHw/wNqc0EIdiIPIA1BMHMiEEH2/wNqQQh2IgpyQf8BcUUEQEEBIQogBEUgC0H/AXFyDQQgBCANEEQNASAIIQcMBgsgASAJTQRAQeCXAkHEADYCAEEAIQoMBAsgDiAPcSAKIBBxciEHAkAgC0H/AXFFBEAgB0EEdCERDAELIAAgCWogByARcjoAACAJQQFqIQkLIAtBf3MhC0EBIQogCEEBaiIHIANJDQIMBAtBACELIAhBAWoiCCADSQ0ACwsgAyAHQQFqIgAgACADSRshBwwCCyAIIQcLIAtB/wFxBEBB4JcCQRw2AgBBfyEMIAdBAWshB0EAIQkMAQsgCg0AQQAhCUF/IQwLAkAgBgRAIAYgAiAHajYCAAwBCyADIAdGDQBB4JcCQRw2AgBBfyEMCyAFBEAgBSAJNgIACyAMC5sBAQN/IANB/v///wdLIANBAXQgAU9yRQRAQQAhASADBH8DQCAAIAFBAXRqIgQgASACai0AACIFQQ9xIgZBCHQgBkH2/wNqQYCyA3FqQYCuAWpBCHY6AAEgBCAFQQR2IgQgBEH2/wNqQQh2QdkBcWpB1wBqOgAAIAFBAWoiASADRw0ACyADQQF0BSABCyAAakEAOgAAIAAPCxAUAAssAQF/IwBBQGoiAyQAIAAgAxAnIAEgA0LAACACQQEQoQEhACADQUBrJAAgAAsuAQF/IwBBQGoiBCQAIAAgBBAnIAEgAiAEQsAAIANBARCjASEAIARBQGskACAACwgAIAAQNkEACywBAX8jAEEgayICJAAgAkEgEB0gACABIAIQpAEaIAJBIBAIIAJBIGokAEEACwsAIAAgASACEKQBCwUAQb9/CwUAQdABC20BAX8jAEFAaiICJAAgAiABQiAQNRogAiACLQAAQfgBcToAACACIAItAB9BP3FBwAByOgAfIAAgAikDEDcAECAAIAIpAwg3AAggACACKQMANwAAIAAgAikDGDcAGCACQcAAEAggAkFAayQAQQALnwQBB38jAEGAAmsiBSQAQX8hCAJAIAEQUQ0AIAVB4ABqIAEQfg0AIwBBoAFrIgYkACMAQeANayICJAAgAkHgA2oiAyAFQeAAaiIEEBkgAkHAAmoiASAEEDogAiABEBMgASACIAMQGiACQaABaiIDIAEQEyACQYAFaiIEIAMQGSABIAIgBBAaIAMgARATIAJBoAZqIgQgAxAZIAEgAiAEEBogAyABEBMgAkHAB2oiBCADEBkgASACIAQQGiADIAEQEyACQeAIaiIEIAMQGSABIAIgBBAaIAMgARATIAJBgApqIgQgAxAZIAEgAiAEEBogAyABEBMgAkGgC2oiBCADEBkgASACIAQQGiADIAEQEyACQcAMaiADEBkgBhB6QfwBIQEDQCACQcACaiAGEDoCQCABIgNB4IUCaiwAACIBQQBKBEAgAkGgAWoiBCACQcACaiIHEBMgByAEIAJB4ANqIAFB/gFxQQF2QaABbGoQGgwBCyABQQBODQAgAkGgAWoiBCACQcACaiIHEBMgByAEIAJB4ANqQQAgAWtB/gFxQQF2QaABbGoQfAsgBiACQcACahATIANBAWshASADDQALIAJB4A1qJAAgBhBWIQEgBkGgAWokACABRQ0AIAUQHCAFIAUgBUGIAWoiAxAVIAVBMGoiARAcIAEgASADEBIgBSAFEDwgASAB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xAGBEXgA+2eX/wc0cP+MOEL/KOL1/9lGJf6s1gn/SEOGAZLA1v8sJnAARLhL/85a+wCV640Atao6AHT07wBcnQIAZq1iAOmJYAF/McsABZuUABeUCf/TegwAIoYa/9vMiACGCCn/4FMr/lUZ9wBtfwD+qYgwAO532//nrdUAzhL+/gi6B/9+CQcBbypIAG807P5gP40Ak79//s1OwP8Oau0Bu9tMAK/zu/5pWa0AVRlZAaLzlAACdtH+IZ4JAIujLv9dRigAbCqO/m/8jv+b35AAM+Wn/0n8m/9edAz/mKDa/5zuJf+z6s//xQCz/5qkjQDhxGgACiMZ/tHU8v9h/d7+uGXlAN4SfwGkiIf/Hs+M/pJh8wCBwBr+yVQh/28KTv+TUbL/BAQYAKHu1/8GjSEANdcO/ym10P/ni50As8vd//+5cQC94qz/cULW/8o+Lf9mQAj/Tq4Q/oV1RP8AQYAUCwEBAEGgFAuwASbolY/CsiewRcP0ifLvmPDV36wF08YzObE4AohtU/wFxxdqcD1N2E+6PAt2DRBnDyogU/osOczGTsf9d5KsA3rs////////////////////////////////////////f+3///////////////////////////////////////9/7v///////////////////////////////////////3/t0/VcGmMSWNac96Le+d4UAEHfFQv88AEQhTuMAb3xJP/4JcMBYNw3ALdMPv/DQj0AMkykAeGkTP9MPaP/dT4fAFGRQP92QQ4AonPW/waKLgB85vT/CoqPADQawgC49EwAgY8pAb70E/97qnr/YoFEAHnVkwBWZR7/oWebAIxZQ//v5b4BQwu1AMbwif7uRbz/6nE8/yX/Of9Fsrb+gNCzAHYaff4DB9b/8TJN/1XLxf/Th/r/GTBk/7vVtP4RWGkAU9GeAQVzYgAErjz+qzdu/9m1Ef8UvKoAkpxm/lfWrv9yepsB6SyqAH8I7wHW7OoArwXbADFqPf8GQtD/Ampu/1HqE//Xa8D/Q5fuABMqbP/lVXEBMkSH/xFqCQAyZwH/UAGoASOYHv8QqLkBOFno/2XS/AAp+kcAzKpP/w4u7/9QTe8AvdZL/xGN+QAmUEz/vlV1AFbkqgCc2NABw8+k/5ZCTP+v4RD/jVBiAUzb8gDGonIALtqY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//////////////9/7f///////////////////////////////////////3/u////////////////////////////////////////fwjJvPNn5glqO6fKhIWuZ7sr+JT+cvNuPPE2HV869U+l0YLmrX9SDlEfbD4rjGgFm2u9Qfur2YMfeSF+ExnN4FsAQaCKAgvBBQjJvPNn5glqO6fKhIWuZ7sr+JT+cvNuPPE2HV869U+l0YLmrX9SDlEfbD4rjGgFm2u9Qfur2YMfeSF+ExnN4FsirijXmC+KQs1l7yORRDdxLztN7M/7wLW824mBpdu16Ti1SPNbwlY5GdAFtvER8VmbTxmvpII/khiBbdrVXhyrQgIDo5iqB9i+b3BFAVuDEoyy5E6+hTEk4rT/1cN9DFVviXvydF2+crGWFjv+sd6ANRLHJacG3JuUJmnPdPGbwdJK8Z7BaZvk4yVPOIZHvu+11YyLxp3BD2WcrHfMoQwkdQIrWW8s6S2D5KZuqoR0StT7Qb3cqbBctVMRg9qI+Xar32buUlE+mBAytC1txjGoPyH7mMgnA7DkDu++x39Zv8KPqD3zC+DGJacKk0eRp9VvggPgUWPKBnBuDgpnKSkU/C/SRoUKtycmySZcOCEbLu0qxFr8bSxN37OVnRMNOFPeY6+LVHMKZaiydzy7Cmp25q7tRy7JwoE7NYIUhSxykmQD8Uyh6L+iATBCvEtmGqiRl/jQcItLwjC+VAajUWzHGFLv1hnoktEQqWVVJAaZ1iogcVeFNQ70uNG7MnCgahDI0NK4FsGkGVOrQVEIbDcemeuO30x3SCeoSJvhtbywNGNaycWzDBw5y4pB40qq2E5z42N3T8qcW6O4stbzby5o/LLvXe6Cj3RgLxdDb2OleHKr8KEUeMiE7DlkGggCx4woHmMj+v++kOm9gt7rbFCkFXnGsvej+b4rU3Lj8nhxxpxhJurOPifKB8LAIce4htEe6+DN1n3a6njRbu5/T331um8Xcqpn8AammMiixX1jCq4N+b4EmD8RG0ccEzULcRuEfQQj9XfbKJMkx0B7q8oyvL7JFQq+njxMDRCcxGcdQ7ZCPsu+1MVMKn5l/Jwpf1ns+tY6q2/LXxdYR0qMGURsgABB4JACCyFTaWdFZDI1NTE5IG5vIEVkMjU1MTkgY29sbGlzaW9ucwEAQbCRAgs1MI5QAAEAAAACAAAAAwAAAAQAAAAFAAAABgAAAAcAAAAIAAAACQAAAAoAAAALAAAADAAAAA0=")||(d=R,R=a.locateFile?a.locateFile(d,c):c+d);var V={35048:function(){return a.getRandomValue()},35084:function(){if(void 0===a.getRandomValue)try{var A="object"==typeof window?window:self,I=void 0!==A.crypto?A.crypto:A.msCrypto,g=function(){var A=new Uint32Array(1);return I.getRandomValues(A),A[0]>>>0};g(),a.getRandomValue=g}catch(A){try{var B=__nccwpck_require__(6113),C=function(){var A=B.randomBytes(4);return(A[0]<<24|A[1]<<16|A[2]<<8|A[3])>>>0};C(),a.getRandomValue=C}catch(A){throw"No secure random number generator found"}}}};function q(A){for(;A.length>0;){var I=A.shift();if("function"!=typeof I){var g=I.func;"number"==typeof g?void 0===I.arg?z(g)():z(g)(I.arg):g(void 0===I.arg?null:I.arg)}else I(a)}}function z(A){return S.get(A)}var j=[];function W(A){try{return s.grow(A-D.byteLength+65535>>>16),U(s.buffer),1}catch(A){}}var O="function"==typeof atob?atob:function(A){var I,g,B,C,Q,E,i="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",n="",a=0;A=A.replace(/[^A-Za-z0-9\+\/\=]/g,"");do{I=i.indexOf(A.charAt(a++))<<2|(C=i.indexOf(A.charAt(a++)))>>4,g=(15&C)<<4|(Q=i.indexOf(A.charAt(a++)))>>2,B=(3&Q)<<6|(E=i.indexOf(A.charAt(a++))),n+=String.fromCharCode(I),64!==Q&&(n+=String.fromCharCode(g)),64!==E&&(n+=String.fromCharCode(B))}while(a<A.length);return n};function Z(A){if(K(A))return function(A){if("boolean"==typeof f&&f){var I=Buffer.from(A,"base64");return new Uint8Array(I.buffer,I.byteOffset,I.byteLength)}try{for(var g=O(A),B=new Uint8Array(g.length),C=0;C<g.length;++C)B[C]=g.charCodeAt(C);return B}catch(A){throw new Error("Converting base64 string to bytes failed.")}}(A.slice(L.length))}var $,AA={a:function(A,I,g,B){N("Assertion failed: "+G(A)+", at: "+[I?G(I):"unknown filename",g,B?G(B):"unknown function"])},d:function(){N("")},b:function(A,I,g){var B=function(A,I){var g;for(j.length=0,I>>=2;g=p[A++];){var B=g<105;B&&1&I&&I++,j.push(B?_[I++>>1]:F[I]),++I}return j}(I,g);return V[A].apply(null,B)},e:function(A,I,g){p.copyWithin(A,I,I+g)},c:function(A){var I,g=p.length,B=2147483648;if((A>>>=0)>B)return!1;for(var C=1;C<=4;C*=2){var Q=g*(1+.2/C);if(Q=Math.min(Q,A+100663296),W(Math.min(B,(I=Math.max(A,Q))+(65536-I%65536)%65536)))return!0}return!1}};function IA(A){function I(){$||($=!0,a.calledRun=!0,k||(q(m),a.onRuntimeInitialized&&a.onRuntimeInitialized(),function(){if(a.postRun)for("function"==typeof a.postRun&&(a.postRun=[a.postRun]);a.postRun.length;)A=a.postRun.shift(),v.unshift(A);var A;q(v)}()))}A=A||o,M>0||(function(){if(a.preRun)for("function"==typeof a.preRun&&(a.preRun=[a.preRun]);a.preRun.length;)A=a.preRun.shift(),b.unshift(A);var A;q(b)}(),M>0||(a.setStatus?(a.setStatus("Running..."),setTimeout((function(){setTimeout((function(){a.setStatus("")}),1),I()}),1)):I()))}if(function(){var A={a:AA};function I(A,I){var g,B=A.exports;a.asm=B,U((s=a.asm.f).buffer),S=a.asm.Ac,g=a.asm.g,m.unshift(g),function(A){if(M--,a.monitorRunDependencies&&a.monitorRunDependencies(M),0==M&&(null!==P&&(clearInterval(P),P=null),Y)){var I=Y;Y=null,I()}}()}function g(A){I(A.instance)}function B(I){return function(){if(!y&&(t||e)){if("function"==typeof fetch&&!X(R))return fetch(R,{credentials:"same-origin"}).then((function(A){if(!A.ok)throw"failed to load wasm binary file at '"+R+"'";return A.arrayBuffer()})).catch((function(){return T(R)}));if(C)return new Promise((function(A,I){C(R,(function(I){A(new Uint8Array(I))}),I)}))}return Promise.resolve().then((function(){return T(R)}))}().then((function(I){return WebAssembly.instantiate(I,A)})).then((function(A){return A})).then(I,(function(A){w("failed to asynchronously prepare wasm: "+A),N(A)}))}if(M++,a.monitorRunDependencies&&a.monitorRunDependencies(M),a.instantiateWasm)try{return a.instantiateWasm(A,I)}catch(A){return w("Module.instantiateWasm callback failed with error: "+A),!1}y||"function"!=typeof WebAssembly.instantiateStreaming||K(R)||X(R)||"function"!=typeof fetch?B(g):fetch(R,{credentials:"same-origin"}).then((function(I){return WebAssembly.instantiateStreaming(I,A).then(g,(function(A){return w("wasm streaming compile failed: "+A),w("falling back to ArrayBuffer instantiation"),B(g)}))}))}(),a.___wasm_call_ctors=function(){return(a.___wasm_call_ctors=a.asm.g).apply(null,arguments)},a._crypto_aead_chacha20poly1305_encrypt_detached=function(){return(a._crypto_aead_chacha20poly1305_encrypt_detached=a.asm.h).apply(null,arguments)},a._crypto_aead_chacha20poly1305_encrypt=function(){return(a._crypto_aead_chacha20poly1305_encrypt=a.asm.i).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_encrypt_detached=function(){return(a._crypto_aead_chacha20poly1305_ietf_encrypt_detached=a.asm.j).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_encrypt=function(){return(a._crypto_aead_chacha20poly1305_ietf_encrypt=a.asm.k).apply(null,arguments)},a._crypto_aead_chacha20poly1305_decrypt_detached=function(){return(a._crypto_aead_chacha20poly1305_decrypt_detached=a.asm.l).apply(null,arguments)},a._crypto_aead_chacha20poly1305_decrypt=function(){return(a._crypto_aead_chacha20poly1305_decrypt=a.asm.m).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_decrypt_detached=function(){return(a._crypto_aead_chacha20poly1305_ietf_decrypt_detached=a.asm.n).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_decrypt=function(){return(a._crypto_aead_chacha20poly1305_ietf_decrypt=a.asm.o).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_keybytes=function(){return(a._crypto_aead_chacha20poly1305_ietf_keybytes=a.asm.p).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_npubbytes=function(){return(a._crypto_aead_chacha20poly1305_ietf_npubbytes=a.asm.q).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_nsecbytes=function(){return(a._crypto_aead_chacha20poly1305_ietf_nsecbytes=a.asm.r).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_abytes=function(){return(a._crypto_aead_chacha20poly1305_ietf_abytes=a.asm.s).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_messagebytes_max=function(){return(a._crypto_aead_chacha20poly1305_ietf_messagebytes_max=a.asm.t).apply(null,arguments)},a._crypto_aead_chacha20poly1305_ietf_keygen=function(){return(a._crypto_aead_chacha20poly1305_ietf_keygen=a.asm.u).apply(null,arguments)},a._crypto_aead_chacha20poly1305_keybytes=function(){return(a._crypto_aead_chacha20poly1305_keybytes=a.asm.v).apply(null,arguments)},a._crypto_aead_chacha20poly1305_npubbytes=function(){return(a._crypto_aead_chacha20poly1305_npubbytes=a.asm.w).apply(null,arguments)},a._crypto_aead_chacha20poly1305_nsecbytes=function(){return(a._crypto_aead_chacha20poly1305_nsecbytes=a.asm.x).apply(null,arguments)},a._crypto_aead_chacha20poly1305_abytes=function(){return(a._crypto_aead_chacha20poly1305_abytes=a.asm.y).apply(null,arguments)},a._crypto_aead_chacha20poly1305_messagebytes_max=function(){return(a._crypto_aead_chacha20poly1305_messagebytes_max=a.asm.z).apply(null,arguments)},a._crypto_aead_chacha20poly1305_keygen=function(){return(a._crypto_aead_chacha20poly1305_keygen=a.asm.A).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_encrypt_detached=function(){return(a._crypto_aead_xchacha20poly1305_ietf_encrypt_detached=a.asm.B).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_encrypt=function(){return(a._crypto_aead_xchacha20poly1305_ietf_encrypt=a.asm.C).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_decrypt_detached=function(){return(a._crypto_aead_xchacha20poly1305_ietf_decrypt_detached=a.asm.D).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_decrypt=function(){return(a._crypto_aead_xchacha20poly1305_ietf_decrypt=a.asm.E).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_keybytes=function(){return(a._crypto_aead_xchacha20poly1305_ietf_keybytes=a.asm.F).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_npubbytes=function(){return(a._crypto_aead_xchacha20poly1305_ietf_npubbytes=a.asm.G).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_nsecbytes=function(){return(a._crypto_aead_xchacha20poly1305_ietf_nsecbytes=a.asm.H).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_abytes=function(){return(a._crypto_aead_xchacha20poly1305_ietf_abytes=a.asm.I).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_messagebytes_max=function(){return(a._crypto_aead_xchacha20poly1305_ietf_messagebytes_max=a.asm.J).apply(null,arguments)},a._crypto_aead_xchacha20poly1305_ietf_keygen=function(){return(a._crypto_aead_xchacha20poly1305_ietf_keygen=a.asm.K).apply(null,arguments)},a._crypto_auth_bytes=function(){return(a._crypto_auth_bytes=a.asm.L).apply(null,arguments)},a._crypto_auth_keybytes=function(){return(a._crypto_auth_keybytes=a.asm.M).apply(null,arguments)},a._crypto_auth=function(){return(a._crypto_auth=a.asm.N).apply(null,arguments)},a._crypto_auth_verify=function(){return(a._crypto_auth_verify=a.asm.O).apply(null,arguments)},a._crypto_auth_keygen=function(){return(a._crypto_auth_keygen=a.asm.P).apply(null,arguments)},a._crypto_box_seedbytes=function(){return(a._crypto_box_seedbytes=a.asm.Q).apply(null,arguments)},a._crypto_box_publickeybytes=function(){return(a._crypto_box_publickeybytes=a.asm.R).apply(null,arguments)},a._crypto_box_secretkeybytes=function(){return(a._crypto_box_secretkeybytes=a.asm.S).apply(null,arguments)},a._crypto_box_beforenmbytes=function(){return(a._crypto_box_beforenmbytes=a.asm.T).apply(null,arguments)},a._crypto_box_noncebytes=function(){return(a._crypto_box_noncebytes=a.asm.U).apply(null,arguments)},a._crypto_box_macbytes=function(){return(a._crypto_box_macbytes=a.asm.V).apply(null,arguments)},a._crypto_box_messagebytes_max=function(){return(a._crypto_box_messagebytes_max=a.asm.W).apply(null,arguments)},a._crypto_box_seed_keypair=function(){return(a._crypto_box_seed_keypair=a.asm.X).apply(null,arguments)},a._crypto_box_keypair=function(){return(a._crypto_box_keypair=a.asm.Y).apply(null,arguments)},a._crypto_box_beforenm=function(){return(a._crypto_box_beforenm=a.asm.Z).apply(null,arguments)},a._crypto_box_detached_afternm=function(){return(a._crypto_box_detached_afternm=a.asm._).apply(null,arguments)},a._crypto_box_detached=function(){return(a._crypto_box_detached=a.asm.$).apply(null,arguments)},a._crypto_box_easy_afternm=function(){return(a._crypto_box_easy_afternm=a.asm.aa).apply(null,arguments)},a._crypto_box_easy=function(){return(a._crypto_box_easy=a.asm.ba).apply(null,arguments)},a._crypto_box_open_detached_afternm=function(){return(a._crypto_box_open_detached_afternm=a.asm.ca).apply(null,arguments)},a._crypto_box_open_detached=function(){return(a._crypto_box_open_detached=a.asm.da).apply(null,arguments)},a._crypto_box_open_easy_afternm=function(){return(a._crypto_box_open_easy_afternm=a.asm.ea).apply(null,arguments)},a._crypto_box_open_easy=function(){return(a._crypto_box_open_easy=a.asm.fa).apply(null,arguments)},a._crypto_box_seal=function(){return(a._crypto_box_seal=a.asm.ga).apply(null,arguments)},a._crypto_box_seal_open=function(){return(a._crypto_box_seal_open=a.asm.ha).apply(null,arguments)},a._crypto_box_sealbytes=function(){return(a._crypto_box_sealbytes=a.asm.ia).apply(null,arguments)},a._crypto_generichash_bytes_min=function(){return(a._crypto_generichash_bytes_min=a.asm.ja).apply(null,arguments)},a._crypto_generichash_bytes_max=function(){return(a._crypto_generichash_bytes_max=a.asm.ka).apply(null,arguments)},a._crypto_generichash_bytes=function(){return(a._crypto_generichash_bytes=a.asm.la).apply(null,arguments)},a._crypto_generichash_keybytes_min=function(){return(a._crypto_generichash_keybytes_min=a.asm.ma).apply(null,arguments)},a._crypto_generichash_keybytes_max=function(){return(a._crypto_generichash_keybytes_max=a.asm.na).apply(null,arguments)},a._crypto_generichash_keybytes=function(){return(a._crypto_generichash_keybytes=a.asm.oa).apply(null,arguments)},a._crypto_generichash_statebytes=function(){return(a._crypto_generichash_statebytes=a.asm.pa).apply(null,arguments)},a._crypto_generichash=function(){return(a._crypto_generichash=a.asm.qa).apply(null,arguments)},a._crypto_generichash_init=function(){return(a._crypto_generichash_init=a.asm.ra).apply(null,arguments)},a._crypto_generichash_update=function(){return(a._crypto_generichash_update=a.asm.sa).apply(null,arguments)},a._crypto_generichash_final=function(){return(a._crypto_generichash_final=a.asm.ta).apply(null,arguments)},a._crypto_generichash_keygen=function(){return(a._crypto_generichash_keygen=a.asm.ua).apply(null,arguments)},a._crypto_hash_bytes=function(){return(a._crypto_hash_bytes=a.asm.va).apply(null,arguments)},a._crypto_hash=function(){return(a._crypto_hash=a.asm.wa).apply(null,arguments)},a._crypto_kdf_bytes_min=function(){return(a._crypto_kdf_bytes_min=a.asm.xa).apply(null,arguments)},a._crypto_kdf_bytes_max=function(){return(a._crypto_kdf_bytes_max=a.asm.ya).apply(null,arguments)},a._crypto_kdf_contextbytes=function(){return(a._crypto_kdf_contextbytes=a.asm.za).apply(null,arguments)},a._crypto_kdf_keybytes=function(){return(a._crypto_kdf_keybytes=a.asm.Aa).apply(null,arguments)},a._crypto_kdf_derive_from_key=function(){return(a._crypto_kdf_derive_from_key=a.asm.Ba).apply(null,arguments)},a._crypto_kdf_keygen=function(){return(a._crypto_kdf_keygen=a.asm.Ca).apply(null,arguments)},a._crypto_kx_seed_keypair=function(){return(a._crypto_kx_seed_keypair=a.asm.Da).apply(null,arguments)},a._crypto_kx_keypair=function(){return(a._crypto_kx_keypair=a.asm.Ea).apply(null,arguments)},a._crypto_kx_client_session_keys=function(){return(a._crypto_kx_client_session_keys=a.asm.Fa).apply(null,arguments)},a._crypto_kx_server_session_keys=function(){return(a._crypto_kx_server_session_keys=a.asm.Ga).apply(null,arguments)},a._crypto_kx_publickeybytes=function(){return(a._crypto_kx_publickeybytes=a.asm.Ha).apply(null,arguments)},a._crypto_kx_secretkeybytes=function(){return(a._crypto_kx_secretkeybytes=a.asm.Ia).apply(null,arguments)},a._crypto_kx_seedbytes=function(){return(a._crypto_kx_seedbytes=a.asm.Ja).apply(null,arguments)},a._crypto_kx_sessionkeybytes=function(){return(a._crypto_kx_sessionkeybytes=a.asm.Ka).apply(null,arguments)},a._crypto_pwhash_alg_argon2i13=function(){return(a._crypto_pwhash_alg_argon2i13=a.asm.La).apply(null,arguments)},a._crypto_pwhash_alg_argon2id13=function(){return(a._crypto_pwhash_alg_argon2id13=a.asm.Ma).apply(null,arguments)},a._crypto_pwhash_alg_default=function(){return(a._crypto_pwhash_alg_default=a.asm.Na).apply(null,arguments)},a._crypto_pwhash_bytes_min=function(){return(a._crypto_pwhash_bytes_min=a.asm.Oa).apply(null,arguments)},a._crypto_pwhash_bytes_max=function(){return(a._crypto_pwhash_bytes_max=a.asm.Pa).apply(null,arguments)},a._crypto_pwhash_passwd_min=function(){return(a._crypto_pwhash_passwd_min=a.asm.Qa).apply(null,arguments)},a._crypto_pwhash_passwd_max=function(){return(a._crypto_pwhash_passwd_max=a.asm.Ra).apply(null,arguments)},a._crypto_pwhash_saltbytes=function(){return(a._crypto_pwhash_saltbytes=a.asm.Sa).apply(null,arguments)},a._crypto_pwhash_strbytes=function(){return(a._crypto_pwhash_strbytes=a.asm.Ta).apply(null,arguments)},a._crypto_pwhash_strprefix=function(){return(a._crypto_pwhash_strprefix=a.asm.Ua).apply(null,arguments)},a._crypto_pwhash_opslimit_min=function(){return(a._crypto_pwhash_opslimit_min=a.asm.Va).apply(null,arguments)},a._crypto_pwhash_opslimit_max=function(){return(a._crypto_pwhash_opslimit_max=a.asm.Wa).apply(null,arguments)},a._crypto_pwhash_memlimit_min=function(){return(a._crypto_pwhash_memlimit_min=a.asm.Xa).apply(null,arguments)},a._crypto_pwhash_memlimit_max=function(){return(a._crypto_pwhash_memlimit_max=a.asm.Ya).apply(null,arguments)},a._crypto_pwhash_opslimit_interactive=function(){return(a._crypto_pwhash_opslimit_interactive=a.asm.Za).apply(null,arguments)},a._crypto_pwhash_memlimit_interactive=function(){return(a._crypto_pwhash_memlimit_interactive=a.asm._a).apply(null,arguments)},a._crypto_pwhash_opslimit_moderate=function(){return(a._crypto_pwhash_opslimit_moderate=a.asm.$a).apply(null,arguments)},a._crypto_pwhash_memlimit_moderate=function(){return(a._crypto_pwhash_memlimit_moderate=a.asm.ab).apply(null,arguments)},a._crypto_pwhash_opslimit_sensitive=function(){return(a._crypto_pwhash_opslimit_sensitive=a.asm.bb).apply(null,arguments)},a._crypto_pwhash_memlimit_sensitive=function(){return(a._crypto_pwhash_memlimit_sensitive=a.asm.cb).apply(null,arguments)},a._crypto_pwhash=function(){return(a._crypto_pwhash=a.asm.db).apply(null,arguments)},a._crypto_pwhash_str=function(){return(a._crypto_pwhash_str=a.asm.eb).apply(null,arguments)},a._crypto_pwhash_str_alg=function(){return(a._crypto_pwhash_str_alg=a.asm.fb).apply(null,arguments)},a._crypto_pwhash_str_verify=function(){return(a._crypto_pwhash_str_verify=a.asm.gb).apply(null,arguments)},a._crypto_pwhash_str_needs_rehash=function(){return(a._crypto_pwhash_str_needs_rehash=a.asm.hb).apply(null,arguments)},a._crypto_scalarmult_base=function(){return(a._crypto_scalarmult_base=a.asm.ib).apply(null,arguments)},a._crypto_scalarmult=function(){return(a._crypto_scalarmult=a.asm.jb).apply(null,arguments)},a._crypto_scalarmult_bytes=function(){return(a._crypto_scalarmult_bytes=a.asm.kb).apply(null,arguments)},a._crypto_scalarmult_scalarbytes=function(){return(a._crypto_scalarmult_scalarbytes=a.asm.lb).apply(null,arguments)},a._crypto_secretbox_keybytes=function(){return(a._crypto_secretbox_keybytes=a.asm.mb).apply(null,arguments)},a._crypto_secretbox_noncebytes=function(){return(a._crypto_secretbox_noncebytes=a.asm.nb).apply(null,arguments)},a._crypto_secretbox_macbytes=function(){return(a._crypto_secretbox_macbytes=a.asm.ob).apply(null,arguments)},a._crypto_secretbox_messagebytes_max=function(){return(a._crypto_secretbox_messagebytes_max=a.asm.pb).apply(null,arguments)},a._crypto_secretbox_keygen=function(){return(a._crypto_secretbox_keygen=a.asm.qb).apply(null,arguments)},a._crypto_secretbox_detached=function(){return(a._crypto_secretbox_detached=a.asm.rb).apply(null,arguments)},a._crypto_secretbox_easy=function(){return(a._crypto_secretbox_easy=a.asm.sb).apply(null,arguments)},a._crypto_secretbox_open_detached=function(){return(a._crypto_secretbox_open_detached=a.asm.tb).apply(null,arguments)},a._crypto_secretbox_open_easy=function(){return(a._crypto_secretbox_open_easy=a.asm.ub).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_keygen=function(){return(a._crypto_secretstream_xchacha20poly1305_keygen=a.asm.vb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_init_push=function(){return(a._crypto_secretstream_xchacha20poly1305_init_push=a.asm.wb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_init_pull=function(){return(a._crypto_secretstream_xchacha20poly1305_init_pull=a.asm.xb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_rekey=function(){return(a._crypto_secretstream_xchacha20poly1305_rekey=a.asm.yb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_push=function(){return(a._crypto_secretstream_xchacha20poly1305_push=a.asm.zb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_pull=function(){return(a._crypto_secretstream_xchacha20poly1305_pull=a.asm.Ab).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_statebytes=function(){return(a._crypto_secretstream_xchacha20poly1305_statebytes=a.asm.Bb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_abytes=function(){return(a._crypto_secretstream_xchacha20poly1305_abytes=a.asm.Cb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_headerbytes=function(){return(a._crypto_secretstream_xchacha20poly1305_headerbytes=a.asm.Db).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_keybytes=function(){return(a._crypto_secretstream_xchacha20poly1305_keybytes=a.asm.Eb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_messagebytes_max=function(){return(a._crypto_secretstream_xchacha20poly1305_messagebytes_max=a.asm.Fb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_tag_message=function(){return(a._crypto_secretstream_xchacha20poly1305_tag_message=a.asm.Gb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_tag_push=function(){return(a._crypto_secretstream_xchacha20poly1305_tag_push=a.asm.Hb).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_tag_rekey=function(){return(a._crypto_secretstream_xchacha20poly1305_tag_rekey=a.asm.Ib).apply(null,arguments)},a._crypto_secretstream_xchacha20poly1305_tag_final=function(){return(a._crypto_secretstream_xchacha20poly1305_tag_final=a.asm.Jb).apply(null,arguments)},a._crypto_shorthash_bytes=function(){return(a._crypto_shorthash_bytes=a.asm.Kb).apply(null,arguments)},a._crypto_shorthash_keybytes=function(){return(a._crypto_shorthash_keybytes=a.asm.Lb).apply(null,arguments)},a._crypto_shorthash=function(){return(a._crypto_shorthash=a.asm.Mb).apply(null,arguments)},a._crypto_shorthash_keygen=function(){return(a._crypto_shorthash_keygen=a.asm.Nb).apply(null,arguments)},a._crypto_sign_statebytes=function(){return(a._crypto_sign_statebytes=a.asm.Ob).apply(null,arguments)},a._crypto_sign_bytes=function(){return(a._crypto_sign_bytes=a.asm.Pb).apply(null,arguments)},a._crypto_sign_seedbytes=function(){return(a._crypto_sign_seedbytes=a.asm.Qb).apply(null,arguments)},a._crypto_sign_publickeybytes=function(){return(a._crypto_sign_publickeybytes=a.asm.Rb).apply(null,arguments)},a._crypto_sign_secretkeybytes=function(){return(a._crypto_sign_secretkeybytes=a.asm.Sb).apply(null,arguments)},a._crypto_sign_messagebytes_max=function(){return(a._crypto_sign_messagebytes_max=a.asm.Tb).apply(null,arguments)},a._crypto_sign_seed_keypair=function(){return(a._crypto_sign_seed_keypair=a.asm.Ub).apply(null,arguments)},a._crypto_sign_keypair=function(){return(a._crypto_sign_keypair=a.asm.Vb).apply(null,arguments)},a._crypto_sign=function(){return(a._crypto_sign=a.asm.Wb).apply(null,arguments)},a._crypto_sign_open=function(){return(a._crypto_sign_open=a.asm.Xb).apply(null,arguments)},a._crypto_sign_detached=function(){return(a._crypto_sign_detached=a.asm.Yb).apply(null,arguments)},a._crypto_sign_verify_detached=function(){return(a._crypto_sign_verify_detached=a.asm.Zb).apply(null,arguments)},a._crypto_sign_init=function(){return(a._crypto_sign_init=a.asm._b).apply(null,arguments)},a._crypto_sign_update=function(){return(a._crypto_sign_update=a.asm.$b).apply(null,arguments)},a._crypto_sign_final_create=function(){return(a._crypto_sign_final_create=a.asm.ac).apply(null,arguments)},a._crypto_sign_final_verify=function(){return(a._crypto_sign_final_verify=a.asm.bc).apply(null,arguments)},a._crypto_sign_ed25519_pk_to_curve25519=function(){return(a._crypto_sign_ed25519_pk_to_curve25519=a.asm.cc).apply(null,arguments)},a._crypto_sign_ed25519_sk_to_curve25519=function(){return(a._crypto_sign_ed25519_sk_to_curve25519=a.asm.dc).apply(null,arguments)},a._randombytes_random=function(){return(a._randombytes_random=a.asm.ec).apply(null,arguments)},a._randombytes_stir=function(){return(a._randombytes_stir=a.asm.fc).apply(null,arguments)},a._randombytes_uniform=function(){return(a._randombytes_uniform=a.asm.gc).apply(null,arguments)},a._randombytes_buf=function(){return(a._randombytes_buf=a.asm.hc).apply(null,arguments)},a._randombytes_buf_deterministic=function(){return(a._randombytes_buf_deterministic=a.asm.ic).apply(null,arguments)},a._randombytes_seedbytes=function(){return(a._randombytes_seedbytes=a.asm.jc).apply(null,arguments)},a._randombytes_close=function(){return(a._randombytes_close=a.asm.kc).apply(null,arguments)},a._randombytes=function(){return(a._randombytes=a.asm.lc).apply(null,arguments)},a._sodium_bin2hex=function(){return(a._sodium_bin2hex=a.asm.mc).apply(null,arguments)},a._sodium_hex2bin=function(){return(a._sodium_hex2bin=a.asm.nc).apply(null,arguments)},a._sodium_base64_encoded_len=function(){return(a._sodium_base64_encoded_len=a.asm.oc).apply(null,arguments)},a._sodium_bin2base64=function(){return(a._sodium_bin2base64=a.asm.pc).apply(null,arguments)},a._sodium_base642bin=function(){return(a._sodium_base642bin=a.asm.qc).apply(null,arguments)},a._sodium_init=function(){return(a._sodium_init=a.asm.rc).apply(null,arguments)},a._sodium_pad=function(){return(a._sodium_pad=a.asm.sc).apply(null,arguments)},a._sodium_unpad=function(){return(a._sodium_unpad=a.asm.tc).apply(null,arguments)},a._sodium_version_string=function(){return(a._sodium_version_string=a.asm.uc).apply(null,arguments)},a._sodium_library_version_major=function(){return(a._sodium_library_version_major=a.asm.vc).apply(null,arguments)},a._sodium_library_version_minor=function(){return(a._sodium_library_version_minor=a.asm.wc).apply(null,arguments)},a._sodium_library_minimal=function(){return(a._sodium_library_minimal=a.asm.xc).apply(null,arguments)},a._malloc=function(){return(a._malloc=a.asm.yc).apply(null,arguments)},a._free=function(){return(a._free=a.asm.zc).apply(null,arguments)},a.setValue=function(A,I,g="i8",B){switch("*"===g.charAt(g.length-1)&&(g="i32"),g){case"i1":case"i8":h[A>>0]=I;break;case"i16":u[A>>1]=I;break;case"i32":F[A>>2]=I;break;case"i64":x=[I>>>0,(J=I,+Math.abs(J)>=1?J>0?(0|Math.min(+Math.floor(J/4294967296),4294967295))>>>0:~~+Math.ceil((J-+(~~J>>>0))/4294967296)>>>0:0)],F[A>>2]=x[0],F[A+4>>2]=x[1];break;case"float":l[A>>2]=I;break;case"double":_[A>>3]=I;break;default:N("invalid type for setValue: "+g)}},a.getValue=function(A,I="i8",g){switch("*"===I.charAt(I.length-1)&&(I="i32"),I){case"i1":case"i8":return h[A>>0];case"i16":return u[A>>1];case"i32":case"i64":return F[A>>2];case"float":return l[A>>2];case"double":return Number(_[A>>3]);default:N("invalid type for getValue: "+I)}return null},a.UTF8ToString=G,Y=function A(){$||IA(),$||(Y=A)},a.run=IA,a.preInit)for("function"==typeof a.preInit&&(a.preInit=[a.preInit]);a.preInit.length>0;)a.preInit.pop()();IA()})).catch((function(){return B.useBackupModule()})),I}"function"==typeof define&&define.amd?define(["exports"],I): true&&"string"!=typeof exports.nodeName?I(exports):A.libsodium=I(A.libsodium_mod||(A.commonJsStrict={}))}(this);


/***/ }),

/***/ 4051:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/*! node-domexception. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> */

if (!globalThis.DOMException) {
  try {
    const { MessageChannel } = __nccwpck_require__(1267),
    port = new MessageChannel().port1,
    ab = new ArrayBuffer()
    port.postMessage(ab, [ab, ab])
  } catch (err) {
    err.constructor.name === 'DOMException' && (
      globalThis.DOMException = err.constructor
    )
  }
}

module.exports = globalThis.DOMException


/***/ }),

/***/ 2264:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

module.exports = __nccwpck_require__(9985);


/***/ }),

/***/ 9985:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


var net = __nccwpck_require__(1808);
var tls = __nccwpck_require__(4404);
var http = __nccwpck_require__(3685);
var https = __nccwpck_require__(5687);
var events = __nccwpck_require__(2361);
var assert = __nccwpck_require__(9491);
var util = __nccwpck_require__(3837);


exports.httpOverHttp = httpOverHttp;
exports.httpsOverHttp = httpsOverHttp;
exports.httpOverHttps = httpOverHttps;
exports.httpsOverHttps = httpsOverHttps;


function httpOverHttp(options) {
  var agent = new TunnelingAgent(options);
  agent.request = http.request;
  return agent;
}

function httpsOverHttp(options) {
  var agent = new TunnelingAgent(options);
  agent.request = http.request;
  agent.createSocket = createSecureSocket;
  agent.defaultPort = 443;
  return agent;
}

function httpOverHttps(options) {
  var agent = new TunnelingAgent(options);
  agent.request = https.request;
  return agent;
}

function httpsOverHttps(options) {
  var agent = new TunnelingAgent(options);
  agent.request = https.request;
  agent.createSocket = createSecureSocket;
  agent.defaultPort = 443;
  return agent;
}


function TunnelingAgent(options) {
  var self = this;
  self.options = options || {};
  self.proxyOptions = self.options.proxy || {};
  self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets;
  self.requests = [];
  self.sockets = [];

  self.on('free', function onFree(socket, host, port, localAddress) {
    var options = toOptions(host, port, localAddress);
    for (var i = 0, len = self.requests.length; i < len; ++i) {
      var pending = self.requests[i];
      if (pending.host === options.host && pending.port === options.port) {
        // Detect the request to connect same origin server,
        // reuse the connection.
        self.requests.splice(i, 1);
        pending.request.onSocket(socket);
        return;
      }
    }
    socket.destroy();
    self.removeSocket(socket);
  });
}
util.inherits(TunnelingAgent, events.EventEmitter);

TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
  var self = this;
  var options = mergeOptions({request: req}, self.options, toOptions(host, port, localAddress));

  if (self.sockets.length >= this.maxSockets) {
    // We are over limit so we'll add it to the queue.
    self.requests.push(options);
    return;
  }

  // If we are under maxSockets create a new one.
  self.createSocket(options, function(socket) {
    socket.on('free', onFree);
    socket.on('close', onCloseOrRemove);
    socket.on('agentRemove', onCloseOrRemove);
    req.onSocket(socket);

    function onFree() {
      self.emit('free', socket, options);
    }

    function onCloseOrRemove(err) {
      self.removeSocket(socket);
      socket.removeListener('free', onFree);
      socket.removeListener('close', onCloseOrRemove);
      socket.removeListener('agentRemove', onCloseOrRemove);
    }
  });
};

TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
  var self = this;
  var placeholder = {};
  self.sockets.push(placeholder);

  var connectOptions = mergeOptions({}, self.proxyOptions, {
    method: 'CONNECT',
    path: options.host + ':' + options.port,
    agent: false,
    headers: {
      host: options.host + ':' + options.port
    }
  });
  if (options.localAddress) {
    connectOptions.localAddress = options.localAddress;
  }
  if (connectOptions.proxyAuth) {
    connectOptions.headers = connectOptions.headers || {};
    connectOptions.headers['Proxy-Authorization'] = 'Basic ' +
        new Buffer(connectOptions.proxyAuth).toString('base64');
  }

  debug('making CONNECT request');
  var connectReq = self.request(connectOptions);
  connectReq.useChunkedEncodingByDefault = false; // for v0.6
  connectReq.once('response', onResponse); // for v0.6
  connectReq.once('upgrade', onUpgrade);   // for v0.6
  connectReq.once('connect', onConnect);   // for v0.7 or later
  connectReq.once('error', onError);
  connectReq.end();

  function onResponse(res) {
    // Very hacky. This is necessary to avoid http-parser leaks.
    res.upgrade = true;
  }

  function onUpgrade(res, socket, head) {
    // Hacky.
    process.nextTick(function() {
      onConnect(res, socket, head);
    });
  }

  function onConnect(res, socket, head) {
    connectReq.removeAllListeners();
    socket.removeAllListeners();

    if (res.statusCode !== 200) {
      debug('tunneling socket could not be established, statusCode=%d',
        res.statusCode);
      socket.destroy();
      var error = new Error('tunneling socket could not be established, ' +
        'statusCode=' + res.statusCode);
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
      self.removeSocket(placeholder);
      return;
    }
    if (head.length > 0) {
      debug('got illegal response body from proxy');
      socket.destroy();
      var error = new Error('got illegal response body from proxy');
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
      self.removeSocket(placeholder);
      return;
    }
    debug('tunneling connection has established');
    self.sockets[self.sockets.indexOf(placeholder)] = socket;
    return cb(socket);
  }

  function onError(cause) {
    connectReq.removeAllListeners();

    debug('tunneling socket could not be established, cause=%s\n',
          cause.message, cause.stack);
    var error = new Error('tunneling socket could not be established, ' +
                          'cause=' + cause.message);
    error.code = 'ECONNRESET';
    options.request.emit('error', error);
    self.removeSocket(placeholder);
  }
};

TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
  var pos = this.sockets.indexOf(socket)
  if (pos === -1) {
    return;
  }
  this.sockets.splice(pos, 1);

  var pending = this.requests.shift();
  if (pending) {
    // If we have pending requests and a socket gets closed a new one
    // needs to be created to take over in the pool for the one that closed.
    this.createSocket(pending, function(socket) {
      pending.request.onSocket(socket);
    });
  }
};

function createSecureSocket(options, cb) {
  var self = this;
  TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
    var hostHeader = options.request.getHeader('host');
    var tlsOptions = mergeOptions({}, self.options, {
      socket: socket,
      servername: hostHeader ? hostHeader.replace(/:.*$/, '') : options.host
    });

    // 0 is dummy port for v0.6
    var secureSocket = tls.connect(0, tlsOptions);
    self.sockets[self.sockets.indexOf(socket)] = secureSocket;
    cb(secureSocket);
  });
}


function toOptions(host, port, localAddress) {
  if (typeof host === 'string') { // since v0.10
    return {
      host: host,
      port: port,
      localAddress: localAddress
    };
  }
  return host; // for v0.11 or later
}

function mergeOptions(target) {
  for (var i = 1, len = arguments.length; i < len; ++i) {
    var overrides = arguments[i];
    if (typeof overrides === 'object') {
      var keys = Object.keys(overrides);
      for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
        var k = keys[j];
        if (overrides[k] !== undefined) {
          target[k] = overrides[k];
        }
      }
    }
  }
  return target;
}


var debug;
if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
  debug = function() {
    var args = Array.prototype.slice.call(arguments);
    if (typeof args[0] === 'string') {
      args[0] = 'TUNNEL: ' + args[0];
    } else {
      args.unshift('TUNNEL:');
    }
    console.error.apply(console, args);
  }
} else {
  debug = function() {};
}
exports.debug = debug; // for test


/***/ }),

/***/ 3160:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
Object.defineProperty(exports, "v1", ({
  enumerable: true,
  get: function () {
    return _v.default;
  }
}));
Object.defineProperty(exports, "v3", ({
  enumerable: true,
  get: function () {
    return _v2.default;
  }
}));
Object.defineProperty(exports, "v4", ({
  enumerable: true,
  get: function () {
    return _v3.default;
  }
}));
Object.defineProperty(exports, "v5", ({
  enumerable: true,
  get: function () {
    return _v4.default;
  }
}));
Object.defineProperty(exports, "NIL", ({
  enumerable: true,
  get: function () {
    return _nil.default;
  }
}));
Object.defineProperty(exports, "version", ({
  enumerable: true,
  get: function () {
    return _version.default;
  }
}));
Object.defineProperty(exports, "validate", ({
  enumerable: true,
  get: function () {
    return _validate.default;
  }
}));
Object.defineProperty(exports, "stringify", ({
  enumerable: true,
  get: function () {
    return _stringify.default;
  }
}));
Object.defineProperty(exports, "parse", ({
  enumerable: true,
  get: function () {
    return _parse.default;
  }
}));

var _v = _interopRequireDefault(__nccwpck_require__(9374));

var _v2 = _interopRequireDefault(__nccwpck_require__(8377));

var _v3 = _interopRequireDefault(__nccwpck_require__(3884));

var _v4 = _interopRequireDefault(__nccwpck_require__(6959));

var _nil = _interopRequireDefault(__nccwpck_require__(590));

var _version = _interopRequireDefault(__nccwpck_require__(6229));

var _validate = _interopRequireDefault(__nccwpck_require__(2525));

var _stringify = _interopRequireDefault(__nccwpck_require__(3192));

var _parse = _interopRequireDefault(__nccwpck_require__(1148));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/***/ }),

/***/ 8981:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('md5').update(bytes).digest();
}

var _default = md5;
exports["default"] = _default;

/***/ }),

/***/ 590:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
var _default = '00000000-0000-0000-0000-000000000000';
exports["default"] = _default;

/***/ }),

/***/ 1148:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(2525));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function parse(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  let v;
  const arr = new Uint8Array(16); // Parse ########-....-....-....-............

  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 0xff;
  arr[2] = v >>> 8 & 0xff;
  arr[3] = v & 0xff; // Parse ........-####-....-....-............

  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 0xff; // Parse ........-....-####-....-............

  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 0xff; // Parse ........-....-....-####-............

  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 0xff; // Parse ........-....-....-....-############
  // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
  arr[11] = v / 0x100000000 & 0xff;
  arr[12] = v >>> 24 & 0xff;
  arr[13] = v >>> 16 & 0xff;
  arr[14] = v >>> 8 & 0xff;
  arr[15] = v & 0xff;
  return arr;
}

var _default = parse;
exports["default"] = _default;

/***/ }),

/***/ 9673:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;
var _default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
exports["default"] = _default;

/***/ }),

/***/ 3111:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = rng;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const rnds8Pool = new Uint8Array(256); // # of random values to pre-allocate

let poolPtr = rnds8Pool.length;

function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    _crypto.default.randomFillSync(rnds8Pool);

    poolPtr = 0;
  }

  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}

/***/ }),

/***/ 6649:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__nccwpck_require__(6113));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('sha1').update(bytes).digest();
}

var _default = sha1;
exports["default"] = _default;

/***/ }),

/***/ 3192:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(2525));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
const byteToHex = [];

for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).substr(1));
}

function stringify(arr, offset = 0) {
  // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase(); // Consistency check for valid UUID.  If this throws, it's likely due to one
  // of the following:
  // - One or more input array values don't map to a hex octet (leading to
  // "undefined" in the uuid)
  // - Invalid input values for the RFC `version` or `variant` fields

  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }

  return uuid;
}

var _default = stringify;
exports["default"] = _default;

/***/ }),

/***/ 9374:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__nccwpck_require__(3111));

var _stringify = _interopRequireDefault(__nccwpck_require__(3192));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html
let _nodeId;

let _clockseq; // Previous uuid creation time


let _lastMSecs = 0;
let _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189

  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || _rng.default)();

    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }

    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


  let msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock

  let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval


  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  } // Per 4.2.1.2 Throw error if too many uuids are requested


  if (nsecs >= 10000) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

  msecs += 12219292800000; // `time_low`

  const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff; // `time_mid`

  const tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff; // `time_high_and_version`

  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

  b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

  b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

  b[i++] = clockseq & 0xff; // `node`

  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf || (0, _stringify.default)(b);
}

var _default = v1;
exports["default"] = _default;

/***/ }),

/***/ 8377:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__nccwpck_require__(2125));

var _md = _interopRequireDefault(__nccwpck_require__(8981));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v3 = (0, _v.default)('v3', 0x30, _md.default);
var _default = v3;
exports["default"] = _default;

/***/ }),

/***/ 2125:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = _default;
exports.URL = exports.DNS = void 0;

var _stringify = _interopRequireDefault(__nccwpck_require__(3192));

var _parse = _interopRequireDefault(__nccwpck_require__(1148));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  const bytes = [];

  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }

  return bytes;
}

const DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
exports.DNS = DNS;
const URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
exports.URL = URL;

function _default(name, version, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === 'string') {
      value = stringToBytes(value);
    }

    if (typeof namespace === 'string') {
      namespace = (0, _parse.default)(namespace);
    }

    if (namespace.length !== 16) {
      throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
    } // Compute hash of namespace and value, Per 4.3
    // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
    // hashfunc([...namespace, ... value])`


    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      offset = offset || 0;

      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }

      return buf;
    }

    return (0, _stringify.default)(bytes);
  } // Function#name is not settable on some platforms (#270)


  try {
    generateUUID.name = name; // eslint-disable-next-line no-empty
  } catch (err) {} // For CommonJS default export support


  generateUUID.DNS = DNS;
  generateUUID.URL = URL;
  return generateUUID;
}

/***/ }),

/***/ 3884:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__nccwpck_require__(3111));

var _stringify = _interopRequireDefault(__nccwpck_require__(3192));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function v4(options, buf, offset) {
  options = options || {};

  const rnds = options.random || (options.rng || _rng.default)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`


  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    offset = offset || 0;

    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }

    return buf;
  }

  return (0, _stringify.default)(rnds);
}

var _default = v4;
exports["default"] = _default;

/***/ }),

/***/ 6959:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__nccwpck_require__(2125));

var _sha = _interopRequireDefault(__nccwpck_require__(6649));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v5 = (0, _v.default)('v5', 0x50, _sha.default);
var _default = v5;
exports["default"] = _default;

/***/ }),

/***/ 2525:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _regex = _interopRequireDefault(__nccwpck_require__(9673));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function validate(uuid) {
  return typeof uuid === 'string' && _regex.default.test(uuid);
}

var _default = validate;
exports["default"] = _default;

/***/ }),

/***/ 6229:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _validate = _interopRequireDefault(__nccwpck_require__(2525));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function version(uuid) {
  if (!(0, _validate.default)(uuid)) {
    throw TypeError('Invalid UUID');
  }

  return parseInt(uuid.substr(14, 1), 16);
}

var _default = version;
exports["default"] = _default;

/***/ }),

/***/ 6467:
/***/ (function(__unused_webpack_module, exports) {

/**
 * web-streams-polyfill v3.2.1
 */
(function (global, factory) {
     true ? factory(exports) :
    0;
}(this, (function (exports) { 'use strict';

    /// <reference lib="es2015.symbol" />
    const SymbolPolyfill = typeof Symbol === 'function' && typeof Symbol.iterator === 'symbol' ?
        Symbol :
        description => `Symbol(${description})`;

    /// <reference lib="dom" />
    function noop() {
        return undefined;
    }
    function getGlobals() {
        if (typeof self !== 'undefined') {
            return self;
        }
        else if (typeof window !== 'undefined') {
            return window;
        }
        else if (typeof global !== 'undefined') {
            return global;
        }
        return undefined;
    }
    const globals = getGlobals();

    function typeIsObject(x) {
        return (typeof x === 'object' && x !== null) || typeof x === 'function';
    }
    const rethrowAssertionErrorRejection = noop;

    const originalPromise = Promise;
    const originalPromiseThen = Promise.prototype.then;
    const originalPromiseResolve = Promise.resolve.bind(originalPromise);
    const originalPromiseReject = Promise.reject.bind(originalPromise);
    function newPromise(executor) {
        return new originalPromise(executor);
    }
    function promiseResolvedWith(value) {
        return originalPromiseResolve(value);
    }
    function promiseRejectedWith(reason) {
        return originalPromiseReject(reason);
    }
    function PerformPromiseThen(promise, onFulfilled, onRejected) {
        // There doesn't appear to be any way to correctly emulate the behaviour from JavaScript, so this is just an
        // approximation.
        return originalPromiseThen.call(promise, onFulfilled, onRejected);
    }
    function uponPromise(promise, onFulfilled, onRejected) {
        PerformPromiseThen(PerformPromiseThen(promise, onFulfilled, onRejected), undefined, rethrowAssertionErrorRejection);
    }
    function uponFulfillment(promise, onFulfilled) {
        uponPromise(promise, onFulfilled);
    }
    function uponRejection(promise, onRejected) {
        uponPromise(promise, undefined, onRejected);
    }
    function transformPromiseWith(promise, fulfillmentHandler, rejectionHandler) {
        return PerformPromiseThen(promise, fulfillmentHandler, rejectionHandler);
    }
    function setPromiseIsHandledToTrue(promise) {
        PerformPromiseThen(promise, undefined, rethrowAssertionErrorRejection);
    }
    const queueMicrotask = (() => {
        const globalQueueMicrotask = globals && globals.queueMicrotask;
        if (typeof globalQueueMicrotask === 'function') {
            return globalQueueMicrotask;
        }
        const resolvedPromise = promiseResolvedWith(undefined);
        return (fn) => PerformPromiseThen(resolvedPromise, fn);
    })();
    function reflectCall(F, V, args) {
        if (typeof F !== 'function') {
            throw new TypeError('Argument is not a function');
        }
        return Function.prototype.apply.call(F, V, args);
    }
    function promiseCall(F, V, args) {
        try {
            return promiseResolvedWith(reflectCall(F, V, args));
        }
        catch (value) {
            return promiseRejectedWith(value);
        }
    }

    // Original from Chromium
    // https://chromium.googlesource.com/chromium/src/+/0aee4434a4dba42a42abaea9bfbc0cd196a63bc1/third_party/blink/renderer/core/streams/SimpleQueue.js
    const QUEUE_MAX_ARRAY_SIZE = 16384;
    /**
     * Simple queue structure.
     *
     * Avoids scalability issues with using a packed array directly by using
     * multiple arrays in a linked list and keeping the array size bounded.
     */
    class SimpleQueue {
        constructor() {
            this._cursor = 0;
            this._size = 0;
            // _front and _back are always defined.
            this._front = {
                _elements: [],
                _next: undefined
            };
            this._back = this._front;
            // The cursor is used to avoid calling Array.shift().
            // It contains the index of the front element of the array inside the
            // front-most node. It is always in the range [0, QUEUE_MAX_ARRAY_SIZE).
            this._cursor = 0;
            // When there is only one node, size === elements.length - cursor.
            this._size = 0;
        }
        get length() {
            return this._size;
        }
        // For exception safety, this method is structured in order:
        // 1. Read state
        // 2. Calculate required state mutations
        // 3. Perform state mutations
        push(element) {
            const oldBack = this._back;
            let newBack = oldBack;
            if (oldBack._elements.length === QUEUE_MAX_ARRAY_SIZE - 1) {
                newBack = {
                    _elements: [],
                    _next: undefined
                };
            }
            // push() is the mutation most likely to throw an exception, so it
            // goes first.
            oldBack._elements.push(element);
            if (newBack !== oldBack) {
                this._back = newBack;
                oldBack._next = newBack;
            }
            ++this._size;
        }
        // Like push(), shift() follows the read -> calculate -> mutate pattern for
        // exception safety.
        shift() { // must not be called on an empty queue
            const oldFront = this._front;
            let newFront = oldFront;
            const oldCursor = this._cursor;
            let newCursor = oldCursor + 1;
            const elements = oldFront._elements;
            const element = elements[oldCursor];
            if (newCursor === QUEUE_MAX_ARRAY_SIZE) {
                newFront = oldFront._next;
                newCursor = 0;
            }
            // No mutations before this point.
            --this._size;
            this._cursor = newCursor;
            if (oldFront !== newFront) {
                this._front = newFront;
            }
            // Permit shifted element to be garbage collected.
            elements[oldCursor] = undefined;
            return element;
        }
        // The tricky thing about forEach() is that it can be called
        // re-entrantly. The queue may be mutated inside the callback. It is easy to
        // see that push() within the callback has no negative effects since the end
        // of the queue is checked for on every iteration. If shift() is called
        // repeatedly within the callback then the next iteration may return an
        // element that has been removed. In this case the callback will be called
        // with undefined values until we either "catch up" with elements that still
        // exist or reach the back of the queue.
        forEach(callback) {
            let i = this._cursor;
            let node = this._front;
            let elements = node._elements;
            while (i !== elements.length || node._next !== undefined) {
                if (i === elements.length) {
                    node = node._next;
                    elements = node._elements;
                    i = 0;
                    if (elements.length === 0) {
                        break;
                    }
                }
                callback(elements[i]);
                ++i;
            }
        }
        // Return the element that would be returned if shift() was called now,
        // without modifying the queue.
        peek() { // must not be called on an empty queue
            const front = this._front;
            const cursor = this._cursor;
            return front._elements[cursor];
        }
    }

    function ReadableStreamReaderGenericInitialize(reader, stream) {
        reader._ownerReadableStream = stream;
        stream._reader = reader;
        if (stream._state === 'readable') {
            defaultReaderClosedPromiseInitialize(reader);
        }
        else if (stream._state === 'closed') {
            defaultReaderClosedPromiseInitializeAsResolved(reader);
        }
        else {
            defaultReaderClosedPromiseInitializeAsRejected(reader, stream._storedError);
        }
    }
    // A client of ReadableStreamDefaultReader and ReadableStreamBYOBReader may use these functions directly to bypass state
    // check.
    function ReadableStreamReaderGenericCancel(reader, reason) {
        const stream = reader._ownerReadableStream;
        return ReadableStreamCancel(stream, reason);
    }
    function ReadableStreamReaderGenericRelease(reader) {
        if (reader._ownerReadableStream._state === 'readable') {
            defaultReaderClosedPromiseReject(reader, new TypeError(`Reader was released and can no longer be used to monitor the stream's closedness`));
        }
        else {
            defaultReaderClosedPromiseResetToRejected(reader, new TypeError(`Reader was released and can no longer be used to monitor the stream's closedness`));
        }
        reader._ownerReadableStream._reader = undefined;
        reader._ownerReadableStream = undefined;
    }
    // Helper functions for the readers.
    function readerLockException(name) {
        return new TypeError('Cannot ' + name + ' a stream using a released reader');
    }
    // Helper functions for the ReadableStreamDefaultReader.
    function defaultReaderClosedPromiseInitialize(reader) {
        reader._closedPromise = newPromise((resolve, reject) => {
            reader._closedPromise_resolve = resolve;
            reader._closedPromise_reject = reject;
        });
    }
    function defaultReaderClosedPromiseInitializeAsRejected(reader, reason) {
        defaultReaderClosedPromiseInitialize(reader);
        defaultReaderClosedPromiseReject(reader, reason);
    }
    function defaultReaderClosedPromiseInitializeAsResolved(reader) {
        defaultReaderClosedPromiseInitialize(reader);
        defaultReaderClosedPromiseResolve(reader);
    }
    function defaultReaderClosedPromiseReject(reader, reason) {
        if (reader._closedPromise_reject === undefined) {
            return;
        }
        setPromiseIsHandledToTrue(reader._closedPromise);
        reader._closedPromise_reject(reason);
        reader._closedPromise_resolve = undefined;
        reader._closedPromise_reject = undefined;
    }
    function defaultReaderClosedPromiseResetToRejected(reader, reason) {
        defaultReaderClosedPromiseInitializeAsRejected(reader, reason);
    }
    function defaultReaderClosedPromiseResolve(reader) {
        if (reader._closedPromise_resolve === undefined) {
            return;
        }
        reader._closedPromise_resolve(undefined);
        reader._closedPromise_resolve = undefined;
        reader._closedPromise_reject = undefined;
    }

    const AbortSteps = SymbolPolyfill('[[AbortSteps]]');
    const ErrorSteps = SymbolPolyfill('[[ErrorSteps]]');
    const CancelSteps = SymbolPolyfill('[[CancelSteps]]');
    const PullSteps = SymbolPolyfill('[[PullSteps]]');

    /// <reference lib="es2015.core" />
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/isFinite#Polyfill
    const NumberIsFinite = Number.isFinite || function (x) {
        return typeof x === 'number' && isFinite(x);
    };

    /// <reference lib="es2015.core" />
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/trunc#Polyfill
    const MathTrunc = Math.trunc || function (v) {
        return v < 0 ? Math.ceil(v) : Math.floor(v);
    };

    // https://heycam.github.io/webidl/#idl-dictionaries
    function isDictionary(x) {
        return typeof x === 'object' || typeof x === 'function';
    }
    function assertDictionary(obj, context) {
        if (obj !== undefined && !isDictionary(obj)) {
            throw new TypeError(`${context} is not an object.`);
        }
    }
    // https://heycam.github.io/webidl/#idl-callback-functions
    function assertFunction(x, context) {
        if (typeof x !== 'function') {
            throw new TypeError(`${context} is not a function.`);
        }
    }
    // https://heycam.github.io/webidl/#idl-object
    function isObject(x) {
        return (typeof x === 'object' && x !== null) || typeof x === 'function';
    }
    function assertObject(x, context) {
        if (!isObject(x)) {
            throw new TypeError(`${context} is not an object.`);
        }
    }
    function assertRequiredArgument(x, position, context) {
        if (x === undefined) {
            throw new TypeError(`Parameter ${position} is required in '${context}'.`);
        }
    }
    function assertRequiredField(x, field, context) {
        if (x === undefined) {
            throw new TypeError(`${field} is required in '${context}'.`);
        }
    }
    // https://heycam.github.io/webidl/#idl-unrestricted-double
    function convertUnrestrictedDouble(value) {
        return Number(value);
    }
    function censorNegativeZero(x) {
        return x === 0 ? 0 : x;
    }
    function integerPart(x) {
        return censorNegativeZero(MathTrunc(x));
    }
    // https://heycam.github.io/webidl/#idl-unsigned-long-long
    function convertUnsignedLongLongWithEnforceRange(value, context) {
        const lowerBound = 0;
        const upperBound = Number.MAX_SAFE_INTEGER;
        let x = Number(value);
        x = censorNegativeZero(x);
        if (!NumberIsFinite(x)) {
            throw new TypeError(`${context} is not a finite number`);
        }
        x = integerPart(x);
        if (x < lowerBound || x > upperBound) {
            throw new TypeError(`${context} is outside the accepted range of ${lowerBound} to ${upperBound}, inclusive`);
        }
        if (!NumberIsFinite(x) || x === 0) {
            return 0;
        }
        // TODO Use BigInt if supported?
        // let xBigInt = BigInt(integerPart(x));
        // xBigInt = BigInt.asUintN(64, xBigInt);
        // return Number(xBigInt);
        return x;
    }

    function assertReadableStream(x, context) {
        if (!IsReadableStream(x)) {
            throw new TypeError(`${context} is not a ReadableStream.`);
        }
    }

    // Abstract operations for the ReadableStream.
    function AcquireReadableStreamDefaultReader(stream) {
        return new ReadableStreamDefaultReader(stream);
    }
    // ReadableStream API exposed for controllers.
    function ReadableStreamAddReadRequest(stream, readRequest) {
        stream._reader._readRequests.push(readRequest);
    }
    function ReadableStreamFulfillReadRequest(stream, chunk, done) {
        const reader = stream._reader;
        const readRequest = reader._readRequests.shift();
        if (done) {
            readRequest._closeSteps();
        }
        else {
            readRequest._chunkSteps(chunk);
        }
    }
    function ReadableStreamGetNumReadRequests(stream) {
        return stream._reader._readRequests.length;
    }
    function ReadableStreamHasDefaultReader(stream) {
        const reader = stream._reader;
        if (reader === undefined) {
            return false;
        }
        if (!IsReadableStreamDefaultReader(reader)) {
            return false;
        }
        return true;
    }
    /**
     * A default reader vended by a {@link ReadableStream}.
     *
     * @public
     */
    class ReadableStreamDefaultReader {
        constructor(stream) {
            assertRequiredArgument(stream, 1, 'ReadableStreamDefaultReader');
            assertReadableStream(stream, 'First parameter');
            if (IsReadableStreamLocked(stream)) {
                throw new TypeError('This stream has already been locked for exclusive reading by another reader');
            }
            ReadableStreamReaderGenericInitialize(this, stream);
            this._readRequests = new SimpleQueue();
        }
        /**
         * Returns a promise that will be fulfilled when the stream becomes closed,
         * or rejected if the stream ever errors or the reader's lock is released before the stream finishes closing.
         */
        get closed() {
            if (!IsReadableStreamDefaultReader(this)) {
                return promiseRejectedWith(defaultReaderBrandCheckException('closed'));
            }
            return this._closedPromise;
        }
        /**
         * If the reader is active, behaves the same as {@link ReadableStream.cancel | stream.cancel(reason)}.
         */
        cancel(reason = undefined) {
            if (!IsReadableStreamDefaultReader(this)) {
                return promiseRejectedWith(defaultReaderBrandCheckException('cancel'));
            }
            if (this._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('cancel'));
            }
            return ReadableStreamReaderGenericCancel(this, reason);
        }
        /**
         * Returns a promise that allows access to the next chunk from the stream's internal queue, if available.
         *
         * If reading a chunk causes the queue to become empty, more data will be pulled from the underlying source.
         */
        read() {
            if (!IsReadableStreamDefaultReader(this)) {
                return promiseRejectedWith(defaultReaderBrandCheckException('read'));
            }
            if (this._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('read from'));
            }
            let resolvePromise;
            let rejectPromise;
            const promise = newPromise((resolve, reject) => {
                resolvePromise = resolve;
                rejectPromise = reject;
            });
            const readRequest = {
                _chunkSteps: chunk => resolvePromise({ value: chunk, done: false }),
                _closeSteps: () => resolvePromise({ value: undefined, done: true }),
                _errorSteps: e => rejectPromise(e)
            };
            ReadableStreamDefaultReaderRead(this, readRequest);
            return promise;
        }
        /**
         * Releases the reader's lock on the corresponding stream. After the lock is released, the reader is no longer active.
         * If the associated stream is errored when the lock is released, the reader will appear errored in the same way
         * from now on; otherwise, the reader will appear closed.
         *
         * A reader's lock cannot be released while it still has a pending read request, i.e., if a promise returned by
         * the reader's {@link ReadableStreamDefaultReader.read | read()} method has not yet been settled. Attempting to
         * do so will throw a `TypeError` and leave the reader locked to the stream.
         */
        releaseLock() {
            if (!IsReadableStreamDefaultReader(this)) {
                throw defaultReaderBrandCheckException('releaseLock');
            }
            if (this._ownerReadableStream === undefined) {
                return;
            }
            if (this._readRequests.length > 0) {
                throw new TypeError('Tried to release a reader lock when that reader has pending read() calls un-settled');
            }
            ReadableStreamReaderGenericRelease(this);
        }
    }
    Object.defineProperties(ReadableStreamDefaultReader.prototype, {
        cancel: { enumerable: true },
        read: { enumerable: true },
        releaseLock: { enumerable: true },
        closed: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStreamDefaultReader.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStreamDefaultReader',
            configurable: true
        });
    }
    // Abstract operations for the readers.
    function IsReadableStreamDefaultReader(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_readRequests')) {
            return false;
        }
        return x instanceof ReadableStreamDefaultReader;
    }
    function ReadableStreamDefaultReaderRead(reader, readRequest) {
        const stream = reader._ownerReadableStream;
        stream._disturbed = true;
        if (stream._state === 'closed') {
            readRequest._closeSteps();
        }
        else if (stream._state === 'errored') {
            readRequest._errorSteps(stream._storedError);
        }
        else {
            stream._readableStreamController[PullSteps](readRequest);
        }
    }
    // Helper functions for the ReadableStreamDefaultReader.
    function defaultReaderBrandCheckException(name) {
        return new TypeError(`ReadableStreamDefaultReader.prototype.${name} can only be used on a ReadableStreamDefaultReader`);
    }

    /// <reference lib="es2018.asynciterable" />
    /* eslint-disable @typescript-eslint/no-empty-function */
    const AsyncIteratorPrototype = Object.getPrototypeOf(Object.getPrototypeOf(async function* () { }).prototype);

    /// <reference lib="es2018.asynciterable" />
    class ReadableStreamAsyncIteratorImpl {
        constructor(reader, preventCancel) {
            this._ongoingPromise = undefined;
            this._isFinished = false;
            this._reader = reader;
            this._preventCancel = preventCancel;
        }
        next() {
            const nextSteps = () => this._nextSteps();
            this._ongoingPromise = this._ongoingPromise ?
                transformPromiseWith(this._ongoingPromise, nextSteps, nextSteps) :
                nextSteps();
            return this._ongoingPromise;
        }
        return(value) {
            const returnSteps = () => this._returnSteps(value);
            return this._ongoingPromise ?
                transformPromiseWith(this._ongoingPromise, returnSteps, returnSteps) :
                returnSteps();
        }
        _nextSteps() {
            if (this._isFinished) {
                return Promise.resolve({ value: undefined, done: true });
            }
            const reader = this._reader;
            if (reader._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('iterate'));
            }
            let resolvePromise;
            let rejectPromise;
            const promise = newPromise((resolve, reject) => {
                resolvePromise = resolve;
                rejectPromise = reject;
            });
            const readRequest = {
                _chunkSteps: chunk => {
                    this._ongoingPromise = undefined;
                    // This needs to be delayed by one microtask, otherwise we stop pulling too early which breaks a test.
                    // FIXME Is this a bug in the specification, or in the test?
                    queueMicrotask(() => resolvePromise({ value: chunk, done: false }));
                },
                _closeSteps: () => {
                    this._ongoingPromise = undefined;
                    this._isFinished = true;
                    ReadableStreamReaderGenericRelease(reader);
                    resolvePromise({ value: undefined, done: true });
                },
                _errorSteps: reason => {
                    this._ongoingPromise = undefined;
                    this._isFinished = true;
                    ReadableStreamReaderGenericRelease(reader);
                    rejectPromise(reason);
                }
            };
            ReadableStreamDefaultReaderRead(reader, readRequest);
            return promise;
        }
        _returnSteps(value) {
            if (this._isFinished) {
                return Promise.resolve({ value, done: true });
            }
            this._isFinished = true;
            const reader = this._reader;
            if (reader._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('finish iterating'));
            }
            if (!this._preventCancel) {
                const result = ReadableStreamReaderGenericCancel(reader, value);
                ReadableStreamReaderGenericRelease(reader);
                return transformPromiseWith(result, () => ({ value, done: true }));
            }
            ReadableStreamReaderGenericRelease(reader);
            return promiseResolvedWith({ value, done: true });
        }
    }
    const ReadableStreamAsyncIteratorPrototype = {
        next() {
            if (!IsReadableStreamAsyncIterator(this)) {
                return promiseRejectedWith(streamAsyncIteratorBrandCheckException('next'));
            }
            return this._asyncIteratorImpl.next();
        },
        return(value) {
            if (!IsReadableStreamAsyncIterator(this)) {
                return promiseRejectedWith(streamAsyncIteratorBrandCheckException('return'));
            }
            return this._asyncIteratorImpl.return(value);
        }
    };
    if (AsyncIteratorPrototype !== undefined) {
        Object.setPrototypeOf(ReadableStreamAsyncIteratorPrototype, AsyncIteratorPrototype);
    }
    // Abstract operations for the ReadableStream.
    function AcquireReadableStreamAsyncIterator(stream, preventCancel) {
        const reader = AcquireReadableStreamDefaultReader(stream);
        const impl = new ReadableStreamAsyncIteratorImpl(reader, preventCancel);
        const iterator = Object.create(ReadableStreamAsyncIteratorPrototype);
        iterator._asyncIteratorImpl = impl;
        return iterator;
    }
    function IsReadableStreamAsyncIterator(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_asyncIteratorImpl')) {
            return false;
        }
        try {
            // noinspection SuspiciousTypeOfGuard
            return x._asyncIteratorImpl instanceof
                ReadableStreamAsyncIteratorImpl;
        }
        catch (_a) {
            return false;
        }
    }
    // Helper functions for the ReadableStream.
    function streamAsyncIteratorBrandCheckException(name) {
        return new TypeError(`ReadableStreamAsyncIterator.${name} can only be used on a ReadableSteamAsyncIterator`);
    }

    /// <reference lib="es2015.core" />
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/isNaN#Polyfill
    const NumberIsNaN = Number.isNaN || function (x) {
        // eslint-disable-next-line no-self-compare
        return x !== x;
    };

    function CreateArrayFromList(elements) {
        // We use arrays to represent lists, so this is basically a no-op.
        // Do a slice though just in case we happen to depend on the unique-ness.
        return elements.slice();
    }
    function CopyDataBlockBytes(dest, destOffset, src, srcOffset, n) {
        new Uint8Array(dest).set(new Uint8Array(src, srcOffset, n), destOffset);
    }
    // Not implemented correctly
    function TransferArrayBuffer(O) {
        return O;
    }
    // Not implemented correctly
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    function IsDetachedBuffer(O) {
        return false;
    }
    function ArrayBufferSlice(buffer, begin, end) {
        // ArrayBuffer.prototype.slice is not available on IE10
        // https://www.caniuse.com/mdn-javascript_builtins_arraybuffer_slice
        if (buffer.slice) {
            return buffer.slice(begin, end);
        }
        const length = end - begin;
        const slice = new ArrayBuffer(length);
        CopyDataBlockBytes(slice, 0, buffer, begin, length);
        return slice;
    }

    function IsNonNegativeNumber(v) {
        if (typeof v !== 'number') {
            return false;
        }
        if (NumberIsNaN(v)) {
            return false;
        }
        if (v < 0) {
            return false;
        }
        return true;
    }
    function CloneAsUint8Array(O) {
        const buffer = ArrayBufferSlice(O.buffer, O.byteOffset, O.byteOffset + O.byteLength);
        return new Uint8Array(buffer);
    }

    function DequeueValue(container) {
        const pair = container._queue.shift();
        container._queueTotalSize -= pair.size;
        if (container._queueTotalSize < 0) {
            container._queueTotalSize = 0;
        }
        return pair.value;
    }
    function EnqueueValueWithSize(container, value, size) {
        if (!IsNonNegativeNumber(size) || size === Infinity) {
            throw new RangeError('Size must be a finite, non-NaN, non-negative number.');
        }
        container._queue.push({ value, size });
        container._queueTotalSize += size;
    }
    function PeekQueueValue(container) {
        const pair = container._queue.peek();
        return pair.value;
    }
    function ResetQueue(container) {
        container._queue = new SimpleQueue();
        container._queueTotalSize = 0;
    }

    /**
     * A pull-into request in a {@link ReadableByteStreamController}.
     *
     * @public
     */
    class ReadableStreamBYOBRequest {
        constructor() {
            throw new TypeError('Illegal constructor');
        }
        /**
         * Returns the view for writing in to, or `null` if the BYOB request has already been responded to.
         */
        get view() {
            if (!IsReadableStreamBYOBRequest(this)) {
                throw byobRequestBrandCheckException('view');
            }
            return this._view;
        }
        respond(bytesWritten) {
            if (!IsReadableStreamBYOBRequest(this)) {
                throw byobRequestBrandCheckException('respond');
            }
            assertRequiredArgument(bytesWritten, 1, 'respond');
            bytesWritten = convertUnsignedLongLongWithEnforceRange(bytesWritten, 'First parameter');
            if (this._associatedReadableByteStreamController === undefined) {
                throw new TypeError('This BYOB request has been invalidated');
            }
            if (IsDetachedBuffer(this._view.buffer)) ;
            ReadableByteStreamControllerRespond(this._associatedReadableByteStreamController, bytesWritten);
        }
        respondWithNewView(view) {
            if (!IsReadableStreamBYOBRequest(this)) {
                throw byobRequestBrandCheckException('respondWithNewView');
            }
            assertRequiredArgument(view, 1, 'respondWithNewView');
            if (!ArrayBuffer.isView(view)) {
                throw new TypeError('You can only respond with array buffer views');
            }
            if (this._associatedReadableByteStreamController === undefined) {
                throw new TypeError('This BYOB request has been invalidated');
            }
            if (IsDetachedBuffer(view.buffer)) ;
            ReadableByteStreamControllerRespondWithNewView(this._associatedReadableByteStreamController, view);
        }
    }
    Object.defineProperties(ReadableStreamBYOBRequest.prototype, {
        respond: { enumerable: true },
        respondWithNewView: { enumerable: true },
        view: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStreamBYOBRequest.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStreamBYOBRequest',
            configurable: true
        });
    }
    /**
     * Allows control of a {@link ReadableStream | readable byte stream}'s state and internal queue.
     *
     * @public
     */
    class ReadableByteStreamController {
        constructor() {
            throw new TypeError('Illegal constructor');
        }
        /**
         * Returns the current BYOB pull request, or `null` if there isn't one.
         */
        get byobRequest() {
            if (!IsReadableByteStreamController(this)) {
                throw byteStreamControllerBrandCheckException('byobRequest');
            }
            return ReadableByteStreamControllerGetBYOBRequest(this);
        }
        /**
         * Returns the desired size to fill the controlled stream's internal queue. It can be negative, if the queue is
         * over-full. An underlying byte source ought to use this information to determine when and how to apply backpressure.
         */
        get desiredSize() {
            if (!IsReadableByteStreamController(this)) {
                throw byteStreamControllerBrandCheckException('desiredSize');
            }
            return ReadableByteStreamControllerGetDesiredSize(this);
        }
        /**
         * Closes the controlled readable stream. Consumers will still be able to read any previously-enqueued chunks from
         * the stream, but once those are read, the stream will become closed.
         */
        close() {
            if (!IsReadableByteStreamController(this)) {
                throw byteStreamControllerBrandCheckException('close');
            }
            if (this._closeRequested) {
                throw new TypeError('The stream has already been closed; do not close it again!');
            }
            const state = this._controlledReadableByteStream._state;
            if (state !== 'readable') {
                throw new TypeError(`The stream (in ${state} state) is not in the readable state and cannot be closed`);
            }
            ReadableByteStreamControllerClose(this);
        }
        enqueue(chunk) {
            if (!IsReadableByteStreamController(this)) {
                throw byteStreamControllerBrandCheckException('enqueue');
            }
            assertRequiredArgument(chunk, 1, 'enqueue');
            if (!ArrayBuffer.isView(chunk)) {
                throw new TypeError('chunk must be an array buffer view');
            }
            if (chunk.byteLength === 0) {
                throw new TypeError('chunk must have non-zero byteLength');
            }
            if (chunk.buffer.byteLength === 0) {
                throw new TypeError(`chunk's buffer must have non-zero byteLength`);
            }
            if (this._closeRequested) {
                throw new TypeError('stream is closed or draining');
            }
            const state = this._controlledReadableByteStream._state;
            if (state !== 'readable') {
                throw new TypeError(`The stream (in ${state} state) is not in the readable state and cannot be enqueued to`);
            }
            ReadableByteStreamControllerEnqueue(this, chunk);
        }
        /**
         * Errors the controlled readable stream, making all future interactions with it fail with the given error `e`.
         */
        error(e = undefined) {
            if (!IsReadableByteStreamController(this)) {
                throw byteStreamControllerBrandCheckException('error');
            }
            ReadableByteStreamControllerError(this, e);
        }
        /** @internal */
        [CancelSteps](reason) {
            ReadableByteStreamControllerClearPendingPullIntos(this);
            ResetQueue(this);
            const result = this._cancelAlgorithm(reason);
            ReadableByteStreamControllerClearAlgorithms(this);
            return result;
        }
        /** @internal */
        [PullSteps](readRequest) {
            const stream = this._controlledReadableByteStream;
            if (this._queueTotalSize > 0) {
                const entry = this._queue.shift();
                this._queueTotalSize -= entry.byteLength;
                ReadableByteStreamControllerHandleQueueDrain(this);
                const view = new Uint8Array(entry.buffer, entry.byteOffset, entry.byteLength);
                readRequest._chunkSteps(view);
                return;
            }
            const autoAllocateChunkSize = this._autoAllocateChunkSize;
            if (autoAllocateChunkSize !== undefined) {
                let buffer;
                try {
                    buffer = new ArrayBuffer(autoAllocateChunkSize);
                }
                catch (bufferE) {
                    readRequest._errorSteps(bufferE);
                    return;
                }
                const pullIntoDescriptor = {
                    buffer,
                    bufferByteLength: autoAllocateChunkSize,
                    byteOffset: 0,
                    byteLength: autoAllocateChunkSize,
                    bytesFilled: 0,
                    elementSize: 1,
                    viewConstructor: Uint8Array,
                    readerType: 'default'
                };
                this._pendingPullIntos.push(pullIntoDescriptor);
            }
            ReadableStreamAddReadRequest(stream, readRequest);
            ReadableByteStreamControllerCallPullIfNeeded(this);
        }
    }
    Object.defineProperties(ReadableByteStreamController.prototype, {
        close: { enumerable: true },
        enqueue: { enumerable: true },
        error: { enumerable: true },
        byobRequest: { enumerable: true },
        desiredSize: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableByteStreamController.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableByteStreamController',
            configurable: true
        });
    }
    // Abstract operations for the ReadableByteStreamController.
    function IsReadableByteStreamController(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_controlledReadableByteStream')) {
            return false;
        }
        return x instanceof ReadableByteStreamController;
    }
    function IsReadableStreamBYOBRequest(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_associatedReadableByteStreamController')) {
            return false;
        }
        return x instanceof ReadableStreamBYOBRequest;
    }
    function ReadableByteStreamControllerCallPullIfNeeded(controller) {
        const shouldPull = ReadableByteStreamControllerShouldCallPull(controller);
        if (!shouldPull) {
            return;
        }
        if (controller._pulling) {
            controller._pullAgain = true;
            return;
        }
        controller._pulling = true;
        // TODO: Test controller argument
        const pullPromise = controller._pullAlgorithm();
        uponPromise(pullPromise, () => {
            controller._pulling = false;
            if (controller._pullAgain) {
                controller._pullAgain = false;
                ReadableByteStreamControllerCallPullIfNeeded(controller);
            }
        }, e => {
            ReadableByteStreamControllerError(controller, e);
        });
    }
    function ReadableByteStreamControllerClearPendingPullIntos(controller) {
        ReadableByteStreamControllerInvalidateBYOBRequest(controller);
        controller._pendingPullIntos = new SimpleQueue();
    }
    function ReadableByteStreamControllerCommitPullIntoDescriptor(stream, pullIntoDescriptor) {
        let done = false;
        if (stream._state === 'closed') {
            done = true;
        }
        const filledView = ReadableByteStreamControllerConvertPullIntoDescriptor(pullIntoDescriptor);
        if (pullIntoDescriptor.readerType === 'default') {
            ReadableStreamFulfillReadRequest(stream, filledView, done);
        }
        else {
            ReadableStreamFulfillReadIntoRequest(stream, filledView, done);
        }
    }
    function ReadableByteStreamControllerConvertPullIntoDescriptor(pullIntoDescriptor) {
        const bytesFilled = pullIntoDescriptor.bytesFilled;
        const elementSize = pullIntoDescriptor.elementSize;
        return new pullIntoDescriptor.viewConstructor(pullIntoDescriptor.buffer, pullIntoDescriptor.byteOffset, bytesFilled / elementSize);
    }
    function ReadableByteStreamControllerEnqueueChunkToQueue(controller, buffer, byteOffset, byteLength) {
        controller._queue.push({ buffer, byteOffset, byteLength });
        controller._queueTotalSize += byteLength;
    }
    function ReadableByteStreamControllerFillPullIntoDescriptorFromQueue(controller, pullIntoDescriptor) {
        const elementSize = pullIntoDescriptor.elementSize;
        const currentAlignedBytes = pullIntoDescriptor.bytesFilled - pullIntoDescriptor.bytesFilled % elementSize;
        const maxBytesToCopy = Math.min(controller._queueTotalSize, pullIntoDescriptor.byteLength - pullIntoDescriptor.bytesFilled);
        const maxBytesFilled = pullIntoDescriptor.bytesFilled + maxBytesToCopy;
        const maxAlignedBytes = maxBytesFilled - maxBytesFilled % elementSize;
        let totalBytesToCopyRemaining = maxBytesToCopy;
        let ready = false;
        if (maxAlignedBytes > currentAlignedBytes) {
            totalBytesToCopyRemaining = maxAlignedBytes - pullIntoDescriptor.bytesFilled;
            ready = true;
        }
        const queue = controller._queue;
        while (totalBytesToCopyRemaining > 0) {
            const headOfQueue = queue.peek();
            const bytesToCopy = Math.min(totalBytesToCopyRemaining, headOfQueue.byteLength);
            const destStart = pullIntoDescriptor.byteOffset + pullIntoDescriptor.bytesFilled;
            CopyDataBlockBytes(pullIntoDescriptor.buffer, destStart, headOfQueue.buffer, headOfQueue.byteOffset, bytesToCopy);
            if (headOfQueue.byteLength === bytesToCopy) {
                queue.shift();
            }
            else {
                headOfQueue.byteOffset += bytesToCopy;
                headOfQueue.byteLength -= bytesToCopy;
            }
            controller._queueTotalSize -= bytesToCopy;
            ReadableByteStreamControllerFillHeadPullIntoDescriptor(controller, bytesToCopy, pullIntoDescriptor);
            totalBytesToCopyRemaining -= bytesToCopy;
        }
        return ready;
    }
    function ReadableByteStreamControllerFillHeadPullIntoDescriptor(controller, size, pullIntoDescriptor) {
        pullIntoDescriptor.bytesFilled += size;
    }
    function ReadableByteStreamControllerHandleQueueDrain(controller) {
        if (controller._queueTotalSize === 0 && controller._closeRequested) {
            ReadableByteStreamControllerClearAlgorithms(controller);
            ReadableStreamClose(controller._controlledReadableByteStream);
        }
        else {
            ReadableByteStreamControllerCallPullIfNeeded(controller);
        }
    }
    function ReadableByteStreamControllerInvalidateBYOBRequest(controller) {
        if (controller._byobRequest === null) {
            return;
        }
        controller._byobRequest._associatedReadableByteStreamController = undefined;
        controller._byobRequest._view = null;
        controller._byobRequest = null;
    }
    function ReadableByteStreamControllerProcessPullIntoDescriptorsUsingQueue(controller) {
        while (controller._pendingPullIntos.length > 0) {
            if (controller._queueTotalSize === 0) {
                return;
            }
            const pullIntoDescriptor = controller._pendingPullIntos.peek();
            if (ReadableByteStreamControllerFillPullIntoDescriptorFromQueue(controller, pullIntoDescriptor)) {
                ReadableByteStreamControllerShiftPendingPullInto(controller);
                ReadableByteStreamControllerCommitPullIntoDescriptor(controller._controlledReadableByteStream, pullIntoDescriptor);
            }
        }
    }
    function ReadableByteStreamControllerPullInto(controller, view, readIntoRequest) {
        const stream = controller._controlledReadableByteStream;
        let elementSize = 1;
        if (view.constructor !== DataView) {
            elementSize = view.constructor.BYTES_PER_ELEMENT;
        }
        const ctor = view.constructor;
        // try {
        const buffer = TransferArrayBuffer(view.buffer);
        // } catch (e) {
        //   readIntoRequest._errorSteps(e);
        //   return;
        // }
        const pullIntoDescriptor = {
            buffer,
            bufferByteLength: buffer.byteLength,
            byteOffset: view.byteOffset,
            byteLength: view.byteLength,
            bytesFilled: 0,
            elementSize,
            viewConstructor: ctor,
            readerType: 'byob'
        };
        if (controller._pendingPullIntos.length > 0) {
            controller._pendingPullIntos.push(pullIntoDescriptor);
            // No ReadableByteStreamControllerCallPullIfNeeded() call since:
            // - No change happens on desiredSize
            // - The source has already been notified of that there's at least 1 pending read(view)
            ReadableStreamAddReadIntoRequest(stream, readIntoRequest);
            return;
        }
        if (stream._state === 'closed') {
            const emptyView = new ctor(pullIntoDescriptor.buffer, pullIntoDescriptor.byteOffset, 0);
            readIntoRequest._closeSteps(emptyView);
            return;
        }
        if (controller._queueTotalSize > 0) {
            if (ReadableByteStreamControllerFillPullIntoDescriptorFromQueue(controller, pullIntoDescriptor)) {
                const filledView = ReadableByteStreamControllerConvertPullIntoDescriptor(pullIntoDescriptor);
                ReadableByteStreamControllerHandleQueueDrain(controller);
                readIntoRequest._chunkSteps(filledView);
                return;
            }
            if (controller._closeRequested) {
                const e = new TypeError('Insufficient bytes to fill elements in the given buffer');
                ReadableByteStreamControllerError(controller, e);
                readIntoRequest._errorSteps(e);
                return;
            }
        }
        controller._pendingPullIntos.push(pullIntoDescriptor);
        ReadableStreamAddReadIntoRequest(stream, readIntoRequest);
        ReadableByteStreamControllerCallPullIfNeeded(controller);
    }
    function ReadableByteStreamControllerRespondInClosedState(controller, firstDescriptor) {
        const stream = controller._controlledReadableByteStream;
        if (ReadableStreamHasBYOBReader(stream)) {
            while (ReadableStreamGetNumReadIntoRequests(stream) > 0) {
                const pullIntoDescriptor = ReadableByteStreamControllerShiftPendingPullInto(controller);
                ReadableByteStreamControllerCommitPullIntoDescriptor(stream, pullIntoDescriptor);
            }
        }
    }
    function ReadableByteStreamControllerRespondInReadableState(controller, bytesWritten, pullIntoDescriptor) {
        ReadableByteStreamControllerFillHeadPullIntoDescriptor(controller, bytesWritten, pullIntoDescriptor);
        if (pullIntoDescriptor.bytesFilled < pullIntoDescriptor.elementSize) {
            return;
        }
        ReadableByteStreamControllerShiftPendingPullInto(controller);
        const remainderSize = pullIntoDescriptor.bytesFilled % pullIntoDescriptor.elementSize;
        if (remainderSize > 0) {
            const end = pullIntoDescriptor.byteOffset + pullIntoDescriptor.bytesFilled;
            const remainder = ArrayBufferSlice(pullIntoDescriptor.buffer, end - remainderSize, end);
            ReadableByteStreamControllerEnqueueChunkToQueue(controller, remainder, 0, remainder.byteLength);
        }
        pullIntoDescriptor.bytesFilled -= remainderSize;
        ReadableByteStreamControllerCommitPullIntoDescriptor(controller._controlledReadableByteStream, pullIntoDescriptor);
        ReadableByteStreamControllerProcessPullIntoDescriptorsUsingQueue(controller);
    }
    function ReadableByteStreamControllerRespondInternal(controller, bytesWritten) {
        const firstDescriptor = controller._pendingPullIntos.peek();
        ReadableByteStreamControllerInvalidateBYOBRequest(controller);
        const state = controller._controlledReadableByteStream._state;
        if (state === 'closed') {
            ReadableByteStreamControllerRespondInClosedState(controller);
        }
        else {
            ReadableByteStreamControllerRespondInReadableState(controller, bytesWritten, firstDescriptor);
        }
        ReadableByteStreamControllerCallPullIfNeeded(controller);
    }
    function ReadableByteStreamControllerShiftPendingPullInto(controller) {
        const descriptor = controller._pendingPullIntos.shift();
        return descriptor;
    }
    function ReadableByteStreamControllerShouldCallPull(controller) {
        const stream = controller._controlledReadableByteStream;
        if (stream._state !== 'readable') {
            return false;
        }
        if (controller._closeRequested) {
            return false;
        }
        if (!controller._started) {
            return false;
        }
        if (ReadableStreamHasDefaultReader(stream) && ReadableStreamGetNumReadRequests(stream) > 0) {
            return true;
        }
        if (ReadableStreamHasBYOBReader(stream) && ReadableStreamGetNumReadIntoRequests(stream) > 0) {
            return true;
        }
        const desiredSize = ReadableByteStreamControllerGetDesiredSize(controller);
        if (desiredSize > 0) {
            return true;
        }
        return false;
    }
    function ReadableByteStreamControllerClearAlgorithms(controller) {
        controller._pullAlgorithm = undefined;
        controller._cancelAlgorithm = undefined;
    }
    // A client of ReadableByteStreamController may use these functions directly to bypass state check.
    function ReadableByteStreamControllerClose(controller) {
        const stream = controller._controlledReadableByteStream;
        if (controller._closeRequested || stream._state !== 'readable') {
            return;
        }
        if (controller._queueTotalSize > 0) {
            controller._closeRequested = true;
            return;
        }
        if (controller._pendingPullIntos.length > 0) {
            const firstPendingPullInto = controller._pendingPullIntos.peek();
            if (firstPendingPullInto.bytesFilled > 0) {
                const e = new TypeError('Insufficient bytes to fill elements in the given buffer');
                ReadableByteStreamControllerError(controller, e);
                throw e;
            }
        }
        ReadableByteStreamControllerClearAlgorithms(controller);
        ReadableStreamClose(stream);
    }
    function ReadableByteStreamControllerEnqueue(controller, chunk) {
        const stream = controller._controlledReadableByteStream;
        if (controller._closeRequested || stream._state !== 'readable') {
            return;
        }
        const buffer = chunk.buffer;
        const byteOffset = chunk.byteOffset;
        const byteLength = chunk.byteLength;
        const transferredBuffer = TransferArrayBuffer(buffer);
        if (controller._pendingPullIntos.length > 0) {
            const firstPendingPullInto = controller._pendingPullIntos.peek();
            if (IsDetachedBuffer(firstPendingPullInto.buffer)) ;
            firstPendingPullInto.buffer = TransferArrayBuffer(firstPendingPullInto.buffer);
        }
        ReadableByteStreamControllerInvalidateBYOBRequest(controller);
        if (ReadableStreamHasDefaultReader(stream)) {
            if (ReadableStreamGetNumReadRequests(stream) === 0) {
                ReadableByteStreamControllerEnqueueChunkToQueue(controller, transferredBuffer, byteOffset, byteLength);
            }
            else {
                if (controller._pendingPullIntos.length > 0) {
                    ReadableByteStreamControllerShiftPendingPullInto(controller);
                }
                const transferredView = new Uint8Array(transferredBuffer, byteOffset, byteLength);
                ReadableStreamFulfillReadRequest(stream, transferredView, false);
            }
        }
        else if (ReadableStreamHasBYOBReader(stream)) {
            // TODO: Ideally in this branch detaching should happen only if the buffer is not consumed fully.
            ReadableByteStreamControllerEnqueueChunkToQueue(controller, transferredBuffer, byteOffset, byteLength);
            ReadableByteStreamControllerProcessPullIntoDescriptorsUsingQueue(controller);
        }
        else {
            ReadableByteStreamControllerEnqueueChunkToQueue(controller, transferredBuffer, byteOffset, byteLength);
        }
        ReadableByteStreamControllerCallPullIfNeeded(controller);
    }
    function ReadableByteStreamControllerError(controller, e) {
        const stream = controller._controlledReadableByteStream;
        if (stream._state !== 'readable') {
            return;
        }
        ReadableByteStreamControllerClearPendingPullIntos(controller);
        ResetQueue(controller);
        ReadableByteStreamControllerClearAlgorithms(controller);
        ReadableStreamError(stream, e);
    }
    function ReadableByteStreamControllerGetBYOBRequest(controller) {
        if (controller._byobRequest === null && controller._pendingPullIntos.length > 0) {
            const firstDescriptor = controller._pendingPullIntos.peek();
            const view = new Uint8Array(firstDescriptor.buffer, firstDescriptor.byteOffset + firstDescriptor.bytesFilled, firstDescriptor.byteLength - firstDescriptor.bytesFilled);
            const byobRequest = Object.create(ReadableStreamBYOBRequest.prototype);
            SetUpReadableStreamBYOBRequest(byobRequest, controller, view);
            controller._byobRequest = byobRequest;
        }
        return controller._byobRequest;
    }
    function ReadableByteStreamControllerGetDesiredSize(controller) {
        const state = controller._controlledReadableByteStream._state;
        if (state === 'errored') {
            return null;
        }
        if (state === 'closed') {
            return 0;
        }
        return controller._strategyHWM - controller._queueTotalSize;
    }
    function ReadableByteStreamControllerRespond(controller, bytesWritten) {
        const firstDescriptor = controller._pendingPullIntos.peek();
        const state = controller._controlledReadableByteStream._state;
        if (state === 'closed') {
            if (bytesWritten !== 0) {
                throw new TypeError('bytesWritten must be 0 when calling respond() on a closed stream');
            }
        }
        else {
            if (bytesWritten === 0) {
                throw new TypeError('bytesWritten must be greater than 0 when calling respond() on a readable stream');
            }
            if (firstDescriptor.bytesFilled + bytesWritten > firstDescriptor.byteLength) {
                throw new RangeError('bytesWritten out of range');
            }
        }
        firstDescriptor.buffer = TransferArrayBuffer(firstDescriptor.buffer);
        ReadableByteStreamControllerRespondInternal(controller, bytesWritten);
    }
    function ReadableByteStreamControllerRespondWithNewView(controller, view) {
        const firstDescriptor = controller._pendingPullIntos.peek();
        const state = controller._controlledReadableByteStream._state;
        if (state === 'closed') {
            if (view.byteLength !== 0) {
                throw new TypeError('The view\'s length must be 0 when calling respondWithNewView() on a closed stream');
            }
        }
        else {
            if (view.byteLength === 0) {
                throw new TypeError('The view\'s length must be greater than 0 when calling respondWithNewView() on a readable stream');
            }
        }
        if (firstDescriptor.byteOffset + firstDescriptor.bytesFilled !== view.byteOffset) {
            throw new RangeError('The region specified by view does not match byobRequest');
        }
        if (firstDescriptor.bufferByteLength !== view.buffer.byteLength) {
            throw new RangeError('The buffer of view has different capacity than byobRequest');
        }
        if (firstDescriptor.bytesFilled + view.byteLength > firstDescriptor.byteLength) {
            throw new RangeError('The region specified by view is larger than byobRequest');
        }
        const viewByteLength = view.byteLength;
        firstDescriptor.buffer = TransferArrayBuffer(view.buffer);
        ReadableByteStreamControllerRespondInternal(controller, viewByteLength);
    }
    function SetUpReadableByteStreamController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, autoAllocateChunkSize) {
        controller._controlledReadableByteStream = stream;
        controller._pullAgain = false;
        controller._pulling = false;
        controller._byobRequest = null;
        // Need to set the slots so that the assert doesn't fire. In the spec the slots already exist implicitly.
        controller._queue = controller._queueTotalSize = undefined;
        ResetQueue(controller);
        controller._closeRequested = false;
        controller._started = false;
        controller._strategyHWM = highWaterMark;
        controller._pullAlgorithm = pullAlgorithm;
        controller._cancelAlgorithm = cancelAlgorithm;
        controller._autoAllocateChunkSize = autoAllocateChunkSize;
        controller._pendingPullIntos = new SimpleQueue();
        stream._readableStreamController = controller;
        const startResult = startAlgorithm();
        uponPromise(promiseResolvedWith(startResult), () => {
            controller._started = true;
            ReadableByteStreamControllerCallPullIfNeeded(controller);
        }, r => {
            ReadableByteStreamControllerError(controller, r);
        });
    }
    function SetUpReadableByteStreamControllerFromUnderlyingSource(stream, underlyingByteSource, highWaterMark) {
        const controller = Object.create(ReadableByteStreamController.prototype);
        let startAlgorithm = () => undefined;
        let pullAlgorithm = () => promiseResolvedWith(undefined);
        let cancelAlgorithm = () => promiseResolvedWith(undefined);
        if (underlyingByteSource.start !== undefined) {
            startAlgorithm = () => underlyingByteSource.start(controller);
        }
        if (underlyingByteSource.pull !== undefined) {
            pullAlgorithm = () => underlyingByteSource.pull(controller);
        }
        if (underlyingByteSource.cancel !== undefined) {
            cancelAlgorithm = reason => underlyingByteSource.cancel(reason);
        }
        const autoAllocateChunkSize = underlyingByteSource.autoAllocateChunkSize;
        if (autoAllocateChunkSize === 0) {
            throw new TypeError('autoAllocateChunkSize must be greater than 0');
        }
        SetUpReadableByteStreamController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, autoAllocateChunkSize);
    }
    function SetUpReadableStreamBYOBRequest(request, controller, view) {
        request._associatedReadableByteStreamController = controller;
        request._view = view;
    }
    // Helper functions for the ReadableStreamBYOBRequest.
    function byobRequestBrandCheckException(name) {
        return new TypeError(`ReadableStreamBYOBRequest.prototype.${name} can only be used on a ReadableStreamBYOBRequest`);
    }
    // Helper functions for the ReadableByteStreamController.
    function byteStreamControllerBrandCheckException(name) {
        return new TypeError(`ReadableByteStreamController.prototype.${name} can only be used on a ReadableByteStreamController`);
    }

    // Abstract operations for the ReadableStream.
    function AcquireReadableStreamBYOBReader(stream) {
        return new ReadableStreamBYOBReader(stream);
    }
    // ReadableStream API exposed for controllers.
    function ReadableStreamAddReadIntoRequest(stream, readIntoRequest) {
        stream._reader._readIntoRequests.push(readIntoRequest);
    }
    function ReadableStreamFulfillReadIntoRequest(stream, chunk, done) {
        const reader = stream._reader;
        const readIntoRequest = reader._readIntoRequests.shift();
        if (done) {
            readIntoRequest._closeSteps(chunk);
        }
        else {
            readIntoRequest._chunkSteps(chunk);
        }
    }
    function ReadableStreamGetNumReadIntoRequests(stream) {
        return stream._reader._readIntoRequests.length;
    }
    function ReadableStreamHasBYOBReader(stream) {
        const reader = stream._reader;
        if (reader === undefined) {
            return false;
        }
        if (!IsReadableStreamBYOBReader(reader)) {
            return false;
        }
        return true;
    }
    /**
     * A BYOB reader vended by a {@link ReadableStream}.
     *
     * @public
     */
    class ReadableStreamBYOBReader {
        constructor(stream) {
            assertRequiredArgument(stream, 1, 'ReadableStreamBYOBReader');
            assertReadableStream(stream, 'First parameter');
            if (IsReadableStreamLocked(stream)) {
                throw new TypeError('This stream has already been locked for exclusive reading by another reader');
            }
            if (!IsReadableByteStreamController(stream._readableStreamController)) {
                throw new TypeError('Cannot construct a ReadableStreamBYOBReader for a stream not constructed with a byte ' +
                    'source');
            }
            ReadableStreamReaderGenericInitialize(this, stream);
            this._readIntoRequests = new SimpleQueue();
        }
        /**
         * Returns a promise that will be fulfilled when the stream becomes closed, or rejected if the stream ever errors or
         * the reader's lock is released before the stream finishes closing.
         */
        get closed() {
            if (!IsReadableStreamBYOBReader(this)) {
                return promiseRejectedWith(byobReaderBrandCheckException('closed'));
            }
            return this._closedPromise;
        }
        /**
         * If the reader is active, behaves the same as {@link ReadableStream.cancel | stream.cancel(reason)}.
         */
        cancel(reason = undefined) {
            if (!IsReadableStreamBYOBReader(this)) {
                return promiseRejectedWith(byobReaderBrandCheckException('cancel'));
            }
            if (this._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('cancel'));
            }
            return ReadableStreamReaderGenericCancel(this, reason);
        }
        /**
         * Attempts to reads bytes into view, and returns a promise resolved with the result.
         *
         * If reading a chunk causes the queue to become empty, more data will be pulled from the underlying source.
         */
        read(view) {
            if (!IsReadableStreamBYOBReader(this)) {
                return promiseRejectedWith(byobReaderBrandCheckException('read'));
            }
            if (!ArrayBuffer.isView(view)) {
                return promiseRejectedWith(new TypeError('view must be an array buffer view'));
            }
            if (view.byteLength === 0) {
                return promiseRejectedWith(new TypeError('view must have non-zero byteLength'));
            }
            if (view.buffer.byteLength === 0) {
                return promiseRejectedWith(new TypeError(`view's buffer must have non-zero byteLength`));
            }
            if (IsDetachedBuffer(view.buffer)) ;
            if (this._ownerReadableStream === undefined) {
                return promiseRejectedWith(readerLockException('read from'));
            }
            let resolvePromise;
            let rejectPromise;
            const promise = newPromise((resolve, reject) => {
                resolvePromise = resolve;
                rejectPromise = reject;
            });
            const readIntoRequest = {
                _chunkSteps: chunk => resolvePromise({ value: chunk, done: false }),
                _closeSteps: chunk => resolvePromise({ value: chunk, done: true }),
                _errorSteps: e => rejectPromise(e)
            };
            ReadableStreamBYOBReaderRead(this, view, readIntoRequest);
            return promise;
        }
        /**
         * Releases the reader's lock on the corresponding stream. After the lock is released, the reader is no longer active.
         * If the associated stream is errored when the lock is released, the reader will appear errored in the same way
         * from now on; otherwise, the reader will appear closed.
         *
         * A reader's lock cannot be released while it still has a pending read request, i.e., if a promise returned by
         * the reader's {@link ReadableStreamBYOBReader.read | read()} method has not yet been settled. Attempting to
         * do so will throw a `TypeError` and leave the reader locked to the stream.
         */
        releaseLock() {
            if (!IsReadableStreamBYOBReader(this)) {
                throw byobReaderBrandCheckException('releaseLock');
            }
            if (this._ownerReadableStream === undefined) {
                return;
            }
            if (this._readIntoRequests.length > 0) {
                throw new TypeError('Tried to release a reader lock when that reader has pending read() calls un-settled');
            }
            ReadableStreamReaderGenericRelease(this);
        }
    }
    Object.defineProperties(ReadableStreamBYOBReader.prototype, {
        cancel: { enumerable: true },
        read: { enumerable: true },
        releaseLock: { enumerable: true },
        closed: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStreamBYOBReader.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStreamBYOBReader',
            configurable: true
        });
    }
    // Abstract operations for the readers.
    function IsReadableStreamBYOBReader(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_readIntoRequests')) {
            return false;
        }
        return x instanceof ReadableStreamBYOBReader;
    }
    function ReadableStreamBYOBReaderRead(reader, view, readIntoRequest) {
        const stream = reader._ownerReadableStream;
        stream._disturbed = true;
        if (stream._state === 'errored') {
            readIntoRequest._errorSteps(stream._storedError);
        }
        else {
            ReadableByteStreamControllerPullInto(stream._readableStreamController, view, readIntoRequest);
        }
    }
    // Helper functions for the ReadableStreamBYOBReader.
    function byobReaderBrandCheckException(name) {
        return new TypeError(`ReadableStreamBYOBReader.prototype.${name} can only be used on a ReadableStreamBYOBReader`);
    }

    function ExtractHighWaterMark(strategy, defaultHWM) {
        const { highWaterMark } = strategy;
        if (highWaterMark === undefined) {
            return defaultHWM;
        }
        if (NumberIsNaN(highWaterMark) || highWaterMark < 0) {
            throw new RangeError('Invalid highWaterMark');
        }
        return highWaterMark;
    }
    function ExtractSizeAlgorithm(strategy) {
        const { size } = strategy;
        if (!size) {
            return () => 1;
        }
        return size;
    }

    function convertQueuingStrategy(init, context) {
        assertDictionary(init, context);
        const highWaterMark = init === null || init === void 0 ? void 0 : init.highWaterMark;
        const size = init === null || init === void 0 ? void 0 : init.size;
        return {
            highWaterMark: highWaterMark === undefined ? undefined : convertUnrestrictedDouble(highWaterMark),
            size: size === undefined ? undefined : convertQueuingStrategySize(size, `${context} has member 'size' that`)
        };
    }
    function convertQueuingStrategySize(fn, context) {
        assertFunction(fn, context);
        return chunk => convertUnrestrictedDouble(fn(chunk));
    }

    function convertUnderlyingSink(original, context) {
        assertDictionary(original, context);
        const abort = original === null || original === void 0 ? void 0 : original.abort;
        const close = original === null || original === void 0 ? void 0 : original.close;
        const start = original === null || original === void 0 ? void 0 : original.start;
        const type = original === null || original === void 0 ? void 0 : original.type;
        const write = original === null || original === void 0 ? void 0 : original.write;
        return {
            abort: abort === undefined ?
                undefined :
                convertUnderlyingSinkAbortCallback(abort, original, `${context} has member 'abort' that`),
            close: close === undefined ?
                undefined :
                convertUnderlyingSinkCloseCallback(close, original, `${context} has member 'close' that`),
            start: start === undefined ?
                undefined :
                convertUnderlyingSinkStartCallback(start, original, `${context} has member 'start' that`),
            write: write === undefined ?
                undefined :
                convertUnderlyingSinkWriteCallback(write, original, `${context} has member 'write' that`),
            type
        };
    }
    function convertUnderlyingSinkAbortCallback(fn, original, context) {
        assertFunction(fn, context);
        return (reason) => promiseCall(fn, original, [reason]);
    }
    function convertUnderlyingSinkCloseCallback(fn, original, context) {
        assertFunction(fn, context);
        return () => promiseCall(fn, original, []);
    }
    function convertUnderlyingSinkStartCallback(fn, original, context) {
        assertFunction(fn, context);
        return (controller) => reflectCall(fn, original, [controller]);
    }
    function convertUnderlyingSinkWriteCallback(fn, original, context) {
        assertFunction(fn, context);
        return (chunk, controller) => promiseCall(fn, original, [chunk, controller]);
    }

    function assertWritableStream(x, context) {
        if (!IsWritableStream(x)) {
            throw new TypeError(`${context} is not a WritableStream.`);
        }
    }

    function isAbortSignal(value) {
        if (typeof value !== 'object' || value === null) {
            return false;
        }
        try {
            return typeof value.aborted === 'boolean';
        }
        catch (_a) {
            // AbortSignal.prototype.aborted throws if its brand check fails
            return false;
        }
    }
    const supportsAbortController = typeof AbortController === 'function';
    /**
     * Construct a new AbortController, if supported by the platform.
     *
     * @internal
     */
    function createAbortController() {
        if (supportsAbortController) {
            return new AbortController();
        }
        return undefined;
    }

    /**
     * A writable stream represents a destination for data, into which you can write.
     *
     * @public
     */
    class WritableStream {
        constructor(rawUnderlyingSink = {}, rawStrategy = {}) {
            if (rawUnderlyingSink === undefined) {
                rawUnderlyingSink = null;
            }
            else {
                assertObject(rawUnderlyingSink, 'First parameter');
            }
            const strategy = convertQueuingStrategy(rawStrategy, 'Second parameter');
            const underlyingSink = convertUnderlyingSink(rawUnderlyingSink, 'First parameter');
            InitializeWritableStream(this);
            const type = underlyingSink.type;
            if (type !== undefined) {
                throw new RangeError('Invalid type is specified');
            }
            const sizeAlgorithm = ExtractSizeAlgorithm(strategy);
            const highWaterMark = ExtractHighWaterMark(strategy, 1);
            SetUpWritableStreamDefaultControllerFromUnderlyingSink(this, underlyingSink, highWaterMark, sizeAlgorithm);
        }
        /**
         * Returns whether or not the writable stream is locked to a writer.
         */
        get locked() {
            if (!IsWritableStream(this)) {
                throw streamBrandCheckException$2('locked');
            }
            return IsWritableStreamLocked(this);
        }
        /**
         * Aborts the stream, signaling that the producer can no longer successfully write to the stream and it is to be
         * immediately moved to an errored state, with any queued-up writes discarded. This will also execute any abort
         * mechanism of the underlying sink.
         *
         * The returned promise will fulfill if the stream shuts down successfully, or reject if the underlying sink signaled
         * that there was an error doing so. Additionally, it will reject with a `TypeError` (without attempting to cancel
         * the stream) if the stream is currently locked.
         */
        abort(reason = undefined) {
            if (!IsWritableStream(this)) {
                return promiseRejectedWith(streamBrandCheckException$2('abort'));
            }
            if (IsWritableStreamLocked(this)) {
                return promiseRejectedWith(new TypeError('Cannot abort a stream that already has a writer'));
            }
            return WritableStreamAbort(this, reason);
        }
        /**
         * Closes the stream. The underlying sink will finish processing any previously-written chunks, before invoking its
         * close behavior. During this time any further attempts to write will fail (without erroring the stream).
         *
         * The method returns a promise that will fulfill if all remaining chunks are successfully written and the stream
         * successfully closes, or rejects if an error is encountered during this process. Additionally, it will reject with
         * a `TypeError` (without attempting to cancel the stream) if the stream is currently locked.
         */
        close() {
            if (!IsWritableStream(this)) {
                return promiseRejectedWith(streamBrandCheckException$2('close'));
            }
            if (IsWritableStreamLocked(this)) {
                return promiseRejectedWith(new TypeError('Cannot close a stream that already has a writer'));
            }
            if (WritableStreamCloseQueuedOrInFlight(this)) {
                return promiseRejectedWith(new TypeError('Cannot close an already-closing stream'));
            }
            return WritableStreamClose(this);
        }
        /**
         * Creates a {@link WritableStreamDefaultWriter | writer} and locks the stream to the new writer. While the stream
         * is locked, no other writer can be acquired until this one is released.
         *
         * This functionality is especially useful for creating abstractions that desire the ability to write to a stream
         * without interruption or interleaving. By getting a writer for the stream, you can ensure nobody else can write at
         * the same time, which would cause the resulting written data to be unpredictable and probably useless.
         */
        getWriter() {
            if (!IsWritableStream(this)) {
                throw streamBrandCheckException$2('getWriter');
            }
            return AcquireWritableStreamDefaultWriter(this);
        }
    }
    Object.defineProperties(WritableStream.prototype, {
        abort: { enumerable: true },
        close: { enumerable: true },
        getWriter: { enumerable: true },
        locked: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(WritableStream.prototype, SymbolPolyfill.toStringTag, {
            value: 'WritableStream',
            configurable: true
        });
    }
    // Abstract operations for the WritableStream.
    function AcquireWritableStreamDefaultWriter(stream) {
        return new WritableStreamDefaultWriter(stream);
    }
    // Throws if and only if startAlgorithm throws.
    function CreateWritableStream(startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, highWaterMark = 1, sizeAlgorithm = () => 1) {
        const stream = Object.create(WritableStream.prototype);
        InitializeWritableStream(stream);
        const controller = Object.create(WritableStreamDefaultController.prototype);
        SetUpWritableStreamDefaultController(stream, controller, startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, highWaterMark, sizeAlgorithm);
        return stream;
    }
    function InitializeWritableStream(stream) {
        stream._state = 'writable';
        // The error that will be reported by new method calls once the state becomes errored. Only set when [[state]] is
        // 'erroring' or 'errored'. May be set to an undefined value.
        stream._storedError = undefined;
        stream._writer = undefined;
        // Initialize to undefined first because the constructor of the controller checks this
        // variable to validate the caller.
        stream._writableStreamController = undefined;
        // This queue is placed here instead of the writer class in order to allow for passing a writer to the next data
        // producer without waiting for the queued writes to finish.
        stream._writeRequests = new SimpleQueue();
        // Write requests are removed from _writeRequests when write() is called on the underlying sink. This prevents
        // them from being erroneously rejected on error. If a write() call is in-flight, the request is stored here.
        stream._inFlightWriteRequest = undefined;
        // The promise that was returned from writer.close(). Stored here because it may be fulfilled after the writer
        // has been detached.
        stream._closeRequest = undefined;
        // Close request is removed from _closeRequest when close() is called on the underlying sink. This prevents it
        // from being erroneously rejected on error. If a close() call is in-flight, the request is stored here.
        stream._inFlightCloseRequest = undefined;
        // The promise that was returned from writer.abort(). This may also be fulfilled after the writer has detached.
        stream._pendingAbortRequest = undefined;
        // The backpressure signal set by the controller.
        stream._backpressure = false;
    }
    function IsWritableStream(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_writableStreamController')) {
            return false;
        }
        return x instanceof WritableStream;
    }
    function IsWritableStreamLocked(stream) {
        if (stream._writer === undefined) {
            return false;
        }
        return true;
    }
    function WritableStreamAbort(stream, reason) {
        var _a;
        if (stream._state === 'closed' || stream._state === 'errored') {
            return promiseResolvedWith(undefined);
        }
        stream._writableStreamController._abortReason = reason;
        (_a = stream._writableStreamController._abortController) === null || _a === void 0 ? void 0 : _a.abort();
        // TypeScript narrows the type of `stream._state` down to 'writable' | 'erroring',
        // but it doesn't know that signaling abort runs author code that might have changed the state.
        // Widen the type again by casting to WritableStreamState.
        const state = stream._state;
        if (state === 'closed' || state === 'errored') {
            return promiseResolvedWith(undefined);
        }
        if (stream._pendingAbortRequest !== undefined) {
            return stream._pendingAbortRequest._promise;
        }
        let wasAlreadyErroring = false;
        if (state === 'erroring') {
            wasAlreadyErroring = true;
            // reason will not be used, so don't keep a reference to it.
            reason = undefined;
        }
        const promise = newPromise((resolve, reject) => {
            stream._pendingAbortRequest = {
                _promise: undefined,
                _resolve: resolve,
                _reject: reject,
                _reason: reason,
                _wasAlreadyErroring: wasAlreadyErroring
            };
        });
        stream._pendingAbortRequest._promise = promise;
        if (!wasAlreadyErroring) {
            WritableStreamStartErroring(stream, reason);
        }
        return promise;
    }
    function WritableStreamClose(stream) {
        const state = stream._state;
        if (state === 'closed' || state === 'errored') {
            return promiseRejectedWith(new TypeError(`The stream (in ${state} state) is not in the writable state and cannot be closed`));
        }
        const promise = newPromise((resolve, reject) => {
            const closeRequest = {
                _resolve: resolve,
                _reject: reject
            };
            stream._closeRequest = closeRequest;
        });
        const writer = stream._writer;
        if (writer !== undefined && stream._backpressure && state === 'writable') {
            defaultWriterReadyPromiseResolve(writer);
        }
        WritableStreamDefaultControllerClose(stream._writableStreamController);
        return promise;
    }
    // WritableStream API exposed for controllers.
    function WritableStreamAddWriteRequest(stream) {
        const promise = newPromise((resolve, reject) => {
            const writeRequest = {
                _resolve: resolve,
                _reject: reject
            };
            stream._writeRequests.push(writeRequest);
        });
        return promise;
    }
    function WritableStreamDealWithRejection(stream, error) {
        const state = stream._state;
        if (state === 'writable') {
            WritableStreamStartErroring(stream, error);
            return;
        }
        WritableStreamFinishErroring(stream);
    }
    function WritableStreamStartErroring(stream, reason) {
        const controller = stream._writableStreamController;
        stream._state = 'erroring';
        stream._storedError = reason;
        const writer = stream._writer;
        if (writer !== undefined) {
            WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer, reason);
        }
        if (!WritableStreamHasOperationMarkedInFlight(stream) && controller._started) {
            WritableStreamFinishErroring(stream);
        }
    }
    function WritableStreamFinishErroring(stream) {
        stream._state = 'errored';
        stream._writableStreamController[ErrorSteps]();
        const storedError = stream._storedError;
        stream._writeRequests.forEach(writeRequest => {
            writeRequest._reject(storedError);
        });
        stream._writeRequests = new SimpleQueue();
        if (stream._pendingAbortRequest === undefined) {
            WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream);
            return;
        }
        const abortRequest = stream._pendingAbortRequest;
        stream._pendingAbortRequest = undefined;
        if (abortRequest._wasAlreadyErroring) {
            abortRequest._reject(storedError);
            WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream);
            return;
        }
        const promise = stream._writableStreamController[AbortSteps](abortRequest._reason);
        uponPromise(promise, () => {
            abortRequest._resolve();
            WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream);
        }, (reason) => {
            abortRequest._reject(reason);
            WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream);
        });
    }
    function WritableStreamFinishInFlightWrite(stream) {
        stream._inFlightWriteRequest._resolve(undefined);
        stream._inFlightWriteRequest = undefined;
    }
    function WritableStreamFinishInFlightWriteWithError(stream, error) {
        stream._inFlightWriteRequest._reject(error);
        stream._inFlightWriteRequest = undefined;
        WritableStreamDealWithRejection(stream, error);
    }
    function WritableStreamFinishInFlightClose(stream) {
        stream._inFlightCloseRequest._resolve(undefined);
        stream._inFlightCloseRequest = undefined;
        const state = stream._state;
        if (state === 'erroring') {
            // The error was too late to do anything, so it is ignored.
            stream._storedError = undefined;
            if (stream._pendingAbortRequest !== undefined) {
                stream._pendingAbortRequest._resolve();
                stream._pendingAbortRequest = undefined;
            }
        }
        stream._state = 'closed';
        const writer = stream._writer;
        if (writer !== undefined) {
            defaultWriterClosedPromiseResolve(writer);
        }
    }
    function WritableStreamFinishInFlightCloseWithError(stream, error) {
        stream._inFlightCloseRequest._reject(error);
        stream._inFlightCloseRequest = undefined;
        // Never execute sink abort() after sink close().
        if (stream._pendingAbortRequest !== undefined) {
            stream._pendingAbortRequest._reject(error);
            stream._pendingAbortRequest = undefined;
        }
        WritableStreamDealWithRejection(stream, error);
    }
    // TODO(ricea): Fix alphabetical order.
    function WritableStreamCloseQueuedOrInFlight(stream) {
        if (stream._closeRequest === undefined && stream._inFlightCloseRequest === undefined) {
            return false;
        }
        return true;
    }
    function WritableStreamHasOperationMarkedInFlight(stream) {
        if (stream._inFlightWriteRequest === undefined && stream._inFlightCloseRequest === undefined) {
            return false;
        }
        return true;
    }
    function WritableStreamMarkCloseRequestInFlight(stream) {
        stream._inFlightCloseRequest = stream._closeRequest;
        stream._closeRequest = undefined;
    }
    function WritableStreamMarkFirstWriteRequestInFlight(stream) {
        stream._inFlightWriteRequest = stream._writeRequests.shift();
    }
    function WritableStreamRejectCloseAndClosedPromiseIfNeeded(stream) {
        if (stream._closeRequest !== undefined) {
            stream._closeRequest._reject(stream._storedError);
            stream._closeRequest = undefined;
        }
        const writer = stream._writer;
        if (writer !== undefined) {
            defaultWriterClosedPromiseReject(writer, stream._storedError);
        }
    }
    function WritableStreamUpdateBackpressure(stream, backpressure) {
        const writer = stream._writer;
        if (writer !== undefined && backpressure !== stream._backpressure) {
            if (backpressure) {
                defaultWriterReadyPromiseReset(writer);
            }
            else {
                defaultWriterReadyPromiseResolve(writer);
            }
        }
        stream._backpressure = backpressure;
    }
    /**
     * A default writer vended by a {@link WritableStream}.
     *
     * @public
     */
    class WritableStreamDefaultWriter {
        constructor(stream) {
            assertRequiredArgument(stream, 1, 'WritableStreamDefaultWriter');
            assertWritableStream(stream, 'First parameter');
            if (IsWritableStreamLocked(stream)) {
                throw new TypeError('This stream has already been locked for exclusive writing by another writer');
            }
            this._ownerWritableStream = stream;
            stream._writer = this;
            const state = stream._state;
            if (state === 'writable') {
                if (!WritableStreamCloseQueuedOrInFlight(stream) && stream._backpressure) {
                    defaultWriterReadyPromiseInitialize(this);
                }
                else {
                    defaultWriterReadyPromiseInitializeAsResolved(this);
                }
                defaultWriterClosedPromiseInitialize(this);
            }
            else if (state === 'erroring') {
                defaultWriterReadyPromiseInitializeAsRejected(this, stream._storedError);
                defaultWriterClosedPromiseInitialize(this);
            }
            else if (state === 'closed') {
                defaultWriterReadyPromiseInitializeAsResolved(this);
                defaultWriterClosedPromiseInitializeAsResolved(this);
            }
            else {
                const storedError = stream._storedError;
                defaultWriterReadyPromiseInitializeAsRejected(this, storedError);
                defaultWriterClosedPromiseInitializeAsRejected(this, storedError);
            }
        }
        /**
         * Returns a promise that will be fulfilled when the stream becomes closed, or rejected if the stream ever errors or
         * the writer’s lock is released before the stream finishes closing.
         */
        get closed() {
            if (!IsWritableStreamDefaultWriter(this)) {
                return promiseRejectedWith(defaultWriterBrandCheckException('closed'));
            }
            return this._closedPromise;
        }
        /**
         * Returns the desired size to fill the stream’s internal queue. It can be negative, if the queue is over-full.
         * A producer can use this information to determine the right amount of data to write.
         *
         * It will be `null` if the stream cannot be successfully written to (due to either being errored, or having an abort
         * queued up). It will return zero if the stream is closed. And the getter will throw an exception if invoked when
         * the writer’s lock is released.
         */
        get desiredSize() {
            if (!IsWritableStreamDefaultWriter(this)) {
                throw defaultWriterBrandCheckException('desiredSize');
            }
            if (this._ownerWritableStream === undefined) {
                throw defaultWriterLockException('desiredSize');
            }
            return WritableStreamDefaultWriterGetDesiredSize(this);
        }
        /**
         * Returns a promise that will be fulfilled when the desired size to fill the stream’s internal queue transitions
         * from non-positive to positive, signaling that it is no longer applying backpressure. Once the desired size dips
         * back to zero or below, the getter will return a new promise that stays pending until the next transition.
         *
         * If the stream becomes errored or aborted, or the writer’s lock is released, the returned promise will become
         * rejected.
         */
        get ready() {
            if (!IsWritableStreamDefaultWriter(this)) {
                return promiseRejectedWith(defaultWriterBrandCheckException('ready'));
            }
            return this._readyPromise;
        }
        /**
         * If the reader is active, behaves the same as {@link WritableStream.abort | stream.abort(reason)}.
         */
        abort(reason = undefined) {
            if (!IsWritableStreamDefaultWriter(this)) {
                return promiseRejectedWith(defaultWriterBrandCheckException('abort'));
            }
            if (this._ownerWritableStream === undefined) {
                return promiseRejectedWith(defaultWriterLockException('abort'));
            }
            return WritableStreamDefaultWriterAbort(this, reason);
        }
        /**
         * If the reader is active, behaves the same as {@link WritableStream.close | stream.close()}.
         */
        close() {
            if (!IsWritableStreamDefaultWriter(this)) {
                return promiseRejectedWith(defaultWriterBrandCheckException('close'));
            }
            const stream = this._ownerWritableStream;
            if (stream === undefined) {
                return promiseRejectedWith(defaultWriterLockException('close'));
            }
            if (WritableStreamCloseQueuedOrInFlight(stream)) {
                return promiseRejectedWith(new TypeError('Cannot close an already-closing stream'));
            }
            return WritableStreamDefaultWriterClose(this);
        }
        /**
         * Releases the writer’s lock on the corresponding stream. After the lock is released, the writer is no longer active.
         * If the associated stream is errored when the lock is released, the writer will appear errored in the same way from
         * now on; otherwise, the writer will appear closed.
         *
         * Note that the lock can still be released even if some ongoing writes have not yet finished (i.e. even if the
         * promises returned from previous calls to {@link WritableStreamDefaultWriter.write | write()} have not yet settled).
         * It’s not necessary to hold the lock on the writer for the duration of the write; the lock instead simply prevents
         * other producers from writing in an interleaved manner.
         */
        releaseLock() {
            if (!IsWritableStreamDefaultWriter(this)) {
                throw defaultWriterBrandCheckException('releaseLock');
            }
            const stream = this._ownerWritableStream;
            if (stream === undefined) {
                return;
            }
            WritableStreamDefaultWriterRelease(this);
        }
        write(chunk = undefined) {
            if (!IsWritableStreamDefaultWriter(this)) {
                return promiseRejectedWith(defaultWriterBrandCheckException('write'));
            }
            if (this._ownerWritableStream === undefined) {
                return promiseRejectedWith(defaultWriterLockException('write to'));
            }
            return WritableStreamDefaultWriterWrite(this, chunk);
        }
    }
    Object.defineProperties(WritableStreamDefaultWriter.prototype, {
        abort: { enumerable: true },
        close: { enumerable: true },
        releaseLock: { enumerable: true },
        write: { enumerable: true },
        closed: { enumerable: true },
        desiredSize: { enumerable: true },
        ready: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(WritableStreamDefaultWriter.prototype, SymbolPolyfill.toStringTag, {
            value: 'WritableStreamDefaultWriter',
            configurable: true
        });
    }
    // Abstract operations for the WritableStreamDefaultWriter.
    function IsWritableStreamDefaultWriter(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_ownerWritableStream')) {
            return false;
        }
        return x instanceof WritableStreamDefaultWriter;
    }
    // A client of WritableStreamDefaultWriter may use these functions directly to bypass state check.
    function WritableStreamDefaultWriterAbort(writer, reason) {
        const stream = writer._ownerWritableStream;
        return WritableStreamAbort(stream, reason);
    }
    function WritableStreamDefaultWriterClose(writer) {
        const stream = writer._ownerWritableStream;
        return WritableStreamClose(stream);
    }
    function WritableStreamDefaultWriterCloseWithErrorPropagation(writer) {
        const stream = writer._ownerWritableStream;
        const state = stream._state;
        if (WritableStreamCloseQueuedOrInFlight(stream) || state === 'closed') {
            return promiseResolvedWith(undefined);
        }
        if (state === 'errored') {
            return promiseRejectedWith(stream._storedError);
        }
        return WritableStreamDefaultWriterClose(writer);
    }
    function WritableStreamDefaultWriterEnsureClosedPromiseRejected(writer, error) {
        if (writer._closedPromiseState === 'pending') {
            defaultWriterClosedPromiseReject(writer, error);
        }
        else {
            defaultWriterClosedPromiseResetToRejected(writer, error);
        }
    }
    function WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer, error) {
        if (writer._readyPromiseState === 'pending') {
            defaultWriterReadyPromiseReject(writer, error);
        }
        else {
            defaultWriterReadyPromiseResetToRejected(writer, error);
        }
    }
    function WritableStreamDefaultWriterGetDesiredSize(writer) {
        const stream = writer._ownerWritableStream;
        const state = stream._state;
        if (state === 'errored' || state === 'erroring') {
            return null;
        }
        if (state === 'closed') {
            return 0;
        }
        return WritableStreamDefaultControllerGetDesiredSize(stream._writableStreamController);
    }
    function WritableStreamDefaultWriterRelease(writer) {
        const stream = writer._ownerWritableStream;
        const releasedError = new TypeError(`Writer was released and can no longer be used to monitor the stream's closedness`);
        WritableStreamDefaultWriterEnsureReadyPromiseRejected(writer, releasedError);
        // The state transitions to "errored" before the sink abort() method runs, but the writer.closed promise is not
        // rejected until afterwards. This means that simply testing state will not work.
        WritableStreamDefaultWriterEnsureClosedPromiseRejected(writer, releasedError);
        stream._writer = undefined;
        writer._ownerWritableStream = undefined;
    }
    function WritableStreamDefaultWriterWrite(writer, chunk) {
        const stream = writer._ownerWritableStream;
        const controller = stream._writableStreamController;
        const chunkSize = WritableStreamDefaultControllerGetChunkSize(controller, chunk);
        if (stream !== writer._ownerWritableStream) {
            return promiseRejectedWith(defaultWriterLockException('write to'));
        }
        const state = stream._state;
        if (state === 'errored') {
            return promiseRejectedWith(stream._storedError);
        }
        if (WritableStreamCloseQueuedOrInFlight(stream) || state === 'closed') {
            return promiseRejectedWith(new TypeError('The stream is closing or closed and cannot be written to'));
        }
        if (state === 'erroring') {
            return promiseRejectedWith(stream._storedError);
        }
        const promise = WritableStreamAddWriteRequest(stream);
        WritableStreamDefaultControllerWrite(controller, chunk, chunkSize);
        return promise;
    }
    const closeSentinel = {};
    /**
     * Allows control of a {@link WritableStream | writable stream}'s state and internal queue.
     *
     * @public
     */
    class WritableStreamDefaultController {
        constructor() {
            throw new TypeError('Illegal constructor');
        }
        /**
         * The reason which was passed to `WritableStream.abort(reason)` when the stream was aborted.
         *
         * @deprecated
         *  This property has been removed from the specification, see https://github.com/whatwg/streams/pull/1177.
         *  Use {@link WritableStreamDefaultController.signal}'s `reason` instead.
         */
        get abortReason() {
            if (!IsWritableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$2('abortReason');
            }
            return this._abortReason;
        }
        /**
         * An `AbortSignal` that can be used to abort the pending write or close operation when the stream is aborted.
         */
        get signal() {
            if (!IsWritableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$2('signal');
            }
            if (this._abortController === undefined) {
                // Older browsers or older Node versions may not support `AbortController` or `AbortSignal`.
                // We don't want to bundle and ship an `AbortController` polyfill together with our polyfill,
                // so instead we only implement support for `signal` if we find a global `AbortController` constructor.
                throw new TypeError('WritableStreamDefaultController.prototype.signal is not supported');
            }
            return this._abortController.signal;
        }
        /**
         * Closes the controlled writable stream, making all future interactions with it fail with the given error `e`.
         *
         * This method is rarely used, since usually it suffices to return a rejected promise from one of the underlying
         * sink's methods. However, it can be useful for suddenly shutting down a stream in response to an event outside the
         * normal lifecycle of interactions with the underlying sink.
         */
        error(e = undefined) {
            if (!IsWritableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$2('error');
            }
            const state = this._controlledWritableStream._state;
            if (state !== 'writable') {
                // The stream is closed, errored or will be soon. The sink can't do anything useful if it gets an error here, so
                // just treat it as a no-op.
                return;
            }
            WritableStreamDefaultControllerError(this, e);
        }
        /** @internal */
        [AbortSteps](reason) {
            const result = this._abortAlgorithm(reason);
            WritableStreamDefaultControllerClearAlgorithms(this);
            return result;
        }
        /** @internal */
        [ErrorSteps]() {
            ResetQueue(this);
        }
    }
    Object.defineProperties(WritableStreamDefaultController.prototype, {
        abortReason: { enumerable: true },
        signal: { enumerable: true },
        error: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(WritableStreamDefaultController.prototype, SymbolPolyfill.toStringTag, {
            value: 'WritableStreamDefaultController',
            configurable: true
        });
    }
    // Abstract operations implementing interface required by the WritableStream.
    function IsWritableStreamDefaultController(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_controlledWritableStream')) {
            return false;
        }
        return x instanceof WritableStreamDefaultController;
    }
    function SetUpWritableStreamDefaultController(stream, controller, startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, highWaterMark, sizeAlgorithm) {
        controller._controlledWritableStream = stream;
        stream._writableStreamController = controller;
        // Need to set the slots so that the assert doesn't fire. In the spec the slots already exist implicitly.
        controller._queue = undefined;
        controller._queueTotalSize = undefined;
        ResetQueue(controller);
        controller._abortReason = undefined;
        controller._abortController = createAbortController();
        controller._started = false;
        controller._strategySizeAlgorithm = sizeAlgorithm;
        controller._strategyHWM = highWaterMark;
        controller._writeAlgorithm = writeAlgorithm;
        controller._closeAlgorithm = closeAlgorithm;
        controller._abortAlgorithm = abortAlgorithm;
        const backpressure = WritableStreamDefaultControllerGetBackpressure(controller);
        WritableStreamUpdateBackpressure(stream, backpressure);
        const startResult = startAlgorithm();
        const startPromise = promiseResolvedWith(startResult);
        uponPromise(startPromise, () => {
            controller._started = true;
            WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller);
        }, r => {
            controller._started = true;
            WritableStreamDealWithRejection(stream, r);
        });
    }
    function SetUpWritableStreamDefaultControllerFromUnderlyingSink(stream, underlyingSink, highWaterMark, sizeAlgorithm) {
        const controller = Object.create(WritableStreamDefaultController.prototype);
        let startAlgorithm = () => undefined;
        let writeAlgorithm = () => promiseResolvedWith(undefined);
        let closeAlgorithm = () => promiseResolvedWith(undefined);
        let abortAlgorithm = () => promiseResolvedWith(undefined);
        if (underlyingSink.start !== undefined) {
            startAlgorithm = () => underlyingSink.start(controller);
        }
        if (underlyingSink.write !== undefined) {
            writeAlgorithm = chunk => underlyingSink.write(chunk, controller);
        }
        if (underlyingSink.close !== undefined) {
            closeAlgorithm = () => underlyingSink.close();
        }
        if (underlyingSink.abort !== undefined) {
            abortAlgorithm = reason => underlyingSink.abort(reason);
        }
        SetUpWritableStreamDefaultController(stream, controller, startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, highWaterMark, sizeAlgorithm);
    }
    // ClearAlgorithms may be called twice. Erroring the same stream in multiple ways will often result in redundant calls.
    function WritableStreamDefaultControllerClearAlgorithms(controller) {
        controller._writeAlgorithm = undefined;
        controller._closeAlgorithm = undefined;
        controller._abortAlgorithm = undefined;
        controller._strategySizeAlgorithm = undefined;
    }
    function WritableStreamDefaultControllerClose(controller) {
        EnqueueValueWithSize(controller, closeSentinel, 0);
        WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller);
    }
    function WritableStreamDefaultControllerGetChunkSize(controller, chunk) {
        try {
            return controller._strategySizeAlgorithm(chunk);
        }
        catch (chunkSizeE) {
            WritableStreamDefaultControllerErrorIfNeeded(controller, chunkSizeE);
            return 1;
        }
    }
    function WritableStreamDefaultControllerGetDesiredSize(controller) {
        return controller._strategyHWM - controller._queueTotalSize;
    }
    function WritableStreamDefaultControllerWrite(controller, chunk, chunkSize) {
        try {
            EnqueueValueWithSize(controller, chunk, chunkSize);
        }
        catch (enqueueE) {
            WritableStreamDefaultControllerErrorIfNeeded(controller, enqueueE);
            return;
        }
        const stream = controller._controlledWritableStream;
        if (!WritableStreamCloseQueuedOrInFlight(stream) && stream._state === 'writable') {
            const backpressure = WritableStreamDefaultControllerGetBackpressure(controller);
            WritableStreamUpdateBackpressure(stream, backpressure);
        }
        WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller);
    }
    // Abstract operations for the WritableStreamDefaultController.
    function WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller) {
        const stream = controller._controlledWritableStream;
        if (!controller._started) {
            return;
        }
        if (stream._inFlightWriteRequest !== undefined) {
            return;
        }
        const state = stream._state;
        if (state === 'erroring') {
            WritableStreamFinishErroring(stream);
            return;
        }
        if (controller._queue.length === 0) {
            return;
        }
        const value = PeekQueueValue(controller);
        if (value === closeSentinel) {
            WritableStreamDefaultControllerProcessClose(controller);
        }
        else {
            WritableStreamDefaultControllerProcessWrite(controller, value);
        }
    }
    function WritableStreamDefaultControllerErrorIfNeeded(controller, error) {
        if (controller._controlledWritableStream._state === 'writable') {
            WritableStreamDefaultControllerError(controller, error);
        }
    }
    function WritableStreamDefaultControllerProcessClose(controller) {
        const stream = controller._controlledWritableStream;
        WritableStreamMarkCloseRequestInFlight(stream);
        DequeueValue(controller);
        const sinkClosePromise = controller._closeAlgorithm();
        WritableStreamDefaultControllerClearAlgorithms(controller);
        uponPromise(sinkClosePromise, () => {
            WritableStreamFinishInFlightClose(stream);
        }, reason => {
            WritableStreamFinishInFlightCloseWithError(stream, reason);
        });
    }
    function WritableStreamDefaultControllerProcessWrite(controller, chunk) {
        const stream = controller._controlledWritableStream;
        WritableStreamMarkFirstWriteRequestInFlight(stream);
        const sinkWritePromise = controller._writeAlgorithm(chunk);
        uponPromise(sinkWritePromise, () => {
            WritableStreamFinishInFlightWrite(stream);
            const state = stream._state;
            DequeueValue(controller);
            if (!WritableStreamCloseQueuedOrInFlight(stream) && state === 'writable') {
                const backpressure = WritableStreamDefaultControllerGetBackpressure(controller);
                WritableStreamUpdateBackpressure(stream, backpressure);
            }
            WritableStreamDefaultControllerAdvanceQueueIfNeeded(controller);
        }, reason => {
            if (stream._state === 'writable') {
                WritableStreamDefaultControllerClearAlgorithms(controller);
            }
            WritableStreamFinishInFlightWriteWithError(stream, reason);
        });
    }
    function WritableStreamDefaultControllerGetBackpressure(controller) {
        const desiredSize = WritableStreamDefaultControllerGetDesiredSize(controller);
        return desiredSize <= 0;
    }
    // A client of WritableStreamDefaultController may use these functions directly to bypass state check.
    function WritableStreamDefaultControllerError(controller, error) {
        const stream = controller._controlledWritableStream;
        WritableStreamDefaultControllerClearAlgorithms(controller);
        WritableStreamStartErroring(stream, error);
    }
    // Helper functions for the WritableStream.
    function streamBrandCheckException$2(name) {
        return new TypeError(`WritableStream.prototype.${name} can only be used on a WritableStream`);
    }
    // Helper functions for the WritableStreamDefaultController.
    function defaultControllerBrandCheckException$2(name) {
        return new TypeError(`WritableStreamDefaultController.prototype.${name} can only be used on a WritableStreamDefaultController`);
    }
    // Helper functions for the WritableStreamDefaultWriter.
    function defaultWriterBrandCheckException(name) {
        return new TypeError(`WritableStreamDefaultWriter.prototype.${name} can only be used on a WritableStreamDefaultWriter`);
    }
    function defaultWriterLockException(name) {
        return new TypeError('Cannot ' + name + ' a stream using a released writer');
    }
    function defaultWriterClosedPromiseInitialize(writer) {
        writer._closedPromise = newPromise((resolve, reject) => {
            writer._closedPromise_resolve = resolve;
            writer._closedPromise_reject = reject;
            writer._closedPromiseState = 'pending';
        });
    }
    function defaultWriterClosedPromiseInitializeAsRejected(writer, reason) {
        defaultWriterClosedPromiseInitialize(writer);
        defaultWriterClosedPromiseReject(writer, reason);
    }
    function defaultWriterClosedPromiseInitializeAsResolved(writer) {
        defaultWriterClosedPromiseInitialize(writer);
        defaultWriterClosedPromiseResolve(writer);
    }
    function defaultWriterClosedPromiseReject(writer, reason) {
        if (writer._closedPromise_reject === undefined) {
            return;
        }
        setPromiseIsHandledToTrue(writer._closedPromise);
        writer._closedPromise_reject(reason);
        writer._closedPromise_resolve = undefined;
        writer._closedPromise_reject = undefined;
        writer._closedPromiseState = 'rejected';
    }
    function defaultWriterClosedPromiseResetToRejected(writer, reason) {
        defaultWriterClosedPromiseInitializeAsRejected(writer, reason);
    }
    function defaultWriterClosedPromiseResolve(writer) {
        if (writer._closedPromise_resolve === undefined) {
            return;
        }
        writer._closedPromise_resolve(undefined);
        writer._closedPromise_resolve = undefined;
        writer._closedPromise_reject = undefined;
        writer._closedPromiseState = 'resolved';
    }
    function defaultWriterReadyPromiseInitialize(writer) {
        writer._readyPromise = newPromise((resolve, reject) => {
            writer._readyPromise_resolve = resolve;
            writer._readyPromise_reject = reject;
        });
        writer._readyPromiseState = 'pending';
    }
    function defaultWriterReadyPromiseInitializeAsRejected(writer, reason) {
        defaultWriterReadyPromiseInitialize(writer);
        defaultWriterReadyPromiseReject(writer, reason);
    }
    function defaultWriterReadyPromiseInitializeAsResolved(writer) {
        defaultWriterReadyPromiseInitialize(writer);
        defaultWriterReadyPromiseResolve(writer);
    }
    function defaultWriterReadyPromiseReject(writer, reason) {
        if (writer._readyPromise_reject === undefined) {
            return;
        }
        setPromiseIsHandledToTrue(writer._readyPromise);
        writer._readyPromise_reject(reason);
        writer._readyPromise_resolve = undefined;
        writer._readyPromise_reject = undefined;
        writer._readyPromiseState = 'rejected';
    }
    function defaultWriterReadyPromiseReset(writer) {
        defaultWriterReadyPromiseInitialize(writer);
    }
    function defaultWriterReadyPromiseResetToRejected(writer, reason) {
        defaultWriterReadyPromiseInitializeAsRejected(writer, reason);
    }
    function defaultWriterReadyPromiseResolve(writer) {
        if (writer._readyPromise_resolve === undefined) {
            return;
        }
        writer._readyPromise_resolve(undefined);
        writer._readyPromise_resolve = undefined;
        writer._readyPromise_reject = undefined;
        writer._readyPromiseState = 'fulfilled';
    }

    /// <reference lib="dom" />
    const NativeDOMException = typeof DOMException !== 'undefined' ? DOMException : undefined;

    /// <reference types="node" />
    function isDOMExceptionConstructor(ctor) {
        if (!(typeof ctor === 'function' || typeof ctor === 'object')) {
            return false;
        }
        try {
            new ctor();
            return true;
        }
        catch (_a) {
            return false;
        }
    }
    function createDOMExceptionPolyfill() {
        // eslint-disable-next-line no-shadow
        const ctor = function DOMException(message, name) {
            this.message = message || '';
            this.name = name || 'Error';
            if (Error.captureStackTrace) {
                Error.captureStackTrace(this, this.constructor);
            }
        };
        ctor.prototype = Object.create(Error.prototype);
        Object.defineProperty(ctor.prototype, 'constructor', { value: ctor, writable: true, configurable: true });
        return ctor;
    }
    // eslint-disable-next-line no-redeclare
    const DOMException$1 = isDOMExceptionConstructor(NativeDOMException) ? NativeDOMException : createDOMExceptionPolyfill();

    function ReadableStreamPipeTo(source, dest, preventClose, preventAbort, preventCancel, signal) {
        const reader = AcquireReadableStreamDefaultReader(source);
        const writer = AcquireWritableStreamDefaultWriter(dest);
        source._disturbed = true;
        let shuttingDown = false;
        // This is used to keep track of the spec's requirement that we wait for ongoing writes during shutdown.
        let currentWrite = promiseResolvedWith(undefined);
        return newPromise((resolve, reject) => {
            let abortAlgorithm;
            if (signal !== undefined) {
                abortAlgorithm = () => {
                    const error = new DOMException$1('Aborted', 'AbortError');
                    const actions = [];
                    if (!preventAbort) {
                        actions.push(() => {
                            if (dest._state === 'writable') {
                                return WritableStreamAbort(dest, error);
                            }
                            return promiseResolvedWith(undefined);
                        });
                    }
                    if (!preventCancel) {
                        actions.push(() => {
                            if (source._state === 'readable') {
                                return ReadableStreamCancel(source, error);
                            }
                            return promiseResolvedWith(undefined);
                        });
                    }
                    shutdownWithAction(() => Promise.all(actions.map(action => action())), true, error);
                };
                if (signal.aborted) {
                    abortAlgorithm();
                    return;
                }
                signal.addEventListener('abort', abortAlgorithm);
            }
            // Using reader and writer, read all chunks from this and write them to dest
            // - Backpressure must be enforced
            // - Shutdown must stop all activity
            function pipeLoop() {
                return newPromise((resolveLoop, rejectLoop) => {
                    function next(done) {
                        if (done) {
                            resolveLoop();
                        }
                        else {
                            // Use `PerformPromiseThen` instead of `uponPromise` to avoid
                            // adding unnecessary `.catch(rethrowAssertionErrorRejection)` handlers
                            PerformPromiseThen(pipeStep(), next, rejectLoop);
                        }
                    }
                    next(false);
                });
            }
            function pipeStep() {
                if (shuttingDown) {
                    return promiseResolvedWith(true);
                }
                return PerformPromiseThen(writer._readyPromise, () => {
                    return newPromise((resolveRead, rejectRead) => {
                        ReadableStreamDefaultReaderRead(reader, {
                            _chunkSteps: chunk => {
                                currentWrite = PerformPromiseThen(WritableStreamDefaultWriterWrite(writer, chunk), undefined, noop);
                                resolveRead(false);
                            },
                            _closeSteps: () => resolveRead(true),
                            _errorSteps: rejectRead
                        });
                    });
                });
            }
            // Errors must be propagated forward
            isOrBecomesErrored(source, reader._closedPromise, storedError => {
                if (!preventAbort) {
                    shutdownWithAction(() => WritableStreamAbort(dest, storedError), true, storedError);
                }
                else {
                    shutdown(true, storedError);
                }
            });
            // Errors must be propagated backward
            isOrBecomesErrored(dest, writer._closedPromise, storedError => {
                if (!preventCancel) {
                    shutdownWithAction(() => ReadableStreamCancel(source, storedError), true, storedError);
                }
                else {
                    shutdown(true, storedError);
                }
            });
            // Closing must be propagated forward
            isOrBecomesClosed(source, reader._closedPromise, () => {
                if (!preventClose) {
                    shutdownWithAction(() => WritableStreamDefaultWriterCloseWithErrorPropagation(writer));
                }
                else {
                    shutdown();
                }
            });
            // Closing must be propagated backward
            if (WritableStreamCloseQueuedOrInFlight(dest) || dest._state === 'closed') {
                const destClosed = new TypeError('the destination writable stream closed before all data could be piped to it');
                if (!preventCancel) {
                    shutdownWithAction(() => ReadableStreamCancel(source, destClosed), true, destClosed);
                }
                else {
                    shutdown(true, destClosed);
                }
            }
            setPromiseIsHandledToTrue(pipeLoop());
            function waitForWritesToFinish() {
                // Another write may have started while we were waiting on this currentWrite, so we have to be sure to wait
                // for that too.
                const oldCurrentWrite = currentWrite;
                return PerformPromiseThen(currentWrite, () => oldCurrentWrite !== currentWrite ? waitForWritesToFinish() : undefined);
            }
            function isOrBecomesErrored(stream, promise, action) {
                if (stream._state === 'errored') {
                    action(stream._storedError);
                }
                else {
                    uponRejection(promise, action);
                }
            }
            function isOrBecomesClosed(stream, promise, action) {
                if (stream._state === 'closed') {
                    action();
                }
                else {
                    uponFulfillment(promise, action);
                }
            }
            function shutdownWithAction(action, originalIsError, originalError) {
                if (shuttingDown) {
                    return;
                }
                shuttingDown = true;
                if (dest._state === 'writable' && !WritableStreamCloseQueuedOrInFlight(dest)) {
                    uponFulfillment(waitForWritesToFinish(), doTheRest);
                }
                else {
                    doTheRest();
                }
                function doTheRest() {
                    uponPromise(action(), () => finalize(originalIsError, originalError), newError => finalize(true, newError));
                }
            }
            function shutdown(isError, error) {
                if (shuttingDown) {
                    return;
                }
                shuttingDown = true;
                if (dest._state === 'writable' && !WritableStreamCloseQueuedOrInFlight(dest)) {
                    uponFulfillment(waitForWritesToFinish(), () => finalize(isError, error));
                }
                else {
                    finalize(isError, error);
                }
            }
            function finalize(isError, error) {
                WritableStreamDefaultWriterRelease(writer);
                ReadableStreamReaderGenericRelease(reader);
                if (signal !== undefined) {
                    signal.removeEventListener('abort', abortAlgorithm);
                }
                if (isError) {
                    reject(error);
                }
                else {
                    resolve(undefined);
                }
            }
        });
    }

    /**
     * Allows control of a {@link ReadableStream | readable stream}'s state and internal queue.
     *
     * @public
     */
    class ReadableStreamDefaultController {
        constructor() {
            throw new TypeError('Illegal constructor');
        }
        /**
         * Returns the desired size to fill the controlled stream's internal queue. It can be negative, if the queue is
         * over-full. An underlying source ought to use this information to determine when and how to apply backpressure.
         */
        get desiredSize() {
            if (!IsReadableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$1('desiredSize');
            }
            return ReadableStreamDefaultControllerGetDesiredSize(this);
        }
        /**
         * Closes the controlled readable stream. Consumers will still be able to read any previously-enqueued chunks from
         * the stream, but once those are read, the stream will become closed.
         */
        close() {
            if (!IsReadableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$1('close');
            }
            if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(this)) {
                throw new TypeError('The stream is not in a state that permits close');
            }
            ReadableStreamDefaultControllerClose(this);
        }
        enqueue(chunk = undefined) {
            if (!IsReadableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$1('enqueue');
            }
            if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(this)) {
                throw new TypeError('The stream is not in a state that permits enqueue');
            }
            return ReadableStreamDefaultControllerEnqueue(this, chunk);
        }
        /**
         * Errors the controlled readable stream, making all future interactions with it fail with the given error `e`.
         */
        error(e = undefined) {
            if (!IsReadableStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException$1('error');
            }
            ReadableStreamDefaultControllerError(this, e);
        }
        /** @internal */
        [CancelSteps](reason) {
            ResetQueue(this);
            const result = this._cancelAlgorithm(reason);
            ReadableStreamDefaultControllerClearAlgorithms(this);
            return result;
        }
        /** @internal */
        [PullSteps](readRequest) {
            const stream = this._controlledReadableStream;
            if (this._queue.length > 0) {
                const chunk = DequeueValue(this);
                if (this._closeRequested && this._queue.length === 0) {
                    ReadableStreamDefaultControllerClearAlgorithms(this);
                    ReadableStreamClose(stream);
                }
                else {
                    ReadableStreamDefaultControllerCallPullIfNeeded(this);
                }
                readRequest._chunkSteps(chunk);
            }
            else {
                ReadableStreamAddReadRequest(stream, readRequest);
                ReadableStreamDefaultControllerCallPullIfNeeded(this);
            }
        }
    }
    Object.defineProperties(ReadableStreamDefaultController.prototype, {
        close: { enumerable: true },
        enqueue: { enumerable: true },
        error: { enumerable: true },
        desiredSize: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStreamDefaultController.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStreamDefaultController',
            configurable: true
        });
    }
    // Abstract operations for the ReadableStreamDefaultController.
    function IsReadableStreamDefaultController(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_controlledReadableStream')) {
            return false;
        }
        return x instanceof ReadableStreamDefaultController;
    }
    function ReadableStreamDefaultControllerCallPullIfNeeded(controller) {
        const shouldPull = ReadableStreamDefaultControllerShouldCallPull(controller);
        if (!shouldPull) {
            return;
        }
        if (controller._pulling) {
            controller._pullAgain = true;
            return;
        }
        controller._pulling = true;
        const pullPromise = controller._pullAlgorithm();
        uponPromise(pullPromise, () => {
            controller._pulling = false;
            if (controller._pullAgain) {
                controller._pullAgain = false;
                ReadableStreamDefaultControllerCallPullIfNeeded(controller);
            }
        }, e => {
            ReadableStreamDefaultControllerError(controller, e);
        });
    }
    function ReadableStreamDefaultControllerShouldCallPull(controller) {
        const stream = controller._controlledReadableStream;
        if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(controller)) {
            return false;
        }
        if (!controller._started) {
            return false;
        }
        if (IsReadableStreamLocked(stream) && ReadableStreamGetNumReadRequests(stream) > 0) {
            return true;
        }
        const desiredSize = ReadableStreamDefaultControllerGetDesiredSize(controller);
        if (desiredSize > 0) {
            return true;
        }
        return false;
    }
    function ReadableStreamDefaultControllerClearAlgorithms(controller) {
        controller._pullAlgorithm = undefined;
        controller._cancelAlgorithm = undefined;
        controller._strategySizeAlgorithm = undefined;
    }
    // A client of ReadableStreamDefaultController may use these functions directly to bypass state check.
    function ReadableStreamDefaultControllerClose(controller) {
        if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(controller)) {
            return;
        }
        const stream = controller._controlledReadableStream;
        controller._closeRequested = true;
        if (controller._queue.length === 0) {
            ReadableStreamDefaultControllerClearAlgorithms(controller);
            ReadableStreamClose(stream);
        }
    }
    function ReadableStreamDefaultControllerEnqueue(controller, chunk) {
        if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(controller)) {
            return;
        }
        const stream = controller._controlledReadableStream;
        if (IsReadableStreamLocked(stream) && ReadableStreamGetNumReadRequests(stream) > 0) {
            ReadableStreamFulfillReadRequest(stream, chunk, false);
        }
        else {
            let chunkSize;
            try {
                chunkSize = controller._strategySizeAlgorithm(chunk);
            }
            catch (chunkSizeE) {
                ReadableStreamDefaultControllerError(controller, chunkSizeE);
                throw chunkSizeE;
            }
            try {
                EnqueueValueWithSize(controller, chunk, chunkSize);
            }
            catch (enqueueE) {
                ReadableStreamDefaultControllerError(controller, enqueueE);
                throw enqueueE;
            }
        }
        ReadableStreamDefaultControllerCallPullIfNeeded(controller);
    }
    function ReadableStreamDefaultControllerError(controller, e) {
        const stream = controller._controlledReadableStream;
        if (stream._state !== 'readable') {
            return;
        }
        ResetQueue(controller);
        ReadableStreamDefaultControllerClearAlgorithms(controller);
        ReadableStreamError(stream, e);
    }
    function ReadableStreamDefaultControllerGetDesiredSize(controller) {
        const state = controller._controlledReadableStream._state;
        if (state === 'errored') {
            return null;
        }
        if (state === 'closed') {
            return 0;
        }
        return controller._strategyHWM - controller._queueTotalSize;
    }
    // This is used in the implementation of TransformStream.
    function ReadableStreamDefaultControllerHasBackpressure(controller) {
        if (ReadableStreamDefaultControllerShouldCallPull(controller)) {
            return false;
        }
        return true;
    }
    function ReadableStreamDefaultControllerCanCloseOrEnqueue(controller) {
        const state = controller._controlledReadableStream._state;
        if (!controller._closeRequested && state === 'readable') {
            return true;
        }
        return false;
    }
    function SetUpReadableStreamDefaultController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, sizeAlgorithm) {
        controller._controlledReadableStream = stream;
        controller._queue = undefined;
        controller._queueTotalSize = undefined;
        ResetQueue(controller);
        controller._started = false;
        controller._closeRequested = false;
        controller._pullAgain = false;
        controller._pulling = false;
        controller._strategySizeAlgorithm = sizeAlgorithm;
        controller._strategyHWM = highWaterMark;
        controller._pullAlgorithm = pullAlgorithm;
        controller._cancelAlgorithm = cancelAlgorithm;
        stream._readableStreamController = controller;
        const startResult = startAlgorithm();
        uponPromise(promiseResolvedWith(startResult), () => {
            controller._started = true;
            ReadableStreamDefaultControllerCallPullIfNeeded(controller);
        }, r => {
            ReadableStreamDefaultControllerError(controller, r);
        });
    }
    function SetUpReadableStreamDefaultControllerFromUnderlyingSource(stream, underlyingSource, highWaterMark, sizeAlgorithm) {
        const controller = Object.create(ReadableStreamDefaultController.prototype);
        let startAlgorithm = () => undefined;
        let pullAlgorithm = () => promiseResolvedWith(undefined);
        let cancelAlgorithm = () => promiseResolvedWith(undefined);
        if (underlyingSource.start !== undefined) {
            startAlgorithm = () => underlyingSource.start(controller);
        }
        if (underlyingSource.pull !== undefined) {
            pullAlgorithm = () => underlyingSource.pull(controller);
        }
        if (underlyingSource.cancel !== undefined) {
            cancelAlgorithm = reason => underlyingSource.cancel(reason);
        }
        SetUpReadableStreamDefaultController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, sizeAlgorithm);
    }
    // Helper functions for the ReadableStreamDefaultController.
    function defaultControllerBrandCheckException$1(name) {
        return new TypeError(`ReadableStreamDefaultController.prototype.${name} can only be used on a ReadableStreamDefaultController`);
    }

    function ReadableStreamTee(stream, cloneForBranch2) {
        if (IsReadableByteStreamController(stream._readableStreamController)) {
            return ReadableByteStreamTee(stream);
        }
        return ReadableStreamDefaultTee(stream);
    }
    function ReadableStreamDefaultTee(stream, cloneForBranch2) {
        const reader = AcquireReadableStreamDefaultReader(stream);
        let reading = false;
        let readAgain = false;
        let canceled1 = false;
        let canceled2 = false;
        let reason1;
        let reason2;
        let branch1;
        let branch2;
        let resolveCancelPromise;
        const cancelPromise = newPromise(resolve => {
            resolveCancelPromise = resolve;
        });
        function pullAlgorithm() {
            if (reading) {
                readAgain = true;
                return promiseResolvedWith(undefined);
            }
            reading = true;
            const readRequest = {
                _chunkSteps: chunk => {
                    // This needs to be delayed a microtask because it takes at least a microtask to detect errors (using
                    // reader._closedPromise below), and we want errors in stream to error both branches immediately. We cannot let
                    // successful synchronously-available reads get ahead of asynchronously-available errors.
                    queueMicrotask(() => {
                        readAgain = false;
                        const chunk1 = chunk;
                        const chunk2 = chunk;
                        // There is no way to access the cloning code right now in the reference implementation.
                        // If we add one then we'll need an implementation for serializable objects.
                        // if (!canceled2 && cloneForBranch2) {
                        //   chunk2 = StructuredDeserialize(StructuredSerialize(chunk2));
                        // }
                        if (!canceled1) {
                            ReadableStreamDefaultControllerEnqueue(branch1._readableStreamController, chunk1);
                        }
                        if (!canceled2) {
                            ReadableStreamDefaultControllerEnqueue(branch2._readableStreamController, chunk2);
                        }
                        reading = false;
                        if (readAgain) {
                            pullAlgorithm();
                        }
                    });
                },
                _closeSteps: () => {
                    reading = false;
                    if (!canceled1) {
                        ReadableStreamDefaultControllerClose(branch1._readableStreamController);
                    }
                    if (!canceled2) {
                        ReadableStreamDefaultControllerClose(branch2._readableStreamController);
                    }
                    if (!canceled1 || !canceled2) {
                        resolveCancelPromise(undefined);
                    }
                },
                _errorSteps: () => {
                    reading = false;
                }
            };
            ReadableStreamDefaultReaderRead(reader, readRequest);
            return promiseResolvedWith(undefined);
        }
        function cancel1Algorithm(reason) {
            canceled1 = true;
            reason1 = reason;
            if (canceled2) {
                const compositeReason = CreateArrayFromList([reason1, reason2]);
                const cancelResult = ReadableStreamCancel(stream, compositeReason);
                resolveCancelPromise(cancelResult);
            }
            return cancelPromise;
        }
        function cancel2Algorithm(reason) {
            canceled2 = true;
            reason2 = reason;
            if (canceled1) {
                const compositeReason = CreateArrayFromList([reason1, reason2]);
                const cancelResult = ReadableStreamCancel(stream, compositeReason);
                resolveCancelPromise(cancelResult);
            }
            return cancelPromise;
        }
        function startAlgorithm() {
            // do nothing
        }
        branch1 = CreateReadableStream(startAlgorithm, pullAlgorithm, cancel1Algorithm);
        branch2 = CreateReadableStream(startAlgorithm, pullAlgorithm, cancel2Algorithm);
        uponRejection(reader._closedPromise, (r) => {
            ReadableStreamDefaultControllerError(branch1._readableStreamController, r);
            ReadableStreamDefaultControllerError(branch2._readableStreamController, r);
            if (!canceled1 || !canceled2) {
                resolveCancelPromise(undefined);
            }
        });
        return [branch1, branch2];
    }
    function ReadableByteStreamTee(stream) {
        let reader = AcquireReadableStreamDefaultReader(stream);
        let reading = false;
        let readAgainForBranch1 = false;
        let readAgainForBranch2 = false;
        let canceled1 = false;
        let canceled2 = false;
        let reason1;
        let reason2;
        let branch1;
        let branch2;
        let resolveCancelPromise;
        const cancelPromise = newPromise(resolve => {
            resolveCancelPromise = resolve;
        });
        function forwardReaderError(thisReader) {
            uponRejection(thisReader._closedPromise, r => {
                if (thisReader !== reader) {
                    return;
                }
                ReadableByteStreamControllerError(branch1._readableStreamController, r);
                ReadableByteStreamControllerError(branch2._readableStreamController, r);
                if (!canceled1 || !canceled2) {
                    resolveCancelPromise(undefined);
                }
            });
        }
        function pullWithDefaultReader() {
            if (IsReadableStreamBYOBReader(reader)) {
                ReadableStreamReaderGenericRelease(reader);
                reader = AcquireReadableStreamDefaultReader(stream);
                forwardReaderError(reader);
            }
            const readRequest = {
                _chunkSteps: chunk => {
                    // This needs to be delayed a microtask because it takes at least a microtask to detect errors (using
                    // reader._closedPromise below), and we want errors in stream to error both branches immediately. We cannot let
                    // successful synchronously-available reads get ahead of asynchronously-available errors.
                    queueMicrotask(() => {
                        readAgainForBranch1 = false;
                        readAgainForBranch2 = false;
                        const chunk1 = chunk;
                        let chunk2 = chunk;
                        if (!canceled1 && !canceled2) {
                            try {
                                chunk2 = CloneAsUint8Array(chunk);
                            }
                            catch (cloneE) {
                                ReadableByteStreamControllerError(branch1._readableStreamController, cloneE);
                                ReadableByteStreamControllerError(branch2._readableStreamController, cloneE);
                                resolveCancelPromise(ReadableStreamCancel(stream, cloneE));
                                return;
                            }
                        }
                        if (!canceled1) {
                            ReadableByteStreamControllerEnqueue(branch1._readableStreamController, chunk1);
                        }
                        if (!canceled2) {
                            ReadableByteStreamControllerEnqueue(branch2._readableStreamController, chunk2);
                        }
                        reading = false;
                        if (readAgainForBranch1) {
                            pull1Algorithm();
                        }
                        else if (readAgainForBranch2) {
                            pull2Algorithm();
                        }
                    });
                },
                _closeSteps: () => {
                    reading = false;
                    if (!canceled1) {
                        ReadableByteStreamControllerClose(branch1._readableStreamController);
                    }
                    if (!canceled2) {
                        ReadableByteStreamControllerClose(branch2._readableStreamController);
                    }
                    if (branch1._readableStreamController._pendingPullIntos.length > 0) {
                        ReadableByteStreamControllerRespond(branch1._readableStreamController, 0);
                    }
                    if (branch2._readableStreamController._pendingPullIntos.length > 0) {
                        ReadableByteStreamControllerRespond(branch2._readableStreamController, 0);
                    }
                    if (!canceled1 || !canceled2) {
                        resolveCancelPromise(undefined);
                    }
                },
                _errorSteps: () => {
                    reading = false;
                }
            };
            ReadableStreamDefaultReaderRead(reader, readRequest);
        }
        function pullWithBYOBReader(view, forBranch2) {
            if (IsReadableStreamDefaultReader(reader)) {
                ReadableStreamReaderGenericRelease(reader);
                reader = AcquireReadableStreamBYOBReader(stream);
                forwardReaderError(reader);
            }
            const byobBranch = forBranch2 ? branch2 : branch1;
            const otherBranch = forBranch2 ? branch1 : branch2;
            const readIntoRequest = {
                _chunkSteps: chunk => {
                    // This needs to be delayed a microtask because it takes at least a microtask to detect errors (using
                    // reader._closedPromise below), and we want errors in stream to error both branches immediately. We cannot let
                    // successful synchronously-available reads get ahead of asynchronously-available errors.
                    queueMicrotask(() => {
                        readAgainForBranch1 = false;
                        readAgainForBranch2 = false;
                        const byobCanceled = forBranch2 ? canceled2 : canceled1;
                        const otherCanceled = forBranch2 ? canceled1 : canceled2;
                        if (!otherCanceled) {
                            let clonedChunk;
                            try {
                                clonedChunk = CloneAsUint8Array(chunk);
                            }
                            catch (cloneE) {
                                ReadableByteStreamControllerError(byobBranch._readableStreamController, cloneE);
                                ReadableByteStreamControllerError(otherBranch._readableStreamController, cloneE);
                                resolveCancelPromise(ReadableStreamCancel(stream, cloneE));
                                return;
                            }
                            if (!byobCanceled) {
                                ReadableByteStreamControllerRespondWithNewView(byobBranch._readableStreamController, chunk);
                            }
                            ReadableByteStreamControllerEnqueue(otherBranch._readableStreamController, clonedChunk);
                        }
                        else if (!byobCanceled) {
                            ReadableByteStreamControllerRespondWithNewView(byobBranch._readableStreamController, chunk);
                        }
                        reading = false;
                        if (readAgainForBranch1) {
                            pull1Algorithm();
                        }
                        else if (readAgainForBranch2) {
                            pull2Algorithm();
                        }
                    });
                },
                _closeSteps: chunk => {
                    reading = false;
                    const byobCanceled = forBranch2 ? canceled2 : canceled1;
                    const otherCanceled = forBranch2 ? canceled1 : canceled2;
                    if (!byobCanceled) {
                        ReadableByteStreamControllerClose(byobBranch._readableStreamController);
                    }
                    if (!otherCanceled) {
                        ReadableByteStreamControllerClose(otherBranch._readableStreamController);
                    }
                    if (chunk !== undefined) {
                        if (!byobCanceled) {
                            ReadableByteStreamControllerRespondWithNewView(byobBranch._readableStreamController, chunk);
                        }
                        if (!otherCanceled && otherBranch._readableStreamController._pendingPullIntos.length > 0) {
                            ReadableByteStreamControllerRespond(otherBranch._readableStreamController, 0);
                        }
                    }
                    if (!byobCanceled || !otherCanceled) {
                        resolveCancelPromise(undefined);
                    }
                },
                _errorSteps: () => {
                    reading = false;
                }
            };
            ReadableStreamBYOBReaderRead(reader, view, readIntoRequest);
        }
        function pull1Algorithm() {
            if (reading) {
                readAgainForBranch1 = true;
                return promiseResolvedWith(undefined);
            }
            reading = true;
            const byobRequest = ReadableByteStreamControllerGetBYOBRequest(branch1._readableStreamController);
            if (byobRequest === null) {
                pullWithDefaultReader();
            }
            else {
                pullWithBYOBReader(byobRequest._view, false);
            }
            return promiseResolvedWith(undefined);
        }
        function pull2Algorithm() {
            if (reading) {
                readAgainForBranch2 = true;
                return promiseResolvedWith(undefined);
            }
            reading = true;
            const byobRequest = ReadableByteStreamControllerGetBYOBRequest(branch2._readableStreamController);
            if (byobRequest === null) {
                pullWithDefaultReader();
            }
            else {
                pullWithBYOBReader(byobRequest._view, true);
            }
            return promiseResolvedWith(undefined);
        }
        function cancel1Algorithm(reason) {
            canceled1 = true;
            reason1 = reason;
            if (canceled2) {
                const compositeReason = CreateArrayFromList([reason1, reason2]);
                const cancelResult = ReadableStreamCancel(stream, compositeReason);
                resolveCancelPromise(cancelResult);
            }
            return cancelPromise;
        }
        function cancel2Algorithm(reason) {
            canceled2 = true;
            reason2 = reason;
            if (canceled1) {
                const compositeReason = CreateArrayFromList([reason1, reason2]);
                const cancelResult = ReadableStreamCancel(stream, compositeReason);
                resolveCancelPromise(cancelResult);
            }
            return cancelPromise;
        }
        function startAlgorithm() {
            return;
        }
        branch1 = CreateReadableByteStream(startAlgorithm, pull1Algorithm, cancel1Algorithm);
        branch2 = CreateReadableByteStream(startAlgorithm, pull2Algorithm, cancel2Algorithm);
        forwardReaderError(reader);
        return [branch1, branch2];
    }

    function convertUnderlyingDefaultOrByteSource(source, context) {
        assertDictionary(source, context);
        const original = source;
        const autoAllocateChunkSize = original === null || original === void 0 ? void 0 : original.autoAllocateChunkSize;
        const cancel = original === null || original === void 0 ? void 0 : original.cancel;
        const pull = original === null || original === void 0 ? void 0 : original.pull;
        const start = original === null || original === void 0 ? void 0 : original.start;
        const type = original === null || original === void 0 ? void 0 : original.type;
        return {
            autoAllocateChunkSize: autoAllocateChunkSize === undefined ?
                undefined :
                convertUnsignedLongLongWithEnforceRange(autoAllocateChunkSize, `${context} has member 'autoAllocateChunkSize' that`),
            cancel: cancel === undefined ?
                undefined :
                convertUnderlyingSourceCancelCallback(cancel, original, `${context} has member 'cancel' that`),
            pull: pull === undefined ?
                undefined :
                convertUnderlyingSourcePullCallback(pull, original, `${context} has member 'pull' that`),
            start: start === undefined ?
                undefined :
                convertUnderlyingSourceStartCallback(start, original, `${context} has member 'start' that`),
            type: type === undefined ? undefined : convertReadableStreamType(type, `${context} has member 'type' that`)
        };
    }
    function convertUnderlyingSourceCancelCallback(fn, original, context) {
        assertFunction(fn, context);
        return (reason) => promiseCall(fn, original, [reason]);
    }
    function convertUnderlyingSourcePullCallback(fn, original, context) {
        assertFunction(fn, context);
        return (controller) => promiseCall(fn, original, [controller]);
    }
    function convertUnderlyingSourceStartCallback(fn, original, context) {
        assertFunction(fn, context);
        return (controller) => reflectCall(fn, original, [controller]);
    }
    function convertReadableStreamType(type, context) {
        type = `${type}`;
        if (type !== 'bytes') {
            throw new TypeError(`${context} '${type}' is not a valid enumeration value for ReadableStreamType`);
        }
        return type;
    }

    function convertReaderOptions(options, context) {
        assertDictionary(options, context);
        const mode = options === null || options === void 0 ? void 0 : options.mode;
        return {
            mode: mode === undefined ? undefined : convertReadableStreamReaderMode(mode, `${context} has member 'mode' that`)
        };
    }
    function convertReadableStreamReaderMode(mode, context) {
        mode = `${mode}`;
        if (mode !== 'byob') {
            throw new TypeError(`${context} '${mode}' is not a valid enumeration value for ReadableStreamReaderMode`);
        }
        return mode;
    }

    function convertIteratorOptions(options, context) {
        assertDictionary(options, context);
        const preventCancel = options === null || options === void 0 ? void 0 : options.preventCancel;
        return { preventCancel: Boolean(preventCancel) };
    }

    function convertPipeOptions(options, context) {
        assertDictionary(options, context);
        const preventAbort = options === null || options === void 0 ? void 0 : options.preventAbort;
        const preventCancel = options === null || options === void 0 ? void 0 : options.preventCancel;
        const preventClose = options === null || options === void 0 ? void 0 : options.preventClose;
        const signal = options === null || options === void 0 ? void 0 : options.signal;
        if (signal !== undefined) {
            assertAbortSignal(signal, `${context} has member 'signal' that`);
        }
        return {
            preventAbort: Boolean(preventAbort),
            preventCancel: Boolean(preventCancel),
            preventClose: Boolean(preventClose),
            signal
        };
    }
    function assertAbortSignal(signal, context) {
        if (!isAbortSignal(signal)) {
            throw new TypeError(`${context} is not an AbortSignal.`);
        }
    }

    function convertReadableWritablePair(pair, context) {
        assertDictionary(pair, context);
        const readable = pair === null || pair === void 0 ? void 0 : pair.readable;
        assertRequiredField(readable, 'readable', 'ReadableWritablePair');
        assertReadableStream(readable, `${context} has member 'readable' that`);
        const writable = pair === null || pair === void 0 ? void 0 : pair.writable;
        assertRequiredField(writable, 'writable', 'ReadableWritablePair');
        assertWritableStream(writable, `${context} has member 'writable' that`);
        return { readable, writable };
    }

    /**
     * A readable stream represents a source of data, from which you can read.
     *
     * @public
     */
    class ReadableStream {
        constructor(rawUnderlyingSource = {}, rawStrategy = {}) {
            if (rawUnderlyingSource === undefined) {
                rawUnderlyingSource = null;
            }
            else {
                assertObject(rawUnderlyingSource, 'First parameter');
            }
            const strategy = convertQueuingStrategy(rawStrategy, 'Second parameter');
            const underlyingSource = convertUnderlyingDefaultOrByteSource(rawUnderlyingSource, 'First parameter');
            InitializeReadableStream(this);
            if (underlyingSource.type === 'bytes') {
                if (strategy.size !== undefined) {
                    throw new RangeError('The strategy for a byte stream cannot have a size function');
                }
                const highWaterMark = ExtractHighWaterMark(strategy, 0);
                SetUpReadableByteStreamControllerFromUnderlyingSource(this, underlyingSource, highWaterMark);
            }
            else {
                const sizeAlgorithm = ExtractSizeAlgorithm(strategy);
                const highWaterMark = ExtractHighWaterMark(strategy, 1);
                SetUpReadableStreamDefaultControllerFromUnderlyingSource(this, underlyingSource, highWaterMark, sizeAlgorithm);
            }
        }
        /**
         * Whether or not the readable stream is locked to a {@link ReadableStreamDefaultReader | reader}.
         */
        get locked() {
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('locked');
            }
            return IsReadableStreamLocked(this);
        }
        /**
         * Cancels the stream, signaling a loss of interest in the stream by a consumer.
         *
         * The supplied `reason` argument will be given to the underlying source's {@link UnderlyingSource.cancel | cancel()}
         * method, which might or might not use it.
         */
        cancel(reason = undefined) {
            if (!IsReadableStream(this)) {
                return promiseRejectedWith(streamBrandCheckException$1('cancel'));
            }
            if (IsReadableStreamLocked(this)) {
                return promiseRejectedWith(new TypeError('Cannot cancel a stream that already has a reader'));
            }
            return ReadableStreamCancel(this, reason);
        }
        getReader(rawOptions = undefined) {
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('getReader');
            }
            const options = convertReaderOptions(rawOptions, 'First parameter');
            if (options.mode === undefined) {
                return AcquireReadableStreamDefaultReader(this);
            }
            return AcquireReadableStreamBYOBReader(this);
        }
        pipeThrough(rawTransform, rawOptions = {}) {
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('pipeThrough');
            }
            assertRequiredArgument(rawTransform, 1, 'pipeThrough');
            const transform = convertReadableWritablePair(rawTransform, 'First parameter');
            const options = convertPipeOptions(rawOptions, 'Second parameter');
            if (IsReadableStreamLocked(this)) {
                throw new TypeError('ReadableStream.prototype.pipeThrough cannot be used on a locked ReadableStream');
            }
            if (IsWritableStreamLocked(transform.writable)) {
                throw new TypeError('ReadableStream.prototype.pipeThrough cannot be used on a locked WritableStream');
            }
            const promise = ReadableStreamPipeTo(this, transform.writable, options.preventClose, options.preventAbort, options.preventCancel, options.signal);
            setPromiseIsHandledToTrue(promise);
            return transform.readable;
        }
        pipeTo(destination, rawOptions = {}) {
            if (!IsReadableStream(this)) {
                return promiseRejectedWith(streamBrandCheckException$1('pipeTo'));
            }
            if (destination === undefined) {
                return promiseRejectedWith(`Parameter 1 is required in 'pipeTo'.`);
            }
            if (!IsWritableStream(destination)) {
                return promiseRejectedWith(new TypeError(`ReadableStream.prototype.pipeTo's first argument must be a WritableStream`));
            }
            let options;
            try {
                options = convertPipeOptions(rawOptions, 'Second parameter');
            }
            catch (e) {
                return promiseRejectedWith(e);
            }
            if (IsReadableStreamLocked(this)) {
                return promiseRejectedWith(new TypeError('ReadableStream.prototype.pipeTo cannot be used on a locked ReadableStream'));
            }
            if (IsWritableStreamLocked(destination)) {
                return promiseRejectedWith(new TypeError('ReadableStream.prototype.pipeTo cannot be used on a locked WritableStream'));
            }
            return ReadableStreamPipeTo(this, destination, options.preventClose, options.preventAbort, options.preventCancel, options.signal);
        }
        /**
         * Tees this readable stream, returning a two-element array containing the two resulting branches as
         * new {@link ReadableStream} instances.
         *
         * Teeing a stream will lock it, preventing any other consumer from acquiring a reader.
         * To cancel the stream, cancel both of the resulting branches; a composite cancellation reason will then be
         * propagated to the stream's underlying source.
         *
         * Note that the chunks seen in each branch will be the same object. If the chunks are not immutable,
         * this could allow interference between the two branches.
         */
        tee() {
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('tee');
            }
            const branches = ReadableStreamTee(this);
            return CreateArrayFromList(branches);
        }
        values(rawOptions = undefined) {
            if (!IsReadableStream(this)) {
                throw streamBrandCheckException$1('values');
            }
            const options = convertIteratorOptions(rawOptions, 'First parameter');
            return AcquireReadableStreamAsyncIterator(this, options.preventCancel);
        }
    }
    Object.defineProperties(ReadableStream.prototype, {
        cancel: { enumerable: true },
        getReader: { enumerable: true },
        pipeThrough: { enumerable: true },
        pipeTo: { enumerable: true },
        tee: { enumerable: true },
        values: { enumerable: true },
        locked: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ReadableStream.prototype, SymbolPolyfill.toStringTag, {
            value: 'ReadableStream',
            configurable: true
        });
    }
    if (typeof SymbolPolyfill.asyncIterator === 'symbol') {
        Object.defineProperty(ReadableStream.prototype, SymbolPolyfill.asyncIterator, {
            value: ReadableStream.prototype.values,
            writable: true,
            configurable: true
        });
    }
    // Abstract operations for the ReadableStream.
    // Throws if and only if startAlgorithm throws.
    function CreateReadableStream(startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark = 1, sizeAlgorithm = () => 1) {
        const stream = Object.create(ReadableStream.prototype);
        InitializeReadableStream(stream);
        const controller = Object.create(ReadableStreamDefaultController.prototype);
        SetUpReadableStreamDefaultController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, highWaterMark, sizeAlgorithm);
        return stream;
    }
    // Throws if and only if startAlgorithm throws.
    function CreateReadableByteStream(startAlgorithm, pullAlgorithm, cancelAlgorithm) {
        const stream = Object.create(ReadableStream.prototype);
        InitializeReadableStream(stream);
        const controller = Object.create(ReadableByteStreamController.prototype);
        SetUpReadableByteStreamController(stream, controller, startAlgorithm, pullAlgorithm, cancelAlgorithm, 0, undefined);
        return stream;
    }
    function InitializeReadableStream(stream) {
        stream._state = 'readable';
        stream._reader = undefined;
        stream._storedError = undefined;
        stream._disturbed = false;
    }
    function IsReadableStream(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_readableStreamController')) {
            return false;
        }
        return x instanceof ReadableStream;
    }
    function IsReadableStreamLocked(stream) {
        if (stream._reader === undefined) {
            return false;
        }
        return true;
    }
    // ReadableStream API exposed for controllers.
    function ReadableStreamCancel(stream, reason) {
        stream._disturbed = true;
        if (stream._state === 'closed') {
            return promiseResolvedWith(undefined);
        }
        if (stream._state === 'errored') {
            return promiseRejectedWith(stream._storedError);
        }
        ReadableStreamClose(stream);
        const reader = stream._reader;
        if (reader !== undefined && IsReadableStreamBYOBReader(reader)) {
            reader._readIntoRequests.forEach(readIntoRequest => {
                readIntoRequest._closeSteps(undefined);
            });
            reader._readIntoRequests = new SimpleQueue();
        }
        const sourceCancelPromise = stream._readableStreamController[CancelSteps](reason);
        return transformPromiseWith(sourceCancelPromise, noop);
    }
    function ReadableStreamClose(stream) {
        stream._state = 'closed';
        const reader = stream._reader;
        if (reader === undefined) {
            return;
        }
        defaultReaderClosedPromiseResolve(reader);
        if (IsReadableStreamDefaultReader(reader)) {
            reader._readRequests.forEach(readRequest => {
                readRequest._closeSteps();
            });
            reader._readRequests = new SimpleQueue();
        }
    }
    function ReadableStreamError(stream, e) {
        stream._state = 'errored';
        stream._storedError = e;
        const reader = stream._reader;
        if (reader === undefined) {
            return;
        }
        defaultReaderClosedPromiseReject(reader, e);
        if (IsReadableStreamDefaultReader(reader)) {
            reader._readRequests.forEach(readRequest => {
                readRequest._errorSteps(e);
            });
            reader._readRequests = new SimpleQueue();
        }
        else {
            reader._readIntoRequests.forEach(readIntoRequest => {
                readIntoRequest._errorSteps(e);
            });
            reader._readIntoRequests = new SimpleQueue();
        }
    }
    // Helper functions for the ReadableStream.
    function streamBrandCheckException$1(name) {
        return new TypeError(`ReadableStream.prototype.${name} can only be used on a ReadableStream`);
    }

    function convertQueuingStrategyInit(init, context) {
        assertDictionary(init, context);
        const highWaterMark = init === null || init === void 0 ? void 0 : init.highWaterMark;
        assertRequiredField(highWaterMark, 'highWaterMark', 'QueuingStrategyInit');
        return {
            highWaterMark: convertUnrestrictedDouble(highWaterMark)
        };
    }

    // The size function must not have a prototype property nor be a constructor
    const byteLengthSizeFunction = (chunk) => {
        return chunk.byteLength;
    };
    try {
        Object.defineProperty(byteLengthSizeFunction, 'name', {
            value: 'size',
            configurable: true
        });
    }
    catch (_a) {
        // This property is non-configurable in older browsers, so ignore if this throws.
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/name#browser_compatibility
    }
    /**
     * A queuing strategy that counts the number of bytes in each chunk.
     *
     * @public
     */
    class ByteLengthQueuingStrategy {
        constructor(options) {
            assertRequiredArgument(options, 1, 'ByteLengthQueuingStrategy');
            options = convertQueuingStrategyInit(options, 'First parameter');
            this._byteLengthQueuingStrategyHighWaterMark = options.highWaterMark;
        }
        /**
         * Returns the high water mark provided to the constructor.
         */
        get highWaterMark() {
            if (!IsByteLengthQueuingStrategy(this)) {
                throw byteLengthBrandCheckException('highWaterMark');
            }
            return this._byteLengthQueuingStrategyHighWaterMark;
        }
        /**
         * Measures the size of `chunk` by returning the value of its `byteLength` property.
         */
        get size() {
            if (!IsByteLengthQueuingStrategy(this)) {
                throw byteLengthBrandCheckException('size');
            }
            return byteLengthSizeFunction;
        }
    }
    Object.defineProperties(ByteLengthQueuingStrategy.prototype, {
        highWaterMark: { enumerable: true },
        size: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(ByteLengthQueuingStrategy.prototype, SymbolPolyfill.toStringTag, {
            value: 'ByteLengthQueuingStrategy',
            configurable: true
        });
    }
    // Helper functions for the ByteLengthQueuingStrategy.
    function byteLengthBrandCheckException(name) {
        return new TypeError(`ByteLengthQueuingStrategy.prototype.${name} can only be used on a ByteLengthQueuingStrategy`);
    }
    function IsByteLengthQueuingStrategy(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_byteLengthQueuingStrategyHighWaterMark')) {
            return false;
        }
        return x instanceof ByteLengthQueuingStrategy;
    }

    // The size function must not have a prototype property nor be a constructor
    const countSizeFunction = () => {
        return 1;
    };
    try {
        Object.defineProperty(countSizeFunction, 'name', {
            value: 'size',
            configurable: true
        });
    }
    catch (_a) {
        // This property is non-configurable in older browsers, so ignore if this throws.
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/name#browser_compatibility
    }
    /**
     * A queuing strategy that counts the number of chunks.
     *
     * @public
     */
    class CountQueuingStrategy {
        constructor(options) {
            assertRequiredArgument(options, 1, 'CountQueuingStrategy');
            options = convertQueuingStrategyInit(options, 'First parameter');
            this._countQueuingStrategyHighWaterMark = options.highWaterMark;
        }
        /**
         * Returns the high water mark provided to the constructor.
         */
        get highWaterMark() {
            if (!IsCountQueuingStrategy(this)) {
                throw countBrandCheckException('highWaterMark');
            }
            return this._countQueuingStrategyHighWaterMark;
        }
        /**
         * Measures the size of `chunk` by always returning 1.
         * This ensures that the total queue size is a count of the number of chunks in the queue.
         */
        get size() {
            if (!IsCountQueuingStrategy(this)) {
                throw countBrandCheckException('size');
            }
            return countSizeFunction;
        }
    }
    Object.defineProperties(CountQueuingStrategy.prototype, {
        highWaterMark: { enumerable: true },
        size: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(CountQueuingStrategy.prototype, SymbolPolyfill.toStringTag, {
            value: 'CountQueuingStrategy',
            configurable: true
        });
    }
    // Helper functions for the CountQueuingStrategy.
    function countBrandCheckException(name) {
        return new TypeError(`CountQueuingStrategy.prototype.${name} can only be used on a CountQueuingStrategy`);
    }
    function IsCountQueuingStrategy(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_countQueuingStrategyHighWaterMark')) {
            return false;
        }
        return x instanceof CountQueuingStrategy;
    }

    function convertTransformer(original, context) {
        assertDictionary(original, context);
        const flush = original === null || original === void 0 ? void 0 : original.flush;
        const readableType = original === null || original === void 0 ? void 0 : original.readableType;
        const start = original === null || original === void 0 ? void 0 : original.start;
        const transform = original === null || original === void 0 ? void 0 : original.transform;
        const writableType = original === null || original === void 0 ? void 0 : original.writableType;
        return {
            flush: flush === undefined ?
                undefined :
                convertTransformerFlushCallback(flush, original, `${context} has member 'flush' that`),
            readableType,
            start: start === undefined ?
                undefined :
                convertTransformerStartCallback(start, original, `${context} has member 'start' that`),
            transform: transform === undefined ?
                undefined :
                convertTransformerTransformCallback(transform, original, `${context} has member 'transform' that`),
            writableType
        };
    }
    function convertTransformerFlushCallback(fn, original, context) {
        assertFunction(fn, context);
        return (controller) => promiseCall(fn, original, [controller]);
    }
    function convertTransformerStartCallback(fn, original, context) {
        assertFunction(fn, context);
        return (controller) => reflectCall(fn, original, [controller]);
    }
    function convertTransformerTransformCallback(fn, original, context) {
        assertFunction(fn, context);
        return (chunk, controller) => promiseCall(fn, original, [chunk, controller]);
    }

    // Class TransformStream
    /**
     * A transform stream consists of a pair of streams: a {@link WritableStream | writable stream},
     * known as its writable side, and a {@link ReadableStream | readable stream}, known as its readable side.
     * In a manner specific to the transform stream in question, writes to the writable side result in new data being
     * made available for reading from the readable side.
     *
     * @public
     */
    class TransformStream {
        constructor(rawTransformer = {}, rawWritableStrategy = {}, rawReadableStrategy = {}) {
            if (rawTransformer === undefined) {
                rawTransformer = null;
            }
            const writableStrategy = convertQueuingStrategy(rawWritableStrategy, 'Second parameter');
            const readableStrategy = convertQueuingStrategy(rawReadableStrategy, 'Third parameter');
            const transformer = convertTransformer(rawTransformer, 'First parameter');
            if (transformer.readableType !== undefined) {
                throw new RangeError('Invalid readableType specified');
            }
            if (transformer.writableType !== undefined) {
                throw new RangeError('Invalid writableType specified');
            }
            const readableHighWaterMark = ExtractHighWaterMark(readableStrategy, 0);
            const readableSizeAlgorithm = ExtractSizeAlgorithm(readableStrategy);
            const writableHighWaterMark = ExtractHighWaterMark(writableStrategy, 1);
            const writableSizeAlgorithm = ExtractSizeAlgorithm(writableStrategy);
            let startPromise_resolve;
            const startPromise = newPromise(resolve => {
                startPromise_resolve = resolve;
            });
            InitializeTransformStream(this, startPromise, writableHighWaterMark, writableSizeAlgorithm, readableHighWaterMark, readableSizeAlgorithm);
            SetUpTransformStreamDefaultControllerFromTransformer(this, transformer);
            if (transformer.start !== undefined) {
                startPromise_resolve(transformer.start(this._transformStreamController));
            }
            else {
                startPromise_resolve(undefined);
            }
        }
        /**
         * The readable side of the transform stream.
         */
        get readable() {
            if (!IsTransformStream(this)) {
                throw streamBrandCheckException('readable');
            }
            return this._readable;
        }
        /**
         * The writable side of the transform stream.
         */
        get writable() {
            if (!IsTransformStream(this)) {
                throw streamBrandCheckException('writable');
            }
            return this._writable;
        }
    }
    Object.defineProperties(TransformStream.prototype, {
        readable: { enumerable: true },
        writable: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(TransformStream.prototype, SymbolPolyfill.toStringTag, {
            value: 'TransformStream',
            configurable: true
        });
    }
    function InitializeTransformStream(stream, startPromise, writableHighWaterMark, writableSizeAlgorithm, readableHighWaterMark, readableSizeAlgorithm) {
        function startAlgorithm() {
            return startPromise;
        }
        function writeAlgorithm(chunk) {
            return TransformStreamDefaultSinkWriteAlgorithm(stream, chunk);
        }
        function abortAlgorithm(reason) {
            return TransformStreamDefaultSinkAbortAlgorithm(stream, reason);
        }
        function closeAlgorithm() {
            return TransformStreamDefaultSinkCloseAlgorithm(stream);
        }
        stream._writable = CreateWritableStream(startAlgorithm, writeAlgorithm, closeAlgorithm, abortAlgorithm, writableHighWaterMark, writableSizeAlgorithm);
        function pullAlgorithm() {
            return TransformStreamDefaultSourcePullAlgorithm(stream);
        }
        function cancelAlgorithm(reason) {
            TransformStreamErrorWritableAndUnblockWrite(stream, reason);
            return promiseResolvedWith(undefined);
        }
        stream._readable = CreateReadableStream(startAlgorithm, pullAlgorithm, cancelAlgorithm, readableHighWaterMark, readableSizeAlgorithm);
        // The [[backpressure]] slot is set to undefined so that it can be initialised by TransformStreamSetBackpressure.
        stream._backpressure = undefined;
        stream._backpressureChangePromise = undefined;
        stream._backpressureChangePromise_resolve = undefined;
        TransformStreamSetBackpressure(stream, true);
        stream._transformStreamController = undefined;
    }
    function IsTransformStream(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_transformStreamController')) {
            return false;
        }
        return x instanceof TransformStream;
    }
    // This is a no-op if both sides are already errored.
    function TransformStreamError(stream, e) {
        ReadableStreamDefaultControllerError(stream._readable._readableStreamController, e);
        TransformStreamErrorWritableAndUnblockWrite(stream, e);
    }
    function TransformStreamErrorWritableAndUnblockWrite(stream, e) {
        TransformStreamDefaultControllerClearAlgorithms(stream._transformStreamController);
        WritableStreamDefaultControllerErrorIfNeeded(stream._writable._writableStreamController, e);
        if (stream._backpressure) {
            // Pretend that pull() was called to permit any pending write() calls to complete. TransformStreamSetBackpressure()
            // cannot be called from enqueue() or pull() once the ReadableStream is errored, so this will will be the final time
            // _backpressure is set.
            TransformStreamSetBackpressure(stream, false);
        }
    }
    function TransformStreamSetBackpressure(stream, backpressure) {
        // Passes also when called during construction.
        if (stream._backpressureChangePromise !== undefined) {
            stream._backpressureChangePromise_resolve();
        }
        stream._backpressureChangePromise = newPromise(resolve => {
            stream._backpressureChangePromise_resolve = resolve;
        });
        stream._backpressure = backpressure;
    }
    // Class TransformStreamDefaultController
    /**
     * Allows control of the {@link ReadableStream} and {@link WritableStream} of the associated {@link TransformStream}.
     *
     * @public
     */
    class TransformStreamDefaultController {
        constructor() {
            throw new TypeError('Illegal constructor');
        }
        /**
         * Returns the desired size to fill the readable side’s internal queue. It can be negative, if the queue is over-full.
         */
        get desiredSize() {
            if (!IsTransformStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException('desiredSize');
            }
            const readableController = this._controlledTransformStream._readable._readableStreamController;
            return ReadableStreamDefaultControllerGetDesiredSize(readableController);
        }
        enqueue(chunk = undefined) {
            if (!IsTransformStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException('enqueue');
            }
            TransformStreamDefaultControllerEnqueue(this, chunk);
        }
        /**
         * Errors both the readable side and the writable side of the controlled transform stream, making all future
         * interactions with it fail with the given error `e`. Any chunks queued for transformation will be discarded.
         */
        error(reason = undefined) {
            if (!IsTransformStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException('error');
            }
            TransformStreamDefaultControllerError(this, reason);
        }
        /**
         * Closes the readable side and errors the writable side of the controlled transform stream. This is useful when the
         * transformer only needs to consume a portion of the chunks written to the writable side.
         */
        terminate() {
            if (!IsTransformStreamDefaultController(this)) {
                throw defaultControllerBrandCheckException('terminate');
            }
            TransformStreamDefaultControllerTerminate(this);
        }
    }
    Object.defineProperties(TransformStreamDefaultController.prototype, {
        enqueue: { enumerable: true },
        error: { enumerable: true },
        terminate: { enumerable: true },
        desiredSize: { enumerable: true }
    });
    if (typeof SymbolPolyfill.toStringTag === 'symbol') {
        Object.defineProperty(TransformStreamDefaultController.prototype, SymbolPolyfill.toStringTag, {
            value: 'TransformStreamDefaultController',
            configurable: true
        });
    }
    // Transform Stream Default Controller Abstract Operations
    function IsTransformStreamDefaultController(x) {
        if (!typeIsObject(x)) {
            return false;
        }
        if (!Object.prototype.hasOwnProperty.call(x, '_controlledTransformStream')) {
            return false;
        }
        return x instanceof TransformStreamDefaultController;
    }
    function SetUpTransformStreamDefaultController(stream, controller, transformAlgorithm, flushAlgorithm) {
        controller._controlledTransformStream = stream;
        stream._transformStreamController = controller;
        controller._transformAlgorithm = transformAlgorithm;
        controller._flushAlgorithm = flushAlgorithm;
    }
    function SetUpTransformStreamDefaultControllerFromTransformer(stream, transformer) {
        const controller = Object.create(TransformStreamDefaultController.prototype);
        let transformAlgorithm = (chunk) => {
            try {
                TransformStreamDefaultControllerEnqueue(controller, chunk);
                return promiseResolvedWith(undefined);
            }
            catch (transformResultE) {
                return promiseRejectedWith(transformResultE);
            }
        };
        let flushAlgorithm = () => promiseResolvedWith(undefined);
        if (transformer.transform !== undefined) {
            transformAlgorithm = chunk => transformer.transform(chunk, controller);
        }
        if (transformer.flush !== undefined) {
            flushAlgorithm = () => transformer.flush(controller);
        }
        SetUpTransformStreamDefaultController(stream, controller, transformAlgorithm, flushAlgorithm);
    }
    function TransformStreamDefaultControllerClearAlgorithms(controller) {
        controller._transformAlgorithm = undefined;
        controller._flushAlgorithm = undefined;
    }
    function TransformStreamDefaultControllerEnqueue(controller, chunk) {
        const stream = controller._controlledTransformStream;
        const readableController = stream._readable._readableStreamController;
        if (!ReadableStreamDefaultControllerCanCloseOrEnqueue(readableController)) {
            throw new TypeError('Readable side is not in a state that permits enqueue');
        }
        // We throttle transform invocations based on the backpressure of the ReadableStream, but we still
        // accept TransformStreamDefaultControllerEnqueue() calls.
        try {
            ReadableStreamDefaultControllerEnqueue(readableController, chunk);
        }
        catch (e) {
            // This happens when readableStrategy.size() throws.
            TransformStreamErrorWritableAndUnblockWrite(stream, e);
            throw stream._readable._storedError;
        }
        const backpressure = ReadableStreamDefaultControllerHasBackpressure(readableController);
        if (backpressure !== stream._backpressure) {
            TransformStreamSetBackpressure(stream, true);
        }
    }
    function TransformStreamDefaultControllerError(controller, e) {
        TransformStreamError(controller._controlledTransformStream, e);
    }
    function TransformStreamDefaultControllerPerformTransform(controller, chunk) {
        const transformPromise = controller._transformAlgorithm(chunk);
        return transformPromiseWith(transformPromise, undefined, r => {
            TransformStreamError(controller._controlledTransformStream, r);
            throw r;
        });
    }
    function TransformStreamDefaultControllerTerminate(controller) {
        const stream = controller._controlledTransformStream;
        const readableController = stream._readable._readableStreamController;
        ReadableStreamDefaultControllerClose(readableController);
        const error = new TypeError('TransformStream terminated');
        TransformStreamErrorWritableAndUnblockWrite(stream, error);
    }
    // TransformStreamDefaultSink Algorithms
    function TransformStreamDefaultSinkWriteAlgorithm(stream, chunk) {
        const controller = stream._transformStreamController;
        if (stream._backpressure) {
            const backpressureChangePromise = stream._backpressureChangePromise;
            return transformPromiseWith(backpressureChangePromise, () => {
                const writable = stream._writable;
                const state = writable._state;
                if (state === 'erroring') {
                    throw writable._storedError;
                }
                return TransformStreamDefaultControllerPerformTransform(controller, chunk);
            });
        }
        return TransformStreamDefaultControllerPerformTransform(controller, chunk);
    }
    function TransformStreamDefaultSinkAbortAlgorithm(stream, reason) {
        // abort() is not called synchronously, so it is possible for abort() to be called when the stream is already
        // errored.
        TransformStreamError(stream, reason);
        return promiseResolvedWith(undefined);
    }
    function TransformStreamDefaultSinkCloseAlgorithm(stream) {
        // stream._readable cannot change after construction, so caching it across a call to user code is safe.
        const readable = stream._readable;
        const controller = stream._transformStreamController;
        const flushPromise = controller._flushAlgorithm();
        TransformStreamDefaultControllerClearAlgorithms(controller);
        // Return a promise that is fulfilled with undefined on success.
        return transformPromiseWith(flushPromise, () => {
            if (readable._state === 'errored') {
                throw readable._storedError;
            }
            ReadableStreamDefaultControllerClose(readable._readableStreamController);
        }, r => {
            TransformStreamError(stream, r);
            throw readable._storedError;
        });
    }
    // TransformStreamDefaultSource Algorithms
    function TransformStreamDefaultSourcePullAlgorithm(stream) {
        // Invariant. Enforced by the promises returned by start() and pull().
        TransformStreamSetBackpressure(stream, false);
        // Prevent the next pull() call until there is backpressure.
        return stream._backpressureChangePromise;
    }
    // Helper functions for the TransformStreamDefaultController.
    function defaultControllerBrandCheckException(name) {
        return new TypeError(`TransformStreamDefaultController.prototype.${name} can only be used on a TransformStreamDefaultController`);
    }
    // Helper functions for the TransformStream.
    function streamBrandCheckException(name) {
        return new TypeError(`TransformStream.prototype.${name} can only be used on a TransformStream`);
    }

    exports.ByteLengthQueuingStrategy = ByteLengthQueuingStrategy;
    exports.CountQueuingStrategy = CountQueuingStrategy;
    exports.ReadableByteStreamController = ReadableByteStreamController;
    exports.ReadableStream = ReadableStream;
    exports.ReadableStreamBYOBReader = ReadableStreamBYOBReader;
    exports.ReadableStreamBYOBRequest = ReadableStreamBYOBRequest;
    exports.ReadableStreamDefaultController = ReadableStreamDefaultController;
    exports.ReadableStreamDefaultReader = ReadableStreamDefaultReader;
    exports.TransformStream = TransformStream;
    exports.TransformStreamDefaultController = TransformStreamDefaultController;
    exports.WritableStream = WritableStream;
    exports.WritableStreamDefaultController = WritableStreamDefaultController;
    exports.WritableStreamDefaultWriter = WritableStreamDefaultWriter;

    Object.defineProperty(exports, '__esModule', { value: true });

})));
//# sourceMappingURL=ponyfill.es2018.js.map


/***/ }),

/***/ 9491:
/***/ ((module) => {

"use strict";
module.exports = require("assert");

/***/ }),

/***/ 4300:
/***/ ((module) => {

"use strict";
module.exports = require("buffer");

/***/ }),

/***/ 6113:
/***/ ((module) => {

"use strict";
module.exports = require("crypto");

/***/ }),

/***/ 2361:
/***/ ((module) => {

"use strict";
module.exports = require("events");

/***/ }),

/***/ 7147:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 3685:
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ 5687:
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ 1808:
/***/ ((module) => {

"use strict";
module.exports = require("net");

/***/ }),

/***/ 7742:
/***/ ((module) => {

"use strict";
module.exports = require("node:process");

/***/ }),

/***/ 2477:
/***/ ((module) => {

"use strict";
module.exports = require("node:stream/web");

/***/ }),

/***/ 2037:
/***/ ((module) => {

"use strict";
module.exports = require("os");

/***/ }),

/***/ 1017:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ }),

/***/ 4404:
/***/ ((module) => {

"use strict";
module.exports = require("tls");

/***/ }),

/***/ 3837:
/***/ ((module) => {

"use strict";
module.exports = require("util");

/***/ }),

/***/ 1267:
/***/ ((module) => {

"use strict";
module.exports = require("worker_threads");

/***/ }),

/***/ 5118:
/***/ ((__unused_webpack_module, __unused_webpack_exports, __nccwpck_require__) => {

/* c8 ignore start */
// 64 KiB (same size chrome slice theirs blob into Uint8array's)
const POOL_SIZE = 65536

if (!globalThis.ReadableStream) {
  // `node:stream/web` got introduced in v16.5.0 as experimental
  // and it's preferred over the polyfilled version. So we also
  // suppress the warning that gets emitted by NodeJS for using it.
  try {
    const process = __nccwpck_require__(7742)
    const { emitWarning } = process
    try {
      process.emitWarning = () => {}
      Object.assign(globalThis, __nccwpck_require__(2477))
      process.emitWarning = emitWarning
    } catch (error) {
      process.emitWarning = emitWarning
      throw error
    }
  } catch (error) {
    // fallback to polyfill implementation
    Object.assign(globalThis, __nccwpck_require__(6467))
  }
}

try {
  // Don't use node: prefix for this, require+node: is not supported until node v14.14
  // Only `import()` can use prefix in 12.20 and later
  const { Blob } = __nccwpck_require__(4300)
  if (Blob && !Blob.prototype.stream) {
    Blob.prototype.stream = function name (params) {
      let position = 0
      const blob = this

      return new ReadableStream({
        type: 'bytes',
        async pull (ctrl) {
          const chunk = blob.slice(position, Math.min(blob.size, position + POOL_SIZE))
          const buffer = await chunk.arrayBuffer()
          position += buffer.byteLength
          ctrl.enqueue(new Uint8Array(buffer))

          if (position === blob.size) {
            ctrl.close()
          }
        }
      })
    }
  }
} catch (error) {}
/* c8 ignore end */


/***/ }),

/***/ 5909:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __nccwpck_require__) => {

"use strict";
/* harmony export */ __nccwpck_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* unused harmony export File */
/* harmony import */ var _index_js__WEBPACK_IMPORTED_MODULE_0__ = __nccwpck_require__(3184);


const _File = class File extends _index_js__WEBPACK_IMPORTED_MODULE_0__/* ["default"] */ .Z {
  #lastModified = 0
  #name = ''

  /**
   * @param {*[]} fileBits
   * @param {string} fileName
   * @param {{lastModified?: number, type?: string}} options
   */// @ts-ignore
  constructor (fileBits, fileName, options = {}) {
    if (arguments.length < 2) {
      throw new TypeError(`Failed to construct 'File': 2 arguments required, but only ${arguments.length} present.`)
    }
    super(fileBits, options)

    if (options === null) options = {}

    // Simulate WebIDL type casting for NaN value in lastModified option.
    const lastModified = options.lastModified === undefined ? Date.now() : Number(options.lastModified)
    if (!Number.isNaN(lastModified)) {
      this.#lastModified = lastModified
    }

    this.#name = String(fileName)
  }

  get name () {
    return this.#name
  }

  get lastModified () {
    return this.#lastModified
  }

  get [Symbol.toStringTag] () {
    return 'File'
  }

  static [Symbol.hasInstance] (object) {
    return !!object && object instanceof _index_js__WEBPACK_IMPORTED_MODULE_0__/* ["default"] */ .Z &&
      /^(File)$/.test(object[Symbol.toStringTag])
  }
}

/** @type {typeof globalThis.File} */// @ts-ignore
const File = _File
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (File);


/***/ }),

/***/ 7176:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __nccwpck_require__) => {

"use strict";

// EXPORTS
__nccwpck_require__.d(__webpack_exports__, {
  "t6": () => (/* reexport */ fetch_blob/* default */.Z),
  "$B": () => (/* reexport */ file/* default */.Z),
  "xB": () => (/* binding */ blobFrom),
  "SX": () => (/* binding */ blobFromSync),
  "e2": () => (/* binding */ fileFrom),
  "RA": () => (/* binding */ fileFromSync)
});

// UNUSED EXPORTS: default

;// CONCATENATED MODULE: external "node:fs"
const external_node_fs_namespaceObject = require("node:fs");
;// CONCATENATED MODULE: external "node:path"
const external_node_path_namespaceObject = require("node:path");
// EXTERNAL MODULE: ./node_modules/node-domexception/index.js
var node_domexception = __nccwpck_require__(4051);
// EXTERNAL MODULE: ./node_modules/fetch-blob/file.js
var file = __nccwpck_require__(5909);
// EXTERNAL MODULE: ./node_modules/fetch-blob/index.js
var fetch_blob = __nccwpck_require__(3184);
;// CONCATENATED MODULE: ./node_modules/fetch-blob/from.js







const { stat } = external_node_fs_namespaceObject.promises

/**
 * @param {string} path filepath on the disk
 * @param {string} [type] mimetype to use
 */
const blobFromSync = (path, type) => fromBlob((0,external_node_fs_namespaceObject.statSync)(path), path, type)

/**
 * @param {string} path filepath on the disk
 * @param {string} [type] mimetype to use
 * @returns {Promise<Blob>}
 */
const blobFrom = (path, type) => stat(path).then(stat => fromBlob(stat, path, type))

/**
 * @param {string} path filepath on the disk
 * @param {string} [type] mimetype to use
 * @returns {Promise<File>}
 */
const fileFrom = (path, type) => stat(path).then(stat => fromFile(stat, path, type))

/**
 * @param {string} path filepath on the disk
 * @param {string} [type] mimetype to use
 */
const fileFromSync = (path, type) => fromFile((0,external_node_fs_namespaceObject.statSync)(path), path, type)

// @ts-ignore
const fromBlob = (stat, path, type = '') => new fetch_blob/* default */.Z([new BlobDataItem({
  path,
  size: stat.size,
  lastModified: stat.mtimeMs,
  start: 0
})], { type })

// @ts-ignore
const fromFile = (stat, path, type = '') => new file/* default */.Z([new BlobDataItem({
  path,
  size: stat.size,
  lastModified: stat.mtimeMs,
  start: 0
})], (0,external_node_path_namespaceObject.basename)(path), { type, lastModified: stat.mtimeMs })

/**
 * This is a blob backed up by a file on the disk
 * with minium requirement. Its wrapped around a Blob as a blobPart
 * so you have no direct access to this.
 *
 * @private
 */
class BlobDataItem {
  #path
  #start

  constructor (options) {
    this.#path = options.path
    this.#start = options.start
    this.size = options.size
    this.lastModified = options.lastModified
  }

  /**
   * Slicing arguments is first validated and formatted
   * to not be out of range by Blob.prototype.slice
   */
  slice (start, end) {
    return new BlobDataItem({
      path: this.#path,
      lastModified: this.lastModified,
      size: end - start,
      start: this.#start + start
    })
  }

  async * stream () {
    const { mtimeMs } = await stat(this.#path)
    if (mtimeMs > this.lastModified) {
      throw new node_domexception('The requested file could not be read, typically due to permission problems that have occurred after a reference to a file was acquired.', 'NotReadableError')
    }
    yield * (0,external_node_fs_namespaceObject.createReadStream)(this.#path, {
      start: this.#start,
      end: this.#start + this.size - 1
    })
  }

  get [Symbol.toStringTag] () {
    return 'Blob'
  }
}

/* harmony default export */ const from = ((/* unused pure expression or super */ null && (blobFromSync)));



/***/ }),

/***/ 3184:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __nccwpck_require__) => {

"use strict";
/* harmony export */ __nccwpck_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* unused harmony export Blob */
/* harmony import */ var _streams_cjs__WEBPACK_IMPORTED_MODULE_0__ = __nccwpck_require__(5118);
/*! fetch-blob. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> */

// TODO (jimmywarting): in the feature use conditional loading with top level await (requires 14.x)
// Node has recently added whatwg stream into core



// 64 KiB (same size chrome slice theirs blob into Uint8array's)
const POOL_SIZE = 65536

/** @param {(Blob | Uint8Array)[]} parts */
async function * toIterator (parts, clone = true) {
  for (const part of parts) {
    if ('stream' in part) {
      yield * (/** @type {AsyncIterableIterator<Uint8Array>} */ (part.stream()))
    } else if (ArrayBuffer.isView(part)) {
      if (clone) {
        let position = part.byteOffset
        const end = part.byteOffset + part.byteLength
        while (position !== end) {
          const size = Math.min(end - position, POOL_SIZE)
          const chunk = part.buffer.slice(position, position + size)
          position += chunk.byteLength
          yield new Uint8Array(chunk)
        }
      } else {
        yield part
      }
    /* c8 ignore next 10 */
    } else {
      // For blobs that have arrayBuffer but no stream method (nodes buffer.Blob)
      let position = 0, b = (/** @type {Blob} */ (part))
      while (position !== b.size) {
        const chunk = b.slice(position, Math.min(b.size, position + POOL_SIZE))
        const buffer = await chunk.arrayBuffer()
        position += buffer.byteLength
        yield new Uint8Array(buffer)
      }
    }
  }
}

const _Blob = class Blob {
  /** @type {Array.<(Blob|Uint8Array)>} */
  #parts = []
  #type = ''
  #size = 0
  #endings = 'transparent'

  /**
   * The Blob() constructor returns a new Blob object. The content
   * of the blob consists of the concatenation of the values given
   * in the parameter array.
   *
   * @param {*} blobParts
   * @param {{ type?: string, endings?: string }} [options]
   */
  constructor (blobParts = [], options = {}) {
    if (typeof blobParts !== 'object' || blobParts === null) {
      throw new TypeError('Failed to construct \'Blob\': The provided value cannot be converted to a sequence.')
    }

    if (typeof blobParts[Symbol.iterator] !== 'function') {
      throw new TypeError('Failed to construct \'Blob\': The object must have a callable @@iterator property.')
    }

    if (typeof options !== 'object' && typeof options !== 'function') {
      throw new TypeError('Failed to construct \'Blob\': parameter 2 cannot convert to dictionary.')
    }

    if (options === null) options = {}

    const encoder = new TextEncoder()
    for (const element of blobParts) {
      let part
      if (ArrayBuffer.isView(element)) {
        part = new Uint8Array(element.buffer.slice(element.byteOffset, element.byteOffset + element.byteLength))
      } else if (element instanceof ArrayBuffer) {
        part = new Uint8Array(element.slice(0))
      } else if (element instanceof Blob) {
        part = element
      } else {
        part = encoder.encode(`${element}`)
      }

      this.#size += ArrayBuffer.isView(part) ? part.byteLength : part.size
      this.#parts.push(part)
    }

    this.#endings = `${options.endings === undefined ? 'transparent' : options.endings}`
    const type = options.type === undefined ? '' : String(options.type)
    this.#type = /^[\x20-\x7E]*$/.test(type) ? type : ''
  }

  /**
   * The Blob interface's size property returns the
   * size of the Blob in bytes.
   */
  get size () {
    return this.#size
  }

  /**
   * The type property of a Blob object returns the MIME type of the file.
   */
  get type () {
    return this.#type
  }

  /**
   * The text() method in the Blob interface returns a Promise
   * that resolves with a string containing the contents of
   * the blob, interpreted as UTF-8.
   *
   * @return {Promise<string>}
   */
  async text () {
    // More optimized than using this.arrayBuffer()
    // that requires twice as much ram
    const decoder = new TextDecoder()
    let str = ''
    for await (const part of toIterator(this.#parts, false)) {
      str += decoder.decode(part, { stream: true })
    }
    // Remaining
    str += decoder.decode()
    return str
  }

  /**
   * The arrayBuffer() method in the Blob interface returns a
   * Promise that resolves with the contents of the blob as
   * binary data contained in an ArrayBuffer.
   *
   * @return {Promise<ArrayBuffer>}
   */
  async arrayBuffer () {
    // Easier way... Just a unnecessary overhead
    // const view = new Uint8Array(this.size);
    // await this.stream().getReader({mode: 'byob'}).read(view);
    // return view.buffer;

    const data = new Uint8Array(this.size)
    let offset = 0
    for await (const chunk of toIterator(this.#parts, false)) {
      data.set(chunk, offset)
      offset += chunk.length
    }

    return data.buffer
  }

  stream () {
    const it = toIterator(this.#parts, true)

    return new globalThis.ReadableStream({
      // @ts-ignore
      type: 'bytes',
      async pull (ctrl) {
        const chunk = await it.next()
        chunk.done ? ctrl.close() : ctrl.enqueue(chunk.value)
      },

      async cancel () {
        await it.return()
      }
    })
  }

  /**
   * The Blob interface's slice() method creates and returns a
   * new Blob object which contains data from a subset of the
   * blob on which it's called.
   *
   * @param {number} [start]
   * @param {number} [end]
   * @param {string} [type]
   */
  slice (start = 0, end = this.size, type = '') {
    const { size } = this

    let relativeStart = start < 0 ? Math.max(size + start, 0) : Math.min(start, size)
    let relativeEnd = end < 0 ? Math.max(size + end, 0) : Math.min(end, size)

    const span = Math.max(relativeEnd - relativeStart, 0)
    const parts = this.#parts
    const blobParts = []
    let added = 0

    for (const part of parts) {
      // don't add the overflow to new blobParts
      if (added >= span) {
        break
      }

      const size = ArrayBuffer.isView(part) ? part.byteLength : part.size
      if (relativeStart && size <= relativeStart) {
        // Skip the beginning and change the relative
        // start & end position as we skip the unwanted parts
        relativeStart -= size
        relativeEnd -= size
      } else {
        let chunk
        if (ArrayBuffer.isView(part)) {
          chunk = part.subarray(relativeStart, Math.min(size, relativeEnd))
          added += chunk.byteLength
        } else {
          chunk = part.slice(relativeStart, Math.min(size, relativeEnd))
          added += chunk.size
        }
        relativeEnd -= size
        blobParts.push(chunk)
        relativeStart = 0 // All next sequential parts should start at 0
      }
    }

    const blob = new Blob([], { type: String(type).toLowerCase() })
    blob.#size = span
    blob.#parts = blobParts

    return blob
  }

  get [Symbol.toStringTag] () {
    return 'Blob'
  }

  static [Symbol.hasInstance] (object) {
    return (
      object &&
      typeof object === 'object' &&
      typeof object.constructor === 'function' &&
      (
        typeof object.stream === 'function' ||
        typeof object.arrayBuffer === 'function'
      ) &&
      /^(Blob|File)$/.test(object[Symbol.toStringTag])
    )
  }
}

Object.defineProperties(_Blob.prototype, {
  size: { enumerable: true },
  type: { enumerable: true },
  slice: { enumerable: true }
})

/** @type {typeof globalThis.Blob} */
const Blob = _Blob
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Blob);


/***/ }),

/***/ 8670:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __nccwpck_require__) => {

"use strict";
/* harmony export */ __nccwpck_require__.d(__webpack_exports__, {
/* harmony export */   "Ct": () => (/* binding */ FormData),
/* harmony export */   "au": () => (/* binding */ formDataToBlob)
/* harmony export */ });
/* unused harmony export File */
/* harmony import */ var fetch_blob__WEBPACK_IMPORTED_MODULE_0__ = __nccwpck_require__(3184);
/* harmony import */ var fetch_blob_file_js__WEBPACK_IMPORTED_MODULE_1__ = __nccwpck_require__(5909);
/*! formdata-polyfill. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> */




var {toStringTag:t,iterator:i,hasInstance:h}=Symbol,
r=Math.random,
m='append,set,get,getAll,delete,keys,values,entries,forEach,constructor'.split(','),
f=(a,b,c)=>(a+='',/^(Blob|File)$/.test(b && b[t])?[(c=c!==void 0?c+'':b[t]=='File'?b.name:'blob',a),b.name!==c||b[t]=='blob'?new fetch_blob_file_js__WEBPACK_IMPORTED_MODULE_1__/* ["default"] */ .Z([b],c,b):b]:[a,b+'']),
e=(c,f)=>(f?c:c.replace(/\r?\n|\r/g,'\r\n')).replace(/\n/g,'%0A').replace(/\r/g,'%0D').replace(/"/g,'%22'),
x=(n, a, e)=>{if(a.length<e){throw new TypeError(`Failed to execute '${n}' on 'FormData': ${e} arguments required, but only ${a.length} present.`)}}

const File = (/* unused pure expression or super */ null && (F))

/** @type {typeof globalThis.FormData} */
const FormData = class FormData {
#d=[];
constructor(...a){if(a.length)throw new TypeError(`Failed to construct 'FormData': parameter 1 is not of type 'HTMLFormElement'.`)}
get [t]() {return 'FormData'}
[i](){return this.entries()}
static [h](o) {return o&&typeof o==='object'&&o[t]==='FormData'&&!m.some(m=>typeof o[m]!='function')}
append(...a){x('append',arguments,2);this.#d.push(f(...a))}
delete(a){x('delete',arguments,1);a+='';this.#d=this.#d.filter(([b])=>b!==a)}
get(a){x('get',arguments,1);a+='';for(var b=this.#d,l=b.length,c=0;c<l;c++)if(b[c][0]===a)return b[c][1];return null}
getAll(a,b){x('getAll',arguments,1);b=[];a+='';this.#d.forEach(c=>c[0]===a&&b.push(c[1]));return b}
has(a){x('has',arguments,1);a+='';return this.#d.some(b=>b[0]===a)}
forEach(a,b){x('forEach',arguments,1);for(var [c,d]of this)a.call(b,d,c,this)}
set(...a){x('set',arguments,2);var b=[],c=!0;a=f(...a);this.#d.forEach(d=>{d[0]===a[0]?c&&(c=!b.push(a)):b.push(d)});c&&b.push(a);this.#d=b}
*entries(){yield*this.#d}
*keys(){for(var[a]of this)yield a}
*values(){for(var[,a]of this)yield a}}

/** @param {FormData} F */
function formDataToBlob (F,B=fetch_blob__WEBPACK_IMPORTED_MODULE_0__/* ["default"] */ .Z){
var b=`${r()}${r()}`.replace(/\./g, '').slice(-28).padStart(32, '-'),c=[],p=`--${b}\r\nContent-Disposition: form-data; name="`
F.forEach((v,n)=>typeof v=='string'
?c.push(p+e(n)+`"\r\n\r\n${v.replace(/\r(?!\n)|(?<!\r)\n/g, '\r\n')}\r\n`)
:c.push(p+e(n)+`"; filename="${e(v.name, 1)}"\r\nContent-Type: ${v.type||"application/octet-stream"}\r\n\r\n`, v, '\r\n'))
c.push(`--${b}--`)
return new B(c,{type:"multipart/form-data; boundary="+b})}


/***/ }),

/***/ 5085:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __nccwpck_require__) => {

"use strict";
// ESM COMPAT FLAG
__nccwpck_require__.r(__webpack_exports__);

// EXPORTS
__nccwpck_require__.d(__webpack_exports__, {
  "AbortError": () => (/* reexport */ AbortError),
  "Blob": () => (/* reexport */ from/* Blob */.t6),
  "FetchError": () => (/* reexport */ FetchError),
  "File": () => (/* reexport */ from/* File */.$B),
  "FormData": () => (/* reexport */ esm_min/* FormData */.Ct),
  "Headers": () => (/* reexport */ Headers),
  "Request": () => (/* reexport */ Request),
  "Response": () => (/* reexport */ Response),
  "blobFrom": () => (/* reexport */ from/* blobFrom */.xB),
  "blobFromSync": () => (/* reexport */ from/* blobFromSync */.SX),
  "default": () => (/* binding */ fetch),
  "fileFrom": () => (/* reexport */ from/* fileFrom */.e2),
  "fileFromSync": () => (/* reexport */ from/* fileFromSync */.RA),
  "isRedirect": () => (/* reexport */ isRedirect)
});

;// CONCATENATED MODULE: external "node:http"
const external_node_http_namespaceObject = require("node:http");
;// CONCATENATED MODULE: external "node:https"
const external_node_https_namespaceObject = require("node:https");
;// CONCATENATED MODULE: external "node:zlib"
const external_node_zlib_namespaceObject = require("node:zlib");
;// CONCATENATED MODULE: external "node:stream"
const external_node_stream_namespaceObject = require("node:stream");
;// CONCATENATED MODULE: external "node:buffer"
const external_node_buffer_namespaceObject = require("node:buffer");
;// CONCATENATED MODULE: ./node_modules/data-uri-to-buffer/dist/index.js
/**
 * Returns a `Buffer` instance from the given data URI `uri`.
 *
 * @param {String} uri Data URI to turn into a Buffer instance
 * @returns {Buffer} Buffer instance from Data URI
 * @api public
 */
function dataUriToBuffer(uri) {
    if (!/^data:/i.test(uri)) {
        throw new TypeError('`uri` does not appear to be a Data URI (must begin with "data:")');
    }
    // strip newlines
    uri = uri.replace(/\r?\n/g, '');
    // split the URI up into the "metadata" and the "data" portions
    const firstComma = uri.indexOf(',');
    if (firstComma === -1 || firstComma <= 4) {
        throw new TypeError('malformed data: URI');
    }
    // remove the "data:" scheme and parse the metadata
    const meta = uri.substring(5, firstComma).split(';');
    let charset = '';
    let base64 = false;
    const type = meta[0] || 'text/plain';
    let typeFull = type;
    for (let i = 1; i < meta.length; i++) {
        if (meta[i] === 'base64') {
            base64 = true;
        }
        else if (meta[i]) {
            typeFull += `;${meta[i]}`;
            if (meta[i].indexOf('charset=') === 0) {
                charset = meta[i].substring(8);
            }
        }
    }
    // defaults to US-ASCII only if type is not provided
    if (!meta[0] && !charset.length) {
        typeFull += ';charset=US-ASCII';
        charset = 'US-ASCII';
    }
    // get the encoded data portion and decode URI-encoded chars
    const encoding = base64 ? 'base64' : 'ascii';
    const data = unescape(uri.substring(firstComma + 1));
    const buffer = Buffer.from(data, encoding);
    // set `.type` and `.typeFull` properties to MIME type
    buffer.type = type;
    buffer.typeFull = typeFull;
    // set the `.charset` property
    buffer.charset = charset;
    return buffer;
}
/* harmony default export */ const dist = (dataUriToBuffer);
//# sourceMappingURL=index.js.map
;// CONCATENATED MODULE: external "node:util"
const external_node_util_namespaceObject = require("node:util");
// EXTERNAL MODULE: ./node_modules/fetch-blob/index.js
var fetch_blob = __nccwpck_require__(3184);
// EXTERNAL MODULE: ./node_modules/formdata-polyfill/esm.min.js
var esm_min = __nccwpck_require__(8670);
;// CONCATENATED MODULE: ./node_modules/node-fetch/src/errors/base.js
class FetchBaseError extends Error {
	constructor(message, type) {
		super(message);
		// Hide custom error implementation details from end-users
		Error.captureStackTrace(this, this.constructor);

		this.type = type;
	}

	get name() {
		return this.constructor.name;
	}

	get [Symbol.toStringTag]() {
		return this.constructor.name;
	}
}

;// CONCATENATED MODULE: ./node_modules/node-fetch/src/errors/fetch-error.js



/**
 * @typedef {{ address?: string, code: string, dest?: string, errno: number, info?: object, message: string, path?: string, port?: number, syscall: string}} SystemError
*/

/**
 * FetchError interface for operational errors
 */
class FetchError extends FetchBaseError {
	/**
	 * @param  {string} message -      Error message for human
	 * @param  {string} [type] -        Error type for machine
	 * @param  {SystemError} [systemError] - For Node.js system error
	 */
	constructor(message, type, systemError) {
		super(message, type);
		// When err.type is `system`, err.erroredSysCall contains system error and err.code contains system error code
		if (systemError) {
			// eslint-disable-next-line no-multi-assign
			this.code = this.errno = systemError.code;
			this.erroredSysCall = systemError.syscall;
		}
	}
}

;// CONCATENATED MODULE: ./node_modules/node-fetch/src/utils/is.js
/**
 * Is.js
 *
 * Object type checks.
 */

const NAME = Symbol.toStringTag;

/**
 * Check if `obj` is a URLSearchParams object
 * ref: https://github.com/node-fetch/node-fetch/issues/296#issuecomment-307598143
 * @param {*} object - Object to check for
 * @return {boolean}
 */
const isURLSearchParameters = object => {
	return (
		typeof object === 'object' &&
		typeof object.append === 'function' &&
		typeof object.delete === 'function' &&
		typeof object.get === 'function' &&
		typeof object.getAll === 'function' &&
		typeof object.has === 'function' &&
		typeof object.set === 'function' &&
		typeof object.sort === 'function' &&
		object[NAME] === 'URLSearchParams'
	);
};

/**
 * Check if `object` is a W3C `Blob` object (which `File` inherits from)
 * @param {*} object - Object to check for
 * @return {boolean}
 */
const isBlob = object => {
	return (
		object &&
		typeof object === 'object' &&
		typeof object.arrayBuffer === 'function' &&
		typeof object.type === 'string' &&
		typeof object.stream === 'function' &&
		typeof object.constructor === 'function' &&
		/^(Blob|File)$/.test(object[NAME])
	);
};

/**
 * Check if `obj` is an instance of AbortSignal.
 * @param {*} object - Object to check for
 * @return {boolean}
 */
const isAbortSignal = object => {
	return (
		typeof object === 'object' && (
			object[NAME] === 'AbortSignal' ||
			object[NAME] === 'EventTarget'
		)
	);
};

/**
 * isDomainOrSubdomain reports whether sub is a subdomain (or exact match) of
 * the parent domain.
 *
 * Both domains must already be in canonical form.
 * @param {string|URL} original
 * @param {string|URL} destination
 */
const isDomainOrSubdomain = (destination, original) => {
	const orig = new URL(original).hostname;
	const dest = new URL(destination).hostname;

	return orig === dest || orig.endsWith(`.${dest}`);
};

/**
 * isSameProtocol reports whether the two provided URLs use the same protocol.
 *
 * Both domains must already be in canonical form.
 * @param {string|URL} original
 * @param {string|URL} destination
 */
const isSameProtocol = (destination, original) => {
	const orig = new URL(original).protocol;
	const dest = new URL(destination).protocol;

	return orig === dest;
};

;// CONCATENATED MODULE: ./node_modules/node-fetch/src/body.js

/**
 * Body.js
 *
 * Body interface provides common methods for Request and Response
 */












const pipeline = (0,external_node_util_namespaceObject.promisify)(external_node_stream_namespaceObject.pipeline);
const INTERNALS = Symbol('Body internals');

/**
 * Body mixin
 *
 * Ref: https://fetch.spec.whatwg.org/#body
 *
 * @param   Stream  body  Readable stream
 * @param   Object  opts  Response options
 * @return  Void
 */
class Body {
	constructor(body, {
		size = 0
	} = {}) {
		let boundary = null;

		if (body === null) {
			// Body is undefined or null
			body = null;
		} else if (isURLSearchParameters(body)) {
			// Body is a URLSearchParams
			body = external_node_buffer_namespaceObject.Buffer.from(body.toString());
		} else if (isBlob(body)) {
			// Body is blob
		} else if (external_node_buffer_namespaceObject.Buffer.isBuffer(body)) {
			// Body is Buffer
		} else if (external_node_util_namespaceObject.types.isAnyArrayBuffer(body)) {
			// Body is ArrayBuffer
			body = external_node_buffer_namespaceObject.Buffer.from(body);
		} else if (ArrayBuffer.isView(body)) {
			// Body is ArrayBufferView
			body = external_node_buffer_namespaceObject.Buffer.from(body.buffer, body.byteOffset, body.byteLength);
		} else if (body instanceof external_node_stream_namespaceObject) {
			// Body is stream
		} else if (body instanceof esm_min/* FormData */.Ct) {
			// Body is FormData
			body = (0,esm_min/* formDataToBlob */.au)(body);
			boundary = body.type.split('=')[1];
		} else {
			// None of the above
			// coerce to string then buffer
			body = external_node_buffer_namespaceObject.Buffer.from(String(body));
		}

		let stream = body;

		if (external_node_buffer_namespaceObject.Buffer.isBuffer(body)) {
			stream = external_node_stream_namespaceObject.Readable.from(body);
		} else if (isBlob(body)) {
			stream = external_node_stream_namespaceObject.Readable.from(body.stream());
		}

		this[INTERNALS] = {
			body,
			stream,
			boundary,
			disturbed: false,
			error: null
		};
		this.size = size;

		if (body instanceof external_node_stream_namespaceObject) {
			body.on('error', error_ => {
				const error = error_ instanceof FetchBaseError ?
					error_ :
					new FetchError(`Invalid response body while trying to fetch ${this.url}: ${error_.message}`, 'system', error_);
				this[INTERNALS].error = error;
			});
		}
	}

	get body() {
		return this[INTERNALS].stream;
	}

	get bodyUsed() {
		return this[INTERNALS].disturbed;
	}

	/**
	 * Decode response as ArrayBuffer
	 *
	 * @return  Promise
	 */
	async arrayBuffer() {
		const {buffer, byteOffset, byteLength} = await consumeBody(this);
		return buffer.slice(byteOffset, byteOffset + byteLength);
	}

	async formData() {
		const ct = this.headers.get('content-type');

		if (ct.startsWith('application/x-www-form-urlencoded')) {
			const formData = new esm_min/* FormData */.Ct();
			const parameters = new URLSearchParams(await this.text());

			for (const [name, value] of parameters) {
				formData.append(name, value);
			}

			return formData;
		}

		const {toFormData} = await __nccwpck_require__.e(/* import() */ 414).then(__nccwpck_require__.bind(__nccwpck_require__, 3414));
		return toFormData(this.body, ct);
	}

	/**
	 * Return raw response as Blob
	 *
	 * @return Promise
	 */
	async blob() {
		const ct = (this.headers && this.headers.get('content-type')) || (this[INTERNALS].body && this[INTERNALS].body.type) || '';
		const buf = await this.arrayBuffer();

		return new fetch_blob/* default */.Z([buf], {
			type: ct
		});
	}

	/**
	 * Decode response as json
	 *
	 * @return  Promise
	 */
	async json() {
		const text = await this.text();
		return JSON.parse(text);
	}

	/**
	 * Decode response as text
	 *
	 * @return  Promise
	 */
	async text() {
		const buffer = await consumeBody(this);
		return new TextDecoder().decode(buffer);
	}

	/**
	 * Decode response as buffer (non-spec api)
	 *
	 * @return  Promise
	 */
	buffer() {
		return consumeBody(this);
	}
}

Body.prototype.buffer = (0,external_node_util_namespaceObject.deprecate)(Body.prototype.buffer, 'Please use \'response.arrayBuffer()\' instead of \'response.buffer()\'', 'node-fetch#buffer');

// In browsers, all properties are enumerable.
Object.defineProperties(Body.prototype, {
	body: {enumerable: true},
	bodyUsed: {enumerable: true},
	arrayBuffer: {enumerable: true},
	blob: {enumerable: true},
	json: {enumerable: true},
	text: {enumerable: true},
	data: {get: (0,external_node_util_namespaceObject.deprecate)(() => {},
		'data doesn\'t exist, use json(), text(), arrayBuffer(), or body instead',
		'https://github.com/node-fetch/node-fetch/issues/1000 (response)')}
});

/**
 * Consume and convert an entire Body to a Buffer.
 *
 * Ref: https://fetch.spec.whatwg.org/#concept-body-consume-body
 *
 * @return Promise
 */
async function consumeBody(data) {
	if (data[INTERNALS].disturbed) {
		throw new TypeError(`body used already for: ${data.url}`);
	}

	data[INTERNALS].disturbed = true;

	if (data[INTERNALS].error) {
		throw data[INTERNALS].error;
	}

	const {body} = data;

	// Body is null
	if (body === null) {
		return external_node_buffer_namespaceObject.Buffer.alloc(0);
	}

	/* c8 ignore next 3 */
	if (!(body instanceof external_node_stream_namespaceObject)) {
		return external_node_buffer_namespaceObject.Buffer.alloc(0);
	}

	// Body is stream
	// get ready to actually consume the body
	const accum = [];
	let accumBytes = 0;

	try {
		for await (const chunk of body) {
			if (data.size > 0 && accumBytes + chunk.length > data.size) {
				const error = new FetchError(`content size at ${data.url} over limit: ${data.size}`, 'max-size');
				body.destroy(error);
				throw error;
			}

			accumBytes += chunk.length;
			accum.push(chunk);
		}
	} catch (error) {
		const error_ = error instanceof FetchBaseError ? error : new FetchError(`Invalid response body while trying to fetch ${data.url}: ${error.message}`, 'system', error);
		throw error_;
	}

	if (body.readableEnded === true || body._readableState.ended === true) {
		try {
			if (accum.every(c => typeof c === 'string')) {
				return external_node_buffer_namespaceObject.Buffer.from(accum.join(''));
			}

			return external_node_buffer_namespaceObject.Buffer.concat(accum, accumBytes);
		} catch (error) {
			throw new FetchError(`Could not create Buffer from response body for ${data.url}: ${error.message}`, 'system', error);
		}
	} else {
		throw new FetchError(`Premature close of server response while trying to fetch ${data.url}`);
	}
}

/**
 * Clone body given Res/Req instance
 *
 * @param   Mixed   instance       Response or Request instance
 * @param   String  highWaterMark  highWaterMark for both PassThrough body streams
 * @return  Mixed
 */
const clone = (instance, highWaterMark) => {
	let p1;
	let p2;
	let {body} = instance[INTERNALS];

	// Don't allow cloning a used body
	if (instance.bodyUsed) {
		throw new Error('cannot clone body after it is used');
	}

	// Check that body is a stream and not form-data object
	// note: we can't clone the form-data object without having it as a dependency
	if ((body instanceof external_node_stream_namespaceObject) && (typeof body.getBoundary !== 'function')) {
		// Tee instance body
		p1 = new external_node_stream_namespaceObject.PassThrough({highWaterMark});
		p2 = new external_node_stream_namespaceObject.PassThrough({highWaterMark});
		body.pipe(p1);
		body.pipe(p2);
		// Set instance body to teed body and return the other teed body
		instance[INTERNALS].stream = p1;
		body = p2;
	}

	return body;
};

const getNonSpecFormDataBoundary = (0,external_node_util_namespaceObject.deprecate)(
	body => body.getBoundary(),
	'form-data doesn\'t follow the spec and requires special treatment. Use alternative package',
	'https://github.com/node-fetch/node-fetch/issues/1167'
);

/**
 * Performs the operation "extract a `Content-Type` value from |object|" as
 * specified in the specification:
 * https://fetch.spec.whatwg.org/#concept-bodyinit-extract
 *
 * This function assumes that instance.body is present.
 *
 * @param {any} body Any options.body input
 * @returns {string | null}
 */
const extractContentType = (body, request) => {
	// Body is null or undefined
	if (body === null) {
		return null;
	}

	// Body is string
	if (typeof body === 'string') {
		return 'text/plain;charset=UTF-8';
	}

	// Body is a URLSearchParams
	if (isURLSearchParameters(body)) {
		return 'application/x-www-form-urlencoded;charset=UTF-8';
	}

	// Body is blob
	if (isBlob(body)) {
		return body.type || null;
	}

	// Body is a Buffer (Buffer, ArrayBuffer or ArrayBufferView)
	if (external_node_buffer_namespaceObject.Buffer.isBuffer(body) || external_node_util_namespaceObject.types.isAnyArrayBuffer(body) || ArrayBuffer.isView(body)) {
		return null;
	}

	if (body instanceof esm_min/* FormData */.Ct) {
		return `multipart/form-data; boundary=${request[INTERNALS].boundary}`;
	}

	// Detect form data input from form-data module
	if (body && typeof body.getBoundary === 'function') {
		return `multipart/form-data;boundary=${getNonSpecFormDataBoundary(body)}`;
	}

	// Body is stream - can't really do much about this
	if (body instanceof external_node_stream_namespaceObject) {
		return null;
	}

	// Body constructor defaults other things to string
	return 'text/plain;charset=UTF-8';
};

/**
 * The Fetch Standard treats this as if "total bytes" is a property on the body.
 * For us, we have to explicitly get it with a function.
 *
 * ref: https://fetch.spec.whatwg.org/#concept-body-total-bytes
 *
 * @param {any} obj.body Body object from the Body instance.
 * @returns {number | null}
 */
const getTotalBytes = request => {
	const {body} = request[INTERNALS];

	// Body is null or undefined
	if (body === null) {
		return 0;
	}

	// Body is Blob
	if (isBlob(body)) {
		return body.size;
	}

	// Body is Buffer
	if (external_node_buffer_namespaceObject.Buffer.isBuffer(body)) {
		return body.length;
	}

	// Detect form data input from form-data module
	if (body && typeof body.getLengthSync === 'function') {
		return body.hasKnownLength && body.hasKnownLength() ? body.getLengthSync() : null;
	}

	// Body is stream
	return null;
};

/**
 * Write a Body to a Node.js WritableStream (e.g. http.Request) object.
 *
 * @param {Stream.Writable} dest The stream to write to.
 * @param obj.body Body object from the Body instance.
 * @returns {Promise<void>}
 */
const writeToStream = async (dest, {body}) => {
	if (body === null) {
		// Body is null
		dest.end();
	} else {
		// Body is stream
		await pipeline(body, dest);
	}
};

;// CONCATENATED MODULE: ./node_modules/node-fetch/src/headers.js
/**
 * Headers.js
 *
 * Headers class offers convenient helpers
 */




/* c8 ignore next 9 */
const validateHeaderName = typeof external_node_http_namespaceObject.validateHeaderName === 'function' ?
	external_node_http_namespaceObject.validateHeaderName :
	name => {
		if (!/^[\^`\-\w!#$%&'*+.|~]+$/.test(name)) {
			const error = new TypeError(`Header name must be a valid HTTP token [${name}]`);
			Object.defineProperty(error, 'code', {value: 'ERR_INVALID_HTTP_TOKEN'});
			throw error;
		}
	};

/* c8 ignore next 9 */
const validateHeaderValue = typeof external_node_http_namespaceObject.validateHeaderValue === 'function' ?
	external_node_http_namespaceObject.validateHeaderValue :
	(name, value) => {
		if (/[^\t\u0020-\u007E\u0080-\u00FF]/.test(value)) {
			const error = new TypeError(`Invalid character in header content ["${name}"]`);
			Object.defineProperty(error, 'code', {value: 'ERR_INVALID_CHAR'});
			throw error;
		}
	};

/**
 * @typedef {Headers | Record<string, string> | Iterable<readonly [string, string]> | Iterable<Iterable<string>>} HeadersInit
 */

/**
 * This Fetch API interface allows you to perform various actions on HTTP request and response headers.
 * These actions include retrieving, setting, adding to, and removing.
 * A Headers object has an associated header list, which is initially empty and consists of zero or more name and value pairs.
 * You can add to this using methods like append() (see Examples.)
 * In all methods of this interface, header names are matched by case-insensitive byte sequence.
 *
 */
class Headers extends URLSearchParams {
	/**
	 * Headers class
	 *
	 * @constructor
	 * @param {HeadersInit} [init] - Response headers
	 */
	constructor(init) {
		// Validate and normalize init object in [name, value(s)][]
		/** @type {string[][]} */
		let result = [];
		if (init instanceof Headers) {
			const raw = init.raw();
			for (const [name, values] of Object.entries(raw)) {
				result.push(...values.map(value => [name, value]));
			}
		} else if (init == null) { // eslint-disable-line no-eq-null, eqeqeq
			// No op
		} else if (typeof init === 'object' && !external_node_util_namespaceObject.types.isBoxedPrimitive(init)) {
			const method = init[Symbol.iterator];
			// eslint-disable-next-line no-eq-null, eqeqeq
			if (method == null) {
				// Record<ByteString, ByteString>
				result.push(...Object.entries(init));
			} else {
				if (typeof method !== 'function') {
					throw new TypeError('Header pairs must be iterable');
				}

				// Sequence<sequence<ByteString>>
				// Note: per spec we have to first exhaust the lists then process them
				result = [...init]
					.map(pair => {
						if (
							typeof pair !== 'object' || external_node_util_namespaceObject.types.isBoxedPrimitive(pair)
						) {
							throw new TypeError('Each header pair must be an iterable object');
						}

						return [...pair];
					}).map(pair => {
						if (pair.length !== 2) {
							throw new TypeError('Each header pair must be a name/value tuple');
						}

						return [...pair];
					});
			}
		} else {
			throw new TypeError('Failed to construct \'Headers\': The provided value is not of type \'(sequence<sequence<ByteString>> or record<ByteString, ByteString>)');
		}

		// Validate and lowercase
		result =
			result.length > 0 ?
				result.map(([name, value]) => {
					validateHeaderName(name);
					validateHeaderValue(name, String(value));
					return [String(name).toLowerCase(), String(value)];
				}) :
				undefined;

		super(result);

		// Returning a Proxy that will lowercase key names, validate parameters and sort keys
		// eslint-disable-next-line no-constructor-return
		return new Proxy(this, {
			get(target, p, receiver) {
				switch (p) {
					case 'append':
					case 'set':
						return (name, value) => {
							validateHeaderName(name);
							validateHeaderValue(name, String(value));
							return URLSearchParams.prototype[p].call(
								target,
								String(name).toLowerCase(),
								String(value)
							);
						};

					case 'delete':
					case 'has':
					case 'getAll':
						return name => {
							validateHeaderName(name);
							return URLSearchParams.prototype[p].call(
								target,
								String(name).toLowerCase()
							);
						};

					case 'keys':
						return () => {
							target.sort();
							return new Set(URLSearchParams.prototype.keys.call(target)).keys();
						};

					default:
						return Reflect.get(target, p, receiver);
				}
			}
		});
		/* c8 ignore next */
	}

	get [Symbol.toStringTag]() {
		return this.constructor.name;
	}

	toString() {
		return Object.prototype.toString.call(this);
	}

	get(name) {
		const values = this.getAll(name);
		if (values.length === 0) {
			return null;
		}

		let value = values.join(', ');
		if (/^content-encoding$/i.test(name)) {
			value = value.toLowerCase();
		}

		return value;
	}

	forEach(callback, thisArg = undefined) {
		for (const name of this.keys()) {
			Reflect.apply(callback, thisArg, [this.get(name), name, this]);
		}
	}

	* values() {
		for (const name of this.keys()) {
			yield this.get(name);
		}
	}

	/**
	 * @type {() => IterableIterator<[string, string]>}
	 */
	* entries() {
		for (const name of this.keys()) {
			yield [name, this.get(name)];
		}
	}

	[Symbol.iterator]() {
		return this.entries();
	}

	/**
	 * Node-fetch non-spec method
	 * returning all headers and their values as array
	 * @returns {Record<string, string[]>}
	 */
	raw() {
		return [...this.keys()].reduce((result, key) => {
			result[key] = this.getAll(key);
			return result;
		}, {});
	}

	/**
	 * For better console.log(headers) and also to convert Headers into Node.js Request compatible format
	 */
	[Symbol.for('nodejs.util.inspect.custom')]() {
		return [...this.keys()].reduce((result, key) => {
			const values = this.getAll(key);
			// Http.request() only supports string as Host header.
			// This hack makes specifying custom Host header possible.
			if (key === 'host') {
				result[key] = values[0];
			} else {
				result[key] = values.length > 1 ? values : values[0];
			}

			return result;
		}, {});
	}
}

/**
 * Re-shaping object for Web IDL tests
 * Only need to do it for overridden methods
 */
Object.defineProperties(
	Headers.prototype,
	['get', 'entries', 'forEach', 'values'].reduce((result, property) => {
		result[property] = {enumerable: true};
		return result;
	}, {})
);

/**
 * Create a Headers object from an http.IncomingMessage.rawHeaders, ignoring those that do
 * not conform to HTTP grammar productions.
 * @param {import('http').IncomingMessage['rawHeaders']} headers
 */
function fromRawHeaders(headers = []) {
	return new Headers(
		headers
			// Split into pairs
			.reduce((result, value, index, array) => {
				if (index % 2 === 0) {
					result.push(array.slice(index, index + 2));
				}

				return result;
			}, [])
			.filter(([name, value]) => {
				try {
					validateHeaderName(name);
					validateHeaderValue(name, String(value));
					return true;
				} catch {
					return false;
				}
			})

	);
}

;// CONCATENATED MODULE: ./node_modules/node-fetch/src/utils/is-redirect.js
const redirectStatus = new Set([301, 302, 303, 307, 308]);

/**
 * Redirect code matching
 *
 * @param {number} code - Status code
 * @return {boolean}
 */
const isRedirect = code => {
	return redirectStatus.has(code);
};

;// CONCATENATED MODULE: ./node_modules/node-fetch/src/response.js
/**
 * Response.js
 *
 * Response class provides content decoding
 */





const response_INTERNALS = Symbol('Response internals');

/**
 * Response class
 *
 * Ref: https://fetch.spec.whatwg.org/#response-class
 *
 * @param   Stream  body  Readable stream
 * @param   Object  opts  Response options
 * @return  Void
 */
class Response extends Body {
	constructor(body = null, options = {}) {
		super(body, options);

		// eslint-disable-next-line no-eq-null, eqeqeq, no-negated-condition
		const status = options.status != null ? options.status : 200;

		const headers = new Headers(options.headers);

		if (body !== null && !headers.has('Content-Type')) {
			const contentType = extractContentType(body, this);
			if (contentType) {
				headers.append('Content-Type', contentType);
			}
		}

		this[response_INTERNALS] = {
			type: 'default',
			url: options.url,
			status,
			statusText: options.statusText || '',
			headers,
			counter: options.counter,
			highWaterMark: options.highWaterMark
		};
	}

	get type() {
		return this[response_INTERNALS].type;
	}

	get url() {
		return this[response_INTERNALS].url || '';
	}

	get status() {
		return this[response_INTERNALS].status;
	}

	/**
	 * Convenience property representing if the request ended normally
	 */
	get ok() {
		return this[response_INTERNALS].status >= 200 && this[response_INTERNALS].status < 300;
	}

	get redirected() {
		return this[response_INTERNALS].counter > 0;
	}

	get statusText() {
		return this[response_INTERNALS].statusText;
	}

	get headers() {
		return this[response_INTERNALS].headers;
	}

	get highWaterMark() {
		return this[response_INTERNALS].highWaterMark;
	}

	/**
	 * Clone this response
	 *
	 * @return  Response
	 */
	clone() {
		return new Response(clone(this, this.highWaterMark), {
			type: this.type,
			url: this.url,
			status: this.status,
			statusText: this.statusText,
			headers: this.headers,
			ok: this.ok,
			redirected: this.redirected,
			size: this.size,
			highWaterMark: this.highWaterMark
		});
	}

	/**
	 * @param {string} url    The URL that the new response is to originate from.
	 * @param {number} status An optional status code for the response (e.g., 302.)
	 * @returns {Response}    A Response object.
	 */
	static redirect(url, status = 302) {
		if (!isRedirect(status)) {
			throw new RangeError('Failed to execute "redirect" on "response": Invalid status code');
		}

		return new Response(null, {
			headers: {
				location: new URL(url).toString()
			},
			status
		});
	}

	static error() {
		const response = new Response(null, {status: 0, statusText: ''});
		response[response_INTERNALS].type = 'error';
		return response;
	}

	static json(data = undefined, init = {}) {
		const body = JSON.stringify(data);

		if (body === undefined) {
			throw new TypeError('data is not JSON serializable');
		}

		const headers = new Headers(init && init.headers);

		if (!headers.has('content-type')) {
			headers.set('content-type', 'application/json');
		}

		return new Response(body, {
			...init,
			headers
		});
	}

	get [Symbol.toStringTag]() {
		return 'Response';
	}
}

Object.defineProperties(Response.prototype, {
	type: {enumerable: true},
	url: {enumerable: true},
	status: {enumerable: true},
	ok: {enumerable: true},
	redirected: {enumerable: true},
	statusText: {enumerable: true},
	headers: {enumerable: true},
	clone: {enumerable: true}
});

;// CONCATENATED MODULE: external "node:url"
const external_node_url_namespaceObject = require("node:url");
;// CONCATENATED MODULE: ./node_modules/node-fetch/src/utils/get-search.js
const getSearch = parsedURL => {
	if (parsedURL.search) {
		return parsedURL.search;
	}

	const lastOffset = parsedURL.href.length - 1;
	const hash = parsedURL.hash || (parsedURL.href[lastOffset] === '#' ? '#' : '');
	return parsedURL.href[lastOffset - hash.length] === '?' ? '?' : '';
};

;// CONCATENATED MODULE: external "node:net"
const external_node_net_namespaceObject = require("node:net");
;// CONCATENATED MODULE: ./node_modules/node-fetch/src/utils/referrer.js


/**
 * @external URL
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/URL|URL}
 */

/**
 * @module utils/referrer
 * @private
 */

/**
 * @see {@link https://w3c.github.io/webappsec-referrer-policy/#strip-url|Referrer Policy §8.4. Strip url for use as a referrer}
 * @param {string} URL
 * @param {boolean} [originOnly=false]
 */
function stripURLForUseAsAReferrer(url, originOnly = false) {
	// 1. If url is null, return no referrer.
	if (url == null) { // eslint-disable-line no-eq-null, eqeqeq
		return 'no-referrer';
	}

	url = new URL(url);

	// 2. If url's scheme is a local scheme, then return no referrer.
	if (/^(about|blob|data):$/.test(url.protocol)) {
		return 'no-referrer';
	}

	// 3. Set url's username to the empty string.
	url.username = '';

	// 4. Set url's password to null.
	// Note: `null` appears to be a mistake as this actually results in the password being `"null"`.
	url.password = '';

	// 5. Set url's fragment to null.
	// Note: `null` appears to be a mistake as this actually results in the fragment being `"#null"`.
	url.hash = '';

	// 6. If the origin-only flag is true, then:
	if (originOnly) {
		// 6.1. Set url's path to null.
		// Note: `null` appears to be a mistake as this actually results in the path being `"/null"`.
		url.pathname = '';

		// 6.2. Set url's query to null.
		// Note: `null` appears to be a mistake as this actually results in the query being `"?null"`.
		url.search = '';
	}

	// 7. Return url.
	return url;
}

/**
 * @see {@link https://w3c.github.io/webappsec-referrer-policy/#enumdef-referrerpolicy|enum ReferrerPolicy}
 */
const ReferrerPolicy = new Set([
	'',
	'no-referrer',
	'no-referrer-when-downgrade',
	'same-origin',
	'origin',
	'strict-origin',
	'origin-when-cross-origin',
	'strict-origin-when-cross-origin',
	'unsafe-url'
]);

/**
 * @see {@link https://w3c.github.io/webappsec-referrer-policy/#default-referrer-policy|default referrer policy}
 */
const DEFAULT_REFERRER_POLICY = 'strict-origin-when-cross-origin';

/**
 * @see {@link https://w3c.github.io/webappsec-referrer-policy/#referrer-policies|Referrer Policy §3. Referrer Policies}
 * @param {string} referrerPolicy
 * @returns {string} referrerPolicy
 */
function validateReferrerPolicy(referrerPolicy) {
	if (!ReferrerPolicy.has(referrerPolicy)) {
		throw new TypeError(`Invalid referrerPolicy: ${referrerPolicy}`);
	}

	return referrerPolicy;
}

/**
 * @see {@link https://w3c.github.io/webappsec-secure-contexts/#is-origin-trustworthy|Referrer Policy §3.2. Is origin potentially trustworthy?}
 * @param {external:URL} url
 * @returns `true`: "Potentially Trustworthy", `false`: "Not Trustworthy"
 */
function isOriginPotentiallyTrustworthy(url) {
	// 1. If origin is an opaque origin, return "Not Trustworthy".
	// Not applicable

	// 2. Assert: origin is a tuple origin.
	// Not for implementations

	// 3. If origin's scheme is either "https" or "wss", return "Potentially Trustworthy".
	if (/^(http|ws)s:$/.test(url.protocol)) {
		return true;
	}

	// 4. If origin's host component matches one of the CIDR notations 127.0.0.0/8 or ::1/128 [RFC4632], return "Potentially Trustworthy".
	const hostIp = url.host.replace(/(^\[)|(]$)/g, '');
	const hostIPVersion = (0,external_node_net_namespaceObject.isIP)(hostIp);

	if (hostIPVersion === 4 && /^127\./.test(hostIp)) {
		return true;
	}

	if (hostIPVersion === 6 && /^(((0+:){7})|(::(0+:){0,6}))0*1$/.test(hostIp)) {
		return true;
	}

	// 5. If origin's host component is "localhost" or falls within ".localhost", and the user agent conforms to the name resolution rules in [let-localhost-be-localhost], return "Potentially Trustworthy".
	// We are returning FALSE here because we cannot ensure conformance to
	// let-localhost-be-loalhost (https://tools.ietf.org/html/draft-west-let-localhost-be-localhost)
	if (url.host === 'localhost' || url.host.endsWith('.localhost')) {
		return false;
	}

	// 6. If origin's scheme component is file, return "Potentially Trustworthy".
	if (url.protocol === 'file:') {
		return true;
	}

	// 7. If origin's scheme component is one which the user agent considers to be authenticated, return "Potentially Trustworthy".
	// Not supported

	// 8. If origin has been configured as a trustworthy origin, return "Potentially Trustworthy".
	// Not supported

	// 9. Return "Not Trustworthy".
	return false;
}

/**
 * @see {@link https://w3c.github.io/webappsec-secure-contexts/#is-url-trustworthy|Referrer Policy §3.3. Is url potentially trustworthy?}
 * @param {external:URL} url
 * @returns `true`: "Potentially Trustworthy", `false`: "Not Trustworthy"
 */
function isUrlPotentiallyTrustworthy(url) {
	// 1. If url is "about:blank" or "about:srcdoc", return "Potentially Trustworthy".
	if (/^about:(blank|srcdoc)$/.test(url)) {
		return true;
	}

	// 2. If url's scheme is "data", return "Potentially Trustworthy".
	if (url.protocol === 'data:') {
		return true;
	}

	// Note: The origin of blob: and filesystem: URLs is the origin of the context in which they were
	// created. Therefore, blobs created in a trustworthy origin will themselves be potentially
	// trustworthy.
	if (/^(blob|filesystem):$/.test(url.protocol)) {
		return true;
	}

	// 3. Return the result of executing §3.2 Is origin potentially trustworthy? on url's origin.
	return isOriginPotentiallyTrustworthy(url);
}

/**
 * Modifies the referrerURL to enforce any extra security policy considerations.
 * @see {@link https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer|Referrer Policy §8.3. Determine request's Referrer}, step 7
 * @callback module:utils/referrer~referrerURLCallback
 * @param {external:URL} referrerURL
 * @returns {external:URL} modified referrerURL
 */

/**
 * Modifies the referrerOrigin to enforce any extra security policy considerations.
 * @see {@link https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer|Referrer Policy §8.3. Determine request's Referrer}, step 7
 * @callback module:utils/referrer~referrerOriginCallback
 * @param {external:URL} referrerOrigin
 * @returns {external:URL} modified referrerOrigin
 */

/**
 * @see {@link https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer|Referrer Policy §8.3. Determine request's Referrer}
 * @param {Request} request
 * @param {object} o
 * @param {module:utils/referrer~referrerURLCallback} o.referrerURLCallback
 * @param {module:utils/referrer~referrerOriginCallback} o.referrerOriginCallback
 * @returns {external:URL} Request's referrer
 */
function determineRequestsReferrer(request, {referrerURLCallback, referrerOriginCallback} = {}) {
	// There are 2 notes in the specification about invalid pre-conditions.  We return null, here, for
	// these cases:
	// > Note: If request's referrer is "no-referrer", Fetch will not call into this algorithm.
	// > Note: If request's referrer policy is the empty string, Fetch will not call into this
	// > algorithm.
	if (request.referrer === 'no-referrer' || request.referrerPolicy === '') {
		return null;
	}

	// 1. Let policy be request's associated referrer policy.
	const policy = request.referrerPolicy;

	// 2. Let environment be request's client.
	// not applicable to node.js

	// 3. Switch on request's referrer:
	if (request.referrer === 'about:client') {
		return 'no-referrer';
	}

	// "a URL": Let referrerSource be request's referrer.
	const referrerSource = request.referrer;

	// 4. Let request's referrerURL be the result of stripping referrerSource for use as a referrer.
	let referrerURL = stripURLForUseAsAReferrer(referrerSource);

	// 5. Let referrerOrigin be the result of stripping referrerSource for use as a referrer, with the
	//    origin-only flag set to true.
	let referrerOrigin = stripURLForUseAsAReferrer(referrerSource, true);

	// 6. If the result of serializing referrerURL is a string whose length is greater than 4096, set
	//    referrerURL to referrerOrigin.
	if (referrerURL.toString().length > 4096) {
		referrerURL = referrerOrigin;
	}

	// 7. The user agent MAY alter referrerURL or referrerOrigin at this point to enforce arbitrary
	//    policy considerations in the interests of minimizing data leakage. For example, the user
	//    agent could strip the URL down to an origin, modify its host, replace it with an empty
	//    string, etc.
	if (referrerURLCallback) {
		referrerURL = referrerURLCallback(referrerURL);
	}

	if (referrerOriginCallback) {
		referrerOrigin = referrerOriginCallback(referrerOrigin);
	}

	// 8.Execute the statements corresponding to the value of policy:
	const currentURL = new URL(request.url);

	switch (policy) {
		case 'no-referrer':
			return 'no-referrer';

		case 'origin':
			return referrerOrigin;

		case 'unsafe-url':
			return referrerURL;

		case 'strict-origin':
			// 1. If referrerURL is a potentially trustworthy URL and request's current URL is not a
			//    potentially trustworthy URL, then return no referrer.
			if (isUrlPotentiallyTrustworthy(referrerURL) && !isUrlPotentiallyTrustworthy(currentURL)) {
				return 'no-referrer';
			}

			// 2. Return referrerOrigin.
			return referrerOrigin.toString();

		case 'strict-origin-when-cross-origin':
			// 1. If the origin of referrerURL and the origin of request's current URL are the same, then
			//    return referrerURL.
			if (referrerURL.origin === currentURL.origin) {
				return referrerURL;
			}

			// 2. If referrerURL is a potentially trustworthy URL and request's current URL is not a
			//    potentially trustworthy URL, then return no referrer.
			if (isUrlPotentiallyTrustworthy(referrerURL) && !isUrlPotentiallyTrustworthy(currentURL)) {
				return 'no-referrer';
			}

			// 3. Return referrerOrigin.
			return referrerOrigin;

		case 'same-origin':
			// 1. If the origin of referrerURL and the origin of request's current URL are the same, then
			//    return referrerURL.
			if (referrerURL.origin === currentURL.origin) {
				return referrerURL;
			}

			// 2. Return no referrer.
			return 'no-referrer';

		case 'origin-when-cross-origin':
			// 1. If the origin of referrerURL and the origin of request's current URL are the same, then
			//    return referrerURL.
			if (referrerURL.origin === currentURL.origin) {
				return referrerURL;
			}

			// Return referrerOrigin.
			return referrerOrigin;

		case 'no-referrer-when-downgrade':
			// 1. If referrerURL is a potentially trustworthy URL and request's current URL is not a
			//    potentially trustworthy URL, then return no referrer.
			if (isUrlPotentiallyTrustworthy(referrerURL) && !isUrlPotentiallyTrustworthy(currentURL)) {
				return 'no-referrer';
			}

			// 2. Return referrerURL.
			return referrerURL;

		default:
			throw new TypeError(`Invalid referrerPolicy: ${policy}`);
	}
}

/**
 * @see {@link https://w3c.github.io/webappsec-referrer-policy/#parse-referrer-policy-from-header|Referrer Policy §8.1. Parse a referrer policy from a Referrer-Policy header}
 * @param {Headers} headers Response headers
 * @returns {string} policy
 */
function parseReferrerPolicyFromHeader(headers) {
	// 1. Let policy-tokens be the result of extracting header list values given `Referrer-Policy`
	//    and response’s header list.
	const policyTokens = (headers.get('referrer-policy') || '').split(/[,\s]+/);

	// 2. Let policy be the empty string.
	let policy = '';

	// 3. For each token in policy-tokens, if token is a referrer policy and token is not the empty
	//    string, then set policy to token.
	// Note: This algorithm loops over multiple policy values to allow deployment of new policy
	// values with fallbacks for older user agents, as described in § 11.1 Unknown Policy Values.
	for (const token of policyTokens) {
		if (token && ReferrerPolicy.has(token)) {
			policy = token;
		}
	}

	// 4. Return policy.
	return policy;
}

;// CONCATENATED MODULE: ./node_modules/node-fetch/src/request.js
/**
 * Request.js
 *
 * Request class contains server only options
 *
 * All spec algorithm step numbers are based on https://fetch.spec.whatwg.org/commit-snapshots/ae716822cb3a61843226cd090eefc6589446c1d2/.
 */









const request_INTERNALS = Symbol('Request internals');

/**
 * Check if `obj` is an instance of Request.
 *
 * @param  {*} object
 * @return {boolean}
 */
const isRequest = object => {
	return (
		typeof object === 'object' &&
		typeof object[request_INTERNALS] === 'object'
	);
};

const doBadDataWarn = (0,external_node_util_namespaceObject.deprecate)(() => {},
	'.data is not a valid RequestInit property, use .body instead',
	'https://github.com/node-fetch/node-fetch/issues/1000 (request)');

/**
 * Request class
 *
 * Ref: https://fetch.spec.whatwg.org/#request-class
 *
 * @param   Mixed   input  Url or Request instance
 * @param   Object  init   Custom options
 * @return  Void
 */
class Request extends Body {
	constructor(input, init = {}) {
		let parsedURL;

		// Normalize input and force URL to be encoded as UTF-8 (https://github.com/node-fetch/node-fetch/issues/245)
		if (isRequest(input)) {
			parsedURL = new URL(input.url);
		} else {
			parsedURL = new URL(input);
			input = {};
		}

		if (parsedURL.username !== '' || parsedURL.password !== '') {
			throw new TypeError(`${parsedURL} is an url with embedded credentials.`);
		}

		let method = init.method || input.method || 'GET';
		if (/^(delete|get|head|options|post|put)$/i.test(method)) {
			method = method.toUpperCase();
		}

		if (!isRequest(init) && 'data' in init) {
			doBadDataWarn();
		}

		// eslint-disable-next-line no-eq-null, eqeqeq
		if ((init.body != null || (isRequest(input) && input.body !== null)) &&
			(method === 'GET' || method === 'HEAD')) {
			throw new TypeError('Request with GET/HEAD method cannot have body');
		}

		const inputBody = init.body ?
			init.body :
			(isRequest(input) && input.body !== null ?
				clone(input) :
				null);

		super(inputBody, {
			size: init.size || input.size || 0
		});

		const headers = new Headers(init.headers || input.headers || {});

		if (inputBody !== null && !headers.has('Content-Type')) {
			const contentType = extractContentType(inputBody, this);
			if (contentType) {
				headers.set('Content-Type', contentType);
			}
		}

		let signal = isRequest(input) ?
			input.signal :
			null;
		if ('signal' in init) {
			signal = init.signal;
		}

		// eslint-disable-next-line no-eq-null, eqeqeq
		if (signal != null && !isAbortSignal(signal)) {
			throw new TypeError('Expected signal to be an instanceof AbortSignal or EventTarget');
		}

		// §5.4, Request constructor steps, step 15.1
		// eslint-disable-next-line no-eq-null, eqeqeq
		let referrer = init.referrer == null ? input.referrer : init.referrer;
		if (referrer === '') {
			// §5.4, Request constructor steps, step 15.2
			referrer = 'no-referrer';
		} else if (referrer) {
			// §5.4, Request constructor steps, step 15.3.1, 15.3.2
			const parsedReferrer = new URL(referrer);
			// §5.4, Request constructor steps, step 15.3.3, 15.3.4
			referrer = /^about:(\/\/)?client$/.test(parsedReferrer) ? 'client' : parsedReferrer;
		} else {
			referrer = undefined;
		}

		this[request_INTERNALS] = {
			method,
			redirect: init.redirect || input.redirect || 'follow',
			headers,
			parsedURL,
			signal,
			referrer
		};

		// Node-fetch-only options
		this.follow = init.follow === undefined ? (input.follow === undefined ? 20 : input.follow) : init.follow;
		this.compress = init.compress === undefined ? (input.compress === undefined ? true : input.compress) : init.compress;
		this.counter = init.counter || input.counter || 0;
		this.agent = init.agent || input.agent;
		this.highWaterMark = init.highWaterMark || input.highWaterMark || 16384;
		this.insecureHTTPParser = init.insecureHTTPParser || input.insecureHTTPParser || false;

		// §5.4, Request constructor steps, step 16.
		// Default is empty string per https://fetch.spec.whatwg.org/#concept-request-referrer-policy
		this.referrerPolicy = init.referrerPolicy || input.referrerPolicy || '';
	}

	/** @returns {string} */
	get method() {
		return this[request_INTERNALS].method;
	}

	/** @returns {string} */
	get url() {
		return (0,external_node_url_namespaceObject.format)(this[request_INTERNALS].parsedURL);
	}

	/** @returns {Headers} */
	get headers() {
		return this[request_INTERNALS].headers;
	}

	get redirect() {
		return this[request_INTERNALS].redirect;
	}

	/** @returns {AbortSignal} */
	get signal() {
		return this[request_INTERNALS].signal;
	}

	// https://fetch.spec.whatwg.org/#dom-request-referrer
	get referrer() {
		if (this[request_INTERNALS].referrer === 'no-referrer') {
			return '';
		}

		if (this[request_INTERNALS].referrer === 'client') {
			return 'about:client';
		}

		if (this[request_INTERNALS].referrer) {
			return this[request_INTERNALS].referrer.toString();
		}

		return undefined;
	}

	get referrerPolicy() {
		return this[request_INTERNALS].referrerPolicy;
	}

	set referrerPolicy(referrerPolicy) {
		this[request_INTERNALS].referrerPolicy = validateReferrerPolicy(referrerPolicy);
	}

	/**
	 * Clone this request
	 *
	 * @return  Request
	 */
	clone() {
		return new Request(this);
	}

	get [Symbol.toStringTag]() {
		return 'Request';
	}
}

Object.defineProperties(Request.prototype, {
	method: {enumerable: true},
	url: {enumerable: true},
	headers: {enumerable: true},
	redirect: {enumerable: true},
	clone: {enumerable: true},
	signal: {enumerable: true},
	referrer: {enumerable: true},
	referrerPolicy: {enumerable: true}
});

/**
 * Convert a Request to Node.js http request options.
 *
 * @param {Request} request - A Request instance
 * @return The options object to be passed to http.request
 */
const getNodeRequestOptions = request => {
	const {parsedURL} = request[request_INTERNALS];
	const headers = new Headers(request[request_INTERNALS].headers);

	// Fetch step 1.3
	if (!headers.has('Accept')) {
		headers.set('Accept', '*/*');
	}

	// HTTP-network-or-cache fetch steps 2.4-2.7
	let contentLengthValue = null;
	if (request.body === null && /^(post|put)$/i.test(request.method)) {
		contentLengthValue = '0';
	}

	if (request.body !== null) {
		const totalBytes = getTotalBytes(request);
		// Set Content-Length if totalBytes is a number (that is not NaN)
		if (typeof totalBytes === 'number' && !Number.isNaN(totalBytes)) {
			contentLengthValue = String(totalBytes);
		}
	}

	if (contentLengthValue) {
		headers.set('Content-Length', contentLengthValue);
	}

	// 4.1. Main fetch, step 2.6
	// > If request's referrer policy is the empty string, then set request's referrer policy to the
	// > default referrer policy.
	if (request.referrerPolicy === '') {
		request.referrerPolicy = DEFAULT_REFERRER_POLICY;
	}

	// 4.1. Main fetch, step 2.7
	// > If request's referrer is not "no-referrer", set request's referrer to the result of invoking
	// > determine request's referrer.
	if (request.referrer && request.referrer !== 'no-referrer') {
		request[request_INTERNALS].referrer = determineRequestsReferrer(request);
	} else {
		request[request_INTERNALS].referrer = 'no-referrer';
	}

	// 4.5. HTTP-network-or-cache fetch, step 6.9
	// > If httpRequest's referrer is a URL, then append `Referer`/httpRequest's referrer, serialized
	// >  and isomorphic encoded, to httpRequest's header list.
	if (request[request_INTERNALS].referrer instanceof URL) {
		headers.set('Referer', request.referrer);
	}

	// HTTP-network-or-cache fetch step 2.11
	if (!headers.has('User-Agent')) {
		headers.set('User-Agent', 'node-fetch');
	}

	// HTTP-network-or-cache fetch step 2.15
	if (request.compress && !headers.has('Accept-Encoding')) {
		headers.set('Accept-Encoding', 'gzip, deflate, br');
	}

	let {agent} = request;
	if (typeof agent === 'function') {
		agent = agent(parsedURL);
	}

	if (!headers.has('Connection') && !agent) {
		headers.set('Connection', 'close');
	}

	// HTTP-network fetch step 4.2
	// chunked encoding is handled by Node.js

	const search = getSearch(parsedURL);

	// Pass the full URL directly to request(), but overwrite the following
	// options:
	const options = {
		// Overwrite search to retain trailing ? (issue #776)
		path: parsedURL.pathname + search,
		// The following options are not expressed in the URL
		method: request.method,
		headers: headers[Symbol.for('nodejs.util.inspect.custom')](),
		insecureHTTPParser: request.insecureHTTPParser,
		agent
	};

	return {
		/** @type {URL} */
		parsedURL,
		options
	};
};

;// CONCATENATED MODULE: ./node_modules/node-fetch/src/errors/abort-error.js


/**
 * AbortError interface for cancelled requests
 */
class AbortError extends FetchBaseError {
	constructor(message, type = 'aborted') {
		super(message, type);
	}
}

// EXTERNAL MODULE: ./node_modules/fetch-blob/from.js + 2 modules
var from = __nccwpck_require__(7176);
;// CONCATENATED MODULE: ./node_modules/node-fetch/src/index.js
/**
 * Index.js
 *
 * a request API compatible with window.fetch
 *
 * All spec algorithm step numbers are based on https://fetch.spec.whatwg.org/commit-snapshots/ae716822cb3a61843226cd090eefc6589446c1d2/.
 */
























const supportedSchemas = new Set(['data:', 'http:', 'https:']);

/**
 * Fetch function
 *
 * @param   {string | URL | import('./request').default} url - Absolute url or Request instance
 * @param   {*} [options_] - Fetch options
 * @return  {Promise<import('./response').default>}
 */
async function fetch(url, options_) {
	return new Promise((resolve, reject) => {
		// Build request object
		const request = new Request(url, options_);
		const {parsedURL, options} = getNodeRequestOptions(request);
		if (!supportedSchemas.has(parsedURL.protocol)) {
			throw new TypeError(`node-fetch cannot load ${url}. URL scheme "${parsedURL.protocol.replace(/:$/, '')}" is not supported.`);
		}

		if (parsedURL.protocol === 'data:') {
			const data = dist(request.url);
			const response = new Response(data, {headers: {'Content-Type': data.typeFull}});
			resolve(response);
			return;
		}

		// Wrap http.request into fetch
		const send = (parsedURL.protocol === 'https:' ? external_node_https_namespaceObject : external_node_http_namespaceObject).request;
		const {signal} = request;
		let response = null;

		const abort = () => {
			const error = new AbortError('The operation was aborted.');
			reject(error);
			if (request.body && request.body instanceof external_node_stream_namespaceObject.Readable) {
				request.body.destroy(error);
			}

			if (!response || !response.body) {
				return;
			}

			response.body.emit('error', error);
		};

		if (signal && signal.aborted) {
			abort();
			return;
		}

		const abortAndFinalize = () => {
			abort();
			finalize();
		};

		// Send request
		const request_ = send(parsedURL.toString(), options);

		if (signal) {
			signal.addEventListener('abort', abortAndFinalize);
		}

		const finalize = () => {
			request_.abort();
			if (signal) {
				signal.removeEventListener('abort', abortAndFinalize);
			}
		};

		request_.on('error', error => {
			reject(new FetchError(`request to ${request.url} failed, reason: ${error.message}`, 'system', error));
			finalize();
		});

		fixResponseChunkedTransferBadEnding(request_, error => {
			if (response && response.body) {
				response.body.destroy(error);
			}
		});

		/* c8 ignore next 18 */
		if (process.version < 'v14') {
			// Before Node.js 14, pipeline() does not fully support async iterators and does not always
			// properly handle when the socket close/end events are out of order.
			request_.on('socket', s => {
				let endedWithEventsCount;
				s.prependListener('end', () => {
					endedWithEventsCount = s._eventsCount;
				});
				s.prependListener('close', hadError => {
					// if end happened before close but the socket didn't emit an error, do it now
					if (response && endedWithEventsCount < s._eventsCount && !hadError) {
						const error = new Error('Premature close');
						error.code = 'ERR_STREAM_PREMATURE_CLOSE';
						response.body.emit('error', error);
					}
				});
			});
		}

		request_.on('response', response_ => {
			request_.setTimeout(0);
			const headers = fromRawHeaders(response_.rawHeaders);

			// HTTP fetch step 5
			if (isRedirect(response_.statusCode)) {
				// HTTP fetch step 5.2
				const location = headers.get('Location');

				// HTTP fetch step 5.3
				let locationURL = null;
				try {
					locationURL = location === null ? null : new URL(location, request.url);
				} catch {
					// error here can only be invalid URL in Location: header
					// do not throw when options.redirect == manual
					// let the user extract the errorneous redirect URL
					if (request.redirect !== 'manual') {
						reject(new FetchError(`uri requested responds with an invalid redirect URL: ${location}`, 'invalid-redirect'));
						finalize();
						return;
					}
				}

				// HTTP fetch step 5.5
				switch (request.redirect) {
					case 'error':
						reject(new FetchError(`uri requested responds with a redirect, redirect mode is set to error: ${request.url}`, 'no-redirect'));
						finalize();
						return;
					case 'manual':
						// Nothing to do
						break;
					case 'follow': {
						// HTTP-redirect fetch step 2
						if (locationURL === null) {
							break;
						}

						// HTTP-redirect fetch step 5
						if (request.counter >= request.follow) {
							reject(new FetchError(`maximum redirect reached at: ${request.url}`, 'max-redirect'));
							finalize();
							return;
						}

						// HTTP-redirect fetch step 6 (counter increment)
						// Create a new Request object.
						const requestOptions = {
							headers: new Headers(request.headers),
							follow: request.follow,
							counter: request.counter + 1,
							agent: request.agent,
							compress: request.compress,
							method: request.method,
							body: clone(request),
							signal: request.signal,
							size: request.size,
							referrer: request.referrer,
							referrerPolicy: request.referrerPolicy
						};

						// when forwarding sensitive headers like "Authorization",
						// "WWW-Authenticate", and "Cookie" to untrusted targets,
						// headers will be ignored when following a redirect to a domain
						// that is not a subdomain match or exact match of the initial domain.
						// For example, a redirect from "foo.com" to either "foo.com" or "sub.foo.com"
						// will forward the sensitive headers, but a redirect to "bar.com" will not.
						// headers will also be ignored when following a redirect to a domain using
						// a different protocol. For example, a redirect from "https://foo.com" to "http://foo.com"
						// will not forward the sensitive headers
						if (!isDomainOrSubdomain(request.url, locationURL) || !isSameProtocol(request.url, locationURL)) {
							for (const name of ['authorization', 'www-authenticate', 'cookie', 'cookie2']) {
								requestOptions.headers.delete(name);
							}
						}

						// HTTP-redirect fetch step 9
						if (response_.statusCode !== 303 && request.body && options_.body instanceof external_node_stream_namespaceObject.Readable) {
							reject(new FetchError('Cannot follow redirect with body being a readable stream', 'unsupported-redirect'));
							finalize();
							return;
						}

						// HTTP-redirect fetch step 11
						if (response_.statusCode === 303 || ((response_.statusCode === 301 || response_.statusCode === 302) && request.method === 'POST')) {
							requestOptions.method = 'GET';
							requestOptions.body = undefined;
							requestOptions.headers.delete('content-length');
						}

						// HTTP-redirect fetch step 14
						const responseReferrerPolicy = parseReferrerPolicyFromHeader(headers);
						if (responseReferrerPolicy) {
							requestOptions.referrerPolicy = responseReferrerPolicy;
						}

						// HTTP-redirect fetch step 15
						resolve(fetch(new Request(locationURL, requestOptions)));
						finalize();
						return;
					}

					default:
						return reject(new TypeError(`Redirect option '${request.redirect}' is not a valid value of RequestRedirect`));
				}
			}

			// Prepare response
			if (signal) {
				response_.once('end', () => {
					signal.removeEventListener('abort', abortAndFinalize);
				});
			}

			let body = (0,external_node_stream_namespaceObject.pipeline)(response_, new external_node_stream_namespaceObject.PassThrough(), error => {
				if (error) {
					reject(error);
				}
			});
			// see https://github.com/nodejs/node/pull/29376
			/* c8 ignore next 3 */
			if (process.version < 'v12.10') {
				response_.on('aborted', abortAndFinalize);
			}

			const responseOptions = {
				url: request.url,
				status: response_.statusCode,
				statusText: response_.statusMessage,
				headers,
				size: request.size,
				counter: request.counter,
				highWaterMark: request.highWaterMark
			};

			// HTTP-network fetch step 12.1.1.3
			const codings = headers.get('Content-Encoding');

			// HTTP-network fetch step 12.1.1.4: handle content codings

			// in following scenarios we ignore compression support
			// 1. compression support is disabled
			// 2. HEAD request
			// 3. no Content-Encoding header
			// 4. no content response (204)
			// 5. content not modified response (304)
			if (!request.compress || request.method === 'HEAD' || codings === null || response_.statusCode === 204 || response_.statusCode === 304) {
				response = new Response(body, responseOptions);
				resolve(response);
				return;
			}

			// For Node v6+
			// Be less strict when decoding compressed responses, since sometimes
			// servers send slightly invalid responses that are still accepted
			// by common browsers.
			// Always using Z_SYNC_FLUSH is what cURL does.
			const zlibOptions = {
				flush: external_node_zlib_namespaceObject.Z_SYNC_FLUSH,
				finishFlush: external_node_zlib_namespaceObject.Z_SYNC_FLUSH
			};

			// For gzip
			if (codings === 'gzip' || codings === 'x-gzip') {
				body = (0,external_node_stream_namespaceObject.pipeline)(body, external_node_zlib_namespaceObject.createGunzip(zlibOptions), error => {
					if (error) {
						reject(error);
					}
				});
				response = new Response(body, responseOptions);
				resolve(response);
				return;
			}

			// For deflate
			if (codings === 'deflate' || codings === 'x-deflate') {
				// Handle the infamous raw deflate response from old servers
				// a hack for old IIS and Apache servers
				const raw = (0,external_node_stream_namespaceObject.pipeline)(response_, new external_node_stream_namespaceObject.PassThrough(), error => {
					if (error) {
						reject(error);
					}
				});
				raw.once('data', chunk => {
					// See http://stackoverflow.com/questions/37519828
					if ((chunk[0] & 0x0F) === 0x08) {
						body = (0,external_node_stream_namespaceObject.pipeline)(body, external_node_zlib_namespaceObject.createInflate(), error => {
							if (error) {
								reject(error);
							}
						});
					} else {
						body = (0,external_node_stream_namespaceObject.pipeline)(body, external_node_zlib_namespaceObject.createInflateRaw(), error => {
							if (error) {
								reject(error);
							}
						});
					}

					response = new Response(body, responseOptions);
					resolve(response);
				});
				raw.once('end', () => {
					// Some old IIS servers return zero-length OK deflate responses, so
					// 'data' is never emitted. See https://github.com/node-fetch/node-fetch/pull/903
					if (!response) {
						response = new Response(body, responseOptions);
						resolve(response);
					}
				});
				return;
			}

			// For br
			if (codings === 'br') {
				body = (0,external_node_stream_namespaceObject.pipeline)(body, external_node_zlib_namespaceObject.createBrotliDecompress(), error => {
					if (error) {
						reject(error);
					}
				});
				response = new Response(body, responseOptions);
				resolve(response);
				return;
			}

			// Otherwise, use response as-is
			response = new Response(body, responseOptions);
			resolve(response);
		});

		// eslint-disable-next-line promise/prefer-await-to-then
		writeToStream(request_, request).catch(reject);
	});
}

function fixResponseChunkedTransferBadEnding(request, errorCallback) {
	const LAST_CHUNK = external_node_buffer_namespaceObject.Buffer.from('0\r\n\r\n');

	let isChunkedTransfer = false;
	let properLastChunkReceived = false;
	let previousChunk;

	request.on('response', response => {
		const {headers} = response;
		isChunkedTransfer = headers['transfer-encoding'] === 'chunked' && !headers['content-length'];
	});

	request.on('socket', socket => {
		const onSocketClose = () => {
			if (isChunkedTransfer && !properLastChunkReceived) {
				const error = new Error('Premature close');
				error.code = 'ERR_STREAM_PREMATURE_CLOSE';
				errorCallback(error);
			}
		};

		const onData = buf => {
			properLastChunkReceived = external_node_buffer_namespaceObject.Buffer.compare(buf.slice(-5), LAST_CHUNK) === 0;

			// Sometimes final 0-length chunk and end of message code are in separate packets
			if (!properLastChunkReceived && previousChunk) {
				properLastChunkReceived = (
					external_node_buffer_namespaceObject.Buffer.compare(previousChunk.slice(-3), LAST_CHUNK.slice(0, 3)) === 0 &&
					external_node_buffer_namespaceObject.Buffer.compare(buf.slice(-2), LAST_CHUNK.slice(3)) === 0
				);
			}

			previousChunk = buf;
		};

		socket.prependListener('close', onSocketClose);
		socket.on('data', onData);

		request.on('close', () => {
			socket.removeListener('close', onSocketClose);
			socket.removeListener('data', onData);
		});
	});
}


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId].call(module.exports, module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__nccwpck_require__.m = __webpack_modules__;
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__nccwpck_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__nccwpck_require__.o(definition, key) && !__nccwpck_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/ensure chunk */
/******/ 	(() => {
/******/ 		__nccwpck_require__.f = {};
/******/ 		// This file contains only the entry chunk.
/******/ 		// The chunk loading function for additional chunks
/******/ 		__nccwpck_require__.e = (chunkId) => {
/******/ 			return Promise.all(Object.keys(__nccwpck_require__.f).reduce((promises, key) => {
/******/ 				__nccwpck_require__.f[key](chunkId, promises);
/******/ 				return promises;
/******/ 			}, []));
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/get javascript chunk filename */
/******/ 	(() => {
/******/ 		// This function allow to reference async chunks
/******/ 		__nccwpck_require__.u = (chunkId) => {
/******/ 			// return url for filenames based on template
/******/ 			return "" + chunkId + ".index.js";
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__nccwpck_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__nccwpck_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/******/ 	/* webpack/runtime/require chunk loading */
/******/ 	(() => {
/******/ 		// no baseURI
/******/ 		
/******/ 		// object to store loaded chunks
/******/ 		// "1" means "loaded", otherwise not loaded yet
/******/ 		var installedChunks = {
/******/ 			179: 1
/******/ 		};
/******/ 		
/******/ 		// no on chunks loaded
/******/ 		
/******/ 		var installChunk = (chunk) => {
/******/ 			var moreModules = chunk.modules, chunkIds = chunk.ids, runtime = chunk.runtime;
/******/ 			for(var moduleId in moreModules) {
/******/ 				if(__nccwpck_require__.o(moreModules, moduleId)) {
/******/ 					__nccwpck_require__.m[moduleId] = moreModules[moduleId];
/******/ 				}
/******/ 			}
/******/ 			if(runtime) runtime(__nccwpck_require__);
/******/ 			for(var i = 0; i < chunkIds.length; i++)
/******/ 				installedChunks[chunkIds[i]] = 1;
/******/ 		
/******/ 		};
/******/ 		
/******/ 		// require() chunk loading for javascript
/******/ 		__nccwpck_require__.f.require = (chunkId, promises) => {
/******/ 			// "1" is the signal for "already loaded"
/******/ 			if(!installedChunks[chunkId]) {
/******/ 				if(true) { // all chunks have JS
/******/ 					installChunk(require("./" + __nccwpck_require__.u(chunkId)));
/******/ 				} else installedChunks[chunkId] = 1;
/******/ 			}
/******/ 		};
/******/ 		
/******/ 		// no external install chunk
/******/ 		
/******/ 		// no HMR
/******/ 		
/******/ 		// no HMR manifest
/******/ 	})();
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __nccwpck_require__(4514);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;
//# sourceMappingURL=index.js.map