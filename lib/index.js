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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = __importDefault(require("@actions/core"));
const libsodium_wrappers_1 = __importDefault(require("libsodium-wrappers"));
try {
    const secretsToken = core_1.default.getInput("secrets-token");
    const tumblrClientID = core_1.default.getInput("tumblr-client-id");
    const tumblrClientSecret = core_1.default.getInput("tumblr-client-secret");
    const tumblrRefreshToken = core_1.default.getInput("tumblr-refresn-token");
    const repo = core_1.default.getInput("repo");
    handleCIAuth(repo, secretsToken, tumblrRefreshToken, tumblrClientID, tumblrClientSecret).then(token => {
        core_1.default.setOutput("tumblr-token", token);
    });
}
catch (error) {
    core_1.default.setFailed(error.message);
}
//You didn't have to make me do this, tumblr
function handleCIAuth(repo, secretsToken, refreshToken, clientID, clientSecret) {
    return __awaiter(this, void 0, void 0, function* () {
        const request = yield fetch("https://api.tumblr.com/v2/oauth2/token", {
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
        const response = yield request.json();
        console.log(JSON.stringify(response));
        //Get the public key from github to encrypt the secret
        const githubPublicKey = yield fetch(`https://api.github.com/repos/${repo}/actions/secrets/public-key`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
                "User-Agent": "X-GitHub-Api-Version: 2022-11-28",
                "Authorization": `token ${secretsToken}`,
            },
        });
        const githubPublicKeyResponse = yield githubPublicKey.json();
        console.log(JSON.stringify(githubPublicKeyResponse));
        //Encrypt the refresh token using the public key
        const secret = yield libsodium_wrappers_1.default.ready.then(() => {
            // Convert Secret & Base64 key to Uint8Array.
            let binkey = libsodium_wrappers_1.default.from_base64(githubPublicKeyResponse.key, libsodium_wrappers_1.default.base64_variants.ORIGINAL);
            let binsec = libsodium_wrappers_1.default.from_string(response.refresh_token);
            //Encrypt the secret using LibSodium
            let encBytes = libsodium_wrappers_1.default.crypto_box_seal(binsec, binkey);
            // Convert encrypted Uint8Array to Base64
            return libsodium_wrappers_1.default.to_base64(encBytes, libsodium_wrappers_1.default.base64_variants.ORIGINAL);
        });
        //Update the github secret with the new refresh token for the next run
        yield fetch("https://api.github.com/repos/MarkSuckerberg/typeblr/actions/secrets/TUMBLR_REFRESH_TOKEN", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
                "User-Agent": "X-GitHub-Api-Version: 2022-11-28",
                "Authorization": `token ${secretsToken}`,
            },
            body: JSON.stringify({
                encrypted_value: secret,
                key_id: githubPublicKeyResponse.key_id,
            }),
        });
        return response.access_token;
    });
}
exports.default = handleCIAuth;
