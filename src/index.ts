import * as core from "@actions/core";
import libsodium from "libsodium-wrappers";
import fetch from "node-fetch";
const apiURL = process.env["GITHUB_API_URL"] || "https://api.github.com";

async function run() {
	try {
		const secretsToken = core.getInput("secrets-token");
		const tumblrClientID = core.getInput("tumblr-client-id");
		const tumblrClientSecret = core.getInput("tumblr-client-secret");
		const tumblrRefreshToken = core.getInput("tumblr-refresh-token");
		const repository = core.getInput("repository");
		const tokenName = core.getInput("token-name");

		const token = await handleCIAuth(
			repository,
			secretsToken,
			tumblrRefreshToken,
			tumblrClientID,
			tumblrClientSecret,
			tokenName
		);

		core.setOutput("tumblr-token", token);
		core.setSecret(token);
		core.exportVariable("TUMBLR_TOKEN", token)
	} catch (error) {
		if (error instanceof Error) core.setFailed(error.message);
	}
}

//You didn't have to make me do this, tumblr
async function handleCIAuth(
	repo: string,
	secretsToken: string,
	refreshToken: string,
	clientID: string,
	clientSecret: string,
	tokenName: string
) {
	core.debug("Getting new token...");
	const request = await fetch("https://api.tumblr.com/v2/oauth2/token", {
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
		throw new Error(
			`Failed to get new token: ${request.status} ${
				request.statusText
			} ${await request.text()}`
		);

	const response = (await request.json()) as {
		access_token: string;
		refresh_token: string;
		expires_in: number;
		token_type: string;
		scope: string;
	};

	core.debug(`Got new token, fetching github public key at url ${apiURL}/repos/${repo}/actions/secrets/public-key...`);
	//Get the public key from github to encrypt the secret
	const githubPublicKey = await fetch(`${apiURL}/repos/${repo}/actions/secrets/public-key`, {
		method: "GET",
		headers: {
			"Content-Type": "application/json",
			"Accept": "application/vnd.github+json",
			"User-Agent": "X-GitHub-Api-Version: 2022-11-28",
			"Authorization": `Bearer ${secretsToken}`,
		},
	});

	if (!githubPublicKey.ok)
		throw new Error(
			`Failed to get github public key: ${githubPublicKey.status} ${
				githubPublicKey.statusText
			} ${await githubPublicKey.text()}`
		);

	const githubPublicKeyResponse = (await githubPublicKey.json()) as {
		key_id: string;
		key: string;
	};

	//Encrypt the refresh token using the public key
	const refreshTokenSecret = await encryptSecret(response.refresh_token, githubPublicKeyResponse.key);

	core.debug("Updating secret...");
	//Update the github secret with the new refresh token for the next run
	const secretUpdate = await fetch(`${apiURL}/repos/${repo}/actions/secrets/${tokenName}`, {
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
		throw new Error(
			`Failed to update secret: ${secretUpdate.statusText} ${secretUpdate.status} ${
				secretUpdate.statusText
			} ${await secretUpdate.text()}`
		);

	return response.access_token;
}

async function encryptSecret(secret: string, key: string) {
	return libsodium.ready.then(() => {
		// Convert Secret & Base64 key to Uint8Array.
		let binkey = libsodium.from_base64(key, libsodium.base64_variants.ORIGINAL);
		let binsec = libsodium.from_string(secret);

		//Encrypt the secret using LibSodium
		let encBytes = libsodium.crypto_box_seal(binsec, binkey);

		// Convert encrypted Uint8Array to Base64
		return libsodium.to_base64(encBytes, libsodium.base64_variants.ORIGINAL);
	});
}

run();
