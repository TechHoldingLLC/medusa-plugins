// Load modules.
var util = require('util');
import passport from 'passport-strategy';
import {
	CognitoIdentityProviderClient,
	GetUserCommand,
	GetUserCommandOutput,
	AdminInitiateAuthCommand,
	NotAuthorizedException,
	AdminInitiateAuthCommandOutput,
} from '@aws-sdk/client-cognito-identity-provider';
import { CognitoOptions } from './types';

type GetUserByRefreshTokenOutput = {
	newAccessToken: string;
	user: GetUserCommandOutput;
};

/**
 * This function uses the opensource [`passport-startegy`](https://www.npmjs.com/package/passport-strategy/) to create a custom strategy for Cognito.
 *
 * @param options: CognitoOption
 * @param verify: Function
 */
function CognitoStrategy(options: CognitoOptions, verify) {
	if (!options) throw new Error('Cognito strategy requires options');
	if (!verify) throw new Error('Cognito strategy requires a verify callback');

	passport.Strategy.call(this);
	this.region = options.region;
	this.name = options;
	this._userPoolId = options.userPoolId;
	this._clientId = options.clientId;
	this._accessKeyId = options.accessKeyId;
	this._secretAccessKey = options.secretAccessKey;
	this._verify = verify;
	this.cognitoClient = new CognitoIdentityProviderClient({
		region: this.region,
		apiVersion: '2016-04-18',
		credentials: {
			accessKeyId: this._accessKeyId,
			secretAccessKey: this._secretAccessKey,
		},
	});
}

// Inherit from `passport-strategy`.
util.inherits(CognitoStrategy, passport.Strategy);

/**
 * Authenticate request
 *
 * @param {http.IncomingMessage} req
 * @param {object} options
 * @access protected
 */
CognitoStrategy.prototype.authenticate = async function (req, options) {
	let user: GetUserCommandOutput;
	let accessToken: string = req.query.accessToken;
	let refreshToken: string = req.query.refreshToken;

	if (!accessToken && !refreshToken) {
		return this.fail({ message: options.badRequestMessage || 'Missing token' }, 400);
	}

	/**
	 * Encloses `this` in self variable because `this` won't be available in function `verified`
	 */
	const self = this;

	/**
	 * Required function which will be called to verify and respond to the client
	 * Note: This function can be configured for various usecases.
	 * @param err: Error
	 * @param user: User
	 * @param info: any
	 * @returns Function
	 */
	function verified(err, user, info) {
		if (err) {
			return self.error(err);
		}
		if (!user) {
			return self.fail(info);
		}
		self.success(user, info);
	}

	try {
		// useful if user wants to login with credential
		// user = await this.authenticateUserWithCred(req.query, this.cognitoClient, this._userPoolId, this._clientId);

		// find cognito user by accessToken
		if (accessToken) {
			user = await this.getUserDetails(accessToken, this.cognitoClient);
		} else if (refreshToken) {
			// find cognito user by refreshToken
			const result: GetUserByRefreshTokenOutput = await this.validateUserByRefreshToken(refreshToken);
			accessToken = result.newAccessToken;
			user = result.user;
		}

		// set a profile
		const profile = {
			username: user.Username,
			attributes: user.UserAttributes,
			email: user.UserAttributes.find((attr) => attr.Name === 'email').Value || '',
			name: user.UserAttributes.find((attr) => attr.Name === 'name').Value || '',
		};
		this.success(profile, {});
		this._verify(req, accessToken, refreshToken, profile, {}, verified);
	} catch (error) {
		console.error(error);
		this.fail(error);
	}
};

// commenting as not being used
// CognitoStrategy.prototype.authenticateUserWithCred = async (body, cognitoClient, UserPoolId, ClientId) => {
// 	return await cognitoClient.send(
// 		new AdminInitiateAuthCommand({
// 			AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
// 			AuthParameters: {
// 				USERNAME: body.username,
// 				PASSWORD: body.password,
// 			},
// 			UserPoolId,
// 			ClientId,
// 		})
// 	);
// };

/**
 * Gets user details by an access_token
 * @param accessToken: string
 * @returns Promise<GetUserCommandOutput | NotAuthorizedException>
 */
CognitoStrategy.prototype.getUserDetails = async function (
	accessToken: string
): Promise<GetUserCommandOutput | NotAuthorizedException> {
	return await this.cognitoClient.send(
		new GetUserCommand({
			AccessToken: accessToken,
		})
	);
};

/**
 * Fecthes new access_token and returns user details
 * @param refreshToken: string
 * @returns Promise<GetUserByRefreshTokenOutput | NotAuthorizedException>
 */
CognitoStrategy.prototype.validateUserByRefreshToken = async function (
	refreshToken: string
): Promise<GetUserByRefreshTokenOutput | NotAuthorizedException> {
	const newAccessToken = await this.getAccessToken(refreshToken);
	const user = await this.getUserDetails(newAccessToken.AuthenticationResult.AccessToken);
	return {
		user,
		newAccessToken: newAccessToken.AuthenticationResult.AccessToken,
	};
};

/**
 * Fetches an access_token
 * @param refreshToken: string
 * @returns Promise<AdminInitiateAuthCommandOutput>
 */
CognitoStrategy.prototype.getAccessToken = async function (
	refreshToken: string
): Promise<AdminInitiateAuthCommandOutput> {
	return this.cognitoClient.send(
		new AdminInitiateAuthCommand({
			AuthFlow: 'REFRESH_TOKEN_AUTH',
			AuthParameters: {
				REFRESH_TOKEN: refreshToken,
			},
			UserPoolId: this._userPoolId,
			ClientId: this._clientId,
		})
	);
};

module.exports = CognitoStrategy;
