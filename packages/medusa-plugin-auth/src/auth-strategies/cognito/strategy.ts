import PassportStartegy from 'passport-strategy';
import { CognitoIdentityProviderClient, GetUserCommand } from '@aws-sdk/client-cognito-identity-provider'; // ES Modules import
import { CognitoOptions } from './types';
import { Request } from 'express';

const COGNITO_ADMIN_STRATEGY_NAME = 'cognito.admin.medusa-auth-plugin';
const COGNITO_STORE_STRATEGY_NAME = 'cognito.store.medusa-auth-plugin';

/**
 * This class extends the opensource [`passport-startegy`](https://www.npmjs.com/package/passport-strategy/) to create a custom strategy for Cognito.
 *
 * This strategy aims to handle token based authentication with Cognito.
 * The tokens are created from seprate platform and issued in cookies under the same domain for client to set in the `request query`.
 *
 * The client will pass the `access_token` in the `req.query` object which will be used to fetch the user information.
 * The `req` will be responded with user details stored in the `Cognito` or `NOT_FOUND` error.
 *
 * The Cognito [`GetUser API`](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html) is used to fetch the user details.
 */
class CognitoStrategy extends PassportStartegy {
	private userPoolId: string;
	private clientId: string;
	private verify: Function;
	private region: string;
	private accessKeyId: string;
	private secretAccessKey: string;
	private cognitoClient: CognitoIdentityProviderClient;

	constructor(options: CognitoOptions, verify) {
		super(options, verify);

		this.userPoolId = options.userPoolId;
		this.clientId = options.clientId;
		this.region = options.region;
		this.accessKeyId = options.accessKeyId;
		this.secretAccessKey = options.secretAccessKey;
		this.cognitoClient = new CognitoIdentityProviderClient({
			region: this.region,
		});
	}

	async authenticate(req: Request, options) {
		console.log({
			options,
		});
		try {
			const accessToken: string = typeof req.query.access_token === 'string' ? req.query.access_token : '';
			// throw error if access_token is not found
			if (!req.query.access_token) {
				throw `ACCESS_TOKEN not found in the request's query`;
			}
			// find user by access_token
			const authenticatedUser = await this.getUser(accessToken);
			console.log(
				JSON.stringify(
					{
						authenticatedUser,
					},
					undefined,
					2
				)
			);
			return authenticatedUser;
		} catch (error) {
			throw error;
		}
	}

	async getUser(accessToken: string) {
		try {
			return await this.cognitoClient.send(
				new GetUserCommand({
					AccessToken: accessToken,
				})
			);
		} catch (error) {
			throw error;
		}
	}
}

export { CognitoStrategy, COGNITO_ADMIN_STRATEGY_NAME, COGNITO_STORE_STRATEGY_NAME };
