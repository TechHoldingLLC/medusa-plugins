import { MedusaContainer } from '@medusajs/medusa';
import { AttributeType } from '@aws-sdk/client-cognito-identity-provider';
import { AuthOptions } from '../../types';

export const COGNITO_ADMIN_STRATEGY_NAME = 'cognito.admin.medusa-auth-plugin';
export const COGNITO_STORE_STRATEGY_NAME = 'cognito.store.medusa-auth-plugin';

export type Profile = { emails: { value: string }[]; name?: { givenName?: string; familyName?: string } };
export type CognitoProfile = { email: string; name: string; username: string; attributes: AttributeType[] };
export type ExtraParams = {};

export type CognitoOptions = {
	region?: string;
	accessKeyId?: string;
	secretAccessKey?: string;
	userPoolId?: string;
	clientId?: string;
	admin?: {
		callbackUrl: string;
		successRedirect: string;
		failureRedirect: string;
		/**
		 * Default /admin/auth/cognito
		 */
		authPath?: string;
		/**
		 * Default /admin/auth/cognito/cb
		 */
		authCallbackPath?: string;
		/**
		 * The default verify callback function will be used if this configuration is not specified
		 */
		verifyCallback?: (
			container: MedusaContainer,
			req: Request,
			accessToken: string,
			refreshToken: string,
			profile: Profile,
			extraParams: ExtraParams,
			strict?: AuthOptions['strict']
		) => Promise<null | { id: string } | never>;

		expiresIn?: number;
	};
	store?: {
		callbackUrl: string;
		successRedirect: string;
		failureRedirect: string;
		/**
		 * Default /store/auth/cognito
		 */
		authPath?: string;
		/**
		 * Default /store/auth/cognito/cb
		 */
		authCallbackPath?: string;
		/**
		 * The default verify callback function will be used if this configuration is not specified
		 */
		verifyCallback?: (
			container: MedusaContainer,
			req: Request,
			accessToken: string,
			refreshToken: string,
			profile: Profile,
			extraParams: ExtraParams,
			strict?: AuthOptions['strict']
		) => Promise<null | { id: string } | never>;

		expiresIn?: number;
	};
};
