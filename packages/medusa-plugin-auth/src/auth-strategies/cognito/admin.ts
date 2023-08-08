const CognitoStrategy = require('./startegy');
import { ConfigModule, MedusaContainer } from '@medusajs/medusa';
import { Router } from 'express';

import { passportAuthRoutesBuilder } from '../../core/passport/utils/auth-routes-builder';
import { validateAdminCallback } from '../../core/validate-callback';
import { PassportStrategy } from '../../core/passport/Strategy';

import { AuthOptions } from '../../types';

import { CognitoOptions, CognitoProfile, COGNITO_ADMIN_STRATEGY_NAME, ExtraParams, Profile } from './types';

export class CognitoAdminStrategy extends PassportStrategy(CognitoStrategy, COGNITO_ADMIN_STRATEGY_NAME) {
	constructor(
		protected readonly container: MedusaContainer,
		protected readonly configModule: ConfigModule,
		protected readonly strategyOptions: CognitoOptions,
		protected readonly strict?: AuthOptions['strict']
	) {
		super({
			region: strategyOptions.region,
			accessKeyId: strategyOptions.accessKeyId,
			secretAccessKey: strategyOptions.secretAccessKey,
			userPoolId: strategyOptions.userPoolId,
			clientId: strategyOptions.clientId,
			callbackURL: strategyOptions.admin.callbackUrl,
			passReqToCallback: true,
			state: true,
		});
	}

	async validate(
		req: Request,
		accessToken: string,
		refreshToken: string,
		profile: CognitoProfile,
		extraParams: ExtraParams
	) {
		const authProfile: Profile = {
			emails: [{ value: profile.email }],
			name: { givenName: profile.name },
		};
		if (this.strategyOptions.admin.verifyCallback) {
			const validateRes = await this.strategyOptions.admin.verifyCallback(
				this.container,
				req,
				accessToken,
				refreshToken,
				authProfile,
				extraParams,
				this.strict
			);

			return {
				...validateRes,
				accessToken,
			};
		}

		const validateRes = await validateAdminCallback(authProfile, {
			container: this.container,
			strategyErrorIdentifier: 'cognito',
			strict: this.strict,
		});
		return {
			...validateRes,
			accessToken,
		};
	}
}

/**
 * Returns the router that holds the cognito admin authentication routes
 * @param cognito
 * @param configModule
 */
export function getCognitoAdminAuthRouter(cognito: CognitoOptions, configModule: ConfigModule): Router {
	return passportAuthRoutesBuilder({
		domain: 'admin',
		configModule,
		authPath: cognito.admin.authPath ?? '/admin/auth/cognito',
		authCallbackPath: cognito.admin.authCallbackPath ?? '/admin/auth/cognito/cb',
		successRedirect: cognito.admin.successRedirect,
		strategyName: COGNITO_ADMIN_STRATEGY_NAME,
		passportAuthenticateMiddlewareOptions: {
			scope: 'openid email profile',
		},
		passportCallbackAuthenticateMiddlewareOptions: {
			failureRedirect: cognito.admin.failureRedirect,
		},
		expiresIn: cognito.admin.expiresIn,
	});
}
