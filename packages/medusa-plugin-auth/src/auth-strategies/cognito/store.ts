const CognitoStrategy = require('./startegy');
import { ConfigModule, MedusaContainer } from '@medusajs/medusa';
import { Router } from 'express';

import { passportAuthRoutesBuilder } from '../../core/passport/utils/auth-routes-builder';
import { validateStoreCallback } from '../../core/validate-callback';
import { PassportStrategy } from '../../core/passport/Strategy';

import { AuthOptions } from '../../types';

import { CognitoOptions, ExtraParams, Profile, COGNITO_STORE_STRATEGY_NAME } from './types';

export class CognitoStoreStrategy extends PassportStrategy(CognitoStrategy, COGNITO_STORE_STRATEGY_NAME) {
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
			callbackURL: strategyOptions.store.callbackUrl,
			passReqToCallback: true,
			state: true,
		});
	}

	async validate(
		req: Request,
		accessToken: string,
		refreshToken: string,
		extraParams: ExtraParams,
		profile: Profile
	) {
		if (this.strategyOptions.store.verifyCallback) {
			const validateRes = await this.strategyOptions.store.verifyCallback(
				this.container,
				req,
				accessToken,
				refreshToken,
				profile,
				extraParams,
				this.strict
			);

			return {
				...validateRes,
				accessToken,
			};
		}
		const validateRes = await validateStoreCallback(profile, {
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
 * Returns the router that holds the cognito store authentication routes
 * @param cognito
 * @param configModule
 */
export function getCognitoStoreAuthRouter(cognito: CognitoOptions, configModule: ConfigModule): Router {
	return passportAuthRoutesBuilder({
		domain: 'store',
		configModule,
		authPath: cognito.store.authPath ?? '/store/auth/cognito',
		authCallbackPath: cognito.store.authCallbackPath ?? '/store/auth/cognito/cb',
		successRedirect: cognito.store.successRedirect,
		strategyName: COGNITO_STORE_STRATEGY_NAME,
		passportAuthenticateMiddlewareOptions: {
			scope: 'openid email profile',
		},
		passportCallbackAuthenticateMiddlewareOptions: {
			failureRedirect: cognito.store.failureRedirect,
		},
		expiresIn: cognito.store.expiresIn,
	});
}
