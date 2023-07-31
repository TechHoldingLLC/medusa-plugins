import { ConfigModule, MedusaContainer } from '@medusajs/medusa/dist/types/global';
import { AuthOptions, StrategyExport } from '../../types';
import { Router } from 'express';
import { getCognitoAdminAuthRouter, CognitoAdminStrategy } from './admin';
import { getCognitoStoreAuthRouter, CognitoStoreStrategy } from './store';

export * from './admin';
export * from './store';
export * from './types';

export default {
	load: (container: MedusaContainer, configModule: ConfigModule, options: AuthOptions): void => {
		if (options.cognito?.admin) {
			new CognitoAdminStrategy(container, configModule, options.cognito, options.strict);
		}

		if (options.cognito?.store) {
			new CognitoStoreStrategy(container, configModule, options.cognito, options.strict);
		}
	},
	getRouter: (configModule: ConfigModule, options: AuthOptions): Router[] => {
		const routers = [];

		if (options.cognito?.admin) {
			routers.push(getCognitoAdminAuthRouter(options.cognito, configModule));
		}

		if (options.cognito?.store) {
			routers.push(getCognitoStoreAuthRouter(options.cognito, configModule));
		}

		return routers;
	},
} as StrategyExport;
