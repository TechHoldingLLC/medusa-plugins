import { CognitoStoreStrategy } from '../../store';
import { ConfigModule, MedusaContainer } from '@medusajs/medusa/dist/types/global';
import { AUTH_PROVIDER_KEY, CUSTOMER_METADATA_KEY } from '../../../../types';
import { CognitoOptions, COGNITO_STORE_STRATEGY_NAME, Profile, ExtraParams } from '../../types';

describe('Auth0 store strategy verify callback', function () {
	const existsEmail = 'exists@test.fr';
	const existsEmailWithMeta = 'exist2s@test.fr';
	const existsEmailWithMetaAndProviderKey = 'exist3s@test.fr';
	const existsEmailWithMetaButWrongProviderKey = 'exist4s@test.fr';

	let container: MedusaContainer;
	let req: Request;
	let accessToken: string;
	let refreshToken: string;
	let profile: Profile;
	let extraParams: ExtraParams;
	let cognitoStoreStrategy: CognitoStoreStrategy;
	let updateFn;
	let createFn;

	beforeEach(() => {
		profile = {
			emails: [{ value: existsEmail }],
		};

		extraParams = {};
		updateFn = jest.fn().mockImplementation(async () => {
			return { id: 'test' };
		});
		createFn = jest.fn().mockImplementation(async () => {
			return { id: 'test' };
		});

		container = {
			resolve: <T>(name: string): T => {
				const container_ = {
					manager: {
						transaction: function (cb) {
							return cb();
						},
					},
					customerService: {
						withTransaction: function () {
							return this;
						},
						create: createFn,
						update: updateFn,
						retrieveRegisteredByEmail: jest.fn().mockImplementation(async (email: string) => {
							if (email === existsEmail) {
								return {
									id: 'test',
								};
							}

							if (email === existsEmailWithMeta) {
								return {
									id: 'test2',
									metadata: {
										[CUSTOMER_METADATA_KEY]: true,
									},
								};
							}

							if (email === existsEmailWithMetaAndProviderKey) {
								return {
									id: 'test3',
									metadata: {
										[CUSTOMER_METADATA_KEY]: true,
										[AUTH_PROVIDER_KEY]: COGNITO_STORE_STRATEGY_NAME,
									},
								};
							}

							if (email === existsEmailWithMetaButWrongProviderKey) {
								return {
									id: 'test4',
									metadata: {
										[CUSTOMER_METADATA_KEY]: true,
										[AUTH_PROVIDER_KEY]: 'fake_provider_key',
									},
								};
							}

							return;
						}),
					},
				};

				return container_[name];
			},
		} as MedusaContainer;
	});

	describe('when strict is set to store', function () {
		beforeEach(() => {
			cognitoStoreStrategy = new CognitoStoreStrategy(
				container,
				{} as ConfigModule,
				{
					region: 'fakeRegion',
					accessKeyId: 'fake',
					secretAccessKey: 'fake',
					userPoolId: 'fake',
					clientId: 'fake',
					store: { callbackUrl: '/fakeCallbackUrl' },
				} as CognitoOptions,
				'store'
			);
		});

		afterEach(() => {
			jest.clearAllMocks();
		});

		it('should succeed', async () => {
			profile = {
				emails: [{ value: existsEmailWithMetaAndProviderKey }],
			};

			const data = await cognitoStoreStrategy.validate(req, accessToken, refreshToken, extraParams, profile);
			expect(data).toEqual(
				expect.objectContaining({
					id: 'test3',
				})
			);
		});

		it('should fail when the customer exists without the metadata', async () => {
			profile = {
				emails: [{ value: existsEmail }],
			};

			const err = await cognitoStoreStrategy
				.validate(req, accessToken, refreshToken, extraParams, profile)
				.catch((err) => err);
			expect(err).toEqual(new Error(`Customer with email ${existsEmail} already exists`));
		});

		it('should update customer metadata when the customer exsits with ONLY customer metadata key', async () => {
			profile = {
				emails: [{ value: existsEmailWithMeta }],
			};

			const data = await cognitoStoreStrategy.validate(req, accessToken, refreshToken, extraParams, profile);
			expect(data).toEqual(
				expect.objectContaining({
					id: 'test2',
				})
			);
			expect(updateFn).toHaveBeenCalledTimes(1);
		});

		it('should fail when the metadata exists but auth provider key is wrong', async () => {
			profile = {
				emails: [{ value: existsEmailWithMetaButWrongProviderKey }],
			};

			const err = await cognitoStoreStrategy
				.validate(req, accessToken, refreshToken, extraParams, profile)
				.catch((err) => err);
			expect(err).toEqual(
				new Error(`Customer with email ${existsEmailWithMetaButWrongProviderKey} already exists`)
			);
		});

		it('should succeed and create a new customer if it has not been found', async () => {
			profile = {
				emails: [{ value: 'fake' }],
				name: {
					givenName: 'test',
					familyName: 'test',
				},
			};

			const data = await cognitoStoreStrategy.validate(req, accessToken, refreshToken, extraParams, profile);
			expect(data).toEqual(
				expect.objectContaining({
					id: 'test',
				})
			);
			expect(createFn).toHaveBeenCalledTimes(1);
		});
	});

	describe('when strict is set to admin', function () {
		beforeEach(() => {
			cognitoStoreStrategy = new CognitoStoreStrategy(
				container,
				{} as ConfigModule,
				{
					region: 'fakeRegion',
					accessKeyId: 'fake',
					secretAccessKey: 'fake',
					userPoolId: 'fake',
					clientId: 'fake',
					store: { callbackUrl: '/fakeCallbackUrl' },
				} as CognitoOptions,
				'admin'
			);
		});

		afterEach(() => {
			jest.clearAllMocks();
		});

		it('should succeed', async () => {
			profile = {
				emails: [{ value: existsEmailWithMetaAndProviderKey }],
			};

			const data = await cognitoStoreStrategy.validate(req, accessToken, refreshToken, extraParams, profile);
			expect(data).toEqual(
				expect.objectContaining({
					id: 'test3',
				})
			);
		});

		it('should succeed when the customer exists without the metadata', async () => {
			profile = {
				emails: [{ value: existsEmail }],
			};

			const data = await cognitoStoreStrategy.validate(req, accessToken, refreshToken, extraParams, profile);
			expect(data).toEqual(
				expect.objectContaining({
					id: 'test',
				})
			);
		});

		it('should update customer metadata when the customer exsits with ONLY customer metadata key', async () => {
			profile = {
				emails: [{ value: existsEmailWithMeta }],
			};

			const data = await cognitoStoreStrategy.validate(req, accessToken, refreshToken, extraParams, profile);
			expect(data).toEqual(
				expect.objectContaining({
					id: 'test2',
				})
			);
			expect(updateFn).toHaveBeenCalledTimes(1);
		});

		it('should succeed when the metadata exists but auth provider key is wrong', async () => {
			profile = {
				emails: [{ value: existsEmailWithMetaButWrongProviderKey }],
			};

			const data = await cognitoStoreStrategy.validate(req, accessToken, refreshToken, extraParams, profile);
			expect(data).toEqual(
				expect.objectContaining({
					id: 'test4',
				})
			);
		});

		it('should succeed and create a new customer if it has not been found', async () => {
			profile = {
				emails: [{ value: 'fake' }],
				name: {
					givenName: 'test',
					familyName: 'test',
				},
			};

			const data = await cognitoStoreStrategy.validate(req, accessToken, refreshToken, extraParams, profile);
			expect(data).toEqual(
				expect.objectContaining({
					id: 'test',
				})
			);
			expect(createFn).toHaveBeenCalledTimes(1);
		});
	});
});
