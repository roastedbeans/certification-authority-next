/** @type {import('next').NextConfig} */
const nextConfig = {
	async headers() {
		return [
			{
				source: '/(.*)',
				headers: [
					{ key: 'Access-Control-Allow-Credentials', value: 'true' },
					{ key: 'Access-Control-Allow-Origin', value: 'http://localhost:4000' },
					{ key: 'Access-Control-Allow-Origin', value: 'http://localhost:4200' },
					{ key: 'Access-Control-Allow-Methods', value: 'GET,DELETE,PATCH,POST,PUT' },
					{
						key: 'Access-Control-Allow-Headers',
						value:
							'access-control-allow-origin, Authorization, x-api-tran-id, X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version',
					},
				],
			},
		];
	},
};

export default nextConfig;
