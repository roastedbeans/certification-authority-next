import Link from 'next/link';

export default function Home() {
	return (
		<main className='flex min-h-screen flex-col items-center justify-center p-24'>
			<h1 className='text-4xl font-bold mb-8'>Certification Authority</h1>
			<Link
				href='/security-dashboard'
				className='px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600'>
				Open Security Dashboard
			</Link>
		</main>
	);
}
