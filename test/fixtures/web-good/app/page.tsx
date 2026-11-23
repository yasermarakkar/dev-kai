import Image from 'next/image';
import Script from 'next/script';
import { CloseButton } from '../components/CloseButton';

export default function Home() {
  return (
    <main id="main">
      <h1>Welcome</h1>
      <h2>New this week</h2>
      <Image src="/hero.webp" alt="Customers trying on the autumn collection" width={1200} height={600} priority />
      <form>
        <label htmlFor="email">Email</label>
        <input id="email" type="email" autoComplete="email" />
        <button type="submit">Subscribe</button>
      </form>
      <CloseButton />
      <Script src="https://cdn.example-analytics.com/tag.js" strategy="lazyOnload" />
    </main>
  );
}
