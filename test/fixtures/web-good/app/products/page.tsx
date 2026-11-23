import { format } from 'date-fns';

type Product = { id: string; name: string; updatedAt: string };

export default async function Products() {
  const products: Product[] = await fetch('https://api.example.com/products', { next: { revalidate: 60 } }).then((r) => r.json());
  return (
    <main id="main">
      <h1>Products</h1>
      <ul>
        {products.map((p) => (
          <li key={p.id}>
            <a href={`/products/${p.id}`}>{p.name}</a> <span>{format(new Date(p.updatedAt), 'PP')}</span>
          </li>
        ))}
      </ul>
    </main>
  );
}
