import { useEffect, useState } from 'react';

export default function Products() {
  const [items, setItems] = useState([]);
  useEffect(() => {
    fetch('/api/products').then((r) => r.json()).then(setItems);
  });
  return (
    <ul>
      {items.map((p) => <li onClick={() => select(p)}>{p.name}</li>)}
    </ul>
  );
}
