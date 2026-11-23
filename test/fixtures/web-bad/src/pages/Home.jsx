import moment from 'moment';
import _ from 'lodash';
import { motion } from 'framer-motion';

export default function Home() {
  return (
    <main>
      <h1>Welcome</h1>
      <h4>Updated {moment().fromNow()}</h4>
      <img src="/hero.png" />
      <motion.div animate={{ scale: 1.2 }} className="text-gray-400">Big sale</motion.div>
      <form>
        <input type="email" placeholder="Email" />
        <button type="submit">Subscribe</button>
      </form>
      <div className="card" onClick={() => alert('open')}>Open offer</div>
      <a href="#" onClick={() => window.history.back()}>Back</a>
      <button onClick={() => close()}>
        <svg viewBox="0 0 10 10"><path d="M0 0L10 10" /></svg>
      </button>
      <p>{_.capitalize('hello')}</p>
    </main>
  );
}
