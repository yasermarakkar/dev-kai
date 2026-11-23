import http from 'k6/http';
import { check } from 'k6';

export const options = {
  stages: [{ duration: '2m', target: 200 }, { duration: '5m', target: 200 }, { duration: '1m', target: 0 }],
  thresholds: { http_req_failed: ['rate<0.01'], http_req_duration: ['p(95)<300'] },
};

export default function () {
  const res = http.get(`${__ENV.BASE_URL}/v1/users?name=alice`);
  check(res, { ok: (r) => r.status === 200 });
}
