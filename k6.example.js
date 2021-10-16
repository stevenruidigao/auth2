import http from 'k6/http';
import { sleep } from 'k6';

export default function () {
	http.post('http://localhost:8080/api/auth/login', JSON.stringify({
		username: 'test',
		passwordHash: 'test'
	}), {
		headers: {
			'Content-Type': 'application/json',
		},
	});

	sleep(0.1);
}
