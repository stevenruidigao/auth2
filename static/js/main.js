function goLogin() {
	window.location.href = "/login";
}

function login() {
	username = document.getElementById("username")
	password = document.getElementById("password")

	if (username != null && password != null) {
		POSTData("/api/auth/login", {"username": username.value, "passwordHash": password.value}).then(response => {
			if (response.success) {
				window.location.href = "/logged_in";
			}
		});
	}
}

function register() {
	username = document.getElementById("username")
	password = document.getElementById("password")

	if (username != null && password != null) {
		POSTData("/api/auth/register", {"username": username.value, "passwordHash": password.value}).then(response => {
			if (response.success) {
				window.location.href = "/registered";
			}
		});
	}
}

async function POSTData(url, data) {
	const response = await fetch(url, {
		method: 'POST',
		mode: 'cors', // no-cors, *cors, same-origin
		cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
		credentials: 'same-origin', // include, *same-origin, omit
		headers: {
			'Content-Type': 'application/json'
		},
		redirect: 'follow', // manual, *follow, error
		referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
		body: JSON.stringify(data)
	});

	return response.json(); // parses JSON response into native JavaScript objects
}
