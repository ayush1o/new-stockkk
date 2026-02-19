const API_BASE = window.location.origin;

function getToken() {
    return localStorage.getItem('fidelityToken');
}

async function apiRequest(path, options = {}) {
    const token = getToken();
    const headers = {
        'Content-Type': 'application/json',
        ...(options.headers || {})
    };

    if (token) headers.Authorization = `Bearer ${token}`;

    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(data.error || 'Request failed');
    }
    return data;
}

const profileBtn = document.getElementById('profileBtn');
if (profileBtn) {
    profileBtn.addEventListener('click', () => {
        localStorage.removeItem('fidelityToken');
        localStorage.removeItem('fidelityUser');
        window.location.href = 'login.html';
    });
}

const signup = document.getElementById('signupForm');
if (signup) {
    signup.addEventListener('submit', async function (e) {
        e.preventDefault();

        const name = signup.querySelector('input[type="text"]').value.trim();
        const email = signup.querySelector('input[type="email"]').value.trim().toLowerCase();
        const passwords = signup.querySelectorAll('input[type="password"]');
        const password = passwords[0].value;
        const confirmPassword = passwords[1].value;

        if (password !== confirmPassword) {
            alert('Passwords do not match ❌');
            return;
        }

        try {
            const data = await apiRequest('/auth/signup', {
                method: 'POST',
                body: JSON.stringify({ name, email, password })
            });

            localStorage.setItem('fidelityToken', data.token);
            localStorage.setItem('fidelityUser', JSON.stringify(data.user));

            alert('Account Created ✅');
            window.location.href = 'index.html';
        } catch (error) {
            alert(error.message);
        }
    });
}

const login = document.getElementById('loginForm');
if (login) {
    login.addEventListener('submit', async function (e) {
        e.preventDefault();

        const email = login.querySelector('input[type="email"]').value.trim().toLowerCase();
        const password = login.querySelector('input[type="password"]').value;

        try {
            const data = await apiRequest('/auth/login', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });

            localStorage.setItem('fidelityToken', data.token);
            localStorage.setItem('fidelityUser', JSON.stringify(data.user));

            alert('Login Successful ✅');
            window.location.href = 'index.html';
        } catch (error) {
            alert(error.message || 'Invalid Login ❌');
        }
    });
}

const walletBtn = document.getElementById('walletBtn');
if (walletBtn) {
    walletBtn.onclick = async () => {
        try {
            const dashboard = await apiRequest('/dashboard');
            alert(`Wallet Balance: ₹${dashboard.wallet_balance}`);
        } catch (error) {
            alert(error.message);
        }
    };
}

const spinWheel = document.getElementById('spinWheel');
if (spinWheel) {
    spinWheel.onclick = async () => {
        try {
            const status = await apiRequest('/spin/status');
            if (!status.can_spin) {
                alert('Spin unavailable today or deactivated by admin.');
                return;
            }
            const result = await apiRequest('/spin/play', { method: 'POST', body: JSON.stringify({}) });
            alert(`Spin Result: ${result.reward.reward_name}`);
        } catch (error) {
            alert(error.message);
        }
    };
}
