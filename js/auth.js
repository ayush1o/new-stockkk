/* ================= PROFILE CLICK ================= */

const profileBtn = document.getElementById("profileBtn");

if (profileBtn) {
    profileBtn.addEventListener("click", () => {
        window.location.href = "login.html";
    });
}


/* ================= SIGNUP ================= */

const signup = document.getElementById("signupForm");

if (signup) {
    signup.addEventListener("submit", function (e) {
        e.preventDefault();

        const email = signup.querySelector('input[type="email"]').value;
        const password = signup.querySelectorAll('input[type="password"]')[0].value;

        localStorage.setItem("fidelityUser", JSON.stringify({
            email,
            password
        }));

        alert("Account Created ✅");
        window.location.href = "login.html";
    });
}


/* ================= LOGIN ================= */

const login = document.getElementById("loginForm");

if (login) {
    login.addEventListener("submit", function (e) {
        e.preventDefault();

        const email = login.querySelector('input[type="email"]').value;
        const password = login.querySelector('input[type="password"]').value;

        const savedUser = JSON.parse(localStorage.getItem("fidelityUser"));

        if (savedUser &&
            savedUser.email === email &&
            savedUser.password === password) {

            alert("Login Successful ✅");
            window.location.href = "index.html";

        } else {
            alert("Invalid Login ❌");
        }
    });
}
document.getElementById("walletBtn").onclick = () => {
    window.location.href = "wallet.html";
};

document.getElementById("spinWheel").onclick = () => {
    window.location.href = "spin.html";
};

