function goToRegister() {
    window.location.href = 'register.html';
}

function goToForgotPassword() {
    window.location.href = 'forgot-password.html';
}

function goToLogin() {
    window.location.href = 'index.html';
}

function goToPdf() {
    window.location.href = 'pdf.html';
}
function goToDashboard() {
    window.location.href = 'dashboard.html';
}

function showToast(msg) {
    const toast = document.createElement('div');
    toast.classList.add('toast');
    toast.textContent = msg;

    document.body.appendChild(toast);

    // Automatically remove the toast after a certain duration (e.g., 3 seconds)
    setTimeout(function() {
        toast.remove();
    }, 3000);
}

async function registerUser(email, password, username) {
    const requestBody = {
        username : username,
        password: password,
        email: email,
        first_name: "jane",
        last_name : "doe"
    };

    const fetchOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': '*/*'
        },
        body: JSON.stringify(requestBody)
    };

    console.log('Request Body:', requestBody);
    console.log('Fetch Options:', fetchOptions);

    try {
        const response = await fetch('http://95.214.177.119/user/register', fetchOptions);

        if (!response.ok) {
            const errorText = await response.text(); // Get the error response text
            throw new Error(`HTTP error! Status: ${response.status} Response: ${errorText}`);
        }

        const data = await response.json();

        if (data.success) {
            // Store the token in session storage
            sessionStorage.setItem('accessToken', data.access_token);
            // Redirect to the PDF page on successful login
            goToLogin();
        } else {
            // Handle login failure
            showToast(data.message || 'Login failed. Please try again.');
        }

        return data;
    } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred. Please try again.');
        throw error; // Rethrow the error to be caught by the caller if needed
    }
}

function checkRegister() {
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;
    var confirmPassword = document.getElementById('passwordNew').value;
    var username = document.getElementById('username').value;

    // Store email, password, and confirmPassword in session storage
    sessionStorage.setItem('registerEmail', email);
    sessionStorage.setItem('registerPassword', password);
    sessionStorage.setItem('confirmPassword', confirmPassword);
    sessionStorage.setItem('registerUsername', username);

    
    if (password == confirmPassword) {
        console.log("trying to register")
        registerUser(email, password, username)
    } else {
        showToast("Passwords do not match");
    }
}

async function loginUser(email, password) {
    const requestBody = {
        username: email,
        password: password
    };

    const fetchOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': '*/*'
        },
        body: JSON.stringify(requestBody)
    };

    console.log('Request Body:', requestBody);
    console.log('Fetch Options:', fetchOptions);

    try {
        const response = await fetch('http://95.214.177.119/user/login', fetchOptions);

        if (!response.ok) {
            const errorText = await response.text(); // Get the error response text
            throw new Error(`HTTP error! Status: ${response.status} Response: ${errorText}`);
        }

        const data = await response.json();

        if (data.success && data.pdf_uploaded) {
            // Store the token in session storage
            sessionStorage.setItem('accessToken', data.access_token);
            // Redirect to the PDF page on successful login
            goToDashboard();
        } 
        else if(data.success && !data.pdf_uploadedata){
            // Store the token in session storage
            sessionStorage.setItem('accessToken', data.access_token);
            // Redirect to the dashboard since the pdf is already uploaded before
            goToPdf();
        }
        else {
            // Handle login failure
            showToast(data.message || 'Login failed. Please try again.');
        }

        return data;
    } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred. Please try again.');
        throw error; // Rethrow the error to be caught by the caller if needed
    }
}

function checkLogin() {
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;

    sessionStorage.setItem('registerEmail', email);
    sessionStorage.setItem('registerPassword', password);
 
    console.log("trying to login");
    loginUser(email, password); // Call the loginUser function with email and password
    
}
