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

function checkEmail(email){
    if (email.indexOf('@') === -1) {
        return false; // Email does not contain "@"
    }
    if (email.length < 6) {
        return false; // Email is too short
    }

    return true;
}

function registerUser(email, password){
    //register api call
    goToLogin();
}

function checkRegister(){
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;
    var confirmPassword = document.getElementById('passwordNew').value;

    // Store email, password, and confirmPassword in session storage
    sessionStorage.setItem('registerEmail', email);
    sessionStorage.setItem('registerPassword', password);
    sessionStorage.setItem('confirmPassword', confirmPassword);

    if(!checkEmail(email)){
        showToast("Enter a valid email");
    }
    else if(password == "" || password.length < 5){
        showToast("Please enter a valid password");
    }
    else if(password == confirmPassword){
        console.log(password, " ", confirmPassword)
        console.log("trying to register")
        registerUser(email, password)
    }
    else{
        showToast("Passwords does not match");
    }
}

function loginUser(email, password){
    //login api call
    goToDashboard(); //if login is succesfull
}

function checkLogin(){
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;

    sessionStorage.setItem('registerEmail', email);
    sessionStorage.setItem('registerPassword', password);

    if(!checkEmail(email)){
        showToast("Enter a valid email");
    }
    else if(password == "" || password.length < 5){
        showToast("Please enter a valid password");
    }
    else{
        console.log("trying to login")
        goToPdf();
    }
}