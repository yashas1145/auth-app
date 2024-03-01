function handleRegisterBtn() {
    document.getElementById("login").toggleAttribute("hidden");
    document.getElementById("register").toggleAttribute("hidden");
    
    let registerBtn = document.getElementById("register-btn");
    if (registerBtn.innerText == 'Not a user? Register') {
        registerBtn.innerText = 'Back to login page';
    } else if (registerBtn.innerText == 'Back to login page') {
        registerBtn.innerText = 'Not a user? Register';
    }
}