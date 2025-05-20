document.querySelector('.toggle-password').addEventListener('click', function() {
    const passwordInput = document.querySelector('#password');
    const eyeIcon = this;
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        eyeIcon.style.opacity = '1';
    } else {
        passwordInput.type = 'password';
        eyeIcon.style.opacity = '0.7';
    }
});

// Ajout de la possibilité d'utiliser la touche Entrée pour l'œil
document.querySelector('.toggle-password').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        this.click();
    }
});