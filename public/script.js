document.addEventListener('DOMContentLoaded', () => {
    // Elementos del DOM
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const showLogin = document.getElementById('showLogin');
    const showRegister = document.getElementById('showRegister');
    
    // Cambiar entre formularios
    showRegister.addEventListener('click', (e) => {
        e.preventDefault();
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
    });
    
    showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        registerForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
    });
    
    // Manejar registro
    document.getElementById('register').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const nombre = document.getElementById('nombre').value;
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPassword').value;
        
        try {
            // **CORRECCIÓN AQUÍ: USAR RUTA RELATIVA**
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ nombre, email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                alert('¡Registro exitoso! Bienvenido al camino místico');
                registerForm.classList.add('hidden');
                loginForm.classList.remove('hidden');
            } else {
                alert(data.mensaje);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Error en el registro');
        }
    });
    
    // Manejar login con soporte para administrador
    document.getElementById('login').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        try {
            // **CORRECCIÓN AQUÍ: USAR RUTA RELATIVA**
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                console.log('Login exitoso, token guardado en cookie');
                
                // Verificar si es administrador y redirigir accordingly
                if (data.isAdmin) {
                    console.log('Redirigiendo al panel de administración');
                    window.location.href = data.redirect; // Esto será '/admin'
                } else {
                    console.log('Redirigiendo al dashboard de usuario');
                    window.location.href = data.redirect; // Esto será '/dashboard'
                }
            } else {
                alert(data.mensaje);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Error en el inicio de sesión');
        }
    });
});
