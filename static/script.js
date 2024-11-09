document.addEventListener('DOMContentLoaded', function() {
    const uploadForm = document.getElementById('upload-form');
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');

    if (uploadForm) {
        const fileInput = document.getElementById('file-upload');
        const fileName = document.getElementById('file-name');
        const analysisResult = document.getElementById('analysis-result');

        fileInput.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                fileName.textContent = `Selected file: ${e.target.files[0].name}`;
            } else {
                fileName.textContent = '';
            }
        });

        uploadForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!fileInput.files.length) {
                return;
            }

            const file = fileInput.files[0];
            
            if (file.size > 10 * 1024 * 1024) {
                alert('File size exceeds 10MB limit');
                return;
            }

            analysisResult.style.display = 'block';
            analysisResult.textContent = 'Analyzing...';
            analysisResult.style.backgroundColor = '#f0f0f0';

            const formData = new FormData();
            formData.append('image', file);

            try {
                const response = await fetch('/detect', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.error) {
                    analysisResult.textContent = `Error: ${data.error}`;
                    analysisResult.style.backgroundColor = '#ffe6e6';
                } else {
                    const probability = (data.fake_probability * 100).toFixed(2);
                    if (probability > 50) {
                        analysisResult.textContent = `This image is likely a deepfake (${probability}% probability)`;
                        analysisResult.style.backgroundColor = '#ffe6e6';
                    } else {
                        analysisResult.textContent = `This image appears to be authentic (${probability}% fake probability)`;
                        analysisResult.style.backgroundColor = '#e6ffe6';
                    }
                }
            } catch (error) {
                analysisResult.textContent = `Error: ${error.message}`;
                analysisResult.style.backgroundColor = '#ffe6e6';
            }
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams(new FormData(loginForm))
                });
                if (response.redirected) {
                    window.location.href = response.url;
                }
            } catch (error) {
                console.error('Login failed:', error);
            }
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            try {
                const response = await fetch('/signup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams(new FormData(signupForm))
                });
                if (response.redirected) {
                    window.location.href = response.url;
                }
            } catch (error) {
                console.error('Signup failed:', error);
            }
        });
    }

    const hamburger = document.querySelector('.hamburger');
    const mobileMenu = document.querySelector('.mobile-menu');
    const closeMenu = document.querySelector('.close-menu');

    if (hamburger && mobileMenu && closeMenu) {
        hamburger.addEventListener('click', () => {
            mobileMenu.classList.add('active');
            mobileMenu.style.display = 'block';
        });

        closeMenu.addEventListener('click', () => {
            mobileMenu.classList.remove('active');
            setTimeout(() => {
                mobileMenu.style.display = 'none';
            }, 300);
        });
    }
});
