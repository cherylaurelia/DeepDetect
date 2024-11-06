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

        uploadForm.addEventListener('submit', function(e) {
            e.preventDefault();
            if (fileInput.files.length > 0) {
                analysisResult.style.display = 'block';
                analysisResult.textContent = 'Analyzing...';
                analysisResult.style.backgroundColor = '#f0f0f0';

                // analysis
                setTimeout(() => {
                    const isReal = Math.random() > 0.5;
                    if (isReal) {
                        analysisResult.textContent = 'This video appears to be authentic.';
                        analysisResult.style.backgroundColor = '#e6ffe6';
                    } else {
                        analysisResult.textContent = 'This video may be a deepfake.';
                        analysisResult.style.backgroundColor = '#ffe6e6';
                    }
                }, 3000);
            }
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            setTimeout(() => {
                alert(`Login attempt with email: ${email}`);
                // send this data to a server for authentication
            }, 1000);
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            //  signup
            setTimeout(() => {
                alert(`Signup attempt with name: ${name} and email: ${email}`);
                // send this data to a server to create a new account
            }, 1000);
        });
    }
});
