// Toggle password visibility
document.addEventListener('DOMContentLoaded', function() {
    const togglePassword = document.querySelector('.toggle-password');
    if (togglePassword) {
        togglePassword.addEventListener('click', function() {
            const passwordInput = document.querySelector('#password');
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            
            // Update icon
            const img = this.querySelector('img');
            if (type === 'password') {
                img.src = '/static/images/eye-icon.svg';
            } else {
                img.src = '/static/images/eye-off-icon.svg';
            }
        });
    }

    // File deletion handling
    const deleteButtons = document.querySelectorAll('.delete-file');
    const deleteModal = document.getElementById('deleteModal');
    if (deleteButtons.length && deleteModal) {
        let fileToDelete = null;
        const modal = new bootstrap.Modal(deleteModal);

        deleteButtons.forEach(button => {
            button.addEventListener('click', function() {
                fileToDelete = this.dataset.fileId;
                modal.show();
            });
        });

        document.getElementById('confirmDelete').addEventListener('click', function() {
            if (fileToDelete) {
                fetch(`/api/files/${fileToDelete}`, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrf_token')
                    }
                })
                .then(response => {
                    if (response.ok) {
                        // Remove file element from DOM
                        const fileElement = document.querySelector(`[data-file-id="${fileToDelete}"]`).closest('.file-item');
                        fileElement.remove();
                        // Show success message
                        showNotification('File deleted successfully', 'success');
                    } else {
                        throw new Error('Failed to delete file');
                    }
                })
                .catch(error => {
                    showNotification('Error deleting file', 'error');
                })
                .finally(() => {
                    modal.hide();
                    fileToDelete = null;
                });
            }
        });
    }

    // User deletion handling
    const deleteUserButtons = document.querySelectorAll('.delete-user');
    const deleteUserModal = document.getElementById('deleteUserModal');
    if (deleteUserButtons.length && deleteUserModal) {
        let userToDelete = null;
        const modal = new bootstrap.Modal(deleteUserModal);

        deleteUserButtons.forEach(button => {
            button.addEventListener('click', function() {
                userToDelete = this.dataset.userId;
                modal.show();
            });
        });

        document.getElementById('confirmDeleteUser').addEventListener('click', function() {
            if (userToDelete) {
                fetch(`/admin/users/${userToDelete}`, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrf_token')
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Remove user element from DOM
                        const userElement = document.querySelector(`[data-user-id="${userToDelete}"]`).closest('.user-item');
                        if (userElement) {
                            userElement.remove();
                        } else {
                            // Reload page if element not found (fallback)
                            window.location.reload();
                        }
                        showNotification('User deleted successfully', 'success');
                    } else {
                        throw new Error(data.message || 'Failed to delete user');
                    }
                })
                .catch(error => {
                    showNotification(error.message || 'Error deleting user', 'error');
                })
                .finally(() => {
                    modal.hide();
                    userToDelete = null;
                });
            }
        });
    }
});

// Helper function to get CSRF token from cookies
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show notification-toast`;
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// File upload handling
const fileUploadForm = document.getElementById('fileUploadForm');
if (fileUploadForm) {
    fileUploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(this);
        const progressBar = document.querySelector('.progress-bar');
        const uploadButton = this.querySelector('button[type="submit"]');
        
        // Disable button and show progress
        uploadButton.disabled = true;
        progressBar.style.width = '0%';
        progressBar.parentElement.classList.remove('d-none');
        
        fetch(this.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRFToken': getCookie('csrf_token')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('File uploaded successfully', 'success');
                // Redirect to browse page or refresh file list
                window.location.href = data.redirect_url;
            } else {
                throw new Error(data.message || 'Upload failed');
            }
        })
        .catch(error => {
            showNotification(error.message, 'error');
        })
        .finally(() => {
            // Reset form and UI
            uploadButton.disabled = false;
            progressBar.parentElement.classList.add('d-none');
            this.reset();
        });
    });
}