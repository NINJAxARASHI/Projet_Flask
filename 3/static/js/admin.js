function showAddUserModal() {
    document.getElementById('addUserModal').style.display = 'flex';
}

function hideAddUserModal() {
    document.getElementById('addUserModal').style.display = 'none';
}

document.getElementById('addUserForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const formData = {
        email: document.getElementById('email').value,
        password: document.getElementById('password').value,
        storage_limit: document.getElementById('storage_limit').value * 1024 * 1024 * 1024, // Convert to bytes
        is_admin: document.getElementById('is_admin').checked
    };
    
    try {
        const response = await fetch('/admin/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (data.success) {
            location.reload();
        } else {
            alert(data.message);
        }
    } catch (error) {
        alert('An error occurred');
    }
});

function showNotification(message, type = 'success') {
    const notif = document.getElementById('notification');
    notif.textContent = message;
    notif.className = `notification show ${type}`;
    setTimeout(() => {
        notif.classList.remove('show');
    }, 3500);
}

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user?')) {
        return;
    }
    const url = `/admin/users/${userId}`;
    console.log('Attempting to delete user with URL:', url);
    try {
        const response = await fetch(url, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin'
        });
        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);
        if (response.redirected) {
            console.log('Redirected to:', response.url);
            window.location.href = response.url;
            return;
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Response data:', data);
        if (data.success) {
            showNotification('User deleted successfully', 'success');
            setTimeout(() => location.reload(), 1200);
        } else {
            showNotification(data.message || 'Failed to delete user', 'error');
        }
    } catch (error) {
        console.error('Error details:', error);
        if (error.message.includes('<!DOCTYPE')) {
            showNotification('Your session has expired. Please log in again.', 'error');
            setTimeout(() => window.location.href = '/login', 1500);
        } else {
            showNotification('Error: ' + error.message, 'error');
        }
    }
}

// Ajout d'un event listener pour tous les boutons de suppression utilisateur
document.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', function() {
        const userId = this.getAttribute('data-user-id');
        deleteUser(userId);
    });
});