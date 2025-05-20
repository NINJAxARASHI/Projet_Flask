document.addEventListener('DOMContentLoaded', function() {
    // Gestion de l'arborescence des dossiers
    const folderToggles = document.querySelectorAll('.folder-toggle');
    
    folderToggles.forEach(toggle => {
        toggle.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const folderItem = this.closest('.folder');
            folderItem.classList.toggle('expanded');
        });
    });
    
    // Gestion des modales
    const newFolderBtn = document.getElementById('new-folder-btn');
    const uploadBtn = document.getElementById('upload-btn');
    const newFolderModal = document.getElementById('new-folder-modal');
    const uploadModal = document.getElementById('upload-modal');
    const closeButtons = document.querySelectorAll('.close-modal, .cancel-btn');
    
    if (newFolderBtn) {
        newFolderBtn.addEventListener('click', function() {
            newFolderModal.classList.add('show');
        });
    }
    
    if (uploadBtn) {
        uploadBtn.addEventListener('click', function() {
            uploadModal.classList.add('show');
        });
    }
    
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const modal = this.closest('.modal');
            modal.classList.remove('show');
        });
    });
    
    // Fermer la modale si on clique en dehors
    window.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            e.target.classList.remove('show');
        }
    });
    
    // Gestion de la suppression des dossiers
    const deleteFolderButtons = document.querySelectorAll('.delete-folder');
    
    deleteFolderButtons.forEach(button => {
        button.addEventListener('click', function() {
            const folderId = this.getAttribute('data-id');
            if (confirm('Êtes-vous sûr de vouloir supprimer ce dossier ? Cette action est irréversible.')) {
                // Créer un formulaire pour envoyer la demande de suppression
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = window.location.pathname;
                
                const actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'delete_folder';
                
                const folderIdInput = document.createElement('input');
                folderIdInput.type = 'hidden';
                folderIdInput.name = 'folder_id';
                folderIdInput.value = folderId;
                
                form.appendChild(actionInput);
                form.appendChild(folderIdInput);
                document.body.appendChild(form);
                form.submit();
            }
        });
    });
    
    // Gestion de la suppression des fichiers
    const deleteFileButtons = document.querySelectorAll('.delete-file');
    
    deleteFileButtons.forEach(button => {
        button.addEventListener('click', function() {
            const fileId = this.getAttribute('data-id');
            if (confirm('Êtes-vous sûr de vouloir supprimer ce fichier ? Cette action est irréversible.')) {
                // Créer un formulaire pour envoyer la demande de suppression
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = window.location.pathname;
                
                const actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'delete_file';
                
                const fileIdInput = document.createElement('input');
                fileIdInput.type = 'hidden';
                fileIdInput.name = 'file_id';
                fileIdInput.value = fileId;
                
                form.appendChild(actionInput);
                form.appendChild(fileIdInput);
                document.body.appendChild(form);
                form.submit();
            }
        });
    });
});