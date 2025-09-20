// Fonctions utilitaires pour la plateforme anti-phishing
document.addEventListener('DOMContentLoaded', function() {
    // Validation du formulaire de détection
    const detectionForm = document.getElementById('detection-form');
    if (detectionForm) {
        detectionForm.addEventListener('submit', function(e) {
            const urlInput = document.getElementById('url');
            if (!isValidUrl(urlInput.value)) {
                e.preventDefault();
                alert('Veuillez entrer une URL valide (commençant par http:// ou https://)');
                urlInput.focus();
            }
        });
    }

    // Fonctionnalité de copie d'URL
    const copyButtons = document.querySelectorAll('.copy-url');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const urlToCopy = this.getAttribute('data-url');
            copyToClipboard(urlToCopy);
            this.textContent = '✓ Copié!';
            setTimeout(() => {
                this.textContent = 'Copier';
            }, 2000);
        });
    });

    // Animation des résultats
    const verdictElement = document.querySelector('.verdict');
    if (verdictElement) {
        verdictElement.style.opacity = '0';
        setTimeout(() => {
            verdictElement.style.transition = 'opacity 0.5s ease-in';
            verdictElement.style.opacity = '1';
        }, 300);
    }
});

// Validation d'URL
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Copie dans le presse-papier
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        console.log('URL copiée dans le presse-papier');
    }).catch(err => {
        console.error('Erreur lors de la copie: ', err);
    });
}

// Fonction pour analyser une URL via l'API (si vous en créez une)
async function analyzeUrl(url) {
    try {
        const response = await fetch('/api/detect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        return await response.json();
    } catch (error) {
        console.error('Erreur:', error);
        return { error: 'Échec de l\'analyse' };
    }
}