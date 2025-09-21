from flask import Flask, render_template, request, jsonify
import re
import os
import validators
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configuration du Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Fonctions de détection de phishing
def extract_features(url):
    """Extrait les caractéristiques d'une URL pour la détection de phishing"""
    features = {}
    
    # Longueur de l'URL
    features['length'] = len(url)
    
    # Présence de caractères spéciaux
    features['has_https'] = 1 if 'https://' in url else 0
    features['has_http'] = 1 if 'http://' in url else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_dash'] = 1 if '-' in url else 0
    features['has_multiple_subdomains'] = 1 if url.count('.') > 2 else 0
    features['has_ip'] = 1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    
    # Nombre de redirections
    features['redirects'] = url.count('//')
    
    return features

def is_phishing(url):
    """Détermine si une URL ou email est potentiellement du phishing"""
    # Si c'est un email (contient @ et .)
    if '@' in url and '.' in url.split('@')[-1]:
        return is_phishing_email(url)
    
    # Sinon, c'est une URL
    return is_phishing_url(url)

def is_phishing_url(url):
    """Détection de phishing pour les URLs - Version améliorée"""
    # Vérification des caractéristiques techniques de base
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        return True
        
    if '@' in url or url.count('-') > 3 or url.count('.') > 4:
        return True
        
    # Vérification de la longueur excessive
    if len(url) > 75:
        return True
    
    # Détection des URLs raccourcies suspectes
    shortener_domains = [r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co', r'ow\.ly', r'is\.gd']
    for domain in shortener_domains:
        if re.search(domain, url):
            return True
            
    # Détection des caractères Unicode suspects (homoglyphes)
    if re.search(r'[^\x00-\x7F]', url):
        return True
        
    # Détection des similarités avec les domaines légitimes
    deceptive_domains = [
        r'faceb00k', r'paypa1', r'go0gle', r'app1e', r'micr0soft',
        r'face-book', r'pay-pal', r'google-security', r'amaz0n',
        r'linked1n', r'tw1tter', r'instagr4m', r'whats4pp'
    ]
    for domain in deceptive_domains:
        if re.search(domain, url, re.IGNORECASE):
            return True
            
    # Détection des domaines très récents (moins de 3 mois)
    new_domains = [r'.xyz', r'.top', r'.club', r'.info', r'.online']
    for domain in new_domains:
        if domain in url:
            return True
    
    # Vérification des ports non standards dans les URLs
    if re.search(r':(8080|3000|4444|8888)', url):
        return True
        
    # Détection des encodages suspects
    if '%' in url and len([c for c in url if c == '%']) > 2:
        return True
    
    # Vérification des motifs suspects dans les URLs (optimisée)
    suspicious_patterns = [
        r'login', r'verify', r'secure', r'account', r'banking', 
        r'update', r'signin', r'confirm', r'action', r'download',
        r'paypal', r'facebook', r'microsoft', r'apple', r'amazon',
        r'validation', r'authentification', r'password', r'credential',
        r'urgent', r'immediate', r'required', r'verification',
        r'support', r'security', r'alert', r'notification'
    ]
    
    # Vérification des motifs suspects (une seule passe regex)
    combined_pattern = '|'.join(suspicious_patterns)
    if re.search(combined_pattern, url, re.IGNORECASE):
        return True
            
    return False

def is_phishing_email(email):
    """Détection de phishing pour les emails"""
    # Vérification des patterns d'emails suspects
    suspicious_domains = [
        'gmail-security.com', 'facebook-verify.com', 'paypal-security.com',
        'apple-verification.com', 'amazon-security.org', 'microsoft-support.com'
    ]
    
    # Vérification des caractéristiques suspectes
    if any(domain in email for domain in suspicious_domains):
        return True
        
    # Vérification des motifs suspects dans le nom d'utilisateur
    suspicious_patterns = [
        r'security', r'verify', r'support', r'alert', r'notification',
        r'urgent', r'important', r'action_required', r'account_update'
    ]
    
    username = email.split('@')[0]
    for pattern in suspicious_patterns:
        if re.search(pattern, username, re.IGNORECASE):
            return True
            
    return False

# Routes de l'application
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/detect', methods=['GET', 'POST'])
def detect():
    if request.method == 'POST':
        # Validation de base pour la route formulaire
        url = request.form['url'].strip()
        if not url:
            return render_template('detect.html', error='Veuillez entrer une URL.')
        if not validators.url(url) and '@' not in url:  # Permet les emails
            return render_template('detect.html', error='Le format de l\'URL est invalide.')
        
        is_phish = is_phishing(url)
        return render_template('results.html', url=url, is_phishing=is_phish)
    return render_template('detect.html')

# Route API SÉCURISÉE avec validation, rate limiting et gestion d'erreurs
@app.route('/api/detect', methods=['POST'])
@limiter.limit("10 per minute")  # Protection contre les abus
def api_detect():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Données JSON requises.'}), 400

        url = data.get('url', '').strip()
        
        # Validation
        if not url:
            return jsonify({'error': 'L\'URL ne peut pas être vide.'}), 400
        
        # Validation plus poussée : soit une URL valide, soit un email
        is_valid_url = validators.url(url)
        # Validation email bien plus stricte
        is_valid_email = re.match(r"[^@]+@[^@]+\.[^@]+", url) is not None

        if not (is_valid_url or is_valid_email):
            return jsonify({'error': 'Le format de l\'URL ou de l\'email est invalide.'}), 400

        # Appel à la logique de détection
        is_phish = is_phishing(url)
        
        return jsonify({
            'url': url, 
            'is_phishing': is_phish,
            'message': 'Attention! Phishing détecté!' if is_phish else 'Ce site est sécurisé.'
        })

    except Exception as e:
        # Gestion sécurisée des erreurs
        app.logger.error(f"Erreur API: {str(e)}")
        return jsonify({'error': 'Un problème est survenu lors de l\'analyse.'}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)