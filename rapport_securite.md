# 🔐 Rapport de Sécurité - Plateforme Anti-Phishing Force N

## Mesures de Sécurité Implémentées

### 1. 🔒 Sécurité des Données et Authentification
- Clé secrète sécurisée via variables d'environnement
- Connexion PostgreSQL sécurisée avec isolation des credentials

### 2. 🛡️ Protection contre les Attaques Web
- **Rate Limiting** : 200 requêtes/jour, 50 requêtes/heure
- **API Limiting** : 10 requêtes/minute pour l'endpoint /api/detect
- Validation stricte des URLs et emails

### 3. 🗄️ Sécurité Base de Données
- PostgreSQL avec connexions sécurisées
- Protection contre les injections SQL avec paramètres sécurisés
- Tables isolées : quiz_results et url_submissions

### 4. 📧 Algorithmes de Détection Anti-Phishing
- Détection d'IP addresses directes dans les URLs
- Identification des domaines trompeurs (faceb00k, paypa1)
- Détection des URLs raccourcies (bit.ly, tinyurl)
- Analyse des patterns d'emails frauduleux

### 5. 👤 Gestion des Sessions et Tracking
- Journalisation des activités utilisateur
- Sessions Flask sécurisées
- Tracking des soumissions pour statistiques

## Tests de Sécurité Réalisés
- ✅ Validation des inputs utilisateur
- ✅ Protection contre le brute force
- ✅ Prévention des injections SQL
- ✅ Détection de patterns de phishing

---

**Développé par :** Babacar DIAW
**Formation :** Vacances Numériques - Force N