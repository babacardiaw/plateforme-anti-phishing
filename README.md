# 🛡️ Plateforme Anti-Phishing Locale

Plateforme de détection et de sensibilisation contre les attaques de phishing, développée dans le cadre de la formation en cybersécurité du programme Vacances Numériques de Force N.

## ✨ Fonctionnalités

- 🔍 **Détection d'URLs suspectes** : Analyse des patterns de phishing dans les URLs
- 📧 **Détection d'emails frauduleux** : Identification des emails de phishing
- 🌐 **Interface web intuitive** : Application Flask avec interface responsive
- 📊 **API REST** : Endpoint JSON pour l'analyse programmatique
- ⚡ **Détection en temps réel** : Analyse immédiate avec système de règles

## 🛠️ Technologies utilisées

- **Backend** : Python 3, Flask
- **Frontend** : HTML5, CSS3, JavaScript
- **Détection** : Expressions régulières, algorithmes de pattern matching
- **Environnement** : Virtualenv, pip

## 🚀 Installation et utilisation

### Prérequis
- Python 3.8+
- pip
- Git

### Installation
```bash
# Cloner le projet
git clone <url-du-projet>

# Se placer dans le dossier
cd PlateFormeAntiFishing

# Créer l'environnement virtuel
python -m venv venv

# Activer l'environnement
# Sur Windows :
.\venv\Scripts\activate
# Sur Mac/Linux :
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt