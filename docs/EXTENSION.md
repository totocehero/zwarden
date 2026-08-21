# Décisions d'ergonomie et de sécurité de l'extension

Ce document fixe les décisions de conception de l'extension **avant** que le
code d'interface n'existe, avec le même sérieux que `CRYPTO.md` fixe le schéma
cryptographique. Chaque section énonce une règle et sa raison ; s'en écarter
demandera un argument, pas un oubli.

---

## 1. Déverrouillage

**La dérivation s'exécute dans le service worker, jamais dans la popup.**
Fermer la popup ne doit pas annuler un déverrouillage en cours, et le matériel
de clé n'a rien à faire dans un contexte d'interface. La popup envoie le mot de
passe au worker, affiche la progression, et reçoit un signal de succès — pas de
clé.

**Le chemin de déverrouillage est unique : `core/vault/unlock()`.**
L'enchaînement prelogin → dérivation → hashs → login → étirement → déballage,
avec l'effacement des clés intermédiaires, est écrit et audité une fois.
Aucun autre code ne recompose cette chorégraphie.

**Déverrouillage hors ligne.** Le premier déverrouillage réussi conserve
localement : le hash `LocalAuthorization`, la clé de coffre enveloppée et les
paramètres KDF validés. Serveur injoignable ⇒ validation par
`verifyLocalPasswordHash` (comparaison à temps constant sur les octets, jamais
`===` sur le base64) puis ouverture sur le dernier état synchronisé. Un
gestionnaire de mots de passe inaccessible pendant une panne serveur est
rédhibitoire.

**Erreurs distinctes à l'écran.** Mot de passe incorrect, limitation de débit
(avec le délai), second facteur requis, captcha requis, serveur injoignable,
KDF refusé : chaque cas a son message. Le routage se fait sur le champ
`code` des erreurs, jamais sur les messages (qui servent aux journaux).

## 2. Cycle de verrouillage

- L'état déverrouillé vit dans `chrome.storage.session` (mémoire seulement) :
  fermeture du navigateur ⇒ verrouillage, gratuitement.
- Minuteur d'inactivité via `chrome.alarms` — le seul mécanisme qui survit à la
  mort du service worker MV3 — configurable, avec verrouillage manuel toujours
  accessible.
- Verrouiller = `userKey.destroy()` **et** purge de `chrome.storage.session`.
  Les deux, systématiquement.
- Le jeton d'accès expirant (~1 h) se renouvelle par `refreshToken()` — jamais
  en redemandant le mot de passe.

## 3. Popup — deux vues commutables

| | Vue « Bitwarden-like » | Vue « Zwarden » |
|---|---|---|
| Public | Migrants de l'extension officielle | Usage quotidien au clavier |
| Ouverture | Liste complète, onglets classiques | Filtrée sur le domaine de l'onglet actif |
| Navigation | Souris d'abord | Recherche focalisée, flèches + Entrée |

Les deux vues sont deux rendus Preact du **même view-model**
(`core/vault/cipherService`) ; le choix est une préférence persistée. Aucune
logique de coffre dans les composants.

Règles communes :

- **Déchiffrement partiel** : au déverrouillage, seuls noms et URIs sont
  déchiffrés (`CipherOverview`). Mot de passe, TOTP et notes le sont à
  l'ouverture de l'item (`CipherDetails`). Latence d'ouverture minimale, moins
  de secrets en clair simultanément.
- **Presse-papiers effacé ~30 s** après la copie d'un secret.
- Mot de passe masqué par défaut ; révélation sur geste explicite.

## 4. Autofill — règles non négociables

Pendant de « MAC avant déchiffrement » côté extension. Deux règles, connues
pour avoir fait défaut à d'autres gestionnaires :

1. **Jamais de remplissage sans geste utilisateur.** Le remplissage
   automatique silencieux est le vecteur classique d'exfiltration par
   formulaire invisible : une page compromise pose un champ caché, le
   gestionnaire le remplit, le script l'exfiltre. Remplir exige un clic sur la
   suggestion ou un raccourci clavier.
2. **Correspondance d'URI par origine** (schéma + hôte + port), jamais par
   sous-chaîne. Un matching laxiste livre les identifiants de `banque.fr` à
   `banque.fr.attaquant.com`. Le matching par domaine de base exigerait la
   Public Suffix List (inacceptable pour le budget de poids) ; l'origine
   stricte est sûre sans elle.

Architecture en deux étages (cf. README) : détecteur léger à `document_start`,
moteur injecté seulement si un champ pertinent existe, et uniquement dans les
pages `http(s)`.

**État : v1 en place.** Le bouton « Remplir » de la popup injecte à la demande
(`chrome.scripting`, cadre principal seulement) un remplisseur qui respecte
les deux règles : geste explicite obligatoire, bouton visible uniquement quand
l'origine de l'item correspond à celle de l'onglet (`uriMatch.ts`), et
revérifiée au moment du clic. Restent pour la v2 : le détecteur en page, la
suggestion inline et les iframes.

## 4 bis. Raccourcis clavier — parité avec l'extension officielle

Pour que la vue « Bitwarden-like » aille au bout de sa promesse, les
raccourcis par défaut reprennent ceux de l'extension officielle (relevés dans
son manifest 2026.7.0) :

| Commande | Raccourci |
|---|---|
| Ouvrir la popup | `Ctrl+Shift+Y` (`Ctrl+Shift+U` sous Linux) |
| Autofill identifiants | `Ctrl+Shift+L` |
| Générer un mot de passe | `Ctrl+Shift+9` |
| Verrouiller le coffre | sans défaut, configurable |

## 4 ter. Manifest — notes relevées sur l'extension officielle

- **CSP** : exécuter du WASM en MV3 exige
  `script-src 'self' 'wasm-unsafe-eval'`. Le module Argon2id (hash-wasm) en a
  besoin — sans cette directive, le déverrouillage Argon2id échouera en
  production alors qu'il passe en tests Node.
- **Permissions** : l'officielle demande 16 permissions dont `webRequest`,
  `tabs`, `unlimitedStorage` et `http(s)://*/*`. Zwarden vise le minimum :
  `storage`, `alarms`, `activeTab`, `scripting`, `clipboardWrite`, plus les
  hôtes strictement nécessaires à l'autofill — et le modèle
  `optional_permissions` pour le reste.
- **Presse-papiers** : l'effacement différé du presse-papiers passe par un
  document offscreen (`offscreen`), le service worker MV3 n'ayant pas accès au
  DOM.

## 5. Premier lancement

- Champ serveur validé immédiatement (`new URL`, HTTPS exigé — HTTP toléré
  pour localhost) avec message explicite.
- Bouton « tester la connexion » = un simple `prelogin`.
- Positionnement affiché : auto-hébergé, aucun service tiers contacté, ni
  télémétrie, ni icônes distantes.
- `deviceIdentifier` : UUID généré une fois, persisté dans
  `chrome.storage.local` — le régénérer crée une session serveur par connexion.
- `deviceType` : fixé par la cible de build (Chrome / Firefox).

## 6. Différenciants retenus

- Badge : nombre de correspondances pour l'onglet actif.
- Copie automatique du TOTP après remplissage (payant chez Bitwarden).
- Budget de poids : popup < 50 Ko, total < 300 Ko (cf. README) — chaque ajout
  d'interface se mesure avec `npm run size`.
