# Décisions d'ergonomie et de sécurité de l'extension

Ce document fixe les décisions de conception de l'extension **avant** que le
code d'interface n'existe, avec le même sérieux que `CRYPTO.md` fixe le schéma
cryptographique. Chaque section énonce une règle et sa raison ; s'en écarter
demandera un argument, pas un oubli.

---

## 1. Déverrouillage

**Cible : la dérivation s'exécute dans le service worker, jamais dans la
popup.** ⏳ *Non encore implémenté — aujourd'hui `unlock()` tourne dans la
popup, qui détient donc la clé.* Fermer la popup ne doit pas annuler un
déverrouillage en cours, et le matériel de clé n'a rien à faire dans un contexte
d'interface. La popup enverra le mot de passe au worker, affichera la
progression, et recevra un signal de succès — pas de clé.

Ce déplacement n'est pas un réglage mais une refonte : « popup sans clé »
implique que **chaque** déchiffrement devienne un aller-retour vers le worker,
donc une couche de messages sur tout le chemin de données. C'est pourquoi il
attend une couverture de tests de l'interface plutôt que d'être tenté à l'aveugle
— et c'est aussi ce qui bloque le raccourci d'autofill (§4 ter).

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
  fermeture du navigateur ⇒ verrouillage, gratuitement. **C'est le défaut** —
  `autoLockMinutes = 0` — et c'est le comportement attendu par qui vient de
  l'extension officielle.
- Un délai d'inactivité optionnel se superpose à cette garantie. « Inactivité »
  signifie *navigateur* inactif, pas *popup* fermée : un utilisateur qui change
  d'onglet et navigue est actif. Compter le temps depuis la dernière ouverture
  de popup redemandait le mot de passe en plein travail — le reproche récurrent
  fait à la version précédente.
- Le service worker en est le seul propriétaire (`background/main.ts`) : il
  écoute `tabs.onActivated`, `windows.onFocusChanged` et `tabs.onUpdated` (sur
  l'onglet au premier plan uniquement, pour qu'une page d'arrière-plan qui se
  rafraîchit ne maintienne pas le coffre ouvert), et enregistre un horodatage
  dans `chrome.storage.session`. La popup ouverte y ajoute son propre battement.
- L'alarme `chrome.alarms` — le seul minuteur qui survit à la mort du service
  worker MV3 — est un **battement d'une minute**, pas une échéance : la
  recréer à chaque événement d'activité se heurterait à la limitation de débit.
  Contrepartie assumée : le verrouillage peut tarder d'au plus une minute.
  La règle de décision est `shouldAutoLock()`, pure et testée.
- Le verrouillage de la session du système (`chrome.idle`, état `locked` :
  écran de verrouillage, veille) verrouille immédiatement, quel que soit le
  délai — c'est ce filet qui rend le défaut « fermeture du navigateur »
  tenable, puisqu'on s'éloigne d'une machine bien plus souvent qu'on ne ferme
  son navigateur. Réglage `lockOnSystemLock`, activé par défaut. L'état `idle`
  (aucune saisie depuis quelques minutes) ne verrouille **pas** : il ne dit
  rien de la présence de l'utilisateur, qui peut lire son écran.
- Verrouiller = `userKey.destroy()` **et** purge de `chrome.storage.session`
  **et** purge de l'état de la popup. Les trois, systématiquement, et d'un seul
  geste : `lockVault()` porte la liste du stockage, `resetVaultState()` celle de
  la mémoire. La seconde n'est pas cosmétique — le code à usage unique affiché
  retient le secret TOTP déchiffré *et* un minuteur qui le recalcule chaque
  seconde, le générateur retient sa production, et le formulaire d'édition le
  mot de passe de l'item ouvert. Rien de tout cela n'est visible après
  verrouillage : c'est précisément ce qui rend l'oubli facile.
- Limite du filet « session du système verrouillée » : il dépend de la remontée
  de l'état `locked` par `chrome.idle`, que tous les environnements de bureau
  n'émettent pas (notamment selon le gestionnaire de session sous Linux). Là où
  l'événement ne vient pas, le défaut `autoLockMinutes = 0` laisse le coffre
  ouvert tant que le navigateur vit — un délai d'inactivité explicite est alors
  le seul recours.
- Le jeton d'accès expirant (~1 h) se renouvelle par `refreshToken()` — jamais
  en redemandant le mot de passe. Les jetons renouvelés sont enregistrés
  **avant** l'écriture qu'ils autorisent : un serveur qui fait tourner les
  jetons de rafraîchissement a déjà invalidé l'ancien, et ne rien enregistrer
  ferait payer un échec réseau d'un déverrouillage complet.

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
- **Presse-papiers écrasé ~30 s** après la copie d'un secret, par **deux**
  mécanismes délibérément redondants : un minuteur dans la popup, qui respecte le
  délai exact tant qu'elle vit, et une alarme `chrome.alarms` qui lui survit et
  déclenche un document hors écran (`src/offscreen/`). La popup seule ne
  suffisait pas — son minuteur mourait avec elle, c'est-à-dire précisément quand
  l'effacement compte. Deux réserves, dites franchement : Chrome ramène toute
  alarme à trente secondes minimum, donc le réglage « 10 secondes » n'est tenu
  que par la popup ; et `execCommand('copy')` ignorant une sélection vide, le
  presse-papiers est **écrasé par une espace**, non vidé. L'effet utile est le
  même, le mot juste n'est pas « effacé ». Verrouiller déclenche l'écrasement
  immédiatement.
- Mot de passe masqué par défaut ; révélation sur geste explicite.
- **Garde par item (`reprompt`).** Un item marqué « redemander le mot de passe
  maître » côté Bitwarden ne livre rien — copie, révélation, code à usage
  unique, remplissage, édition — sans une nouvelle saisie. Trois points de
  conception :
  - la garde se pose **avant** `detailsOf`, donc avant tout déchiffrement : un
    secret protégé n'est pas déchiffré puis caché, il n'est pas déchiffré ;
  - `reprompt` est porté par `CipherOverview`, précisément pour que la garde
    soit lisible sans rien déchiffrer ;
  - la vérification est **hors réseau** : la clé maître est redérivée depuis la
    saisie et comparée au hash local conservé au déverrouillage
    (`verifyLocalPasswordHash`, comparaison à temps constant). Faire valider un
    `reprompt` par le serveur donnerait à qui contrôle le réseau le pouvoir de
    le désarmer.

  Refermer un code ou masquer un mot de passe n'est pas gardé : seule la sortie
  d'un secret l'est.
- **Code à usage unique sur la ligne.** Les items porteurs d'un secret TOTP
  affichent un bouton horloge ; un clic déchiffre le secret, affiche le code
  avec son décompte et le copie. Le code est **recalculé** à chaque seconde à
  partir de l'horloge, jamais décompté : un minuteur JavaScript dérive, et la
  popup peut être gelée — afficher un code périmé serait pire que ne rien
  afficher. `hasTotp` se déduit de la présence du champ chiffré, donc la liste
  sait où poser le bouton sans déchiffrer un secret que personne n'a demandé.
- **Générateur de mots de passe** (`core/generator`), ouvert depuis l'en-tête
  ou depuis le champ mot de passe de l'édition — même panneau, deux points
  d'entrée. Tirage sans biais de modulo (rejet de la tranche incomplète),
  un caractère garanti par classe cochée, puis mélange. Options persistées à
  part des paramètres d'application : la popup et la page d'options
  n'écrivent pas dans le même objet.
- **Les items récemment utilisés remontent en tête.** Copier, révéler ou
  remplir note l'usage (`markUsed`) ; l'ordre est appliqué à l'ouverture
  (`sortByLastUsed`), jamais pendant que la popup est ouverte — un item qui
  remonterait sous le curseur ferait cliquer à côté la fois suivante. Les
  items jamais utilisés gardent l'ordre du serveur. Le journal est plafonné à
  100 entrées et effaçable depuis les options.

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

## 4 bis. Proposer d'enregistrer un identifiant saisi

Trois acteurs, aux rôles volontairement disjoints — c'est le découpage qui
tient la promesse, pas la bonne volonté de chacun :

| Acteur | Voit | Décide |
|---|---|---|
| `content/detector.ts` | Ce que l'utilisateur tape dans la page | Rien — il transmet |
| Service worker | Le réglage, l'état du coffre, la liste d'exclusion | S'il faut *retenir* la capture |
| Popup | Le coffre déchiffré | S'il faut *proposer*, et quoi |

Le détecteur n'a pas la clé et ne connaît pas le coffre ; le worker non plus.
Seule la popup peut dire « ce mot de passe y est déjà » — d'où le fait qu'elle
tranche, à son ouverture, entre trois issues : rien à proposer (même
identifiant, même mot de passe sur cette origine — la connexion ordinaire,
passée sous silence, sans quoi la pastille s'allumerait à chaque connexion et
ne voudrait plus rien dire), mise à jour, ou création.

- **Signal unique : une pastille sur l'icône.** Rien n'est injecté dans la
  page — pas de barre, pas de CSS à isoler, aucune interface qu'un site
  hostile puisse lire, recouvrir ou imiter. Contrepartie assumée : il faut
  ouvrir la popup pour voir la proposition.
- **Détecteur enregistré dynamiquement** (`chrome.scripting`), pas déclaré
  dans le manifest : réglage décoché, il n'y a aucun script dans les pages —
  pas un script qui se tait. La différence entre une promesse et une garantie.
- **Rien ne part sans un clic.** La capture attend ; « Ignorer » la jette,
  « Ne plus proposer ici » ajoute l'hôte à une liste d'exclusion locale.
- **Coffre verrouillé : la capture est refusée**, pas mise en file. Garder un
  mot de passe en clair en mémoire pendant que tout le reste est purgé
  contredirait le §2.
- **Mise à jour non destructrice.** Seul le mot de passe change ; nom,
  dossier, notes, TOTP et champs personnalisés sont repris, et l'ancien mot de
  passe rejoint l'historique.
- **Rapprochement par origine stricte** (`findSaveCandidate`), jamais par
  domaine : un rapprochement laxiste n'afficherait pas une mauvaise ligne, il
  écraserait un mot de passe valide depuis un site voisin.

- **L'identifiant est deviné, jamais garanti.** Aucun site n'est obligé de
  l'annoncer (`autocomplete="username"`). La règle de repli — le dernier champ
  texte rempli avant le mot de passe — se trompe sur les mises en page tordues,
  et l'utilisateur corrige alors dans la popup. Une seule erreur de devinette
  était inacceptable : reprendre le mot de passe lui-même. Le motif « afficher
  le mot de passe » à deux champs (un `password` et un `text` miroir dont le site
  bascule la visibilité) plaçait un champ texte rempli, visible, juste avant le
  champ mot de passe — le candidat parfait pour la règle de proximité. L'item
  créé portait alors le mot de passe en clair dans son champ identifiant. Un
  candidat dont la valeur est exactement le mot de passe est désormais écarté,
  ainsi qu'un champ que le site annonce comme mot de passe.

Limites connues : cadre principal seulement, et les connexions sans `<form>`
ni bouton identifiable échappent au détecteur. Un identifiant manqué se
rattrape à la main ; un identifiant capturé à tort ne coûte qu'un « Ignorer ».

## 4 ter. Raccourcis clavier — parité avec l'extension officielle

Les raccourcis reprennent ceux de l'extension officielle (relevés dans son
manifest 2026.7.0). Seuls sont déclarés ceux qui **peuvent aboutir sans la clé du
coffre**, que le service worker ne détient pas : déclarer un raccourci qui ne
fait rien serait pire que ne pas le déclarer.

| Commande | Raccourci | État |
|---|---|---|
| Ouvrir la popup | `Ctrl+Shift+Y` (`Ctrl+Shift+U` sous Linux) | ✅ `_execute_action` |
| Générer un mot de passe et le copier | `Ctrl+Shift+9` | ✅ engendrer ne demande aucune clé |
| Verrouiller le coffre | sans défaut, configurable | ✅ purge, aucune clé requise |
| Autofill identifiants | `Ctrl+Shift+L` | ⏳ exige la clé dans le worker (§1) |

## 4 quater. Manifest — notes relevées sur l'extension officielle

- **CSP** : exécuter du WASM en MV3 exige
  `script-src 'self' 'wasm-unsafe-eval'`. Le module Argon2id (hash-wasm) en a
  besoin — sans cette directive, le déverrouillage Argon2id échouera en
  production alors qu'il passe en tests Node.
- **Permissions** : l'officielle demande 16 permissions dont `webRequest`,
  `tabs`, `unlimitedStorage` et `http(s)://*/*`. Zwarden vise le minimum :
  `storage`, `alarms`, `idle`, `offscreen`, `activeTab`, `scripting`,
  `clipboardWrite`,
  plus les hôtes strictement nécessaires à l'autofill — et le modèle
  `optional_permissions` pour le reste. `idle` ne donne que les transitions
  actif / inactif / verrouillé de la session : elle sert au verrouillage sur
  écran verrouillé, rien d'autre. Le suivi de l'activité de navigation se
  contente des événements `tabs` et `windows` accessibles sans permission —
  d'où l'absence de `tabs`, dont l'unique apport serait de lire les URL.
- **Presse-papiers** : l'effacement différé passe par un document offscreen
  (`offscreen`), le service worker MV3 n'ayant pas accès au DOM. Implémenté —
  voir §3.

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
